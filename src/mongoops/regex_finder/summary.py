"""Group findings into per-shape summary rows, costliest first. Shared by every renderer.

Ties on time (common when nothing was timed) put shapes that need work before the rest.

Cost is measured per *operation*: one slow query with two regexes is two findings but one
operation, so time and scan counters are summed over distinct ``op_id`` values.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import asdict, dataclass
from typing import Any

from mongoops.common.timeutil import timestamp_ms
from mongoops.regex_finder.analyze import Finding
from mongoops.regex_finder.detector import RegexCategory
from mongoops.regex_finder.fixes import fix_snippet
from mongoops.regex_finder.remedy import NO_ACTION, REMEDY_EFFORT, REMEDY_ORDER, Remedy

CATEGORY_ADVICE: dict[RegexCategory, str] = {
    RegexCategory.PREFIX: "OK: case-sensitive prefix, index range scan possible",
    RegexCategory.ANCHORED: "Anchored but non-literal start: full index scan",
    RegexCategory.UNANCHORED: "Unanchored: scans every index key / document",
    RegexCategory.LEADING_WILDCARD: "Leading wildcard: anchor is useless, scans everything",
    RegexCategory.CASE_INSENSITIVE: (
        "Case-insensitive: $regex cannot use any index efficiently, not even a collation index "
        "(use a lower-cased field, or an equality with a collation)"
    ),
    RegexCategory.NEGATED: "Negated ($not/$nin): no index bounds, every key or document is checked",
}

# Higher = worse; breaks ties between shapes that cost the same time.
SEVERITY: dict[RegexCategory, int] = {
    RegexCategory.PREFIX: 0,
    RegexCategory.ANCHORED: 1,
    RegexCategory.UNANCHORED: 2,
    RegexCategory.NEGATED: 3,
    RegexCategory.LEADING_WILDCARD: 4,
    RegexCategory.CASE_INSENSITIVE: 5,
}


@dataclass(frozen=True, slots=True)
class SummaryRow:
    namespace: str
    field: str
    command: str
    category: RegexCategory
    count: int
    """Regex usages (one operation can hold several)."""
    collscan_count: int
    """Operations that ran as COLLSCAN."""
    max_duration_ms: int
    avg_duration_ms: float
    total_docs_examined: int
    sample_pattern: str
    sample_options: str
    origins: int
    advice: str
    remedy: Remedy
    remedy_how: str
    ops: int = 0
    total_ms: int = 0
    share_pct: float = 0.0
    """Share of all regex time in the report (of operations when no time was logged)."""
    total_keys_examined: int = 0
    total_scanned: int = 0
    """Sum over operations of max(keys examined, docs examined)."""
    total_returned: int = 0
    scanned_per_returned: float = 0.0
    apps: str = ""
    first_seen: str = ""
    last_seen: str = ""
    effort: str = ""
    fix_snippet: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {**asdict(self), "category": str(self.category), "remedy": str(self.remedy)}


def evidence(r: SummaryRow) -> str:
    """What the log shows about a shape, in one sentence."""
    scan = (
        f"{r.total_scanned / max(r.ops, 1):,.0f} keys/docs scanned per op for "
        f"{r.total_returned / max(r.ops, 1):,.0f} returned"
        if r.total_scanned
        else "no scan counters logged"
    )
    collscan = f"COLLSCAN on {r.collscan_count} of {r.ops} op(s), " if r.collscan_count else ""
    return f"{collscan}{scan}."


def distinct_ops(findings: Iterable[Finding]) -> tuple[Finding, ...]:
    """First finding of each logged operation, in input order."""
    seen: dict[str, Finding] = {}
    for f in findings:
        seen.setdefault(f.op_id or f"{f.origin}|{f.timestamp}|{f.path}|{f.pattern}", f)
    return tuple(seen.values())


def total_ms(findings: Iterable[Finding]) -> int:
    return sum(f.duration_ms or 0 for f in distinct_ops(findings))


def share_pct(part_ms: int, part_ops: int, all_ms: int, all_ops: int) -> float:
    """Percentage of regex time, falling back to the share of operations when nothing was timed."""
    if all_ms:
        return round(100 * part_ms / all_ms, 1)
    return round(100 * part_ops / all_ops, 1) if all_ops else 0.0


def summarize(findings: Sequence[Finding]) -> tuple[SummaryRow, ...]:
    """Group findings by (namespace, field, command, category); costliest shapes first."""
    groups: dict[tuple[str, str, str, RegexCategory], list[Finding]] = defaultdict(list)
    for f in findings:
        groups[(f.namespace or "?", f.field, f.command or "?", f.category)].append(f)

    totals = (total_ms(findings), len(distinct_ops(findings)))
    rows = tuple(_summary_row(key, members, totals) for key, members in groups.items())
    return tuple(
        sorted(
            rows,
            key=lambda r: (
                -r.total_ms,
                r.remedy in NO_ACTION,
                -SEVERITY[r.category],
                -r.count,
                -r.max_duration_ms,
                r.namespace,
                r.field,
            ),
        )
    )


def _summary_row(
    key: tuple[str, str, str, RegexCategory], members: list[Finding], totals: tuple[int, int]
) -> SummaryRow:
    namespace, field, command, category = key
    ops = distinct_ops(members)
    durations = [f.duration_ms or 0 for f in ops]
    scanned = sum(max(f.keys_examined or 0, f.docs_examined or 0) for f in ops)
    returned = sum(f.nreturned or 0 for f in ops)
    sample = _dominant(members)
    seen = sorted((f for f in ops if timestamp_ms(f.timestamp) is not None), key=_seen_key)
    return SummaryRow(
        namespace=namespace,
        field=field,
        command=command,
        category=category,
        count=len(members),
        collscan_count=sum(1 for f in ops if "COLLSCAN" in (f.plan_summary or "")),
        max_duration_ms=max(durations, default=0),
        avg_duration_ms=round(sum(durations) / len(durations), 1) if durations else 0.0,
        total_docs_examined=sum(f.docs_examined or 0 for f in ops),
        sample_pattern=sample.pattern,
        sample_options=sample.options,
        origins=len({f.origin for f in members}),
        advice=CATEGORY_ADVICE[category],
        remedy=sample.remedy,
        remedy_how=sample.remedy_how,
        ops=len(ops),
        total_ms=sum(durations),
        share_pct=share_pct(sum(durations), len(ops), *totals),
        total_keys_examined=sum(f.keys_examined or 0 for f in ops),
        total_scanned=scanned,
        total_returned=returned,
        scanned_per_returned=round(scanned / max(returned, 1), 1),
        apps=", ".join(sorted({f.app_name for f in members if f.app_name})),
        first_seen=(seen[0].timestamp or "") if seen else "",
        last_seen=(seen[-1].timestamp or "") if seen else "",
        effort=REMEDY_EFFORT[sample.remedy],
        fix_snippet=fix_snippet(
            remedy=sample.remedy,
            namespace=namespace,
            field=field,
            command=command,
            category=category,
            pattern=sample.pattern,
            options=sample.options,
        ),
    )


def _seen_key(f: Finding) -> int:
    return timestamp_ms(f.timestamp) or 0


def _dominant(members: list[Finding]) -> Finding:
    """A finding carrying the group's most frequent remedy; ties go to the more involved one."""
    counts = Counter(f.remedy for f in members)
    remedy = max(counts, key=lambda r: (counts[r], REMEDY_ORDER[r]))
    return next(f for f in members if f.remedy is remedy)
