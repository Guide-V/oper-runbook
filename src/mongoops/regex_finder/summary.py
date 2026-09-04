"""Group findings into per-shape summary rows, worst first. Shared by every renderer."""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from typing import Any

from mongoops.regex_finder.analyze import Finding
from mongoops.regex_finder.detector import RegexCategory
from mongoops.regex_finder.remedy import REMEDY_ORDER, Remedy

CATEGORY_ADVICE: dict[RegexCategory, str] = {
    RegexCategory.PREFIX: "OK: case-sensitive prefix, index range scan possible",
    RegexCategory.ANCHORED: "Anchored but non-literal start: full index scan",
    RegexCategory.UNANCHORED: "Unanchored: scans every index key / document",
    RegexCategory.LEADING_WILDCARD: "Leading wildcard: anchor is useless, scans everything",
    RegexCategory.CASE_INSENSITIVE: (
        "Case-insensitive: cannot use a regular index "
        "(consider a collation index or a normalised field)"
    ),
    RegexCategory.NEGATED: "Negated ($not/$nin): no index bounds, every key or document is checked",
}

# Higher = worse, used to sort summaries so the most concerning shapes surface first.
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
    collscan_count: int
    max_duration_ms: int
    avg_duration_ms: float
    total_docs_examined: int
    sample_pattern: str
    sample_options: str
    origins: int
    advice: str
    remedy: Remedy
    remedy_how: str

    def to_dict(self) -> dict[str, Any]:
        return {**asdict(self), "category": str(self.category), "remedy": str(self.remedy)}


def summarize(findings: Sequence[Finding]) -> tuple[SummaryRow, ...]:
    """Group findings by (namespace, field, command, category); worst categories first."""
    groups: dict[tuple[str, str, str, RegexCategory], list[Finding]] = defaultdict(list)
    for f in findings:
        groups[(f.namespace or "?", f.field, f.command or "?", f.category)].append(f)

    rows = tuple(_summary_row(key, members) for key, members in groups.items())
    return tuple(sorted(rows, key=lambda r: (-SEVERITY[r.category], -r.count, -r.max_duration_ms)))


def _summary_row(key: tuple[str, str, str, RegexCategory], members: list[Finding]) -> SummaryRow:
    namespace, field, command, category = key
    durations = [f.duration_ms or 0 for f in members]
    remedy, remedy_how = _dominant_remedy(members)
    return SummaryRow(
        namespace=namespace,
        field=field,
        command=command,
        category=category,
        count=len(members),
        collscan_count=sum(1 for f in members if "COLLSCAN" in (f.plan_summary or "")),
        max_duration_ms=max(durations, default=0),
        avg_duration_ms=round(sum(durations) / len(durations), 1) if durations else 0.0,
        total_docs_examined=sum(f.docs_examined or 0 for f in members),
        sample_pattern=members[0].pattern,
        sample_options=members[0].options,
        origins=len({f.origin for f in members}),
        advice=CATEGORY_ADVICE[category],
        remedy=remedy,
        remedy_how=remedy_how,
    )


def _dominant_remedy(members: list[Finding]) -> tuple[Remedy, str]:
    """Most frequent remedy in the group; ties go to the more involved one (it has evidence)."""
    counts = Counter(f.remedy for f in members)
    remedy = max(counts, key=lambda r: (counts[r], REMEDY_ORDER[r]))
    return remedy, next(f.remedy_how for f in members if f.remedy is remedy)
