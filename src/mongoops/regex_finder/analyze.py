"""Join parsed slow queries with detected regex usages into flat, immutable `Finding` records."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import asdict, dataclass
from typing import Any

from mongoops.common.mongolog import SlowQuery, parse_log_line
from mongoops.regex_finder.detector import (
    RegexCategory,
    RegexUsage,
    find_regex_usages,
    find_regex_usages_legacy,
)
from mongoops.regex_finder.remedy import Remedy, recommend, with_field


@dataclass(frozen=True, slots=True)
class SourceLine:
    """A raw log line plus where it came from (process id, host, file...)."""

    line: str
    origin: str
    namespace_hint: str | None = None


@dataclass(frozen=True, slots=True)
class Finding:
    """One regex usage inside one slow operation. Flat so it serialises directly to CSV/JSON."""

    origin: str
    timestamp: str | None
    namespace: str | None
    command: str | None
    field: str
    pattern: str
    options: str
    category: RegexCategory
    operator: str
    path: str
    plan_summary: str | None
    duration_ms: int | None
    keys_examined: int | None
    docs_examined: int | None
    nreturned: int | None
    app_name: str | None
    query_hash: str | None
    truncated: bool
    log_format: str
    remedy: Remedy
    remedy_how: str

    def to_dict(self) -> dict[str, Any]:
        return {**asdict(self), "category": str(self.category), "remedy": str(self.remedy)}


@dataclass(frozen=True, slots=True)
class AnalyzeOptions:
    include_getmore: bool = False
    namespaces: frozenset[str] = frozenset()
    min_duration_ms: int = 0


def analyze_lines(lines: Iterable[SourceLine], opts: AnalyzeOptions) -> Iterator[Finding]:
    """Lazily turn raw log lines into regex findings, applying the filters in ``opts``."""
    for src in lines:
        slow = parse_log_line(src.line)
        if slow is None or not _passes(slow, src, opts):
            continue
        yield from findings_for(slow, src.origin)


def findings_for(slow: SlowQuery, origin: str) -> tuple[Finding, ...]:
    """All regex findings for one slow query (pure)."""
    return tuple(_finding(slow, origin, usage) for usage in regex_usages(slow))


def regex_usages(slow: SlowQuery) -> tuple[RegexUsage, ...]:
    """Detect regex usage in the command (or the originating command for getMore)."""
    if slow.log_format == "legacy":
        return find_regex_usages_legacy(slow.command_text) if slow.command_text else ()
    doc = slow.originating_command if slow.command_name == "getMore" else slow.command
    return find_regex_usages(doc) if doc is not None else ()


def _passes(slow: SlowQuery, src: SourceLine, opts: AnalyzeOptions) -> bool:
    if not opts.include_getmore and slow.command_name == "getMore":
        return False
    ns = slow.namespace or src.namespace_hint
    if opts.namespaces and ns not in opts.namespaces:
        return False
    return (slow.duration_ms or 0) >= opts.min_duration_ms


def _finding(slow: SlowQuery, origin: str, usage: RegexUsage) -> Finding:
    rec = with_field(
        recommend(
            category=usage.category,
            command=slow.command_name,
            pattern=usage.pattern,
            options=usage.options,
            plan_summary=slow.plan_summary,
            keys_examined=slow.keys_examined,
            docs_examined=slow.docs_examined,
            nreturned=slow.nreturned,
            operator=usage.operator,
            path=usage.path,
        ),
        usage.field,
    )
    return Finding(
        origin=origin,
        timestamp=slow.timestamp,
        namespace=slow.namespace,
        command=slow.command_name,
        field=usage.field,
        pattern=usage.pattern,
        options=usage.options,
        category=usage.category,
        operator=usage.operator,
        path=usage.path,
        plan_summary=slow.plan_summary,
        duration_ms=slow.duration_ms,
        keys_examined=slow.keys_examined,
        docs_examined=slow.docs_examined,
        nreturned=slow.nreturned,
        app_name=slow.app_name,
        query_hash=slow.query_hash,
        truncated=slow.truncated,
        log_format=slow.log_format,
        remedy=rec.remedy,
        remedy_how=rec.how,
    )
