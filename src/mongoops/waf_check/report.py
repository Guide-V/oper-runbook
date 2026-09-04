"""Render check results as a rich table, JSON or the self-contained HTML scorecard. Pure."""

from __future__ import annotations

import io
import json
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any, Literal

from rich.console import Console
from rich.table import Table

from mongoops.waf_check.catalog import CATALOG_VERSION
from mongoops.waf_check.model import (
    PILLAR_LABEL,
    STATUS_ORDER,
    CheckResult,
    Kind,
    Pillar,
    Status,
)

OutputFormat = Literal["table", "json", "html"]

ACTION_STATUSES = (Status.FAIL, Status.WARN)


@dataclass(frozen=True, slots=True)
class Scope:
    """What was scored; shown in the header of every format."""

    cluster: str
    project_id: str
    provider: str = ""
    tier: str = ""
    version: str = ""
    policy_profile: str = ""
    policy_path: str = ""
    generated_at: str = ""

    def resolved_time(self) -> str:
        return self.generated_at or datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def sort_results(results: Sequence[CheckResult]) -> tuple[CheckResult, ...]:
    """Worst status first, catalog order within a status (stable sort)."""
    return tuple(sorted(results, key=lambda r: STATUS_ORDER[r.status]))


def count_by_status(results: Sequence[CheckResult]) -> dict[str, int]:
    return {s.value: sum(1 for r in results if r.status is s) for s in Status}


def count_by_pillar(results: Sequence[CheckResult]) -> dict[str, dict[str, int]]:
    return {
        p.value: {
            s.value: sum(1 for r in results if r.pillar is p and r.status is s)
            for s in (Status.FAIL, Status.WARN, Status.UNKNOWN, Status.PASS, Status.DISCUSS)
        }
        for p in Pillar
    }


def render(results: Sequence[CheckResult], scope: Scope, *, fmt: OutputFormat) -> str:
    if fmt == "json":
        return render_json(results, scope)
    if fmt == "html":
        from mongoops.waf_check.html_report import render_html  # keep the import graph lazy

        return render_html(results, scope)
    return render_table(results, scope)


def render_json(results: Sequence[CheckResult], scope: Scope) -> str:
    payload: dict[str, Any] = {
        "framework": "atlas-well-architected",
        "catalog": CATALOG_VERSION,
        "scope": {**asdict(scope), "generated_at": scope.resolved_time()},
        "summary": {"by_status": count_by_status(results), "by_pillar": count_by_pillar(results)},
        "checks": [r.to_dict() for r in sort_results(results) if r.kind is Kind.AUTO],
        "discuss": [
            {
                "id": r.id,
                "pillar": r.pillar.value,
                "title": r.title,
                "what": r.message,
                "doc": r.doc,
            }
            for r in results
            if r.kind is Kind.DISCUSS
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False, default=_jsonable)


def _jsonable(value: Any) -> Any:
    if isinstance(value, tuple | set | frozenset):
        return list(value)
    if isinstance(value, Mapping):
        return dict(value)
    return str(value)


def render_table(results: Sequence[CheckResult], scope: Scope) -> str:
    console = Console(record=True, width=200, file=io.StringIO(), force_terminal=False)
    counts = count_by_status(results)
    console.print(
        f"WAF readiness for cluster {scope.cluster} (project {scope.project_id}, "
        f"{scope.tier or '?'} {scope.provider or ''} MongoDB {scope.version or '?'}, "
        f"policy {scope.policy_profile or 'defaults'})"
    )
    console.print(
        "  ".join(
            f"{s.value} {counts[s.value]}"
            for s in (
                Status.FAIL,
                Status.WARN,
                Status.UNKNOWN,
                Status.PASS,
                Status.NA,
                Status.SKIPPED,
            )
        )
    )
    console.print(_checks_table(tuple(r for r in sort_results(results) if r.kind is Kind.AUTO)))
    discuss = tuple(r for r in results if r.kind is Kind.DISCUSS)
    if discuss:
        console.print(_discuss_table(discuss))
    return console.export_text()


_STATUS_STYLE: Mapping[Status, str] = {
    Status.FAIL: "bold red",
    Status.WARN: "yellow",
    Status.UNKNOWN: "magenta",
    Status.PASS: "green",
    Status.NA: "dim",
    Status.SKIPPED: "dim",
    Status.DISCUSS: "cyan",
}


def _checks_table(results: Sequence[CheckResult]) -> Table:
    t = Table(title=f"Checks ({len(results)})", show_lines=False)
    for col in ("status", "id", "pillar", "check", "finding", "what to do"):
        t.add_column(col, overflow="fold")
    for r in results:
        t.add_row(
            f"[{_STATUS_STYLE[r.status]}]{r.status.value}[/]",
            r.id,
            PILLAR_LABEL[r.pillar],
            r.title,
            r.message,
            r.remedy,
        )
    return t


def _discuss_table(results: Sequence[CheckResult]) -> Table:
    t = Table(title=f"Discuss these ({len(results)}): not visible to the API", show_lines=False)
    for col in ("id", "pillar", "topic", "what to settle"):
        t.add_column(col, overflow="fold")
    for r in results:
        t.add_row(r.id, PILLAR_LABEL[r.pillar], r.title, r.message)
    return t
