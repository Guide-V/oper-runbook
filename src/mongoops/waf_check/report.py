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
    attestations_path: str = ""
    generated_at: str = ""

    def resolved_time(self) -> str:
        return self.generated_at or datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


@dataclass(frozen=True, slots=True)
class ClusterReport:
    """One scored cluster inside a project run."""

    scope: Scope
    results: tuple[CheckResult, ...]


@dataclass(frozen=True, slots=True)
class ProjectScope:
    """What a ``--all-clusters`` run scored."""

    project_id: str
    clusters: tuple[str, ...] = ()
    policy_profile: str = ""
    policy_path: str = ""
    attestations_path: str = ""
    generated_at: str = ""

    def resolved_time(self) -> str:
        return self.generated_at or datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def project_results(reports: Sequence[ClusterReport]) -> tuple[CheckResult, ...]:
    """Every auto result of every cluster, plus the discussion items once (they are
    project-level and identical across clusters). This is what totals and the gate see."""
    auto = tuple(r for rep in reports for r in rep.results if r.kind is Kind.AUTO)
    discuss = tuple(r for r in reports[0].results if r.kind is Kind.DISCUSS) if reports else ()
    return auto + discuss


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
    return json.dumps(
        {
            "framework": "atlas-well-architected",
            "catalog": CATALOG_VERSION,
            **json_payload(results, scope),
        },
        indent=2,
        ensure_ascii=False,
        default=_jsonable,
    )


def json_payload(
    results: Sequence[CheckResult], scope: Scope, *, include_discuss: bool = True
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "scope": {**asdict(scope), "generated_at": scope.resolved_time()},
        "summary": {"by_status": count_by_status(results), "by_pillar": count_by_pillar(results)},
        "checks": [r.to_dict() for r in sort_results(results) if r.kind is Kind.AUTO],
    }
    if include_discuss:
        payload["discuss"] = [discuss_entry(r) for r in results if r.kind is Kind.DISCUSS]
    return payload


def render_project(
    reports: Sequence[ClusterReport], scope: ProjectScope, *, fmt: OutputFormat
) -> str:
    if fmt == "json":
        return render_project_json(reports, scope)
    if fmt == "html":
        from mongoops.waf_check.html_report import render_project_html

        return render_project_html(reports, scope)
    return render_project_table(reports, scope)


def render_project_json(reports: Sequence[ClusterReport], scope: ProjectScope) -> str:
    """Project roll-up plus one per-cluster payload each (same shape as the single-cluster JSON
    minus ``discuss``, which appears once at the top level)."""
    everything = project_results(reports)
    payload: dict[str, Any] = {
        "framework": "atlas-well-architected",
        "catalog": CATALOG_VERSION,
        "scope": {**asdict(scope), "generated_at": scope.resolved_time()},
        "summary": {
            "by_status": count_by_status(everything),
            "by_cluster": {
                rep.scope.cluster: count_by_status(
                    tuple(r for r in rep.results if r.kind is Kind.AUTO)
                )
                for rep in reports
            },
        },
        "clusters": [
            json_payload(rep.results, rep.scope, include_discuss=False) for rep in reports
        ],
        "discuss": [discuss_entry(r) for r in everything if r.kind is Kind.DISCUSS],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False, default=_jsonable)


def render_project_table(reports: Sequence[ClusterReport], scope: ProjectScope) -> str:
    console = Console(record=True, width=200, file=io.StringIO(), force_terminal=False)
    everything = project_results(reports)
    counts = count_by_status(everything)
    console.print(
        f"WAF readiness for project {scope.project_id}: {len(reports)} cluster(s), "
        f"policy {scope.policy_profile or 'defaults'}"
    )
    console.print(
        "  ".join(
            f"{s.value} {counts[s.value]}"
            for s in (Status.FAIL, Status.WARN, Status.UNKNOWN, Status.PASS, Status.NA)
        )
    )
    console.print(_rollup_table(reports))
    actions = cluster_actions(reports)
    if actions:
        console.print(_project_actions_table(actions))
    discuss = tuple(r for r in everything if r.kind is Kind.DISCUSS)
    if discuss:
        console.print(_discuss_table(discuss))
    return console.export_text()


def cluster_actions(reports: Sequence[ClusterReport]) -> tuple[tuple[str, CheckResult], ...]:
    """``(cluster, result)`` for every FAIL / WARN auto check, worst first then by cluster."""
    pairs = tuple(
        (rep.scope.cluster, r)
        for rep in reports
        for r in rep.results
        if r.kind is Kind.AUTO and r.status in ACTION_STATUSES
    )
    return tuple(sorted(pairs, key=lambda p: (STATUS_ORDER[p[1].status], p[0])))


def _rollup_table(reports: Sequence[ClusterReport]) -> Table:
    t = Table(title=f"Clusters ({len(reports)})", show_lines=False)
    for col in ("cluster", "tier", "mongodb", "FAIL", "WARN", "UNKNOWN", "PASS", "NA/off"):
        t.add_column(col, justify="right" if col.isupper() or col == "NA/off" else "left")
    for rep in reports:
        c = count_by_status(tuple(r for r in rep.results if r.kind is Kind.AUTO))
        t.add_row(
            rep.scope.cluster,
            rep.scope.tier or "?",
            rep.scope.version or "?",
            f"[{_STATUS_STYLE[Status.FAIL]}]{c['FAIL']}[/]" if c["FAIL"] else "0",
            f"[{_STATUS_STYLE[Status.WARN]}]{c['WARN']}[/]" if c["WARN"] else "0",
            str(c["UNKNOWN"]),
            str(c["PASS"]),
            str(c["NA"] + c["SKIPPED"]),
        )
    return t


def _project_actions_table(actions: Sequence[tuple[str, CheckResult]]) -> Table:
    t = Table(title=f"Action needed across clusters ({len(actions)})", show_lines=False)
    for col in ("cluster", "status", "id", "check", "finding", "what to do"):
        t.add_column(col, overflow="fold")
    for cluster, r in actions:
        t.add_row(
            cluster,
            f"[{_STATUS_STYLE[r.status]}]{r.status.value}[/]",
            r.id,
            r.title,
            r.message,
            r.remedy,
        )
    return t


def discuss_entry(r: CheckResult) -> dict[str, Any]:
    """A discussion item for JSON: the open question, or the attestation that settled it."""
    return {
        "id": r.id,
        "pillar": r.pillar.value,
        "title": r.title,
        "status": r.status.value,
        "what": r.message,
        "doc": r.doc,
        **{k: r.evidence[k] for k in ("owner", "date", "note", "expired") if k in r.evidence},
    }


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
    open_items = sum(1 for r in results if r.status is Status.DISCUSS)
    t = Table(
        title=f"Discuss these ({open_items} open of {len(results)}): not visible to the API",
        show_lines=False,
    )
    for col in ("status", "id", "pillar", "topic", "what to settle / decision"):
        t.add_column(col, overflow="fold")
    for r in results:
        t.add_row(
            f"[{_STATUS_STYLE[r.status]}]{r.status.value}[/]",
            r.id,
            PILLAR_LABEL[r.pillar],
            r.title,
            r.message + attested_by(r),
        )
    return t


def attested_by(r: CheckResult) -> str:
    """`` (owner, date)`` suffix for an attested discussion item, else empty. Pure."""
    if "owner" not in r.evidence:
        return ""
    return f" ({r.evidence['owner']}, {r.evidence['date']})"
