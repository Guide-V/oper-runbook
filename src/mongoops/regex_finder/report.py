"""Render findings as a rich table, CSV, JSON or a self-contained HTML dashboard."""

from __future__ import annotations

import csv
import io
import json
from collections.abc import Iterable, Sequence
from dataclasses import fields
from typing import Any, Literal

from rich.console import Console
from rich.table import Table

from mongoops.regex_finder.analyze import Finding
from mongoops.regex_finder.html_report import ReportMeta, render_html
from mongoops.regex_finder.summary import CATEGORY_ADVICE, SummaryRow, summarize

__all__ = [
    "CATEGORY_ADVICE",
    "OutputFormat",
    "ReportMeta",
    "SummaryRow",
    "View",
    "render",
    "summarize",
]

OutputFormat = Literal["table", "csv", "json", "html"]
View = Literal["summary", "details", "both"]


def render(
    findings: Sequence[Finding],
    *,
    fmt: OutputFormat,
    view: View,
    max_detail_rows: int | None = None,
    meta: ReportMeta | None = None,
) -> str:
    """Render findings in the requested format. Pure: returns a string, never prints.

    ``meta`` describes where the data came from; only the HTML dashboard displays it.
    """
    summary = summarize(findings)
    if fmt == "json":
        return _render_json(findings, summary, view)
    if fmt == "csv":
        return _render_csv(findings, summary, view)
    if fmt == "html":
        return render_html(findings, summary, meta or ReportMeta(source="unknown", target=""))
    return _render_table(findings, summary, view, max_detail_rows)


def _render_json(findings: Sequence[Finding], summary: Sequence[SummaryRow], view: View) -> str:
    payload: dict[str, Any] = {}
    if view in ("summary", "both"):
        payload["summary"] = [r.to_dict() for r in summary]
    if view in ("details", "both"):
        payload["findings"] = [f.to_dict() for f in findings]
    return json.dumps(payload, indent=2, ensure_ascii=False)


def _render_csv(findings: Sequence[Finding], summary: Sequence[SummaryRow], view: View) -> str:
    # CSV cannot hold two tables; "both" falls back to details (the summary is derivable).
    rows: Iterable[dict[str, Any]]
    if view == "summary":
        rows, header = (r.to_dict() for r in summary), [f.name for f in fields(SummaryRow)]
    else:
        rows, header = (f.to_dict() for f in findings), [f.name for f in fields(Finding)]
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=header, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return buf.getvalue()


def _render_table(
    findings: Sequence[Finding],
    summary: Sequence[SummaryRow],
    view: View,
    max_detail_rows: int | None,
) -> str:
    console = Console(record=True, width=200, file=io.StringIO(), force_terminal=False)
    if not findings:
        console.print("No $regex usage found in the analysed slow queries.")
        return console.export_text()
    if view in ("summary", "both"):
        console.print(_summary_table(summary))
    if view in ("details", "both"):
        console.print(_details_table(findings, max_detail_rows))
    return console.export_text()


def _summary_table(summary: Sequence[SummaryRow]) -> Table:
    t = Table(title=f"$regex usage summary ({len(summary)} shapes)", show_lines=False)
    for col in (
        "namespace",
        "field",
        "cmd",
        "category",
        "count",
        "collscan",
        "max ms",
        "avg ms",
        "docs examined",
        "sample pattern",
        "opts",
        "remedy",
        "advice",
    ):
        t.add_column(col, overflow="fold")
    for r in summary:
        t.add_row(
            r.namespace,
            r.field,
            r.command,
            str(r.category),
            str(r.count),
            str(r.collscan_count),
            str(r.max_duration_ms),
            str(r.avg_duration_ms),
            str(r.total_docs_examined),
            r.sample_pattern,
            r.sample_options,
            str(r.remedy),
            r.advice,
        )
    return t


def _details_table(findings: Sequence[Finding], max_rows: int | None) -> Table:
    shown = findings if max_rows is None else findings[:max_rows]
    suffix = "" if len(shown) == len(findings) else f", showing first {len(shown)}"
    t = Table(title=f"$regex findings ({len(findings)}{suffix})")
    for col in (
        "time",
        "origin",
        "namespace",
        "cmd",
        "field",
        "pattern",
        "opts",
        "category",
        "remedy",
        "plan",
        "ms",
        "keys",
        "docs",
        "ret",
        "app",
    ):
        t.add_column(col, overflow="fold")
    for f in shown:
        t.add_row(
            f.timestamp or "",
            f.origin,
            f.namespace or "",
            f.command or "",
            f.field,
            f.pattern,
            f.options,
            str(f.category),
            str(f.remedy),
            f.plan_summary or "",
            _s(f.duration_ms),
            _s(f.keys_examined),
            _s(f.docs_examined),
            _s(f.nreturned),
            f.app_name or "",
        )
    return t


def _s(value: int | None) -> str:
    return "" if value is None else str(value)
