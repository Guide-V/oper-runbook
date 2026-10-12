"""Render findings as a rich table, CSV, JSON or a self-contained HTML dashboard."""

from __future__ import annotations

import csv
import io
import json
from collections.abc import Iterable, Sequence
from dataclasses import fields
from datetime import UTC, tzinfo
from typing import Any, Literal

from rich.console import Console
from rich.table import Table
from rich.text import Text

from mongoops.common.timeutil import display_timestamp, format_duration_ms
from mongoops.regex_finder.analyze import Finding
from mongoops.regex_finder.hotspots import (
    CollectionSpot,
    DatabaseSpot,
    flat_collections,
    headline,
    hotspots,
)
from mongoops.regex_finder.html_report import ReportMeta, render_html
from mongoops.regex_finder.remedy import NO_ACTION, REMEDY_LABEL
from mongoops.regex_finder.summary import CATEGORY_ADVICE, SummaryRow, evidence, summarize

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
View = Literal["summary", "details", "both", "hotspots"]


def render(
    findings: Sequence[Finding],
    *,
    fmt: OutputFormat,
    view: View,
    max_detail_rows: int | None = None,
    meta: ReportMeta | None = None,
) -> str:
    """Render findings in the requested format. Pure: returns a string, never prints.

    ``meta`` describes where the data came from; the dashboard shows it and the table uses its
    display zone. CSV and JSON keep the log's UTC timestamps.
    """
    summary = summarize(findings)
    spots = hotspots(findings, summary)
    if fmt == "json":
        return _render_json(findings, summary, spots, view)
    if fmt == "csv":
        return _render_csv(findings, summary, spots, view)
    if fmt == "html":
        return render_html(findings, summary, meta or ReportMeta(source="unknown", target=""))
    tz = meta.display_tz if meta else UTC
    return _render_table(findings, summary, spots, view, max_detail_rows, tz)


def _render_json(
    findings: Sequence[Finding],
    summary: Sequence[SummaryRow],
    spots: Sequence[DatabaseSpot],
    view: View,
) -> str:
    payload: dict[str, Any] = {}
    if view in ("summary", "both", "hotspots"):
        payload["headline"] = headline(findings, summary, spots)
        payload["hotspots"] = [d.to_dict() for d in spots]
    if view in ("summary", "both"):
        payload["summary"] = [r.to_dict() for r in summary]
    if view in ("details", "both"):
        payload["findings"] = [f.to_dict() for f in findings]
    return json.dumps(payload, indent=2, ensure_ascii=False)


def _render_csv(
    findings: Sequence[Finding],
    summary: Sequence[SummaryRow],
    spots: Sequence[DatabaseSpot],
    view: View,
) -> str:
    # CSV cannot hold two tables; "both" falls back to details (the summary is derivable).
    rows: Iterable[dict[str, Any]]
    if view == "summary":
        rows, header = (r.to_dict() for r in summary), [f.name for f in fields(SummaryRow)]
    elif view == "hotspots":
        rows = (c.to_dict() for c in flat_collections(spots))
        header = [f.name for f in fields(CollectionSpot)]
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
    spots: Sequence[DatabaseSpot],
    view: View,
    max_detail_rows: int | None,
    tz: tzinfo,
) -> str:
    console = Console(record=True, width=200, file=io.StringIO(), force_terminal=False)
    if not findings:
        console.print("No $regex usage found in the analysed slow queries.")
        return console.export_text()
    if view in ("summary", "both", "hotspots"):
        console.print(Text(headline(findings, summary, spots)), soft_wrap=True)
        console.print()
        console.print(_hotspots_table(spots))
    if view in ("summary", "both"):
        _print_actions(console, summary, tz)
        console.print(_summary_table(summary))
    if view in ("details", "both"):
        console.print(_details_table(findings, max_detail_rows, tz))
    return console.export_text()


def _hotspots_table(spots: Sequence[DatabaseSpot]) -> Table:
    t = Table(title="Where the regex time goes", title_justify="left")
    t.add_column("database / collection", overflow="fold")
    for col in ("time", "share", "ops", "shapes", "to fix"):
        t.add_column(col, justify="right")
    t.add_column("main fix")
    for d in spots:
        t.add_row(*_cells(d.database, *_spot_numbers(d), ""), style="bold")
        for c in d.collections:
            fix = "" if c.main_remedy in NO_ACTION else str(c.main_remedy)
            t.add_row(*_cells(f"  {c.collection}", *_spot_numbers(c), fix))
    return t


def _spot_numbers(spot: DatabaseSpot | CollectionSpot) -> tuple[str, ...]:
    return (
        format_duration_ms(spot.total_ms),
        f"{spot.share_pct:.0f}%",
        f"{spot.ops:,}",
        str(spot.shapes),
        str(spot.to_fix),
    )


def _print_actions(console: Console, summary: Sequence[SummaryRow], tz: tzinfo) -> None:
    work = tuple(r for r in summary if r.remedy not in NO_ACTION)
    console.print()
    console.print(Text("What to do, biggest win first", style="bold"))
    if not work:
        console.print(Text("  Nothing to fix: every shape is index-friendly or too small yet."))
    for i, r in enumerate(work, 1):
        console.print()
        for line in _action_lines(i, r, tz):
            console.print(Text(line), soft_wrap=True)
    quiet = len(summary) - len(work)
    if quiet:
        console.print()
        console.print(Text(f"  {quiet} more shape(s) need no action now (see the table below)."))
    console.print()


def _action_lines(i: int, r: SummaryRow, tz: tzinfo) -> tuple[str, ...]:
    cost = ", ".join(
        p
        for p in (
            f"{format_duration_ms(r.total_ms)} ({r.share_pct:.0f}% of regex time)",
            f"{r.ops:,} op(s)",
            f"last seen {display_timestamp(r.last_seen, tz)}" if r.last_seen else "",
            f"app {r.apps}" if r.apps else "",
        )
        if p
    )
    pad = " " * (len(str(i)) + 3)
    return (
        f" {i}. {r.namespace}  {r.field}  ({r.command}, {r.category})  "
        f"/{r.sample_pattern}/{r.sample_options}",
        f"{pad}{cost}",
        f"{pad}Why: {evidence(r)}",
        f"{pad}Fix: {REMEDY_LABEL[r.remedy]} [{r.effort}]. {r.remedy_how}",
        *(f"{pad}  {line}" for line in r.fix_snippet.splitlines()),
    )


def _summary_table(summary: Sequence[SummaryRow]) -> Table:
    t = Table(title=f"$regex usage summary ({len(summary)} shapes)", show_lines=False)
    for col in (
        "namespace",
        "field",
        "cmd",
        "category",
        "remedy",
        "ops",
        "time",
        "share",
        "max ms",
        "scanned/ret",
        "collscan",
        "sample pattern",
        "opts",
    ):
        t.add_column(col, overflow="fold")
    for r in summary:
        t.add_row(
            *_cells(
                r.namespace,
                r.field,
                r.command,
                str(r.category),
                str(r.remedy),
                str(r.ops),
                format_duration_ms(r.total_ms),
                f"{r.share_pct:.0f}%",
                str(r.max_duration_ms),
                f"{r.scanned_per_returned:,.0f}",
                str(r.collscan_count),
                r.sample_pattern,
                r.sample_options,
            )
        )
    return t


def _details_table(findings: Sequence[Finding], max_rows: int | None, tz: tzinfo) -> Table:
    shown = findings if max_rows is None else findings[:max_rows]
    suffix = "" if len(shown) == len(findings) else f", showing first {len(shown)}"
    t = Table(title=f"$regex findings ({len(findings)}{suffix})")
    t.add_column("time", no_wrap=True)
    for col in (
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
            *_cells(
                display_timestamp(f.timestamp, tz),
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
        )
    return t


def _cells(*values: str) -> tuple[Text, ...]:
    """Plain-text cells: log content such as ``[a-z]`` must not be read as Rich markup."""
    return tuple(Text(v) for v in values)


def _s(value: int | None) -> str:
    return "" if value is None else str(value)
