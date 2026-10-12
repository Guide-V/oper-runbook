"""Self-contained HTML dashboard for regex findings.

One file, no external assets (opens from a laptop, a ticket attachment or an air-gapped EA
jump host). Pure: ``render_html`` returns a string. Inline CSS uses the MongoDB palette; the
only JavaScript is a text filter and column sort for the findings table and copy buttons on the
fix snippets.

Reading order follows the questions an operator asks: how bad is it (headline, KPIs), where is
it (database / collection roll-up), what do I do first (numbered action plan with commands),
then the evidence (shapes, raw findings).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, tzinfo
from html import escape
from typing import Any

from mongoops import __version__
from mongoops.common.html_theme import BASE_CSS, SAFE_HARBOUR_HTML, TABLE_JS
from mongoops.common.timeutil import display_timestamp, format_duration_ms
from mongoops.regex_finder.analyze import Finding
from mongoops.regex_finder.detector import RegexCategory
from mongoops.regex_finder.hotspots import CollectionSpot, DatabaseSpot, headline, hotspots
from mongoops.regex_finder.remedy import (
    NO_ACTION,
    REMEDY_LABEL,
    REMEDY_ORDER,
    SEARCH_DEPLOYMENT_NOTE,
    Remedy,
)
from mongoops.regex_finder.summary import (
    CATEGORY_ADVICE,
    SEVERITY,
    SummaryRow,
    distinct_ops,
    evidence,
)


@dataclass(frozen=True, slots=True)
class ReportMeta:
    """Where the findings came from; shown in the dashboard header."""

    source: str  # atlas | ops-manager | logfile | live
    target: str  # cluster name, host list, file path or credential-free URI
    window: str = ""  # human description of the time window, already in display_tz
    filters: tuple[str, ...] = field(default_factory=tuple)
    generated_at: str = ""  # ISO-8601; empty = now (UTC)
    display_tz: tzinfo = UTC
    """Zone for human-facing times (table and dashboard); CSV / JSON stay UTC."""
    warnings: tuple[str, ...] = field(default_factory=tuple)
    """Data-quality caveats, e.g. a node that hit the slow-query line cap."""


# Severity 0..5 -> badge colour. Green is fine, amber needs a look, red is a scan.
_SEVERITY_CLASS = {0: "ok", 1: "warn", 2: "bad", 3: "bad", 4: "bad", 5: "bad"}

# Remedy -> badge colour: grey nothing/monitor, blue index work, amber query work, green Search.
_REMEDY_CLASS: dict[Remedy, str] = {
    Remedy.NONE: "muted",
    Remedy.MONITOR: "muted",
    Remedy.BTREE_INDEX: "index",
    Remedy.COLLATION_INDEX: "index",
    Remedy.NORMALIZED_FIELD: "index",
    Remedy.REVERSED_FIELD: "index",
    Remedy.REWRITE: "warn",
    Remedy.FIX_FILTER: "warn",
    Remedy.SEARCH: "search",
}

_REGEX_CSS = """
.chip.warn{border-color:var(--warn);background:rgba(194,124,19,.3)}.chip.warn b{color:#FFD58A}
.headline{background:var(--mist);border:1px solid var(--mist2);border-left:6px solid var(--green);
border-radius:var(--r);padding:16px 20px;font-size:16px;line-height:1.55;color:var(--evergreen);
box-shadow:var(--shadow)}
table.spots td.share{width:34%}
.spots .track{background:var(--mist);border-radius:4px;height:12px;overflow:hidden;margin-top:4px}
.spots .fill{height:100%;border-radius:4px;background:var(--forest)}
.spots tr.db td{background:var(--panel);font-weight:600;color:var(--evergreen)}
.spots tr.coll td:first-child{padding-left:30px}
ol.actions{list-style:none;margin:0;padding:0;display:grid;grid-template-columns:minmax(0,1fr);
gap:12px;counter-reset:act}
ol.actions>li{counter-increment:act;position:relative;background:#fff;border:1px solid var(--line);
border-left:5px solid var(--grey);border-radius:var(--r);padding:14px 18px 14px 60px;
box-shadow:var(--shadow)}
ol.actions>li:before{content:counter(act);position:absolute;left:16px;top:14px;width:30px;
height:30px;border-radius:50%;background:var(--evergreen);color:var(--green);font-weight:700;
display:flex;align-items:center;justify-content:center}
ol.actions>li.search{border-left-color:var(--green)}
ol.actions>li.index{border-left-color:var(--evergreen)}
ol.actions>li.warn{border-left-color:var(--warn)}
.actions .what{font-size:15px;font-weight:600}.actions .what code{margin-right:4px;font-size:13px}
.actions .cost{color:var(--grey);font-size:12px;margin-top:4px}
.actions .cost b{color:var(--evergreen);font-size:14px}
.actions .why{margin-top:8px}.actions .why b,.actions .fix b{color:var(--forest)}
.actions .fix{margin-top:8px;display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.effort{font-size:11px;border:1px solid var(--mist2);background:var(--panel);border-radius:999px;
padding:1px 9px;color:var(--grey)}
.actions .how{margin:6px 0 0}
.snippet{position:relative;margin-top:10px}
.snippet pre{margin:0;background:var(--deep);color:var(--mist);border-radius:8px;
padding:12px 70px 12px 14px;overflow-x:auto;font:12px/1.55 ui-monospace,SFMono-Regular,Menlo,
monospace}
.snippet pre code{background:none;color:inherit;padding:0;white-space:pre-wrap;
overflow-wrap:anywhere}
.snippet .copy{position:absolute;top:8px;right:8px;background:var(--green);color:var(--deep);
border:0;border-radius:999px;padding:3px 12px;font-size:11px;font-weight:700;cursor:pointer}
td.pattern{min-width:18ch}td.pattern code{word-break:normal;overflow-wrap:anywhere}
.wide{overflow-x:auto;border-radius:var(--r)}
details.quiet{margin-top:12px;background:#fff;border:1px solid var(--line);border-radius:var(--r);
padding:10px 16px}details.quiet summary{cursor:pointer;color:var(--grey)}
details.quiet li{margin:4px 0}details.quiet code{margin-right:4px}
"""

_COPY_JS = """
(function(){
  Array.prototype.forEach.call(document.querySelectorAll('button.copy'),function(b){
    b.addEventListener('click',function(){
      var text=b.parentNode.querySelector('code').textContent;
      function done(){b.textContent='Copied';setTimeout(function(){b.textContent='Copy';},1500);}
      function fallback(){var t=document.createElement('textarea');t.value=text;
        document.body.appendChild(t);t.select();
        try{document.execCommand('copy');done();}catch(e){}document.body.removeChild(t);}
      if(navigator.clipboard&&window.isSecureContext){navigator.clipboard.writeText(text).then(done,fallback);}
      else{fallback();}
    });
  });
})();
"""

_CSS = BASE_CSS + _REGEX_CSS
_JS = TABLE_JS + _COPY_JS


def render_html(
    findings: Sequence[Finding], summary: Sequence[SummaryRow], meta: ReportMeta
) -> str:
    """Build the whole dashboard as one HTML document."""
    generated = meta.generated_at or datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    tz = meta.display_tz
    spots = hotspots(findings, summary)
    body = (
        _empty_state()
        if not findings
        else "\n".join(
            (
                f'<section><div class="headline">{escape(headline(findings, summary, spots))}'
                "</div></section>",
                _kpis(findings, summary),
                _hotspots_section(spots),
                _actions_section(summary, tz),
                _summary_section(summary),
                _findings_section(findings, tz),
            )
        )
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>$regex usage: {escape(meta.target or meta.source)}</title>
<style>{_CSS}</style></head>
<body>
<header>
  <div class="brand"><i></i>MongoDB Atlas &middot; Performance</div>
  <h1><code>$regex</code> usage dashboard</h1>
  <div class="sub">mongoops regex-finder {escape(__version__)} &middot; slow queries with regular
  expressions: where the time goes and what to change first</div>
  {_chips(meta, generated)}
</header>
<main>
{body}
{_legend()}
</main>
<footer>Generated {escape(generated)} by <code>mongoops regex-finder {escape(meta.source)}</code>.
Time and scan totals count each slow operation once, even when it holds several regexes.
Fix snippets are starting points: review them and check with <code>explain()</code> before
running them in production.{SAFE_HARBOUR_HTML}</footer>
<script>{_JS}</script>
</body></html>
"""


# --- sections ----------------------------------------------------------------------------------


def _chips(meta: ReportMeta, generated: str) -> str:
    items = [("source", meta.source), ("target", meta.target)]
    if meta.window:
        items.append(("window", meta.window))
    items.extend(("filter", f) for f in meta.filters)
    items.append(("generated", generated))
    chips = "".join(
        f'<span class="chip"><b>{escape(k)}</b>{escape(v)}</span>' for k, v in items if v
    ) + "".join(f'<span class="chip warn"><b>warning</b>{escape(w)}</span>' for w in meta.warnings)
    return f'<div class="chips">{chips}</div>'


def _empty_state() -> str:
    return (
        '<section><div class="empty">No <code>$regex</code> usage found in the analysed slow '
        "queries.</div></section>"
    )


def _kpis(findings: Sequence[Finding], summary: Sequence[SummaryRow]) -> str:
    ops = distinct_ops(findings)
    spent = sum(f.duration_ms or 0 for f in ops)
    collscans = sum(1 for f in ops if "COLLSCAN" in (f.plan_summary or ""))
    to_fix = sum(1 for r in summary if r.remedy not in NO_ACTION)
    bad_shapes = sum(1 for r in summary if SEVERITY[r.category] >= 2)
    cards = (
        ("regex time", format_duration_ms(spent), ""),
        ("slow operations with $regex", _fmt_int(len(ops)), ""),
        ("collections affected", _fmt_int(len({f.namespace for f in ops})), ""),
        ("shapes to fix", _fmt_int(to_fix), "alert" if to_fix else "good"),
        ("index-defeating shapes", _fmt_int(bad_shapes), "warn" if bad_shapes else "good"),
        ("COLLSCAN operations", _fmt_int(collscans), "alert" if collscans else "good"),
        ("slowest op", format_duration_ms(max((f.duration_ms or 0 for f in ops), default=0)), ""),
    )
    html = "".join(
        f'<div class="kpi {cls}"><div class="v">{escape(value)}</div>'
        f'<div class="l">{escape(label)}</div></div>'
        for label, value, cls in cards
    )
    return f'<section><h2>At a glance</h2><div class="kpis">{html}</div></section>'


def _hotspots_section(spots: Sequence[DatabaseSpot]) -> str:
    head = _th(("database / collection", "share of regex time"), ("time", "ops", "shapes"), ())
    head += _th((), ("to fix", "COLLSCAN ops"), ("main fix",))
    rows = "".join(_spot_row(d) + "".join(_spot_row(c) for c in d.collections) for d in spots)
    return (
        "<section><h2>Where the regex time goes</h2>"
        f'<table class="spots"><thead><tr>{head}</tr></thead><tbody>{rows}</tbody></table>'
        "</section>"
    )


def _spot_row(spot: DatabaseSpot | CollectionSpot) -> str:
    coll = spot if isinstance(spot, CollectionSpot) else None
    name = coll.collection if coll else spot.database
    fix = _remedy_badge(coll.main_remedy) if coll and coll.main_remedy not in NO_ACTION else ""
    return (
        f'<tr class="{"coll" if coll else "db"}"><td>{escape(name)}</td>'
        f'<td class="share">{spot.share_pct:.0f}%<div class="track"><div class="fill" '
        f'style="width:{min(spot.share_pct, 100):.1f}%"></div></div></td>'
        f'<td class="num">{escape(format_duration_ms(spot.total_ms))}</td>'
        + _num(spot.ops)
        + _num(spot.shapes)
        + _num(spot.to_fix, alert=spot.to_fix > 0)
        + (_num(coll.collscan_ops, alert=coll.collscan_ops > 0) if coll else "<td></td>")
        + f"<td>{fix}</td></tr>"
    )


def _actions_section(summary: Sequence[SummaryRow], tz: tzinfo) -> str:
    work = tuple(r for r in summary if r.remedy not in NO_ACTION)
    quiet = tuple(r for r in summary if r.remedy in NO_ACTION)
    cards = (
        f'<ol class="actions">{"".join(_action_card(r, tz) for r in work)}</ol>'
        if work
        else '<div class="empty">Nothing to fix: every regex shape is index-friendly or too '
        "small to matter yet.</div>"
    )
    note = (
        f'<div class="note">{escape(SEARCH_DEPLOYMENT_NOTE)}</div>'
        if any(r.remedy is Remedy.SEARCH for r in work)
        else ""
    )
    return (
        "<section><h2>What to do, biggest win first</h2>"
        f"{cards}{note}{_quiet_list(quiet)}</section>"
    )


def _action_card(r: SummaryRow, tz: tzinfo) -> str:
    cost = " &middot; ".join(
        p
        for p in (
            f"<b>{escape(format_duration_ms(r.total_ms))}</b> ({r.share_pct:.0f}% of regex time)",
            f"{_fmt_int(r.ops)} op(s)",
            f"last seen {escape(display_timestamp(r.last_seen, tz))}" if r.last_seen else "",
            f"app {escape(r.apps)}" if r.apps else "",
        )
        if p
    )
    snippet = (
        '<div class="snippet"><button class="copy" type="button">Copy</button>'
        f"<pre><code>{escape(r.fix_snippet)}</code></pre></div>"
        if r.fix_snippet
        else ""
    )
    return (
        f'<li class="{_REMEDY_CLASS[r.remedy]}">'
        f'<div class="what"><code>{escape(r.namespace)}</code><code>{escape(r.field)}</code>'
        f" {escape(r.command)} {_badge(r.category)} <code>/{escape(r.sample_pattern)}/"
        f"{escape(r.sample_options)}</code></div>"
        f'<div class="cost">{cost}</div>'
        f'<div class="why"><b>Why:</b> {escape(evidence(r))} {escape(r.advice)}.</div>'
        f'<div class="fix"><b>Fix:</b> {_remedy_badge(r.remedy)} {escape(REMEDY_LABEL[r.remedy])}'
        f' <span class="effort">{escape(r.effort)}</span></div>'
        f'<p class="how">{escape(r.remedy_how)}</p>'
        f"{snippet}</li>"
    )


def _quiet_list(rows: Sequence[SummaryRow]) -> str:
    if not rows:
        return ""
    items = "".join(
        f"<li>{_remedy_badge(r.remedy)} <code>{escape(r.namespace)}</code>"
        f"<code>{escape(r.field)}</code> {escape(r.command)} {_badge(r.category)} "
        f"&times;{r.ops}: {escape(r.remedy_how)}</li>"
        for r in rows
    )
    return (
        f'<details class="quiet"><summary>{len(rows)} shape(s) need no action now</summary>'
        f"<ul>{items}</ul></details>"
    )


def _summary_section(summary: Sequence[SummaryRow]) -> str:
    head = _th(
        ("namespace", "field", "cmd", "category", "remedy"),
        ("ops", "time", "share", "max ms", "avg ms", "scanned / returned", "collscan"),
        ("sample pattern", "opts"),
    )
    body = "".join(
        "<tr>"
        + _td(r.namespace)
        + _td(r.field, code=True, nowrap=True)
        + _td(r.command)
        + f"<td>{_badge(r.category)}</td>"
        + f'<td title="{escape(r.remedy_how)}">{_remedy_badge(r.remedy)}</td>'
        + _num(r.ops)
        + f'<td class="num">{escape(format_duration_ms(r.total_ms))}</td>'
        + f'<td class="num">{r.share_pct:.1f}%</td>'
        + _num(r.max_duration_ms)
        + _num(r.avg_duration_ms)
        + _num(r.scanned_per_returned)
        + _num(r.collscan_count, alert=r.collscan_count > 0)
        + _pattern(r.sample_pattern)
        + _td(r.sample_options, code=True)
        + "</tr>"
        for r in summary
    )
    return (
        f"<section><h2>Shapes ({len(summary)})</h2>"
        f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></section>"
    )


def _findings_section(findings: Sequence[Finding], tz: tzinfo) -> str:
    head = _th(
        ("time", "origin", "namespace", "cmd", "field", "pattern", "opts", "category", "remedy"),
        (),
        ("plan",),
    ) + _th((), ("ms", "keys", "docs", "ret"), ("app",))
    body = "".join(
        "<tr>" + f'<td class="nowrap" title="{escape(f.timestamp or "")}">'
        f"{escape(display_timestamp(f.timestamp, tz))}</td>"
        + _td(f.origin)
        + _td(f.namespace or "")
        + _td(f.command or "")
        + _td(f.field, code=True, nowrap=True)
        + _pattern(f.pattern)
        + _td(f.options, code=True)
        + f"<td>{_badge(f.category)}</td>"
        + f'<td title="{escape(f.remedy_how)}">{_remedy_badge(f.remedy)}</td>'
        + _plan(f.plan_summary)
        + _num(f.duration_ms)
        + _num(f.keys_examined)
        + _num(f.docs_examined)
        + _num(f.nreturned)
        + _td(f.app_name or "")
        + "</tr>"
        for f in findings
    )
    return (
        f"<section><h2>Findings ({len(findings)})</h2>"
        '<div class="toolbar"><input id="flt" type="search" '
        'placeholder="filter: namespace, pattern, plan, app..."><span class="count" id="cnt">'
        '</span><span class="count">click a column header to sort</span></div>'
        '<div class="wide"><table id="findings">'
        f"<thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>"
        "</section>"
    )


def _legend() -> str:
    cats = "".join(
        f"<div>{_badge(cat)}{escape(CATEGORY_ADVICE[cat])}</div>"
        for cat in sorted(RegexCategory, key=lambda c: -SEVERITY[c])
    )
    remedies = "".join(
        f"<div>{_remedy_badge(r)}{escape(REMEDY_LABEL[r])}</div>"
        for r in sorted(Remedy, key=lambda r: -REMEDY_ORDER[r])
    )
    return (
        f'<section><h2>Categories</h2><div class="legend">{cats}</div></section>'
        f'<section><h2>Remedies</h2><div class="legend">{remedies}</div>'
        f'<div class="note">{escape(SEARCH_DEPLOYMENT_NOTE)}</div></section>'
    )


# --- cells -------------------------------------------------------------------------------------


def _th(text: Sequence[str], numeric: Sequence[str], trailing: Sequence[str]) -> str:
    return (
        "".join(f"<th>{escape(t)}</th>" for t in text)
        + "".join(f'<th class="num">{escape(t)}</th>' for t in numeric)
        + "".join(f"<th>{escape(t)}</th>" for t in trailing)
    )


def _td(value: str, *, code: bool = False, nowrap: bool = False) -> str:
    text = escape(value)
    cell = f"<code>{text}</code>" if code and text else text
    return f'<td class="nowrap">{cell}</td>' if nowrap else f"<td>{cell}</td>"


def _pattern(value: str) -> str:
    return f'<td class="pattern"><code>{escape(value)}</code></td>' if value else "<td></td>"


def _num(value: int | float | None, *, alert: bool = False) -> str:
    text = "" if value is None else _fmt_int(value)
    cls = ' class="num plan-collscan"' if alert else ' class="num"'
    return f"<td{cls}>{text}</td>"


def _plan(plan: str | None) -> str:
    text = escape(plan or "")
    if "COLLSCAN" in text:
        return f'<td><span class="plan-collscan">{text}</span></td>'
    return f"<td><code>{text}</code></td>" if text else "<td></td>"


def _badge(cat: RegexCategory) -> str:
    return f'<span class="badge {_sev_class(cat)}">{escape(str(cat))}</span>'


def _remedy_badge(remedy: Remedy) -> str:
    return f'<span class="badge {_REMEDY_CLASS[remedy]}">{escape(str(remedy))}</span>'


def _sev_class(cat: RegexCategory) -> str:
    return _SEVERITY_CLASS[SEVERITY[cat]]


def _fmt_int(value: Any) -> str:
    if isinstance(value, float):
        return f"{value:,.1f}"
    return f"{int(value):,}"
