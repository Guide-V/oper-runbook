"""Self-contained HTML dashboard for regex findings.

One file, no external assets (opens from a laptop, a ticket attachment or an air-gapped EA
jump host). Pure: ``render_html`` returns a string. Inline CSS uses the MongoDB palette; the
only JavaScript is a text filter and column sort for the findings table.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from html import escape
from typing import Any

from mongoops import __version__
from mongoops.regex_finder.analyze import Finding
from mongoops.regex_finder.detector import RegexCategory
from mongoops.regex_finder.remedy import (
    REMEDY_LABEL,
    REMEDY_ORDER,
    SEARCH_DEPLOYMENT_NOTE,
    Remedy,
)
from mongoops.regex_finder.summary import CATEGORY_ADVICE, SEVERITY, SummaryRow


@dataclass(frozen=True, slots=True)
class ReportMeta:
    """Where the findings came from; shown in the dashboard header."""

    source: str  # atlas | ops-manager | logfile | live
    target: str  # cluster name, host list, file path or credential-free URI
    window: str = ""  # human description of the time window, e.g. "since 24h"
    filters: tuple[str, ...] = field(default_factory=tuple)
    generated_at: str = ""  # ISO-8601; empty = now (UTC)


# Severity 0..5 -> badge colour. Green is fine, amber needs a look, red is a scan.
_SEVERITY_CLASS = {0: "ok", 1: "warn", 2: "bad", 3: "bad", 4: "bad", 5: "bad"}

# Remedy -> badge colour: grey nothing/monitor, blue index work, amber query work, green Search.
_REMEDY_CLASS: dict[Remedy, str] = {
    Remedy.NONE: "muted",
    Remedy.MONITOR: "muted",
    Remedy.BTREE_INDEX: "index",
    Remedy.COLLATION_INDEX: "index",
    Remedy.REVERSED_FIELD: "index",
    Remedy.REWRITE: "warn",
    Remedy.FIX_FILTER: "warn",
    Remedy.SEARCH: "search",
}
_INDEX_REMEDIES = frozenset({Remedy.BTREE_INDEX, Remedy.COLLATION_INDEX, Remedy.REVERSED_FIELD})
_QUERY_REMEDIES = frozenset({Remedy.REWRITE, Remedy.FIX_FILTER})

_CSS = """
:root{--green:#00ED64;--forest:#00684A;--evergreen:#023430;--slate:#001E2B;--mist:#E3FCF7;
--grey:#889397;--line:#E8EDEB;--bg:#F9FBFA;--ok:#00684A;--warn:#C27C13;--bad:#DB3030;}
*{box-sizing:border-box}body{margin:0;font:14px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",
Helvetica,Arial,sans-serif;color:var(--slate);background:var(--bg)}
header{background:var(--slate);color:#fff;padding:22px 32px;border-bottom:4px solid var(--green)}
header h1{margin:0 0 4px;font-size:22px;font-weight:600}header h1 code{color:var(--green)}
header .sub{color:#B8C4C2;font-size:13px}
.chips{display:flex;flex-wrap:wrap;gap:8px;margin-top:14px}
.chip{background:var(--evergreen);border:1px solid var(--forest);border-radius:6px;padding:4px 10px;
font-size:12px;color:#E3FCF7}.chip b{color:var(--green);font-weight:600;margin-right:6px}
main{padding:24px 32px;max-width:1600px;margin:0 auto}
section{margin-bottom:28px}h2{font-size:15px;margin:0 0 10px;color:var(--forest);
text-transform:uppercase;letter-spacing:.04em}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px}
.kpi{background:#fff;border:1px solid var(--line);border-radius:8px;padding:14px 16px}
.kpi .v{font-size:28px;font-weight:600;color:var(--slate)}.kpi .l{font-size:12px;color:var(--grey)}
.kpi.alert .v{color:var(--bad)}.kpi.good .v{color:var(--ok)}
.bars{background:#fff;border:1px solid var(--line);border-radius:8px;padding:14px 16px}
.bar{display:grid;grid-template-columns:170px 1fr 60px;align-items:center;gap:12px;margin:6px 0}
.bar .track{background:var(--line);border-radius:4px;height:14px;overflow:hidden}
.bar .fill{height:100%;border-radius:4px}.bar .n{text-align:right;font-variant-numeric:tabular-nums}
.fill.ok{background:var(--ok)}.fill.warn{background:var(--warn)}.fill.bad{background:var(--bad)}
table{width:100%;border-collapse:collapse;background:#fff;border:1px solid var(--line);
border-radius:8px;overflow:hidden;font-size:13px}
th,td{padding:8px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
th{background:var(--mist);color:var(--evergreen);font-weight:600;white-space:nowrap;cursor:pointer;
user-select:none}th:hover{background:#d2f5ea}tr:last-child td{border-bottom:0}
td.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
td.nowrap{white-space:nowrap}td.nowrap code{word-break:normal}
code{font:12px ui-monospace,SFMono-Regular,Menlo,monospace;background:#F1F5F4;padding:1px 5px;
border-radius:4px;word-break:break-all}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600;
color:#fff;white-space:nowrap}.badge.ok{background:var(--ok)}.badge.warn{background:var(--warn)}
.badge.bad{background:var(--bad)}.badge.muted{background:var(--grey)}
.badge.index{background:#016BF8}.badge.search{background:var(--forest)}
.kpi.search .v{color:var(--forest)}.kpi.index .v{color:#016BF8}.kpi.warn .v{color:var(--warn)}
.todo{display:grid;gap:10px}.todo .card{background:#fff;border:1px solid var(--line);
border-radius:8px;padding:12px 16px;border-left:5px solid var(--grey)}
.todo .card.search{border-left-color:var(--forest)}.todo .card.index{border-left-color:#016BF8}
.todo .card.warn{border-left-color:var(--warn)}
.todo h3{margin:0 0 6px;font-size:14px}.todo h3 .n{color:var(--grey);font-weight:400;
margin-left:8px}.todo ul{margin:0;padding-left:18px}.todo li{margin:4px 0}
.todo li code{margin-right:4px}.note{color:var(--grey);font-size:12px;margin-top:8px}
.plan-collscan{color:var(--bad);font-weight:600}
.toolbar{display:flex;gap:10px;align-items:center;margin-bottom:8px}
.toolbar input{flex:1;max-width:420px;padding:7px 10px;border:1px solid var(--line);
border-radius:6px;font-size:13px}.toolbar .count{color:var(--grey);font-size:12px}
.empty{background:#fff;border:1px solid var(--line);border-radius:8px;padding:28px;
text-align:center;color:var(--forest);font-size:16px}
.legend{display:grid;grid-template-columns:repeat(auto-fit,minmax(340px,1fr));gap:8px}
.legend div{background:#fff;border:1px solid var(--line);border-radius:8px;padding:10px 12px;
font-size:12px}.legend .badge{margin-right:8px}
footer{padding:16px 32px;color:var(--grey);font-size:12px;border-top:1px solid var(--line)}
"""

_JS = """
(function(){
  var input=document.getElementById('flt'),table=document.getElementById('findings');
  if(!table)return;
  var rows=Array.prototype.slice.call(table.tBodies[0].rows),count=document.getElementById('cnt');
  function apply(){
    var q=(input.value||'').toLowerCase(),shown=0;
    rows.forEach(function(r){var hit=!q||r.textContent.toLowerCase().indexOf(q)>=0;
      r.style.display=hit?'':'none';if(hit)shown++;});
    count.textContent=shown+' of '+rows.length+' shown';
  }
  input.addEventListener('input',apply);apply();
  var ths=table.tHead.rows[0].cells;
  Array.prototype.forEach.call(ths,function(th,i){
    th.addEventListener('click',function(){
      var asc=th.getAttribute('data-asc')!=='1';
      Array.prototype.forEach.call(ths,function(t){t.removeAttribute('data-asc');});
      th.setAttribute('data-asc',asc?'1':'0');
      var num=th.classList.contains('num');
      rows.sort(function(a,b){
        var x=a.cells[i].textContent,y=b.cells[i].textContent;
        if(num){x=parseFloat(x)||0;y=parseFloat(y)||0;return asc?x-y:y-x;}
        return asc?x.localeCompare(y):y.localeCompare(x);
      });
      rows.forEach(function(r){table.tBodies[0].appendChild(r);});
    });
  });
})();
"""


def render_html(
    findings: Sequence[Finding], summary: Sequence[SummaryRow], meta: ReportMeta
) -> str:
    """Build the whole dashboard as one HTML document."""
    generated = meta.generated_at or datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    body = (
        _empty_state()
        if not findings
        else "\n".join(
            (
                _kpis(findings, summary),
                _todo_section(summary),
                _category_bars(findings),
                _summary_section(summary),
                _findings_section(findings),
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
  <h1><code>$regex</code> usage dashboard</h1>
  <div class="sub">mongoops regex-finder {escape(__version__)} &middot; slow queries with regular
  expressions, grouped by shape and ranked by how badly they defeat indexes</div>
  {_chips(meta, generated)}
</header>
<main>
{body}
{_legend()}
</main>
<footer>Generated {escape(generated)} by <code>mongoops regex-finder {escape(meta.source)}</code>.
Counts are per slow operation logged; one operation with several regexes yields several
usages.</footer>
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
    )
    return f'<div class="chips">{chips}</div>'


def _empty_state() -> str:
    return (
        '<section><div class="empty">No <code>$regex</code> usage found in the analysed slow '
        "queries.</div></section>"
    )


def _kpis(findings: Sequence[Finding], summary: Sequence[SummaryRow]) -> str:
    bad_shapes = sum(1 for r in summary if SEVERITY[r.category] >= 2)
    collscans = sum(1 for f in findings if "COLLSCAN" in (f.plan_summary or ""))
    slowest = max((f.duration_ms or 0 for f in findings), default=0)
    namespaces = len({f.namespace for f in findings})
    search = sum(1 for r in summary if r.remedy is Remedy.SEARCH)
    index_fix = sum(1 for r in summary if r.remedy in _INDEX_REMEDIES)
    query_fix = sum(1 for r in summary if r.remedy in _QUERY_REMEDIES)
    cards = (
        ("regex usages", len(findings), ""),
        ("distinct shapes", len(summary), ""),
        ("index-defeating shapes", bad_shapes, "alert" if bad_shapes else "good"),
        ("COLLSCAN operations", collscans, "alert" if collscans else "good"),
        ("slowest op (ms)", slowest, ""),
        ("namespaces affected", namespaces, ""),
        ("shapes: MongoDB Search", search, "search" if search else ""),
        ("shapes: index fix", index_fix, "index" if index_fix else ""),
        ("shapes: query rewrite", query_fix, "warn" if query_fix else ""),
    )
    html = "".join(
        f'<div class="kpi {cls}"><div class="v">{_fmt_int(value)}</div>'
        f'<div class="l">{escape(label)}</div></div>'
        for label, value, cls in cards
    )
    return f'<section><h2>At a glance</h2><div class="kpis">{html}</div></section>'


def _todo_section(summary: Sequence[SummaryRow]) -> str:
    """One card per remedy (most involved first) listing the shapes it applies to."""
    groups: dict[Remedy, list[SummaryRow]] = {}
    for row in summary:
        groups.setdefault(row.remedy, []).append(row)
    cards = "".join(
        _todo_card(remedy, rows)
        for remedy, rows in sorted(groups.items(), key=lambda kv: -REMEDY_ORDER[kv[0]])
        if remedy is not Remedy.NONE
    )
    note = (
        f'<div class="note">{escape(SEARCH_DEPLOYMENT_NOTE)}</div>'
        if Remedy.SEARCH in groups
        else ""
    )
    if not cards:
        cards = '<div class="card">Every regex shape is already index-friendly.</div>'
    return f'<section><h2>What to do</h2><div class="todo">{cards}</div>{note}</section>'


def _todo_card(remedy: Remedy, rows: Sequence[SummaryRow]) -> str:
    items = "".join(
        f"<li><code>{escape(r.namespace)}</code><code>{escape(r.field)}</code>"
        f"<code>{escape(r.command)}</code> {_badge(r.category)} &times;{r.count}: "
        f"{escape(r.remedy_how)}</li>"
        for r in rows
    )
    return (
        f'<div class="card {_REMEDY_CLASS[remedy]}"><h3>{_remedy_badge(remedy)} '
        f'{escape(REMEDY_LABEL[remedy])}<span class="n">{len(rows)} shape(s)</span></h3>'
        f"<ul>{items}</ul></div>"
    )


def _category_bars(findings: Sequence[Finding]) -> str:
    counts = {cat: sum(1 for f in findings if f.category is cat) for cat in RegexCategory}
    total = max(len(findings), 1)
    rows = "".join(
        f'<div class="bar"><span>{_badge(cat)}</span>'
        f'<div class="track"><div class="fill {_sev_class(cat)}" '
        f'style="width:{100 * n / total:.1f}%"></div></div>'
        f'<span class="n">{n}</span></div>'
        for cat, n in sorted(counts.items(), key=lambda kv: -SEVERITY[kv[0]])
        if n
    )
    return f'<section><h2>By category</h2><div class="bars">{rows}</div></section>'


def _summary_section(summary: Sequence[SummaryRow]) -> str:
    head = _th(
        ("namespace", "field", "cmd", "category", "remedy"),
        ("count", "collscan", "max ms", "avg ms", "docs examined"),
        ("sample pattern", "opts", "advice"),
    )
    body = "".join(
        "<tr>"
        + _td(r.namespace)
        + _td(r.field, code=True, nowrap=True)
        + _td(r.command)
        + f"<td>{_badge(r.category)}</td>"
        + f'<td title="{escape(r.remedy_how)}">{_remedy_badge(r.remedy)}</td>'
        + _num(r.count)
        + _num(r.collscan_count, alert=r.collscan_count > 0)
        + _num(r.max_duration_ms)
        + _num(r.avg_duration_ms)
        + _num(r.total_docs_examined)
        + _td(r.sample_pattern, code=True)
        + _td(r.sample_options, code=True)
        + _td(r.advice)
        + "</tr>"
        for r in summary
    )
    return (
        f"<section><h2>Shapes ({len(summary)})</h2>"
        f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></section>"
    )


def _findings_section(findings: Sequence[Finding]) -> str:
    head = _th(
        ("time", "origin", "namespace", "cmd", "field", "pattern", "opts", "category", "remedy"),
        (),
        ("plan",),
    ) + _th((), ("ms", "keys", "docs", "ret"), ("app",))
    body = "".join(
        "<tr>"
        + _td(f.timestamp or "")
        + _td(f.origin)
        + _td(f.namespace or "")
        + _td(f.command or "")
        + _td(f.field, code=True, nowrap=True)
        + _td(f.pattern, code=True)
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
        f'<table id="findings"><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>'
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
