"""Self-contained HTML scorecard for the WAF readiness check. Pure: ``render_html`` -> str.

Three audiences on one page: the pillar cards for the architect, "Action needed" with evidence
and the Atlas fix for the platform team, and "Discuss these" for the workshop.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from html import escape
from typing import Any

from mongoops import __version__
from mongoops.common.html_theme import BASE_CSS, SAFE_HARBOUR_HTML, TABLE_JS
from mongoops.waf_check.catalog import CATALOG_VERSION
from mongoops.waf_check.model import PILLAR_LABEL, CheckResult, Kind, Pillar, Status
from mongoops.waf_check.report import (
    ACTION_STATUSES,
    ClusterReport,
    ProjectScope,
    Scope,
    attested_by,
    cluster_actions,
    count_by_pillar,
    count_by_status,
    project_results,
    sort_results,
)
from mongoops.waf_check.score import (
    MAX_SCORE,
    TIERS,
    Score,
    fixes_to_next_tier,
    quick_wins,
    score,
    score_by_pillar,
)

_RING_RADIUS = 52
_RING_LEN = 2 * 3.141592653589793 * _RING_RADIUS

_STATUS_CLASS: Mapping[Status, str] = {
    Status.FAIL: "bad",
    Status.WARN: "warn",
    Status.UNKNOWN: "index",  # blue: needs a role, not a fix
    Status.PASS: "ok",
    Status.NA: "muted",
    Status.SKIPPED: "muted",
    Status.DISCUSS: "search",
}

_EXTRA_CSS = """
.pillars{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:12px}
.pillar{background:#fff;border:1px solid var(--line);border-radius:var(--r);padding:14px 16px;
border-top:3px solid var(--forest);box-shadow:var(--shadow)}
.pillar h3{margin:0 0 8px;font-size:14px;color:var(--evergreen);display:flex;
justify-content:space-between;align-items:baseline;gap:8px}
.pillar h3 .ps{font-variant-numeric:tabular-nums;font-weight:700;font-size:16px}
.pillar h3 .ps small{font-size:11px;color:var(--grey);font-weight:400}
.pillar .row{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}
.meter{display:grid;grid-template-columns:repeat(10,1fr);gap:3px;height:8px}
.meter i{display:block;border-radius:2px;background:var(--mist2)}
.meter i.on{background:var(--forest)}
.tier-ok .meter i.on{background:var(--green)}.tier-good .meter i.on{background:var(--forest)}
.tier-warn .meter i.on{background:var(--warn)}.tier-bad .meter i.on{background:var(--bad)}
.evidence{font:11px ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--grey);
white-space:pre-wrap;word-break:break-word;margin-top:6px}
.doc{font-size:12px;margin-left:8px}
.hero{display:grid;grid-template-columns:minmax(320px,1.2fr) minmax(280px,1fr);gap:16px}
.score-card{display:grid;grid-template-columns:auto 1fr;gap:20px;align-items:center;
padding:22px 24px;border-radius:var(--r);color:#fff;position:relative;overflow:hidden;
background:linear-gradient(135deg,var(--deep),var(--evergreen) 60%,var(--forest));
box-shadow:0 10px 30px rgba(0,30,43,.18);border:1px solid rgba(113,246,186,.3)}
.score-card:before{content:"";position:absolute;inset:auto -80px -120px auto;width:300px;
height:300px;border-radius:50%;background:radial-gradient(circle,rgba(0,237,100,.28),
rgba(0,0,0,0) 65%);pointer-events:none}
.ring{position:relative;width:150px;height:150px}
.ring svg{width:150px;height:150px;transform:rotate(-90deg)}
.ring .track{fill:none;stroke:rgba(255,255,255,.14);stroke-width:11}
.ring .arc{fill:none;stroke:var(--green);stroke-width:11;stroke-linecap:round;
stroke-dasharray:0 1000;transition:stroke-dasharray 900ms cubic-bezier(.2,.8,.2,1);
filter:drop-shadow(0 0 8px rgba(0,237,100,.55))}
.tier-good .ring .arc{stroke:var(--green2);filter:drop-shadow(0 0 6px rgba(113,246,186,.5))}
.tier-warn .ring .arc{stroke:#F5B95A;filter:drop-shadow(0 0 6px rgba(245,185,90,.5))}
.tier-bad .ring .arc{stroke:#FF6960;filter:drop-shadow(0 0 6px rgba(255,105,96,.5))}
.ring .num{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;
justify-content:center;font-variant-numeric:tabular-nums}
.ring .num .v{font-size:42px;font-weight:700;line-height:1;letter-spacing:-.02em}
.ring .num .of{font-size:12px;color:var(--mist2);margin-top:2px}
.score-meta{min-width:0}
.score-meta .ctx{font-size:11px;text-transform:uppercase;letter-spacing:.12em;color:var(--green);
font-weight:700}
.score-meta .tier{font-size:24px;font-weight:700;margin:4px 0 6px;letter-spacing:-.01em}
.score-meta .arith{color:var(--mist2);font-size:13px}
.score-meta .next{margin-top:12px;display:inline-block;padding:5px 12px;border-radius:999px;
background:rgba(0,237,100,.14);border:1px solid rgba(0,237,100,.45);font-size:12px;color:#fff}
.score-meta .next b{color:var(--green)}
.tiers{display:flex;gap:4px;margin-top:14px;font-size:10px;color:var(--mist2)}
.tiers span{flex:1;padding:3px 6px;border-radius:4px;background:rgba(255,255,255,.07);
text-align:center;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.tiers span.cur{background:var(--green);color:var(--deep);font-weight:700}
.wins{background:#fff;border:1px solid var(--line);border-radius:var(--r);padding:18px 20px;
box-shadow:var(--shadow);border-top:3px solid var(--green)}
.wins h3{margin:0 0 4px;font-size:14px;color:var(--evergreen)}
.wins .note{margin:0 0 10px}
.wins ol{margin:0;padding:0;list-style:none;display:grid;gap:8px}
.wins li{display:grid;grid-template-columns:auto 1fr;gap:12px;align-items:start;padding:10px 12px;
border-radius:8px;background:var(--panel);border:1px solid var(--line)}
.wins .gain{font-variant-numeric:tabular-nums;font-weight:700;font-size:18px;color:var(--forest);
background:var(--mist);border-radius:8px;padding:4px 10px;white-space:nowrap}
.wins .what{min-width:0}.wins .what b{display:block}.wins .what .n{color:var(--grey);font-size:12px}
.wins .done{color:var(--forest);font-weight:600}
.scoreline{display:inline-flex;align-items:center;gap:8px;font-variant-numeric:tabular-nums}
.scoreline .sv{font-weight:700;font-size:16px}.scoreline .st{font-size:12px;color:var(--grey)}
td .meter{width:90px;display:inline-grid;vertical-align:middle;margin-left:8px}
@media (max-width:900px){.hero{grid-template-columns:1fr}}
@media (max-width:560px){.score-card{grid-template-columns:1fr;justify-items:center;
text-align:center}}
@media (prefers-reduced-motion:reduce){.ring .arc{transition:none}}
"""

# Count the hero number up from 0 and sweep the ring once the page has painted. The final value
# is already in the markup (data-score), so the page is correct without JavaScript and for
# prefers-reduced-motion; the animation is only a reveal.
SCORE_JS = """
(function(){
  var nodes=document.querySelectorAll('[data-score]');if(!nodes.length)return;
  var reduce=window.matchMedia&&window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  Array.prototype.forEach.call(nodes,function(el){
    var target=parseFloat(el.getAttribute('data-score')),v=el.querySelector('.v'),
        arc=el.parentNode.querySelector('.arc'),len=arc?parseFloat(arc.getAttribute('data-len')):0;
    function finish(){if(v)v.textContent=target.toFixed(1);
      if(arc)arc.style.strokeDasharray=len+' 1000';}
    if(reduce||isNaN(target)){finish();return;}
    var t0=null,dur=700;
    requestAnimationFrame(function(){if(arc)arc.style.strokeDasharray=len+' 1000';});
    function step(ts){if(t0===null)t0=ts;var p=Math.min(1,(ts-t0)/dur),e=1-Math.pow(1-p,3);
      if(v)v.textContent=(target*e).toFixed(1);if(p<1)requestAnimationFrame(step);else finish();}
    requestAnimationFrame(step);
  });
})();
"""


def render_html(results: Sequence[CheckResult], scope: Scope) -> str:
    generated = scope.resolved_time()
    auto = tuple(r for r in sort_results(results) if r.kind is Kind.AUTO)
    discuss = tuple(r for r in results if r.kind is Kind.DISCUSS)
    body = "\n".join(
        (
            _hero(results, f"cluster {scope.cluster}"),
            _kpis(results),
            _pillars(results),
            _action_section(results),
            _unknown_section(auto),
            _all_checks(auto),
            _discuss_section(discuss),
        )
    )
    chips = (
        ("cluster", scope.cluster),
        ("project", scope.project_id),
        ("provider", scope.provider),
        ("tier", scope.tier),
        ("mongodb", scope.version),
        ("policy", scope.policy_profile),
        ("policy file", scope.policy_path),
        ("attestations", scope.attestations_path),
        ("generated", generated),
    )
    return _page(
        f"cluster {scope.cluster}", f"<code>{escape(scope.cluster)}</code>", chips, body, generated
    )


def render_project_html(reports: Sequence[ClusterReport], scope: ProjectScope) -> str:
    """One page for a whole project: roll-up first, then every cluster's scorecard, then the
    discussion items once."""
    generated = scope.resolved_time()
    everything = project_results(reports)
    discuss = tuple(r for r in everything if r.kind is Kind.DISCUSS)
    body = "\n".join(
        (
            _hero(everything, f"project {scope.project_id}"),
            _kpis(everything),
            _rollup(reports),
            _project_actions(reports),
            *(_cluster_section(rep) for rep in reports),
            _discuss_section(discuss),
        )
    )
    chips = (
        ("project", scope.project_id),
        ("clusters", str(len(reports))),
        ("policy", scope.policy_profile),
        ("policy file", scope.policy_path),
        ("attestations", scope.attestations_path),
        ("generated", generated),
    )
    return _page(
        f"project {scope.project_id}",
        f"project <code>{escape(scope.project_id)}</code>, {len(reports)} cluster(s)",
        chips,
        body,
        generated,
    )


def _page(
    title: str, heading: str, chips: Sequence[tuple[str, str]], body: str, generated: str
) -> str:
    chip_html = "".join(
        f'<span class="chip"><b>{escape(k)}</b>{escape(v)}</span>' for k, v in chips if v
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WAF readiness: {escape(title)}</title>
<style>{BASE_CSS}{_EXTRA_CSS}</style></head>
<body>
<header>
  <div class="brand"><i></i>MongoDB Atlas &middot; Well-Architected Framework</div>
  <h1>Readiness scorecard: {heading}</h1>
  <div class="sub">mongoops waf-check {escape(__version__)} &middot; catalog
  {escape(CATALOG_VERSION)} &middot; read-only evaluation of the Atlas configuration against the
  landing-zone policy</div>
  <div class="chips">{chip_html}</div>
</header>
<main>
{body}
</main>
<footer>Generated {escape(generated)} by <code>mongoops waf-check atlas</code>. Score: a check the
policy treats as <code>fail</code> is worth 2 points, <code>warn</code> 1 point; passing checks
earn their points and the score is 10 &times; earned / possible. UNKNOWN, NA, off and open
discussion items are not counted, so a narrow API key never lowers the score. Baseline:
<a href="https://www.mongodb.com/docs/atlas/architecture/current/operational-readiness-checklist/">
MongoDB Atlas operational readiness checklist</a>.{SAFE_HARBOUR_HTML}</footer>
<script>{TABLE_JS}</script>
<script>{SCORE_JS}</script>
</body></html>
"""


def _hero(results: Sequence[CheckResult], what: str) -> str:
    """Score ring, tier, arithmetic, distance to the next tier, and the quick wins."""
    s = score(results)
    tier = s.tier
    css = f"tier-{tier.css}" if tier else "tier-none"
    value = s.value
    shown = f"{value:.1f}" if value is not None else "-"
    arc_len = _RING_LEN * (value / MAX_SCORE) if value is not None else 0.0
    arith = (
        f"{s.earned} of {s.possible} points &middot; {s.passed} of {s.scored} scored checks pass"
        if value is not None
        else "nothing could be scored: every check is UNKNOWN, not applicable or off"
    )
    nxt = fixes_to_next_tier(results)
    if value is not None and tier is TIERS[0]:
        next_html = (
            '<div class="next"><b>Top tier.</b> Keep it there: re-run on every change.</div>'
        )
    elif nxt:
        target, n = nxt
        next_html = (
            f'<div class="next"><b>{n} fix{"es" if n != 1 else ""}</b> away from '
            f"{escape(target.label)} ({target.floor:.1f})</div>"
        )
    else:
        next_html = ""
    tiers = "".join(
        f'<span class="{"cur" if t is tier else ""}" title="{t.floor:.1f} and above">'
        f"{escape(t.label)}</span>"
        for t in reversed(TIERS)
    )
    return (
        f'<section class="hero"><div class="score-card {css}">'
        f'<div class="ring"><svg viewBox="0 0 120 120" aria-hidden="true">'
        f'<circle class="track" cx="60" cy="60" r="{_RING_RADIUS}"/>'
        f'<circle class="arc" cx="60" cy="60" r="{_RING_RADIUS}" data-len="{arc_len:.1f}"/></svg>'
        f'<div class="num" data-score="{shown}" role="img" '
        f'aria-label="readiness score {shown} out of 10">'
        f'<span class="v">{shown}</span><span class="of">out of 10</span></div></div>'
        f'<div class="score-meta"><div class="ctx">Readiness score &middot; {escape(what)}</div>'
        f'<div class="tier">{escape(tier.label) if tier else "Not scoreable"}</div>'
        f'<div class="arith">{arith}</div>{next_html}<div class="tiers">{tiers}</div></div></div>'
        + _wins(results, s)
        + "</section>"
    )


def _wins(results: Sequence[CheckResult], total: Score) -> str:
    wins = quick_wins(results)
    if not wins:
        items = '<li><span class="done">Nothing left to fix. Every scored check passes.</span></li>'
    else:
        items = "".join(
            f'<li><span class="gain">+{w.gain:.1f}</span><span class="what">'
            f"<b>{escape(w.result.title)}</b>"
            f'<span class="n">{_badge(w.result.status)} <code>{escape(w.result.id)}</code> '
            f"&middot; {escape(PILLAR_LABEL[w.result.pillar])}"
            f"{f' &middot; {w.occurrences} clusters' if w.occurrences > 1 else ''}"
            "</span></span></li>"
            for w in wins
        )
    return (
        '<div class="wins"><h3>Quick wins</h3><div class="note">Points each fix adds to the '
        f"score (out of {total.possible} possible).</div><ol>{items}</ol></div>"
    )


def _meter(s: Score) -> str:
    """Ten segments; filled = rounded score. Tier colour comes from the wrapping element."""
    on = round(s.value) if s.value is not None else 0
    return (
        '<span class="meter" aria-hidden="true">'
        + "".join(f'<i class="{"on" if i < on else ""}"></i>' for i in range(10))
        + "</span>"
    )


def _scoreline(s: Score) -> str:
    """Compact ``7.4 / 10 Ready with gaps`` with a meter, for tables and section headers."""
    if s.value is None:
        return '<span class="scoreline"><span class="st">not scoreable</span></span>'
    tier = s.tier
    return (
        f'<span class="scoreline tier-{tier.css if tier else "none"}">'
        f'<span class="sv">{s.value:.1f}</span><span class="st">/ 10 &middot; '
        f"{escape(tier.label) if tier else ''}</span>{_meter(s)}</span>"
    )


def _slug(name: str) -> str:
    return "cluster-" + "".join(ch if ch.isalnum() else "-" for ch in name.lower())


def _rollup(reports: Sequence[ClusterReport]) -> str:
    head = "".join(
        f"<th{' class=num' if h.isupper() or h in ('NA/off', 'score') else ''}>{h}</th>"
        for h in (
            "cluster",
            "provider",
            "tier",
            "mongodb",
            "score",
            "FAIL",
            "WARN",
            "UNKNOWN",
            "PASS",
            "NA/off",
        )
    )

    def cell(n: int, status: Status) -> str:
        return (
            f'<td class="num">{_badge(status) if n else ""} {n}</td>'
            if n
            else '<td class="num">0</td>'
        )

    rows = "".join(
        "<tr>"
        f'<td class="nowrap"><a href="#{_slug(rep.scope.cluster)}">'
        f"<code>{escape(rep.scope.cluster)}</code></a></td>"
        f"<td>{escape(rep.scope.provider)}</td><td>{escape(rep.scope.tier)}</td>"
        f"<td>{escape(rep.scope.version)}</td>"
        f'<td class="num">{_scoreline(score(auto))}</td>'
        + cell(c["FAIL"], Status.FAIL)
        + cell(c["WARN"], Status.WARN)
        + cell(c["UNKNOWN"], Status.UNKNOWN)
        + f'<td class="num">{c["PASS"]}</td><td class="num">{c["NA"] + c["SKIPPED"]}</td>'
        "</tr>"
        for rep in reports
        for auto in (tuple(r for r in rep.results if r.kind is Kind.AUTO),)
        for c in (count_by_status(auto),)
    )
    return (
        f"<section><h2>Clusters ({len(reports)})</h2>"
        '<div class="toolbar"><input id="flt" type="search" placeholder="filter clusters...">'
        '<span class="count" id="cnt"></span>'
        '<span class="count">click a column header to sort</span></div>'
        f'<table id="findings"><thead><tr>{head}</tr></thead><tbody>{rows}</tbody></table>'
        "</section>"
    )


def _project_actions(reports: Sequence[ClusterReport]) -> str:
    actions = cluster_actions(reports)
    if not actions:
        cards = '<div class="card">Every evaluated check passes the policy on every cluster.</div>'
    else:
        cards = "".join(_action_card(r, f"{escape(cluster)} &middot; ") for cluster, r in actions)
    return (
        f"<section><h2>Action needed across clusters ({len(actions)})</h2>"
        f'<div class="todo">{cards}</div></section>'
    )


def _cluster_section(rep: ClusterReport) -> str:
    auto = tuple(r for r in sort_results(rep.results) if r.kind is Kind.AUTO)
    s = rep.scope
    meta = " &middot; ".join(escape(v) for v in (s.provider, s.tier, f"MongoDB {s.version}") if v)
    return (
        f'<section id="{_slug(s.cluster)}"><h2>Cluster {escape(s.cluster)}</h2>'
        f'<div class="note">{meta} &middot; {_scoreline(score(auto))}</div>'
        + _pillars(rep.results)
        + _unknown_section(auto)
        + _all_checks(auto, table_id="", toolbar=False)
        + "</section>"
    )


def _kpis(results: Sequence[CheckResult]) -> str:
    counts = count_by_status(results)
    cards = (
        ("failing", counts["FAIL"], "alert" if counts["FAIL"] else "good"),
        ("warnings", counts["WARN"], "warn" if counts["WARN"] else "good"),
        ("could not evaluate", counts["UNKNOWN"], "index" if counts["UNKNOWN"] else ""),
        ("passing", counts["PASS"], "good"),
        ("not applicable / off", counts["NA"] + counts["SKIPPED"], ""),
        ("to discuss", counts["DISCUSS"], "search"),
    )
    html = "".join(
        f'<div class="kpi {cls}"><div class="v">{n}</div><div class="l">{escape(label)}</div></div>'
        for label, n, cls in cards
    )
    return f'<section><h2>At a glance</h2><div class="kpis">{html}</div></section>'


def _pillars(results: Sequence[CheckResult]) -> str:
    by_pillar = count_by_pillar(results)
    scores = score_by_pillar(results)
    cards = "".join(
        f'<div class="pillar tier-{ps.tier.css if ps.tier else "none"}">'
        f"<h3>{escape(PILLAR_LABEL[p])}"
        f'<span class="ps">{f"{ps.value:.1f}" if ps.value is not None else "-"}'
        f"<small> / 10</small></span></h3>{_meter(ps)}"
        '<div class="row">'
        + "".join(
            f'<span class="badge {_STATUS_CLASS[Status(s)]}">{escape(s)} {n}</span>'
            for s, n in by_pillar[p.value].items()
            if n
        )
        + "</div></div>"
        for p in Pillar
        for ps in (scores[p],)
    )
    return f'<section><h2>By pillar</h2><div class="pillars">{cards}</div></section>'


def _action_section(results: Sequence[CheckResult]) -> str:
    """FAIL / WARN from the auto checks and from attested discussion items, worst first."""
    actions = tuple(r for r in sort_results(results) if r.status in ACTION_STATUSES)
    if not actions:
        cards = '<div class="card">Every evaluated check passes the policy.</div>'
    else:
        cards = "".join(_action_card(r) for r in actions)
    return (
        f'<section><h2>Action needed ({len(actions)})</h2><div class="todo">{cards}</div></section>'
    )


def _action_card(r: CheckResult, prefix: str = "") -> str:
    """One FAIL / WARN card; ``prefix`` is already-escaped HTML shown before the id."""
    return (
        f'<div class="card {_STATUS_CLASS[r.status]}"><h3>{_badge(r.status)} '
        f'{escape(r.title)}<span class="n">{prefix}{escape(r.id)} &middot; '
        f"{escape(PILLAR_LABEL[r.pillar])}"
        f"{' &middot; attested' if r.kind is Kind.DISCUSS else ''}</span></h3>"
        f"<div>{escape(r.message + attested_by(r))}</div>"
        f"<div><b>Fix:</b> {escape(r.remedy)}"
        f'<a class="doc" href="{escape(r.doc)}">docs</a></div>'
        f'<div class="evidence">{escape(_evidence(r.evidence))}</div></div>'
    )


def _unknown_section(auto: Sequence[CheckResult]) -> str:
    unknown = tuple(r for r in auto if r.status is Status.UNKNOWN)
    if not unknown:
        return ""
    items = "".join(
        f"<li><code>{escape(r.id)}</code> {escape(r.title)}: {escape(r.message)}</li>"
        for r in unknown
    )
    return (
        f'<section><h2>Could not evaluate ({len(unknown)})</h2><div class="todo">'
        f'<div class="card index"><ul>{items}</ul><div class="note">Re-run with a key that has '
        "the listed role, or accept these as manual checks.</div></div></div></section>"
    )


def _all_checks(
    auto: Sequence[CheckResult], *, table_id: str = "findings", toolbar: bool = True
) -> str:
    head = "".join(
        f"<th>{h}</th>" for h in ("status", "id", "pillar", "check", "finding", "severity", "docs")
    )
    body = "".join(
        "<tr>"
        f"<td>{_badge(r.status)}</td>"
        f'<td class="nowrap"><code>{escape(r.id)}</code></td>'
        f"<td>{escape(PILLAR_LABEL[r.pillar])}</td>"
        f"<td>{escape(r.title)}</td>"
        f'<td title="{escape(_evidence(r.evidence))}">{escape(r.message)}</td>'
        f"<td>{escape(r.severity.value)}</td>"
        f'<td><a href="{escape(r.doc)}">docs</a></td>'
        "</tr>"
        for r in auto
    )
    bar = (
        '<div class="toolbar"><input id="flt" type="search" placeholder="filter: id, pillar, '
        'finding..."><span class="count" id="cnt"></span>'
        '<span class="count">click a column header to sort</span></div>'
        if toolbar
        else ""
    )
    attr = f' id="{table_id}"' if table_id else ""
    return (
        f"<section><h2>All checks ({len(auto)})</h2>{bar}"
        f"<table{attr}><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"
        "</section>"
    )


def _discuss_section(discuss: Sequence[CheckResult]) -> str:
    groups = {p: tuple(r for r in discuss if r.pillar is p) for p in Pillar}
    open_items = sum(1 for r in discuss if r.status is Status.DISCUSS)
    cards = "".join(
        f'<div class="card search"><h3>{escape(PILLAR_LABEL[p])}'
        f'<span class="n">{sum(1 for r in rows if r.status is Status.DISCUSS)} open of '
        f"{len(rows)}</span></h3><ul>"
        + "".join(
            f"<li>{_badge(r.status)} <b>{escape(r.title)}</b>: "
            f"{escape(r.message + attested_by(r))}"
            f'<a class="doc" href="{escape(r.doc)}">docs</a></li>'
            for r in rows
        )
        + "</ul></div>"
        for p, rows in groups.items()
        if rows
    )
    return (
        f"<section><h2>Discuss these ({open_items} open of {len(discuss)})</h2>"
        '<div class="note">People and process items the API cannot see. Settle them in the '
        "landing-zone workshop and record the outcome with <code>waf-check attest-init</code> "
        "and <code>--attest FILE</code>; attested items take the recorded status.</div>"
        f'<div class="todo">{cards}</div></section>'
    )


def _badge(status: Status) -> str:
    return f'<span class="badge {_STATUS_CLASS[status]}">{escape(status.value)}</span>'


def _evidence(evidence: Mapping[str, Any]) -> str:
    if not evidence:
        return ""
    return json.dumps(dict(evidence), ensure_ascii=False, default=_plain, separators=(",", ":"))


def _plain(value: Any) -> Any:
    if isinstance(value, tuple | set | frozenset):
        return list(value)
    if isinstance(value, Mapping):
        return dict(value)
    return str(value)
