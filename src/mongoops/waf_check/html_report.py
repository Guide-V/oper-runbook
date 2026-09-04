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
from mongoops.common.html_theme import BASE_CSS, TABLE_JS
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
.pillars{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}
.pillar{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:14px 16px;
border-top:3px solid var(--forest)}
.pillar h3{margin:0 0 8px;font-size:14px;color:var(--evergreen)}
.pillar .row{display:flex;gap:6px;flex-wrap:wrap}
.evidence{font:11px ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--grey);
white-space:pre-wrap;word-break:break-word;margin-top:6px}
.doc{font-size:12px;margin-left:8px}
"""


def render_html(results: Sequence[CheckResult], scope: Scope) -> str:
    generated = scope.resolved_time()
    auto = tuple(r for r in sort_results(results) if r.kind is Kind.AUTO)
    discuss = tuple(r for r in results if r.kind is Kind.DISCUSS)
    body = "\n".join(
        (
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
  <h1>Atlas Well-Architected readiness: {heading}</h1>
  <div class="sub">mongoops waf-check {escape(__version__)} &middot; catalog
  {escape(CATALOG_VERSION)} &middot; read-only evaluation of the Atlas configuration against the
  landing-zone policy</div>
  <div class="chips">{chip_html}</div>
</header>
<main>
{body}
</main>
<footer>Generated {escape(generated)} by <code>mongoops waf-check atlas</code>. UNKNOWN means the
API key could not read that setting; it is never counted as a failure. Baseline:
<a href="https://www.mongodb.com/docs/atlas/architecture/current/operational-readiness-checklist/">
MongoDB Atlas operational readiness checklist</a>.</footer>
<script>{TABLE_JS}</script>
</body></html>
"""


def _slug(name: str) -> str:
    return "cluster-" + "".join(ch if ch.isalnum() else "-" for ch in name.lower())


def _rollup(reports: Sequence[ClusterReport]) -> str:
    head = "".join(
        f"<th{' class=num' if h.isupper() or h == 'NA/off' else ''}>{h}</th>"
        for h in (
            "cluster",
            "provider",
            "tier",
            "mongodb",
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
        + cell(c["FAIL"], Status.FAIL)
        + cell(c["WARN"], Status.WARN)
        + cell(c["UNKNOWN"], Status.UNKNOWN)
        + f'<td class="num">{c["PASS"]}</td><td class="num">{c["NA"] + c["SKIPPED"]}</td>'
        "</tr>"
        for rep in reports
        for c in (count_by_status(tuple(r for r in rep.results if r.kind is Kind.AUTO)),)
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
        f'<div class="note">{meta}</div>'
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
    cards = "".join(
        f'<div class="pillar"><h3>{escape(PILLAR_LABEL[p])}</h3><div class="row">'
        + "".join(
            f'<span class="badge {_STATUS_CLASS[Status(s)]}">{escape(s)} {n}</span>'
            for s, n in by_pillar[p.value].items()
            if n
        )
        + "</div></div>"
        for p in Pillar
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
