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
    Scope,
    count_by_pillar,
    count_by_status,
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
            _action_section(auto),
            _unknown_section(auto),
            _all_checks(auto),
            _discuss_section(discuss),
        )
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WAF readiness: {escape(scope.cluster)}</title>
<style>{BASE_CSS}{_EXTRA_CSS}</style></head>
<body>
<header>
  <h1>Atlas Well-Architected readiness: <code>{escape(scope.cluster)}</code></h1>
  <div class="sub">mongoops waf-check {escape(__version__)} &middot; catalog
  {escape(CATALOG_VERSION)} &middot; read-only evaluation of the Atlas configuration against the
  landing-zone policy</div>
  {_chips(scope, generated)}
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


def _chips(scope: Scope, generated: str) -> str:
    items = (
        ("cluster", scope.cluster),
        ("project", scope.project_id),
        ("provider", scope.provider),
        ("tier", scope.tier),
        ("mongodb", scope.version),
        ("policy", scope.policy_profile),
        ("policy file", scope.policy_path),
        ("generated", generated),
    )
    chips = "".join(
        f'<span class="chip"><b>{escape(k)}</b>{escape(v)}</span>' for k, v in items if v
    )
    return f'<div class="chips">{chips}</div>'


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


def _action_section(auto: Sequence[CheckResult]) -> str:
    actions = tuple(r for r in auto if r.status in ACTION_STATUSES)
    if not actions:
        cards = '<div class="card">Every evaluated check passes the policy.</div>'
    else:
        cards = "".join(
            f'<div class="card {_STATUS_CLASS[r.status]}"><h3>{_badge(r.status)} '
            f'{escape(r.title)}<span class="n">{escape(r.id)} &middot; '
            f"{escape(PILLAR_LABEL[r.pillar])}</span></h3>"
            f"<div>{escape(r.message)}</div>"
            f"<div><b>Fix:</b> {escape(r.remedy)}"
            f'<a class="doc" href="{escape(r.doc)}">docs</a></div>'
            f'<div class="evidence">{escape(_evidence(r.evidence))}</div></div>'
            for r in actions
        )
    return (
        f'<section><h2>Action needed ({len(actions)})</h2><div class="todo">{cards}</div></section>'
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


def _all_checks(auto: Sequence[CheckResult]) -> str:
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
    return (
        f"<section><h2>All checks ({len(auto)})</h2>"
        '<div class="toolbar"><input id="flt" type="search" placeholder="filter: id, pillar, '
        'finding..."><span class="count" id="cnt"></span>'
        '<span class="count">click a column header to sort</span></div>'
        f'<table id="findings"><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>'
        "</section>"
    )


def _discuss_section(discuss: Sequence[CheckResult]) -> str:
    groups = {p: tuple(r for r in discuss if r.pillar is p) for p in Pillar}
    cards = "".join(
        f'<div class="card search"><h3>{escape(PILLAR_LABEL[p])}'
        f'<span class="n">{len(rows)} topic(s)</span></h3><ul>'
        + "".join(
            f"<li><b>{escape(r.title)}</b>: {escape(r.message)}"
            f'<a class="doc" href="{escape(r.doc)}">docs</a></li>'
            for r in rows
        )
        + "</ul></div>"
        for p, rows in groups.items()
        if rows
    )
    return (
        f"<section><h2>Discuss these ({len(discuss)})</h2>"
        '<div class="note">People and process items the API cannot see. Settle them in the '
        "landing-zone workshop; the tool lists them so they are not forgotten.</div>"
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
