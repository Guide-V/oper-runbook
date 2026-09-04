"""``mongoops waf-check``: score one Atlas cluster against the WAF readiness catalog."""

from __future__ import annotations

import io
import json
import sys
from dataclasses import replace
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import httpx
import typer
import yaml
from rich.console import Console
from rich.table import Table

from mongoops.common import atlas_api
from mongoops.common.perf_advisor import ApiError
from mongoops.waf_check.catalog import CATALOG, CATALOG_VERSION
from mongoops.waf_check.checks import evaluate
from mongoops.waf_check.facts import Facts, collect_atlas, region_configs
from mongoops.waf_check.model import PILLAR_LABEL, CheckResult, Status
from mongoops.waf_check.policy import (
    DEFAULT_POLICY,
    NETWORK_MODES,
    Policy,
    PolicyError,
    load_policy,
    policy_from_mapping,
    render_policy_yaml,
)
from mongoops.waf_check.report import Scope, render

app = typer.Typer(
    name="waf-check",
    help="Atlas Well-Architected readiness scorecard for one cluster (read-only).",
    no_args_is_help=True,
)
err = Console(stderr=True)


class Fmt(StrEnum):
    table = "table"
    json = "json"
    html = "html"


class FailOn(StrEnum):
    never = "never"
    fail = "fail"
    warn = "warn"


def _open_client(base_url: str) -> httpx.Client:
    """Indirection so tests can swap in an ``httpx.MockTransport`` client."""
    return atlas_api.atlas_client(atlas_api.auth_from_env(), base_url=base_url)


def _fail(message: str) -> None:
    err.print(f"[red]error:[/red] {message}")
    raise typer.Exit(code=2)


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _scope(facts: Facts, policy: Policy, policy_path: Path | None) -> Scope:
    tier = next(
        (
            str((rc.get("electableSpecs") or {}).get("instanceSize") or "")
            for rc in region_configs(facts.cluster)
            if (rc.get("electableSpecs") or {}).get("instanceSize")
        ),
        "",
    )
    return Scope(
        cluster=facts.cluster_name,
        project_id=facts.group_id,
        provider=facts.provider,
        tier=tier,
        version=str(
            facts.cluster.get("mongoDBVersion") or facts.cluster.get("mongoDBMajorVersion") or ""
        ),
        policy_profile=policy.profile,
        policy_path=str(policy_path) if policy_path else "built-in defaults",
    )


def exit_code(results: tuple[CheckResult, ...], fail_on: FailOn) -> int:
    """0 unless the gate policy says otherwise. Pure."""
    statuses = {r.status for r in results}
    if fail_on is FailOn.fail and Status.FAIL in statuses:
        return 1
    if fail_on is FailOn.warn and statuses & {Status.FAIL, Status.WARN}:
        return 1
    return 0


@app.command()
def atlas(
    project_id: Annotated[
        str,
        typer.Option("--project-id", "-p", envvar="MONGODB_ATLAS_PROJECT_ID", help="Project id."),
    ],
    cluster: Annotated[str, typer.Option("--cluster", "-c", help="Cluster name to score.")],
    policy_file: Annotated[
        Path | None,
        typer.Option(
            "--policy",
            help="Landing-zone policy YAML (see `waf-check init`). Default: MongoDB defaults.",
        ),
    ] = None,
    fail_on: Annotated[
        FailOn,
        typer.Option("--fail-on", help="Exit 1 when a check has this status or worse."),
    ] = FailOn.never,
    base_url: Annotated[
        str, typer.Option(envvar="MONGODB_ATLAS_OPS_MANAGER_URL", help="Atlas API base URL.")
    ] = atlas_api.DEFAULT_BASE_URL,
    fmt: Annotated[Fmt, typer.Option("--format", "-f", help="Output format.")] = Fmt.table,
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Write output here instead of stdout.")
    ] = None,
    html: Annotated[
        Path | None,
        typer.Option("--html", help="Also write the self-contained HTML scorecard to this file."),
    ] = None,
) -> None:
    """Score one cluster: Atlas Admin API facts x landing-zone policy -> pillar scorecard.

    Read-only. Needs Project Read Only for most checks; auditLog and integrations need
    Project Owner and Performance Advisor needs Project Data Access Read Only. Checks the key
    cannot read are reported as UNKNOWN, never as failures.
    """
    try:
        policy = load_policy(policy_file) if policy_file else DEFAULT_POLICY
    except PolicyError as exc:
        _fail(str(exc))
    try:
        with _open_client(base_url) as client:
            facts = collect_atlas(
                client,
                project_id,
                cluster,
                lambda name, state: err.print(f"[dim]{name}: {state}[/dim]"),
            )
    except (ApiError, ValueError) as exc:
        _fail(str(exc))
    results = evaluate(facts, policy)
    scope = _scope(facts, policy, policy_file)
    text = render(results, scope, fmt=fmt.value)
    if output:
        _write(output, text)
        err.print(f"[green]Wrote {output}[/green]")
    else:
        sys.stdout.write(text if text.endswith("\n") else text + "\n")
    if html:
        _write(html, render(results, scope, fmt="html"))
        err.print(f"[green]Scorecard: {html.resolve().as_uri()}[/green]", soft_wrap=True)
    counts = {s: sum(1 for r in results if r.status is s) for s in Status}
    err.print(
        f"[dim]FAIL {counts[Status.FAIL]}  WARN {counts[Status.WARN]}  "
        f"UNKNOWN {counts[Status.UNKNOWN]}  PASS {counts[Status.PASS]}[/dim]"
    )
    raise typer.Exit(code=exit_code(results, fail_on))


@app.command()
def init(
    output: Annotated[
        Path, typer.Option("--output", "-o", help="Where to write the policy file.")
    ] = Path("landing-zone.yaml"),
    interactive: Annotated[
        bool, typer.Option("--interactive", "-i", help="Ask the landing-zone questions first.")
    ] = False,
    force: Annotated[bool, typer.Option("--force", help="Overwrite an existing file.")] = False,
) -> None:
    """Write a commented landing-zone policy (MongoDB defaults, or your answers with -i)."""
    if output.exists() and not force:
        _fail(f"{output} exists; use --force to overwrite")
    policy = _ask(DEFAULT_POLICY) if interactive else DEFAULT_POLICY
    text = render_policy_yaml(policy)
    policy_from_mapping(yaml.safe_load(text))  # the file we write must load back
    _write(output, text)
    err.print(
        f"[green]Wrote {output}[/green]. Edit it, then run "
        f"`mongoops waf-check atlas -c <cluster> --policy {output}`."
    )


def _ask(base: Policy) -> Policy:
    """The few landing-zone questions that change what the checks expect."""
    typer.echo("Landing-zone questions (Enter keeps the MongoDB default).")
    mode = typer.prompt(
        f"Network connectivity for applications {NETWORK_MODES}", default=base.network_mode
    )
    while mode not in NETWORK_MODES:
        mode = typer.prompt(f"Choose one of {NETWORK_MODES}", default=base.network_mode)
    return replace(
        base,
        profile=typer.prompt("Profile name (e.g. prod, nonprod)", default="landing-zone"),
        network_mode=mode,
        encryption_require_customer_managed_keys=typer.confirm(
            "Require customer-managed encryption keys (BYOK)?",
            default=base.encryption_require_customer_managed_keys,
        ),
        auth_allow_password_users=typer.confirm(
            "Allow password (SCRAM) database users?", default=base.auth_allow_password_users
        ),
        ha_min_electable_nodes=typer.prompt(
            "Minimum electable nodes per shard", default=base.ha_min_electable_nodes, type=int
        ),
        ha_min_regions=typer.prompt("Minimum regions", default=base.ha_min_regions, type=int),
        backup_restore_window_days=typer.prompt(
            "Point-in-time restore window (days, from RPO)",
            default=base.backup_restore_window_days,
            type=int,
        ),
        backup_require_snapshot_copy=typer.confirm(
            "Require snapshot copies to another region?", default=base.backup_require_snapshot_copy
        ),
        tags_required=_csv(
            typer.prompt("Required tags (comma separated)", default=", ".join(base.tags_required))
        ),
        integrations_required=tuple(
            t.upper()
            for t in _csv(
                typer.prompt(
                    "Observability integrations, any of (comma separated, empty = not checked)",
                    default=", ".join(base.integrations_required),
                    show_default=False,
                )
            )
        ),
        performance_require_compute_autoscaling=typer.confirm(
            "Require compute autoscaling?", default=base.performance_require_compute_autoscaling
        ),
    )


def _csv(text: str) -> tuple[str, ...]:
    return tuple(part.strip().lower() for part in text.split(",") if part.strip())


@app.command()
def checks(
    fmt: Annotated[Fmt, typer.Option("--format", "-f", help="table or json.")] = Fmt.table,
) -> None:
    """List the catalog: every check id, pillar, kind and default severity."""
    if fmt is Fmt.json:
        payload = [
            {
                "id": c.id,
                "pillar": c.pillar.value,
                "kind": c.kind.value,
                "default_severity": c.default_severity.value,
                "title": c.title,
                "what": c.what,
                "doc": c.doc,
            }
            for c in CATALOG
        ]
        sys.stdout.write(json.dumps(payload, indent=2) + "\n")
        return
    console = Console(record=True, width=200, file=io.StringIO(), force_terminal=False)
    t = Table(title=f"waf-check catalog {CATALOG_VERSION} ({len(CATALOG)} entries)")
    for col in ("id", "kind", "pillar", "default", "check", "evidence / what to settle"):
        t.add_column(col, overflow="fold")
    for c in CATALOG:
        t.add_row(
            c.id, c.kind.value, PILLAR_LABEL[c.pillar], c.default_severity.value, c.title, c.what
        )
    console.print(t)
    sys.stdout.write(console.export_text())
