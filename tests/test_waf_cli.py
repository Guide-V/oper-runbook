"""waf-check collector against a mock Atlas and the CLI end to end (no network)."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import parse_qs

import httpx
import pytest
from typer.testing import CliRunner

from mongoops.cli import app
from mongoops.waf_check import cli as waf_cli
from mongoops.waf_check.facts import ACCEPT_2024, collect_atlas
from tests import waf_fixtures as fx

runner = CliRunner()
GID = "5f1a" + "0" * 20
API = "/api/atlas/v2"


def _results(items: tuple[dict, ...]) -> httpx.Response:  # type: ignore[type-arg]
    return httpx.Response(200, json={"results": list(items), "totalCount": len(items)})


# One process per fixture cluster (hosts a/b/c.example.net); only b (dev-scratch) logs an
# unanchored case-insensitive regex, the shape regex-finder sends to MongoDB Search.
PROCESSES = (
    {"id": "a.example.net:27017", "hostname": "a.example.net", "port": 27017},
    {"id": "b.example.net:27017", "hostname": "b.example.net", "port": 27017},
)
HOSTILE_LINE = json.dumps(
    {
        "t": {"$date": "2026-09-04T00:00:00.000+00:00"},
        "msg": "Slow query",
        "attr": {
            "type": "command",
            "ns": "shop.products",
            "command": {"find": "products", "filter": {"name": {"$regex": "wid", "$options": "i"}}},
            "planSummary": "COLLSCAN",
            "durationMillis": 900,
            "docsExamined": 500000,
            "nreturned": 3,
        },
    }
)


def atlas_handler(req: httpx.Request) -> httpx.Response:
    """A project with one good cluster; auditLog is forbidden; no compliance policy."""
    path = req.url.path.removeprefix(f"{API}/groups/{GID}")
    if path == "/clusters":
        return _results((fx.BAD_CLUSTER, fx.GOOD_CLUSTER))
    if path == "/processes":
        return _results(PROCESSES)
    if path.startswith("/processes/") and path.endswith("/performanceAdvisor/slowQueryLogs"):
        assert "since" in parse_qs(req.url.query.decode())
        hostile = path.startswith("/processes/b.")
        lines = [{"line": HOSTILE_LINE, "namespace": "shop.products"}] if hostile else []
        return httpx.Response(200, json={"slowQueries": lines})
    if path == "/clusters/prod-orders":
        assert req.headers["Accept"] == ACCEPT_2024
        return httpx.Response(200, json=fx.GOOD_CLUSTER)
    if path == "/clusters/dev-scratch":
        return httpx.Response(200, json=fx.BAD_CLUSTER)
    if path.startswith("/clusters/") and path.endswith("/processArgs"):
        return httpx.Response(200, json=fx.PROCESS_ARGS)
    if path.startswith("/clusters/") and path.endswith("/backup/schedule"):
        return httpx.Response(200, json=fx.BACKUP_SCHEDULE)
    if path.endswith("/performanceAdvisor/suggestedIndexes"):
        return httpx.Response(200, json={"suggestedIndexes": [], "shapes": []})
    if path.startswith("/clusters/"):
        return httpx.Response(404, json={"errorCode": "CLUSTER_NOT_FOUND", "detail": "nope"})
    routes = {
        "/backupCompliancePolicy": lambda: httpx.Response(404, json={"errorCode": "NOT_FOUND"}),
        "/accessList": lambda: _results(fx.ACCESS_LIST_GOOD),
        "/peers": lambda: _results(()),
        "/auditLog": lambda: httpx.Response(
            403, json={"errorCode": "USER_UNAUTHORIZED", "detail": "needs owner"}
        ),
        "/maintenanceWindow": lambda: httpx.Response(200, json=fx.MAINTENANCE),
        "/alertConfigs": lambda: _results(fx.ALERTS_ALL),
        "/integrations": lambda: _results(({"type": "DATADOG"},)),
        "/databaseUsers": lambda: _results(fx.USERS_FEDERATED),
        "/settings": lambda: httpx.Response(200, json=fx.SETTINGS_ON),
    }
    if path == "/peers":
        assert parse_qs(req.url.query.decode())["providerName"] == ["AWS"]
    return routes[path]()


def mock_client() -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(atlas_handler), base_url=f"https://x{API}")


@pytest.fixture(autouse=True)
def _patch_client(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(waf_cli, "_open_client", lambda _base_url: mock_client())


def test_collect_atlas_degrades_per_fact() -> None:
    seen: list[tuple[str, str]] = []
    with mock_client() as client:
        facts = collect_atlas(client, GID, "prod-orders", lambda n, s: seen.append((n, s)))
    assert facts.cluster["name"] == "prod-orders"
    assert facts.audit.available is False
    assert "Project Owner" in facts.audit.error
    assert facts.compliance_policy.available and facts.compliance_policy.value is None
    assert facts.access_list.value == fx.ACCESS_LIST_GOOD
    assert facts.alert_configs.value == fx.ALERTS_ALL
    assert dict(seen)["audit"].startswith("HTTP 403")
    assert dict(seen)["cluster"] == "ok"


def test_atlas_json_and_html(tmp_path: Path) -> None:
    out, html = tmp_path / "r.json", tmp_path / "r.html"
    result = runner.invoke(
        app,
        [
            "waf-check",
            "atlas",
            "-p",
            GID,
            "-c",
            "prod-orders",
            "-f",
            "json",
            "-o",
            str(out),
            "--html",
            str(html),
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(out.read_text())
    assert payload["scope"]["tier"] == "M30"
    assert payload["scope"]["version"] == "8.0.4"
    assert payload["summary"]["by_status"]["FAIL"] == 0
    assert payload["summary"]["by_status"]["UNKNOWN"] == 1  # auditLog needs Project Owner
    assert html.read_text().startswith("<!doctype html>")
    assert "Scorecard:" in result.output


def test_fail_on_gates_exit_code() -> None:
    ok = runner.invoke(app, ["waf-check", "atlas", "-p", GID, "-c", "dev-scratch", "-f", "json"])
    assert ok.exit_code == 0, ok.output
    gated = runner.invoke(
        app,
        ["waf-check", "atlas", "-p", GID, "-c", "dev-scratch", "-f", "json", "--fail-on", "fail"],
    )
    assert gated.exit_code == 1
    warn_gate = runner.invoke(
        app,
        ["waf-check", "atlas", "-p", GID, "-c", "prod-orders", "-f", "json", "--fail-on", "warn"],
    )
    assert warn_gate.exit_code == 0  # good cluster: UNKNOWN does not trip the gate


def _check(payload: dict, check_id: str) -> dict:  # type: ignore[type-arg]
    return next(c for c in payload["checks"] if c["id"] == check_id)


def test_slow_query_scan_feeds_the_regex_check() -> None:
    """Without the flag the check is NA; with it, regex-finder shapes decide the outcome."""
    base = ["waf-check", "atlas", "-p", GID, "-f", "json"]
    off = runner.invoke(app, [*base, "-c", "dev-scratch"])
    assert off.exit_code == 0, off.output
    assert _check(json.loads(off.stdout), "perf.regex.index-hostile")["status"] == "NA"

    good = runner.invoke(app, [*base, "-c", "prod-orders", "--slow-queries-since", "24h"])
    assert good.exit_code == 0, good.output
    assert _check(json.loads(good.stdout), "perf.regex.index-hostile")["status"] == "PASS"

    bad = runner.invoke(
        app, [*base, "-c", "dev-scratch", "--slow-queries-since", "24h", "--fail-on", "warn"]
    )
    assert bad.exit_code == 1, bad.output
    check = _check(json.loads(bad.stdout), "perf.regex.index-hostile")
    assert check["status"] == "WARN"
    assert check["evidence"]["blocking"][0]["remedy"] == "search"
    assert check["evidence"]["blocking"][0]["namespace"] == "shop.products"

    bad_since = runner.invoke(app, [*base, "-c", "dev-scratch", "--slow-queries-since", "soon"])
    assert bad_since.exit_code == 2


def test_all_clusters_scores_the_project_with_one_project_fetch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []

    def counting(req: httpx.Request) -> httpx.Response:
        calls.append(req.url.path.removeprefix(f"{API}/groups/{GID}"))
        return atlas_handler(req)

    monkeypatch.setattr(
        waf_cli,
        "_open_client",
        lambda _b: httpx.Client(
            transport=httpx.MockTransport(counting), base_url=f"https://x{API}"
        ),
    )
    html = tmp_path / "project.html"
    result = runner.invoke(
        app,
        ["waf-check", "atlas", "-p", GID, "--all-clusters", "-f", "json", "--html", str(html)],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["scope"]["clusters"] == ["dev-scratch", "prod-orders"]
    assert [c["scope"]["cluster"] for c in payload["clusters"]] == ["dev-scratch", "prod-orders"]
    assert payload["summary"]["by_cluster"]["dev-scratch"]["FAIL"] > 0
    assert payload["summary"]["by_cluster"]["prod-orders"]["FAIL"] == 0
    assert payload["summary"]["by_status"]["DISCUSS"] == 17  # listed once, not per cluster
    assert "discuss" not in payload["clusters"][0]
    # project facts once, cluster facts per cluster
    assert calls.count("/accessList") == 1 and calls.count("/alertConfigs") == 1
    assert calls.count("/clusters/prod-orders/processArgs") == 1
    assert calls.count("/clusters/dev-scratch/processArgs") == 1
    page = html.read_text()
    assert 'id="cluster-dev-scratch"' in page and 'id="cluster-prod-orders"' in page
    assert "Action needed across clusters" in page

    table = runner.invoke(app, ["waf-check", "atlas", "-p", GID, "--all-clusters"])
    assert table.exit_code == 0, table.output
    assert "2 cluster(s)" in table.stdout and "Clusters (2)" in table.stdout
    gated = runner.invoke(
        app, ["waf-check", "atlas", "-p", GID, "--all-clusters", "-f", "json", "--fail-on", "fail"]
    )
    assert gated.exit_code == 1  # dev-scratch fails


def test_cluster_and_all_clusters_are_exclusive() -> None:
    neither = runner.invoke(app, ["waf-check", "atlas", "-p", GID])
    assert neither.exit_code == 2 and "exactly one" in neither.output
    both = runner.invoke(
        app, ["waf-check", "atlas", "-p", GID, "-c", "prod-orders", "--all-clusters"]
    )
    assert both.exit_code == 2


def test_unknown_cluster_is_a_usage_error() -> None:
    result = runner.invoke(app, ["waf-check", "atlas", "-p", GID, "-c", "missing"])
    assert result.exit_code == 2
    assert "CLUSTER_NOT_FOUND" in result.output


def test_policy_file_applies_and_bad_policy_fails_cleanly(tmp_path: Path) -> None:
    policy = tmp_path / "lz.yaml"
    policy.write_text("profile: strict\nchecks:\n  rel.ha.regions: fail\nha: {min_regions: 2}\n")
    result = runner.invoke(
        app,
        [
            "waf-check",
            "atlas",
            "-p",
            GID,
            "-c",
            "prod-orders",
            "-f",
            "json",
            "--policy",
            str(policy),
        ],
    )
    payload = json.loads(result.stdout)
    assert payload["scope"]["policy_profile"] == "strict"
    regions = next(c for c in payload["checks"] if c["id"] == "rel.ha.regions")
    assert regions["status"] == "FAIL"

    policy.write_text("network: {mode: smoke-signals}\n")
    bad = runner.invoke(
        app, ["waf-check", "atlas", "-p", GID, "-c", "prod-orders", "--policy", str(policy)]
    )
    assert bad.exit_code == 2
    assert "network.mode" in bad.output


def test_init_writes_loadable_policy(tmp_path: Path) -> None:
    target = tmp_path / "landing-zone.yaml"
    result = runner.invoke(app, ["waf-check", "init", "-o", str(target)])
    assert result.exit_code == 0, result.output
    assert "profile: mongodb-defaults" in target.read_text()
    again = runner.invoke(app, ["waf-check", "init", "-o", str(target)])
    assert again.exit_code == 2 and "exists" in again.output
    interactive = runner.invoke(
        app,
        ["waf-check", "init", "-o", str(target), "--force", "-i"],
        input="\n".join(
            ["peering", "prod", "n", "y", "3", "2", "14", "y", "app, env", "datadog", "n", ""]
        ),
    )
    assert interactive.exit_code == 0, interactive.output
    text = target.read_text()
    assert "profile: prod" in text
    assert "mode: peering" in text
    assert "min_regions: 2" in text
    assert "required: [app, env]" in text
    assert "required: [DATADOG]" in text
    assert "require_customer_managed_keys: false" in text


def test_attest_init_then_attested_run_gates(tmp_path: Path) -> None:
    target = tmp_path / "attestations.yaml"
    result = runner.invoke(app, ["waf-check", "attest-init", "-o", str(target)])
    assert result.exit_code == 0, result.output
    again = runner.invoke(app, ["waf-check", "attest-init", "-o", str(target)])
    assert again.exit_code == 2 and "exists" in again.output
    # fill one item in as the workshop would
    text = target.read_text().replace(
        "  rel.discuss.dr-runbook-and-drill:\n    status: open\n    owner:\n    date:\n    note:",
        "  rel.discuss.dr-runbook-and-drill:\n    status: fail\n    owner: sre\n"
        "    date: 2099-01-01\n    note: no restore drill yet",
    )
    target.write_text(text)
    base = ["waf-check", "atlas", "-p", GID, "-c", "prod-orders", "-f", "json"]
    gated = runner.invoke(app, [*base, "--attest", str(target), "--fail-on", "fail"])
    assert gated.exit_code == 1, gated.output
    payload = json.loads(gated.stdout)
    assert payload["scope"]["attestations_path"] == str(target)
    entry = next(d for d in payload["discuss"] if d["id"] == "rel.discuss.dr-runbook-and-drill")
    assert entry["status"] == "FAIL" and entry["note"] == "no restore drill yet"
    assert payload["summary"]["by_status"]["DISCUSS"] == 16
    bad = tmp_path / "bad.yaml"
    bad.write_text("attestations: {sec.audit.enabled: {status: pass}}\n")
    broken = runner.invoke(app, [*base, "--attest", str(bad)])
    assert broken.exit_code == 2 and "not a discussion item" in broken.output


def test_checks_lists_catalog() -> None:
    result = runner.invoke(app, ["waf-check", "checks", "-f", "json"])
    ids = {c["id"] for c in json.loads(result.stdout)}
    assert "sec.audit.enabled" in ids and "rel.discuss.dr-runbook-and-drill" in ids
    table = runner.invoke(app, ["waf-check", "checks"])
    assert "waf-check catalog" in table.stdout
