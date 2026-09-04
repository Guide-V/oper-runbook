"""waf-check: catalog integrity, evaluators, policy, renderers (no network)."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest
import yaml

from mongoops.waf_check import checks as ck
from mongoops.waf_check.catalog import AUTO_CHECKS, CATALOG, DISCUSS_CHECKS
from mongoops.waf_check.facts import Fact
from mongoops.waf_check.model import Kind, Pillar, Severity, Status
from mongoops.waf_check.policy import (
    DEFAULT_POLICY,
    PolicyError,
    load_policy,
    policy_from_mapping,
    render_policy_yaml,
    version_tuple,
)
from mongoops.waf_check.report import Scope, render, sort_results
from tests.waf_fixtures import SHARED_CLUSTER, bad_facts, good_facts

SCOPE = Scope(cluster="prod-orders", project_id="gid", generated_at="2026-09-04 12:00:00 UTC")


def by_id(results):  # type: ignore[no-untyped-def]
    return {r.id: r for r in results}


class TestCatalog:
    def test_ids_unique_and_well_formed(self) -> None:
        ids = [c.id for c in CATALOG]
        assert len(ids) == len(set(ids))
        assert all(c.id.split(".")[0] in ("sec", "rel", "ops", "perf", "cost") for c in CATALOG)
        assert all(c.doc.startswith("https://") for c in CATALOG)

    def test_every_auto_check_has_exactly_one_evaluator(self) -> None:
        assert {c.id for c in AUTO_CHECKS} == set(ck.EVALUATORS)

    def test_every_pillar_has_discussion_items(self) -> None:
        assert {c.pillar for c in DISCUSS_CHECKS} == set(Pillar)
        assert all(
            c.kind is Kind.DISCUSS and c.default_severity is Severity.OFF for c in DISCUSS_CHECKS
        )


class TestEvaluate:
    def test_well_configured_cluster_has_no_actions(self) -> None:
        results = by_id(ck.evaluate(good_facts(), DEFAULT_POLICY))
        assert not [r.id for r in results.values() if r.status in (Status.FAIL, Status.WARN)]
        assert results["sec.network.private-connectivity"].status is Status.PASS
        assert results["ops.tags.required"].status is Status.PASS  # tag keys are case-insensitive
        # policy-off-by-value items say why they were not evaluated
        assert results["rel.backup.snapshot-copy"].status is Status.NA
        assert "require_snapshot_copy" in results["rel.backup.snapshot-copy"].message
        assert results["ops.integrations.observability"].status is Status.NA
        assert results["ops.discuss.org-structure"].status is Status.DISCUSS
        assert len(results) == len(CATALOG)

    def test_badly_configured_cluster_fails_where_it_should(self) -> None:
        results = by_id(ck.evaluate(bad_facts(), DEFAULT_POLICY))
        failing = {r.id for r in results.values() if r.status is Status.FAIL}
        assert failing == {
            "sec.network.no-open-access",
            "sec.tls.minimum-version",
            "rel.ha.electable-nodes",
            "rel.protection.termination-protection",
            "rel.backup.enabled",
        }
        warning = {r.id for r in results.values() if r.status is Status.WARN}
        assert {
            "sec.network.private-connectivity",
            "sec.network.access-list-scoped",
            "sec.auth.no-password-users",
            "sec.encryption.customer-managed-keys",
            "sec.hardening.server-side-javascript-disabled",
            "rel.maintenance.window",
            "rel.maintenance.protected-hours",
            "rel.version.minimum",
            "ops.tags.required",
            "ops.alerts.recommended",
            "ops.project.advisors-enabled",
            "perf.autoscaling.compute",
            "perf.autoscaling.disk",
            "perf.advisor.suggested-indexes",
        } <= warning
        # evidence is concrete, and remedies name the field
        assert results["sec.network.no-open-access"].evidence["open_entries"] == ("0.0.0.0/0",)
        assert results["sec.network.access-list-scoped"].evidence["broad_entries"] == (
            "10.0.0.0/8",
        )
        assert results["sec.auth.no-password-users"].evidence["password_users"] == ("legacy-app",)
        assert results["ops.tags.required"].evidence["missing"] == (
            "environment",
            "contact",
            "criticality",
        )
        assert (
            results["ops.alerts.recommended"]
            .evidence["missing"][0]
            .startswith("OUTSIDE_METRIC_THRESHOLD/DISK_PARTITION_IOPS")
        )
        assert "Terraform" in results["ops.tags.required"].remedy
        # dependent checks explain the dependency instead of double-failing
        assert results["rel.backup.continuous"].status is Status.NA
        assert "rel.backup.enabled" in results["rel.backup.continuous"].message

    def test_unreadable_fact_is_unknown_not_fail(self) -> None:
        results = by_id(ck.evaluate(bad_facts(), DEFAULT_POLICY))
        audit = results["sec.audit.enabled"]
        assert audit.status is Status.UNKNOWN
        assert "Project Owner" in audit.message
        assert audit.remedy == ""

    def test_shared_tier_marks_platform_controls_not_applicable(self) -> None:
        facts = good_facts(
            cluster_name="cluster-free", cluster=SHARED_CLUSTER, process_args=Fact(error="x")
        )
        results = by_id(ck.evaluate(facts, DEFAULT_POLICY))
        for check_id in (
            "sec.tls.minimum-version",
            "sec.audit.enabled",
            "sec.encryption.customer-managed-keys",
            "rel.backup.continuous",
            "perf.autoscaling.compute",
            "perf.advisor.suggested-indexes",
        ):
            assert results[check_id].status is Status.NA, check_id
            assert "shared" in results[check_id].message
        assert results["rel.ha.electable-nodes"].status is Status.PASS
        assert facts.provider == "AWS"

    def test_policy_values_change_expectations(self) -> None:
        strict = replace(
            DEFAULT_POLICY,
            network_mode="peering",
            ha_min_regions=2,
            backup_restore_window_days=14,
            backup_require_snapshot_copy=True,
            backup_require_compliance_policy=True,
            integrations_required=("DATADOG", "PROMETHEUS"),
            performance_require_default_max_time_ms=True,
        )
        results = by_id(ck.evaluate(good_facts(), strict))
        assert results["rel.ha.regions"].status is Status.WARN
        assert results["rel.backup.restore-window"].status is Status.WARN
        assert results["rel.backup.snapshot-copy"].status is Status.PASS
        assert results["rel.backup.compliance-policy"].status is Status.PASS
        assert results["ops.integrations.observability"].status is Status.PASS
        assert results["perf.config.default-max-time-ms"].status is Status.PASS
        relaxed = replace(
            DEFAULT_POLICY, network_mode="ip_allowlist", auth_allow_password_users=True
        )
        results = by_id(ck.evaluate(bad_facts(), relaxed))
        assert results["sec.network.private-connectivity"].status is Status.NA
        assert results["sec.auth.no-password-users"].status is Status.NA
        assert results["sec.network.no-open-access"].status is Status.FAIL  # never relaxed


class TestPolicy:
    def test_defaults_round_trip_through_the_generated_file(self, tmp_path: Path) -> None:
        text = render_policy_yaml()
        path = tmp_path / "landing-zone.yaml"
        path.write_text(text)
        assert load_policy(path) == DEFAULT_POLICY
        assert "sec.audit.enabled: fail" in text
        assert "rel.backup.snapshot-copy: warn" in text

    def test_checked_in_example_matches_the_generator(self) -> None:
        example = Path(__file__).resolve().parents[1] / "examples" / "landing-zone.yaml"
        assert example.read_text() == render_policy_yaml(), (
            "examples/landing-zone.yaml drifted: run `mongoops waf-check init -o "
            "examples/landing-zone.yaml --force`"
        )

    def test_custom_policy_round_trip_and_severity_overrides(self, tmp_path: Path) -> None:
        custom = replace(
            DEFAULT_POLICY,
            profile="prod",
            network_mode="peering",
            tags_required=("app", "env"),
            integrations_required=("DATADOG",),
            severities={**DEFAULT_POLICY.severities, "sec.audit.enabled": Severity.WARN},
        )
        path = tmp_path / "prod.yaml"
        path.write_text(render_policy_yaml(custom))
        loaded = load_policy(path)
        assert loaded == custom
        assert "sec.audit.enabled: warn  # default: fail" in path.read_text()

    def test_partial_file_keeps_defaults_and_applies_severity(self) -> None:
        policy = policy_from_mapping(
            yaml.safe_load(
                """
                network: {mode: ip_allowlist}
                alerts:
                  required: [NO_PRIMARY, OUTSIDE_METRIC_THRESHOLD/CONNECTIONS_PERCENT,
                             {event: HOST_DOWN}]
                checks:
                  sec.audit.enabled: warn
                  rel.backup.enabled: off
                """
            )
        )
        assert policy.network_mode == "ip_allowlist"
        assert policy.ha_min_electable_nodes == 3
        assert [a.label for a in policy.alerts_required] == [
            "NO_PRIMARY",
            "OUTSIDE_METRIC_THRESHOLD/CONNECTIONS_PERCENT",
            "HOST_DOWN",
        ]
        results = by_id(ck.evaluate(bad_facts(), policy))
        assert results["rel.backup.enabled"].status is Status.SKIPPED
        good = by_id(ck.evaluate(good_facts(audit=Fact({"enabled": False})), policy))
        assert good["sec.audit.enabled"].status is Status.WARN

    @pytest.mark.parametrize(
        ("doc", "fragment"),
        [
            ({"nope": 1}, "unknown policy section"),
            ({"network": {"mode": "carrier-pigeon"}}, "network.mode"),
            ({"checks": {"sec.audit.enabled": "maybe"}}, "fail, warn or off"),
            ({"checks": {"sec.discuss.compliance-standards": "fail"}}, "not an auto check"),
            ({"checks": {"typo.check": "fail"}}, "not an auto check"),
            ({"ha": {"min_electable_nodes": "three"}}, "non-negative integer"),
            ({"tls": {"minimum": "SSL3"}}, "tls.minimum"),
            ({"tags": {"required": "application"}}, "expected a list"),
            ({"cluster": {"min_mongodb_major": "latest"}}, "version like 7.0"),
            ([], "mapping at the top level"),
        ],
    )
    def test_rejects_bad_policies_with_a_pointer(self, doc: object, fragment: str) -> None:
        with pytest.raises(PolicyError, match=fragment):
            policy_from_mapping(doc)

    def test_version_tuple(self) -> None:
        assert version_tuple("8.0") == (8, 0)
        assert version_tuple("7.0.12-ent") == (7, 0, 12)
        assert version_tuple("6.0") < version_tuple("7.0")


class TestRender:
    def test_sort_and_json_shape(self) -> None:
        results = ck.evaluate(bad_facts(), DEFAULT_POLICY)
        ordered = sort_results(results)
        assert ordered[0].status is Status.FAIL and ordered[-1].status is Status.DISCUSS
        payload = json.loads(render(results, SCOPE, fmt="json"))
        assert payload["framework"] == "atlas-well-architected"
        assert payload["summary"]["by_status"]["FAIL"] == 5
        assert payload["summary"]["by_pillar"]["security"]["FAIL"] == 2
        assert {c["kind"] for c in payload["checks"]} == {"auto"}
        assert payload["discuss"][0]["id"].endswith("org-structure")
        first = payload["checks"][0]
        assert set(first) >= {"id", "status", "severity", "evidence", "remedy", "doc"}

    def test_table_mentions_scope_and_discussion(self) -> None:
        text = render(ck.evaluate(good_facts(), DEFAULT_POLICY), SCOPE, fmt="table")
        assert "prod-orders" in text
        assert "Discuss these" in text
        assert "FAIL 0" in text

    def test_html_is_self_contained_and_escaped(self) -> None:
        html = render(ck.evaluate(bad_facts(), DEFAULT_POLICY), SCOPE, fmt="html")
        assert html.startswith("<!doctype html>")
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
        for heading in (
            "Action needed (",
            "Could not evaluate (1)",
            "All checks (",
            "Discuss these (",
        ):
            assert heading in html
        assert "Project Owner" in html
        assert "http://" not in html.replace("https://", "")  # no external assets
