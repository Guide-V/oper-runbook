"""waf-check: catalog integrity, evaluators, policy, renderers (no network)."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import date
from pathlib import Path

import pytest
import yaml

from mongoops.waf_check import checks as ck
from mongoops.waf_check import score as sc
from mongoops.waf_check.attest import (
    AttestationError,
    apply_attestations,
    attestations_from_mapping,
    load_attestations,
    render_attestations_yaml,
)
from mongoops.waf_check.catalog import AUTO_CHECKS, CATALOG, DISCUSS_CHECKS
from mongoops.waf_check.facts import Fact
from mongoops.waf_check.model import CheckResult, Kind, Pillar, Severity, Status
from mongoops.waf_check.policy import (
    DEFAULT_POLICY,
    PolicyError,
    load_policy,
    policy_from_mapping,
    render_policy_yaml,
    version_tuple,
)
from mongoops.waf_check.report import Scope, render, sort_results
from tests.waf_fixtures import REGEX_ROWS, SHARED_CLUSTER, bad_facts, good_facts

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
        # suggested indexes: heaviest first, shapes joined, unknown shape ids ignored
        advisor = results["perf.advisor.suggested-indexes"]
        assert advisor.evidence["count"] == 2
        assert advisor.evidence["suggestions"][0] == {
            "namespace": "shop.orders",
            "index": "{sku: 1, ts: -1}",
            "weight": 12.3,
            "slow_queries": 360,
            "avg_ms": 250,
            "inefficiency": 12000,
        }
        assert advisor.message.startswith(
            "2 suggested index(es): shop.orders {sku: 1, ts: -1} (weight 12.3, 360 slow queries "
            "avg 250 ms); shop.events {ts: -1} (weight 1.5, 5 slow queries avg 40 ms)"
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

    def test_regex_check_follows_the_slow_query_scan(self) -> None:
        """NA until scanned; UNKNOWN when the scan could not read; blocking remedies from policy."""
        not_scanned = by_id(ck.evaluate(good_facts(), DEFAULT_POLICY))
        assert not_scanned["perf.regex.index-hostile"].status is Status.NA
        assert "--slow-queries-since" in not_scanned["perf.regex.index-hostile"].message

        unreadable = good_facts(regex_shapes=Fact(error="HTTP 403 reading ..."))
        assert (
            by_id(ck.evaluate(unreadable, DEFAULT_POLICY))["perf.regex.index-hostile"].status
            is Status.UNKNOWN
        )

        scanned = good_facts(regex_shapes=Fact(REGEX_ROWS))
        result = by_id(ck.evaluate(scanned, DEFAULT_POLICY))["perf.regex.index-hostile"]
        assert result.status is Status.WARN
        assert result.evidence["shapes_total"] == 2
        assert [s["remedy"] for s in result.evidence["blocking"]] == ["search"]

        lenient = replace(DEFAULT_POLICY, performance_regex_block_on=("fix_filter",))
        assert (
            by_id(ck.evaluate(scanned, lenient))["perf.regex.index-hostile"].status is Status.PASS
        )
        strict = replace(DEFAULT_POLICY, performance_regex_block_on=("search", "monitor"))
        strict_result = by_id(ck.evaluate(scanned, strict))["perf.regex.index-hostile"]
        assert len(strict_result.evidence["blocking"]) == 2

        shared = good_facts(cluster=SHARED_CLUSTER, regex_shapes=Fact(REGEX_ROWS))
        assert (
            by_id(ck.evaluate(shared, DEFAULT_POLICY))["perf.regex.index-hostile"].status
            is Status.NA
        )


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
            ({"performance": {"regex_block_on": ["search", "pray"]}}, "unknown remedy pray"),
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


class TestAttest:
    FILLED = """
    valid_days: 180
    attestations:
      ops.discuss.infrastructure-as-code:
        status: pass
        owner: platform-team
        date: 2026-08-01
        note: terraform-atlas repo, PR review required
      rel.discuss.dr-runbook-and-drill:
        status: fail
        owner: sre
        date: 2026-08-15
        note: no restore drill yet, planned Q4
      sec.discuss.compliance-standards:
        status: na
        owner: ciso
        date: 2026-01-10
        note: internal only
      perf.discuss.schema-and-index-review:
        status: open
    """

    def test_template_round_trips_and_lists_every_discussion_item(self, tmp_path: Path) -> None:
        text = render_attestations_yaml()
        path = tmp_path / "attestations.yaml"
        path.write_text(text)
        loaded = load_attestations(path)
        assert loaded.items == {} and loaded.valid_days == 365 and loaded.path == str(path)
        assert all(f"  {c.id}:" in text for c in DISCUSS_CHECKS)

    def test_checked_in_example_matches_the_generator(self) -> None:
        example = Path(__file__).resolve().parents[1] / "examples" / "attestations.yaml"
        assert example.read_text() == render_attestations_yaml(), (
            "examples/attestations.yaml drifted: run `mongoops waf-check attest-init -o "
            "examples/attestations.yaml --force`"
        )

    def test_attested_items_take_the_recorded_status(self) -> None:
        attestations = attestations_from_mapping(yaml.safe_load(self.FILLED))
        assert set(attestations.items) == {
            "ops.discuss.infrastructure-as-code",
            "rel.discuss.dr-runbook-and-drill",
            "sec.discuss.compliance-standards",
        }
        results = by_id(
            apply_attestations(
                ck.evaluate(good_facts(), DEFAULT_POLICY),
                attestations,
                today=date(2026, 9, 4),
            )
        )
        iac = results["ops.discuss.infrastructure-as-code"]
        assert iac.status is Status.PASS and iac.kind is Kind.DISCUSS
        assert iac.message == "terraform-atlas repo, PR review required"
        assert iac.evidence["owner"] == "platform-team" and iac.evidence["date"] == "2026-08-01"
        dr = results["rel.discuss.dr-runbook-and-drill"]
        assert dr.status is Status.FAIL
        assert dr.remedy  # the catalog's "what to settle" becomes the remedy
        # expired (2026-01-10 + 180 days < 2026-09-04): back to DISCUSS, old answer shown
        expired = results["sec.discuss.compliance-standards"]
        assert expired.status is Status.DISCUSS
        assert "older than 180 days" in expired.message and expired.evidence["expired"] is True
        assert results["perf.discuss.schema-and-index-review"].status is Status.DISCUSS
        assert results["perf.discuss.schema-and-index-review"].evidence == {}
        # auto checks are untouched
        assert results["sec.network.no-open-access"].status is Status.PASS

    def test_render_shows_attestations_and_gate_sees_them(self) -> None:
        attestations = attestations_from_mapping(yaml.safe_load(self.FILLED))
        results = apply_attestations(
            ck.evaluate(good_facts(), DEFAULT_POLICY), attestations, today=date(2026, 9, 4)
        )
        payload = json.loads(render(results, SCOPE, fmt="json"))
        entry = next(d for d in payload["discuss"] if d["id"] == "rel.discuss.dr-runbook-and-drill")
        assert entry["status"] == "FAIL" and entry["owner"] == "sre"
        assert payload["summary"]["by_status"]["FAIL"] == 1
        html = render(results, SCOPE, fmt="html")
        assert "attested" in html and "(sre, 2026-08-15)" in html
        assert "Discuss these (15 open of 17)" in html
        table = render(results, SCOPE, fmt="table")
        assert "15 open of 17" in table

    @pytest.mark.parametrize(
        ("doc", "fragment"),
        [
            ({"attestations": {"sec.audit.enabled": {"status": "pass"}}}, "not a discussion item"),
            ({"attestations": {"nope": {"status": "pass"}}}, "not a discussion item"),
            (
                {"attestations": {"rel.discuss.dr-runbook-and-drill": {"status": "done"}}},
                "open, pass, fail, warn or na",
            ),
            (
                {
                    "attestations": {
                        "rel.discuss.dr-runbook-and-drill": {"status": "pass", "date": "2026"}
                    }
                },
                "owner: required",
            ),
            (
                {
                    "attestations": {
                        "rel.discuss.dr-runbook-and-drill": {
                            "status": "pass",
                            "owner": "x",
                            "date": "soon",
                        }
                    }
                },
                "YYYY-MM-DD",
            ),
            ({"valid_days": 0}, "positive integer"),
            ({"extra": 1}, "unknown top-level"),
            ([], "mapping at the top level"),
        ],
    )
    def test_rejects_bad_files_with_a_pointer(self, doc: object, fragment: str) -> None:
        with pytest.raises(AttestationError, match=fragment):
            attestations_from_mapping(doc)


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

    def test_score_appears_in_every_format(self) -> None:
        results = ck.evaluate(bad_facts(), DEFAULT_POLICY)
        s = sc.score(results)
        assert s.value is not None
        payload = json.loads(render(results, SCOPE, fmt="json"))
        assert payload["summary"]["score"]["value"] == s.value
        assert payload["summary"]["score"]["tier"] == s.tier.label
        assert set(payload["summary"]["score"]["by_pillar"]) == {p.value for p in Pillar}
        assert f"Score {s.value:.1f} / 10 ({s.tier.label})" in render(results, SCOPE, fmt="table")
        html = render(results, SCOPE, fmt="html")
        assert f'data-score="{s.value:.1f}"' in html
        assert "Quick wins" in html and 'class="meter"' in html
        assert "Made by GuideV. Not an officially supported MongoDB tool." in html


class TestScore:
    """The score is arithmetic over the results, so the tests pin the arithmetic."""

    @staticmethod
    def _r(status: Status, severity: Severity = Severity.FAIL, pillar: Pillar = Pillar.SECURITY):
        return CheckResult(
            id=f"x.{status.value.lower()}.{severity.value}",
            pillar=pillar,
            title="t",
            kind=Kind.AUTO,
            status=status,
            severity=severity,
            message="",
            evidence={},
            remedy="",
            doc="https://example.invalid",
        )

    def test_weights_and_value(self) -> None:
        results = (
            self._r(Status.PASS, Severity.FAIL),  # +2 of 2
            self._r(Status.PASS, Severity.WARN),  # +1 of 1
            self._r(Status.FAIL, Severity.FAIL),  # +0 of 2
            self._r(Status.WARN, Severity.WARN),  # +0 of 1
        )
        s = sc.score(results)
        assert (s.earned, s.possible, s.passed, s.scored) == (3, 6, 2, 4)
        assert s.value == 5.0 and s.tier.label == "Needs work"

    def test_unknown_na_skipped_and_open_discuss_do_not_count(self) -> None:
        base = (self._r(Status.PASS, Severity.FAIL),)
        noise = tuple(self._r(st) for st in (Status.UNKNOWN, Status.NA, Status.SKIPPED))
        discuss = (replace(self._r(Status.DISCUSS, Severity.OFF), kind=Kind.DISCUSS),)
        assert sc.score(base + noise + discuss) == sc.score(base)
        assert sc.score(base).value == 10.0
        assert sc.score(noise).value is None and sc.score(noise).tier is None

    def test_tier_boundaries_use_the_rounded_value(self) -> None:
        assert sc.tier_for(10.0).label == "Well-architected"
        assert sc.tier_for(9.0).label == "Well-architected"
        assert sc.tier_for(8.9).label == "Ready with gaps"
        assert sc.tier_for(7.0).label == "Ready with gaps"
        assert sc.tier_for(6.9).label == "Needs work"
        assert sc.tier_for(5.0).label == "Needs work"
        assert sc.tier_for(4.9).label == "At risk"
        assert sc.tier_for(0.0).label == "At risk"

    def test_attesting_a_discussion_item_moves_the_score(self) -> None:
        results = ck.evaluate(good_facts(), DEFAULT_POLICY)
        before = sc.score(results)
        attested = apply_attestations(
            results,
            attestations_from_mapping(
                {
                    "attestations": {
                        "rel.discuss.dr-runbook-and-drill": {
                            "status": "fail",
                            "owner": "sre",
                            "date": "2026-08-15",
                        }
                    }
                }
            ),
            today=date(2026, 9, 1),
        )
        after = sc.score(attested)
        assert before.value == 10.0
        assert after.possible == before.possible + 2  # attested FAIL weighs like a fail check
        assert after.earned == before.earned
        assert after.value < before.value

    def test_quick_wins_rank_fail_checks_first_and_show_the_gain(self) -> None:
        results = (
            self._r(Status.PASS, Severity.FAIL),
            self._r(Status.WARN, Severity.WARN),
            self._r(Status.FAIL, Severity.FAIL),
        )
        wins = sc.quick_wins(results)
        assert [w.result.status for w in wins] == [Status.FAIL, Status.WARN]
        assert [w.gain for w in wins] == [4.0, 2.0]  # 2/5 and 1/5 of 10
        assert all(w.occurrences == 1 for w in wins)

    def test_quick_wins_group_the_same_check_across_clusters(self) -> None:
        # Two clusters both fail the project-wide network check: one win, doubled gain.
        shared = self._r(Status.FAIL, Severity.FAIL)
        results = (shared, shared, self._r(Status.PASS, Severity.WARN))
        (win,) = sc.quick_wins(results)
        assert win.occurrences == 2 and win.gain == 8.0  # 4 of 5 points
        assert sc.quick_wins((self._r(Status.UNKNOWN),)) == ()

    def test_fixes_to_next_tier(self) -> None:
        # 3 of 6 points -> 5.0 (Needs work). One fail fix -> 5/6 -> 8.3 (Ready with gaps).
        results = (
            self._r(Status.PASS, Severity.FAIL),
            self._r(Status.PASS, Severity.WARN),
            self._r(Status.FAIL, Severity.FAIL),
            self._r(Status.WARN, Severity.WARN),
        )
        target, n = sc.fixes_to_next_tier(results)
        assert (target.label, n) == ("Ready with gaps", 1)
        assert sc.fixes_to_next_tier((self._r(Status.PASS),)) is None  # already top tier
        assert sc.fixes_to_next_tier((self._r(Status.UNKNOWN),)) is None  # nothing scoreable

    def test_fixture_clusters_land_in_sensible_tiers(self) -> None:
        assert sc.score(ck.evaluate(good_facts(), DEFAULT_POLICY)).value == 10.0
        bad = sc.score(ck.evaluate(bad_facts(), DEFAULT_POLICY))
        assert bad.value is not None and bad.value < 7.0
        assert bad.to_dict()["tier"] == bad.tier.label
