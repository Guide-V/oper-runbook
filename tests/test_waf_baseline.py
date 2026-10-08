"""waf-check baseline comparison: JSON round trip, classification, score deltas, renderers."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from mongoops.waf_check import checks as ck
from mongoops.waf_check.attest import apply_attestations, attestations_from_mapping
from mongoops.waf_check.baseline import (
    Baseline,
    BaselineError,
    Change,
    Comparison,
    Snapshot,
    classify,
    compare,
    load_baseline,
    snapshot_from_mapping,
)
from mongoops.waf_check.catalog import CATALOG
from mongoops.waf_check.cli import FailOn, exit_code
from mongoops.waf_check.facts import Fact, Facts
from mongoops.waf_check.model import Status
from mongoops.waf_check.policy import (
    DEFAULT_POLICY,
    Policy,
    policy_fingerprint,
    policy_from_mapping,
)
from mongoops.waf_check.report import ClusterReport, ProjectScope, Scope, render, render_project
from mongoops.waf_check.score import score
from tests.waf_fixtures import ACCESS_LIST_BAD, bad_facts, good_facts

GID = "5f1a" + "0" * 20
BEFORE = "2026-09-01 03:00:00 UTC"
NOW = "2026-09-26 03:00:00 UTC"


def _report(facts: Facts, when: str, policy: Policy = DEFAULT_POLICY) -> ClusterReport:
    return ClusterReport(
        scope=Scope(
            cluster=facts.cluster_name,
            project_id=GID,
            policy_profile=policy.profile,
            policy_fingerprint=policy_fingerprint(policy),
            generated_at=when,
        ),
        results=ck.evaluate(facts, policy),
    )


def cluster_run(facts: Facts, when: str = NOW, policy: Policy = DEFAULT_POLICY) -> Snapshot:
    return Snapshot(reports=(_report(facts, when, policy),))


def project_run(*facts: Facts, when: str = NOW) -> Snapshot:
    reports = tuple(_report(f, when) for f in facts)
    return Snapshot(
        reports=reports,
        project=ProjectScope(
            project_id=GID,
            clusters=tuple(r.scope.cluster for r in reports),
            policy_profile=DEFAULT_POLICY.profile,
            policy_fingerprint=policy_fingerprint(DEFAULT_POLICY),
            generated_at=when,
        ),
    )


def as_text(snapshot: Snapshot, fmt: str = "json", comparison: Comparison | None = None) -> str:
    if snapshot.project is not None:
        return render_project(
            snapshot.reports,
            snapshot.project,
            fmt=fmt,  # type: ignore[arg-type]
            comparison=comparison,
        )
    (rep,) = snapshot.reports
    return render(rep.results, rep.scope, fmt=fmt, comparison=comparison)  # type: ignore[arg-type]


def as_baseline(snapshot: Snapshot, path: str = "reports/baseline.json") -> Baseline:
    """Baselines always go through the JSON the tool writes, like the real workflow."""
    return Baseline(snapshot_from_mapping(json.loads(as_text(snapshot))), path, "ab" * 32)


def kinds(c: Comparison) -> dict[tuple[str, str], Change]:
    return {(ch.cluster, ch.result.id): ch.change for ch in c.changes}


class TestRoundTrip:
    def test_cluster_report_reads_back_identically(self) -> None:
        run = cluster_run(bad_facts())
        back = snapshot_from_mapping(json.loads(as_text(run)))
        assert as_text(back) == as_text(run)
        assert as_text(back, "html") == as_text(run, "html")
        assert score(back.results()) == score(run.results())

    def test_attested_discussion_items_read_back_with_their_status(self) -> None:
        attested = apply_attestations(
            ck.evaluate(good_facts(), DEFAULT_POLICY),
            attestations_from_mapping(
                {
                    "attestations": {
                        "rel.discuss.dr-runbook-and-drill": {
                            "status": "fail",
                            "owner": "sre",
                            "date": "2099-01-01",
                            "note": "no restore drill yet",
                        }
                    }
                }
            ),
        )
        run = Snapshot(reports=(ClusterReport(_report(good_facts(), NOW).scope, attested),))
        back = snapshot_from_mapping(json.loads(as_text(run)))
        drill = next(r for r in back.discuss() if r.id == "rel.discuss.dr-runbook-and-drill")
        assert drill.status is Status.FAIL and drill.evidence["owner"] == "sre"
        assert score(back.results()) == score(run.results())  # attested FAIL still weighs 2
        assert as_text(back) == as_text(run)

    def test_project_report_reads_back_identically(self) -> None:
        run = project_run(good_facts(), bad_facts())
        back = snapshot_from_mapping(json.loads(as_text(run)))
        assert back.project is not None and back.project.clusters == ("prod-orders", "dev-scratch")
        assert as_text(back) == as_text(run)


@pytest.mark.parametrize(
    ("before", "after", "expected", "reason"),
    [
        (Status.PASS, Status.FAIL, Change.REGRESSED, "new finding"),
        (Status.UNKNOWN, Status.WARN, Change.REGRESSED, "new finding"),
        (Status.DISCUSS, Status.FAIL, Change.REGRESSED, "new finding"),  # attested gap
        (Status.WARN, Status.FAIL, Change.REGRESSED, "worse"),
        (Status.FAIL, Status.WARN, Change.IMPROVED, ""),
        (Status.FAIL, Status.PASS, Change.FIXED, ""),
        (Status.WARN, Status.PASS, Change.FIXED, ""),
        (Status.PASS, Status.UNKNOWN, Change.NOT_EVALUATED, ""),  # lost a role
        (Status.FAIL, Status.SKIPPED, Change.NOT_EVALUATED, ""),  # switched off: not a fix
        (Status.FAIL, Status.NA, Change.NOT_EVALUATED, ""),
        (Status.PASS, Status.DISCUSS, Change.NOT_EVALUATED, ""),  # attestation expired
        (Status.UNKNOWN, Status.PASS, Change.NOW_EVALUATED, ""),
        (Status.DISCUSS, Status.PASS, Change.NOW_EVALUATED, ""),
        (Status.PASS, Status.PASS, Change.UNCHANGED, ""),
        (Status.UNKNOWN, Status.NA, Change.UNCHANGED, ""),
        (Status.PASS, None, Change.NOT_EVALUATED, "not in this run"),
        (Status.NA, None, Change.UNCHANGED, ""),
    ],
)
def test_classify(
    before: Status | None, after: Status | None, expected: Change, reason: str
) -> None:
    assert classify(before, after) == (expected, reason)


def test_classify_new_catalog_check_is_never_a_regression() -> None:
    assert classify(None, Status.FAIL, new_check=True) == (Change.NEW_CHECK, "not in the baseline")


class TestCompare:
    def test_fixing_a_cluster_reads_as_fixes_and_a_higher_score(self) -> None:
        base = as_baseline(cluster_run(bad_facts(), BEFORE))
        current = cluster_run(good_facts(cluster_name="dev-scratch"))
        c = compare(base, current)
        moved = kinds(c)
        assert not c.regressed
        assert moved[("dev-scratch", "sec.network.no-open-access")] is Change.FIXED
        assert moved[("dev-scratch", "rel.backup.enabled")] is Change.FIXED
        assert moved[("dev-scratch", "sec.audit.enabled")] is Change.NOW_EVALUATED  # was 403
        assert c.total.delta is not None and c.total.delta > 0 and c.total.direction == "up"
        assert c.baseline_generated_at == BEFORE and c.baseline_path == "reports/baseline.json"
        assert c.unchanged + len(c.changes) == len(CATALOG)  # every check paired exactly once
        assert c.notes == ()
        assert exit_code(current.results(), FailOn.regression, c) == 0
        assert exit_code(current.results(), FailOn.regression, None) == 0

    def test_breaking_a_cluster_reads_as_regressions_and_trips_the_gate(self) -> None:
        base = as_baseline(cluster_run(good_facts(cluster_name="dev-scratch"), BEFORE))
        current = cluster_run(bad_facts())
        c = compare(base, current)
        moved = kinds(c)
        open_access = next(ch for ch in c.regressed if ch.result.id == "sec.network.no-open-access")
        assert (open_access.before, open_access.after) == (Status.PASS, Status.FAIL)
        assert open_access.reason == "new finding"
        # losing the auditLog role is not a regression and not a fix
        assert moved[("dev-scratch", "sec.audit.enabled")] is Change.NOT_EVALUATED
        assert c.changes[0].change is Change.REGRESSED  # worst kind first
        assert c.total.direction == "down"
        assert exit_code(current.results(), FailOn.regression, c) == 1

    def test_warn_to_fail_under_a_changed_policy_is_worse_and_noted(self) -> None:
        lenient = policy_from_mapping({"checks": {"sec.network.no-open-access": "warn"}})
        base = as_baseline(cluster_run(bad_facts(), BEFORE, policy=lenient))
        c = compare(base, cluster_run(bad_facts()))
        (worse,) = c.regressed
        assert (worse.result.id, worse.before, worse.after, worse.reason) == (
            "sec.network.no-open-access",
            Status.WARN,
            Status.FAIL,
            "worse",
        )
        (note,) = c.notes  # same profile name, different rules
        assert "fingerprint" in note and policy_fingerprint(lenient) in note

    def test_switching_a_check_off_is_not_a_fix(self) -> None:
        off = policy_from_mapping(
            {"profile": "lenient", "checks": {"sec.network.no-open-access": "off"}}
        )
        base = as_baseline(cluster_run(bad_facts(), BEFORE))
        c = compare(base, cluster_run(bad_facts(), policy=off))
        assert kinds(c) == {("dev-scratch", "sec.network.no-open-access"): Change.NOT_EVALUATED}
        assert "profile changed from mongodb-defaults to lenient" in c.notes[0]

    def test_check_new_to_the_catalog_is_listed_not_gated(self) -> None:
        payload = json.loads(as_text(cluster_run(good_facts(), BEFORE)))
        payload["catalog"] = "operational-readiness-2026-01"
        payload["checks"] = [
            c for c in payload["checks"] if c["id"] != "sec.network.no-open-access"
        ]
        base = Baseline(snapshot_from_mapping(payload), "old.json", "0" * 64)
        c = compare(base, cluster_run(good_facts(access_list=Fact(ACCESS_LIST_BAD))))
        moved = kinds(c)
        assert moved[("prod-orders", "sec.network.no-open-access")] is Change.NEW_CHECK
        assert moved[("prod-orders", "sec.network.access-list-scoped")] is Change.REGRESSED
        assert all(ch.result.id != "sec.network.no-open-access" for ch in c.regressed)
        assert "catalog changed from operational-readiness-2026-01" in c.notes[0]

    def test_project_tracks_added_and_removed_clusters(self) -> None:
        base = as_baseline(
            project_run(good_facts(), good_facts(cluster_name="old-cluster"), when=BEFORE)
        )
        c = compare(base, project_run(good_facts(), bad_facts()))
        assert (c.clusters_added, c.clusters_removed) == (("dev-scratch",), ("old-cluster",))
        bad_findings = {
            r.id
            for r in ck.evaluate(bad_facts(), DEFAULT_POLICY)
            if r.status.value in ("FAIL", "WARN")
        }
        assert {ch.result.id for ch in c.regressed} == bad_findings
        assert {(ch.cluster, ch.reason) for ch in c.regressed} == {("dev-scratch", "new cluster")}
        assert all(ch.cluster == "dev-scratch" for ch in c.changes)  # prod-orders did not move
        assert list(c.by_cluster) == ["prod-orders", "dev-scratch", "old-cluster"]
        assert c.by_cluster["dev-scratch"].before is None
        assert c.by_cluster["dev-scratch"].direction == "none"
        assert c.by_cluster["old-cluster"].after is None
        assert c.by_cluster["prod-orders"].delta == 0.0

    def test_cluster_run_against_a_project_baseline_uses_that_cluster(self) -> None:
        base = as_baseline(project_run(good_facts(), bad_facts(), when=BEFORE))
        c = compare(base, cluster_run(good_facts(cluster_name="dev-scratch")))
        assert (c.clusters_added, c.clusters_removed) == ((), ())
        assert list(c.by_cluster) == ["dev-scratch"]
        assert kinds(c)[("dev-scratch", "rel.backup.enabled")] is Change.FIXED

    @pytest.mark.parametrize(
        ("baseline", "current", "fragment"),
        [
            (
                lambda: cluster_run(good_facts(), BEFORE),
                lambda: project_run(good_facts()),
                "--all-clusters baseline",
            ),
            (
                lambda: cluster_run(good_facts(), BEFORE),
                lambda: cluster_run(bad_facts()),
                "has no cluster dev-scratch (it covers prod-orders)",
            ),
        ],
    )
    def test_scope_mismatch_is_refused(self, baseline, current, fragment: str) -> None:  # type: ignore[no-untyped-def]
        with pytest.raises(BaselineError, match=fragment.replace("(", r"\(").replace(")", r"\)")):
            compare(as_baseline(baseline()), current())

    def test_other_project_is_refused(self) -> None:
        payload = json.loads(as_text(cluster_run(good_facts(), BEFORE)))
        payload["scope"]["project_id"] = "another"
        base = Baseline(snapshot_from_mapping(payload), "b.json", "0" * 64)
        with pytest.raises(BaselineError, match="baseline is for project another"):
            compare(base, cluster_run(good_facts()))


class TestLoad:
    def test_reads_the_file_and_fingerprints_it(self, tmp_path: Path) -> None:
        path = tmp_path / "base.json"
        path.write_text(as_text(cluster_run(bad_facts(), BEFORE)), encoding="utf-8")
        base = load_baseline(path)
        assert base.sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
        assert base.path == str(path) and base.snapshot.generated_at == BEFORE

    @pytest.mark.parametrize(
        ("content", "fragment"),
        [
            (None, "not found"),
            ("{not json", "not valid JSON"),
            ('{"framework": "something-else"}', "not a waf-check JSON report"),
            ('{"framework": "atlas-well-architected", "checks": []}', "malformed"),
            (
                '{"framework": "atlas-well-architected", "scope": {"cluster": "x", '
                '"project_id": "g"}, "checks": [{"id": "x", "pillar": "nope"}]}',
                "malformed",
            ),
            (
                '{"framework": "atlas-well-architected", "scope": {"project_id": "g"}, '
                '"clusters": []}',
                "no clusters",
            ),
        ],
    )
    def test_bad_files_fail_with_a_pointer(
        self, tmp_path: Path, content: str | None, fragment: str
    ) -> None:
        path = tmp_path / "base.json"
        if content is not None:
            path.write_text(content, encoding="utf-8")
        with pytest.raises(BaselineError, match=fragment):
            load_baseline(path)


class TestRender:
    @staticmethod
    def _fixed() -> tuple[Snapshot, Comparison]:
        base = as_baseline(cluster_run(bad_facts(), BEFORE), path="reports/<base>.json")
        current = cluster_run(good_facts(cluster_name="dev-scratch"))
        return current, compare(base, current)

    def test_json_carries_the_comparison(self) -> None:
        current, c = self._fixed()
        payload = json.loads(as_text(current, comparison=c))["comparison"]
        assert payload["baseline"] == {
            "path": "reports/<base>.json",
            "sha256": "ab" * 32,
            "generated_at": BEFORE,
        }
        assert payload["counts"]["regressed"] == 0 and payload["counts"]["fixed"] > 0
        assert sum(payload["counts"].values()) == len(CATALOG)
        assert payload["score"]["after"] == 10.0
        assert payload["score"]["delta"] == round(10.0 - payload["score"]["before"], 1)
        assert set(payload["by_pillar"]) == {
            "security",
            "reliability",
            "operational_efficiency",
            "performance",
            "cost_optimization",
        }
        first = payload["changes"][0]
        assert set(first) == {
            "cluster",
            "id",
            "pillar",
            "title",
            "change",
            "reason",
            "before",
            "after",
            "message",
        }
        # a report with a comparison is itself a valid baseline for the next run
        assert snapshot_from_mapping(json.loads(as_text(current, comparison=c)))

    def test_table_prints_the_movement(self) -> None:
        current, c = self._fixed()
        text = as_text(current, "table", c)
        assert f"Since baseline {BEFORE}: score" in text
        assert "Changes since baseline (" in text and "Fixed" in text

    def test_html_leads_with_the_changes_and_animates_from_the_baseline(self) -> None:
        current, c = self._fixed()
        html = as_text(current, "html", c)
        assert html.index('id="changes"') < html.index("At a glance")
        assert f'data-from="{c.total.before.value:.1f}"' in html  # type: ignore[union-attr]
        assert '<div class="delta up">' in html and "since baseline" in html
        assert "reports/&lt;base&gt;.json" in html and "<base>" not in html
        assert '<span class="badge ok">Fixed</span>' in html
        assert "<b>baseline</b>" in html  # header chip

    def test_project_html_shows_cluster_deltas(self) -> None:
        base = as_baseline(
            project_run(good_facts(), good_facts(cluster_name="old-cluster"), when=BEFORE)
        )
        current = project_run(good_facts(), bad_facts())
        html = as_text(current, "html", compare(base, current))
        assert "dev-scratch (new)" in html and "old-cluster (not in this run)" in html
        assert '<div class="delta down">' in html
        assert "new cluster" in html and '<span class="why">not in baseline</span> &rarr;' in html

    def test_no_baseline_leaves_every_format_as_before(self) -> None:
        run = cluster_run(bad_facts())
        assert "comparison" not in json.loads(as_text(run))
        assert "Since baseline" not in as_text(run, "table")
        html = as_text(run, "html")
        assert 'id="changes"' not in html and 'data-from="' not in html
