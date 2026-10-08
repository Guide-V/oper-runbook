"""Baseline comparison: this run against an earlier waf-check JSON report, check by check.

After a change window the operations question is "what moved?", not only "what is the state?".
A baseline is any JSON report the tool wrote before (``-f json -o FILE`` or ``--json FILE``). The
comparison pairs every check by cluster and id and classifies how its status moved:

* ``regressed``: a new FAIL / WARN (from PASS, NA, UNKNOWN, off, an open discussion item, or on a
  cluster that is new to the project), or WARN that became FAIL. ``--fail-on regression`` gates
  on these only, so a project with known gaps can adopt the gate without fixing everything first.
* ``improved``: FAIL became WARN. ``fixed``: FAIL / WARN became PASS.
* ``not_evaluated``: PASS / WARN / FAIL became UNKNOWN, NA, off or an open discussion item. Kept
  apart from ``fixed`` on purpose: switching a check off, losing an API role or letting an
  attestation expire must never read as a fix.
* ``now_evaluated``: UNKNOWN / NA / off / open discussion became PASS.
* ``new_check``: the id is not in the baseline at all (newer catalog). Listed, never gated: the
  yardstick changed, not the cluster.

Pure except ``load_baseline``.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, fields, replace
from enum import StrEnum
from pathlib import Path
from typing import Any

from mongoops.waf_check.catalog import BY_ID, CATALOG, CATALOG_VERSION
from mongoops.waf_check.model import CheckResult, Kind, Pillar, Severity, Status
from mongoops.waf_check.report import (
    FRAMEWORK,
    ClusterReport,
    ProjectScope,
    Scope,
    project_results,
)
from mongoops.waf_check.score import Score, score, score_by_pillar

EVALUATED = frozenset({Status.PASS, Status.WARN, Status.FAIL})
FINDINGS = frozenset({Status.WARN, Status.FAIL})


class BaselineError(ValueError):
    """Unreadable baseline, or one that does not cover what this run scored."""


class Change(StrEnum):
    """Declaration order is display order: what needs attention first."""

    REGRESSED = "regressed"
    NOT_EVALUATED = "not_evaluated"
    NEW_CHECK = "new_check"
    IMPROVED = "improved"
    FIXED = "fixed"
    NOW_EVALUATED = "now_evaluated"
    UNCHANGED = "unchanged"

    @property
    def label(self) -> str:
        return CHANGE_LABEL[self]


CHANGE_LABEL: Mapping[Change, str] = {
    Change.REGRESSED: "Regressed",
    Change.NOT_EVALUATED: "No longer evaluated",
    Change.NEW_CHECK: "New check",
    Change.IMPROVED: "Improved",
    Change.FIXED: "Fixed",
    Change.NOW_EVALUATED: "Now evaluated",
    Change.UNCHANGED: "Unchanged",
}
MOVED: tuple[Change, ...] = tuple(c for c in Change if c is not Change.UNCHANGED)
_ORDER: Mapping[Change, int] = {c: i for i, c in enumerate(Change)}


# --- runs -----------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Snapshot:
    """One waf-check run: the clusters it scored, evaluated just now or read back from JSON.

    Every cluster report carries the auto results followed by the (project-level) discussion
    items, exactly like a live run, so the renderers cannot tell the two apart.
    """

    reports: tuple[ClusterReport, ...]
    project: ProjectScope | None = None
    """Set for ``--all-clusters`` runs."""
    catalog: str = CATALOG_VERSION

    @property
    def _header(self) -> Scope | ProjectScope:
        return self.project or self.reports[0].scope

    @property
    def project_id(self) -> str:
        return self._header.project_id

    @property
    def generated_at(self) -> str:
        return self._header.resolved_time()

    @property
    def policy_profile(self) -> str:
        return self._header.policy_profile

    @property
    def policy_fingerprint(self) -> str:
        return self._header.policy_fingerprint

    def results(self) -> tuple[CheckResult, ...]:
        return project_results(self.reports)

    def auto_by_cluster(self) -> Mapping[str, tuple[CheckResult, ...]]:
        return {
            rep.scope.cluster: tuple(r for r in rep.results if r.kind is Kind.AUTO)
            for rep in self.reports
        }

    def discuss(self) -> tuple[CheckResult, ...]:
        return tuple(r for r in self.results() if r.kind is Kind.DISCUSS)


@dataclass(frozen=True, slots=True)
class Baseline:
    snapshot: Snapshot
    path: str
    sha256: str
    """Of the file as read, so a report names exactly which baseline it was compared with."""


def load_baseline(path: Path) -> Baseline:
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        raise BaselineError(f"baseline file not found: {path}") from None
    try:
        data = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BaselineError(f"{path}: not valid JSON: {exc}") from None
    try:
        snapshot = snapshot_from_mapping(data)
    except BaselineError as exc:
        raise BaselineError(f"{path}: {exc}") from None
    return Baseline(snapshot=snapshot, path=str(path), sha256=hashlib.sha256(raw).hexdigest())


def snapshot_from_mapping(data: Any) -> Snapshot:
    """Rebuild a run from its JSON report (cluster or project shape). Pure."""
    if not isinstance(data, Mapping) or data.get("framework") != FRAMEWORK:
        raise BaselineError(
            "not a waf-check JSON report; write one with `-f json -o FILE` or `--json FILE`"
        )
    catalog = str(data.get("catalog") or "")
    try:
        discuss = tuple(_discuss_result(d) for d in data.get("discuss") or ())
        if "clusters" not in data:
            return Snapshot(reports=(_cluster_report(data, discuss),), catalog=catalog)
        reports = tuple(_cluster_report(c, discuss) for c in data["clusters"])
        project = _project_scope(data["scope"])
    except BaselineError:
        raise
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        raise BaselineError(f"malformed waf-check report ({type(exc).__name__}: {exc})") from None
    if not reports:
        raise BaselineError("the report scored no clusters")
    return Snapshot(reports=reports, project=project, catalog=catalog)


_CATALOG_INDEX: Mapping[str, int] = {spec.id: i for i, spec in enumerate(CATALOG)}


def _cluster_report(payload: Mapping[str, Any], discuss: tuple[CheckResult, ...]) -> ClusterReport:
    # JSON lists checks worst first; live runs are in catalog order, which tie-breaks the
    # renderers' stable sorts, so restore it.
    auto = sorted(
        (_auto_result(c) for c in payload["checks"]),
        key=lambda r: _CATALOG_INDEX.get(r.id, len(_CATALOG_INDEX)),
    )
    return ClusterReport(scope=_scope(payload["scope"]), results=(*auto, *discuss))


def _text(data: Mapping[str, Any], key: str) -> str:
    return str(data.get(key) or "")


def _scope(data: Mapping[str, Any]) -> Scope:
    values = {f.name: _text(data, f.name) for f in fields(Scope)}
    if not values["cluster"] or not values["project_id"]:
        raise BaselineError("scope needs cluster and project_id")
    return Scope(**values)


def _project_scope(data: Mapping[str, Any]) -> ProjectScope:
    if not _text(data, "project_id"):
        raise BaselineError("scope needs project_id")
    return ProjectScope(
        project_id=_text(data, "project_id"),
        clusters=tuple(str(c) for c in data.get("clusters") or ()),
        policy_profile=_text(data, "policy_profile"),
        policy_path=_text(data, "policy_path"),
        policy_fingerprint=_text(data, "policy_fingerprint"),
        attestations_path=_text(data, "attestations_path"),
        generated_at=_text(data, "generated_at"),
    )


def _auto_result(d: Mapping[str, Any]) -> CheckResult:
    return CheckResult(
        id=str(d["id"]),
        pillar=Pillar(d["pillar"]),
        title=_text(d, "title"),
        kind=Kind.AUTO,
        status=Status(d["status"]),
        severity=Severity(d["severity"]),
        message=_text(d, "message"),
        evidence=dict(d.get("evidence") or {}),
        remedy=_text(d, "remedy"),
        doc=_text(d, "doc"),
    )


def _discuss_result(d: Mapping[str, Any]) -> CheckResult:
    status = Status(d["status"])
    spec = BY_ID.get(str(d["id"]))
    return CheckResult(
        id=str(d["id"]),
        pillar=Pillar(d["pillar"]),
        title=_text(d, "title"),
        kind=Kind.DISCUSS,
        status=status,
        severity=Severity.OFF,
        message=_text(d, "what"),
        evidence={k: d[k] for k in ("owner", "date", "note", "expired") if k in d},
        remedy=spec.what if spec is not None and status in FINDINGS else "",
        doc=_text(d, "doc"),
    )


# --- comparison -----------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CheckChange:
    cluster: str
    """Empty for the project-level discussion items."""
    result: CheckResult
    """This run's result, or the baseline's when the check is not in this run."""
    before: Status | None
    after: Status | None
    change: Change
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "cluster": self.cluster or None,
            "id": self.result.id,
            "pillar": self.result.pillar.value,
            "title": self.result.title,
            "change": self.change.value,
            "reason": self.reason,
            "before": self.before.value if self.before else None,
            "after": self.after.value if self.after else None,
            "message": self.result.message,
        }


@dataclass(frozen=True, slots=True)
class ScoreChange:
    before: Score | None
    after: Score | None

    @property
    def delta(self) -> float | None:
        b = self.before.value if self.before else None
        a = self.after.value if self.after else None
        return None if a is None or b is None else round(a - b, 1)

    @property
    def direction(self) -> str:
        """``up`` / ``down`` / ``same``, or ``none`` when either side is not scoreable."""
        d = self.delta
        return "none" if d is None else "up" if d > 0 else "down" if d < 0 else "same"

    def to_dict(self) -> dict[str, Any]:
        return {
            "before": self.before.value if self.before else None,
            "after": self.after.value if self.after else None,
            "delta": self.delta,
            "tier_before": _tier(self.before),
            "tier_after": _tier(self.after),
        }


def _tier(s: Score | None) -> str | None:
    tier = s.tier if s else None
    return tier.label if tier else None


@dataclass(frozen=True, slots=True)
class Comparison:
    baseline_path: str
    baseline_sha256: str
    baseline_generated_at: str
    changes: tuple[CheckChange, ...]
    """Everything that moved, worst kind first. Unchanged checks are only counted."""
    unchanged: int
    total: ScoreChange
    by_pillar: Mapping[Pillar, ScoreChange]
    by_cluster: Mapping[str, ScoreChange]
    clusters_added: tuple[str, ...] = ()
    clusters_removed: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()

    @property
    def regressed(self) -> tuple[CheckChange, ...]:
        return tuple(c for c in self.changes if c.change is Change.REGRESSED)

    def tally(self) -> tuple[tuple[Change, int], ...]:
        """Every kind of movement with its count (zeros included), in display order."""
        return tuple((kind, sum(1 for c in self.changes if c.change is kind)) for kind in MOVED)

    def to_dict(self) -> dict[str, Any]:
        return {
            "baseline": {
                "path": self.baseline_path,
                "sha256": self.baseline_sha256,
                "generated_at": self.baseline_generated_at,
            },
            "score": self.total.to_dict(),
            "by_pillar": {p.value: s.to_dict() for p, s in self.by_pillar.items()},
            "by_cluster": {name: s.to_dict() for name, s in self.by_cluster.items()},
            "counts": {
                **{kind.value: n for kind, n in self.tally()},
                Change.UNCHANGED.value: self.unchanged,
            },
            "clusters_added": list(self.clusters_added),
            "clusters_removed": list(self.clusters_removed),
            "notes": list(self.notes),
            "changes": [c.to_dict() for c in self.changes],
        }


def classify(
    before: Status | None, after: Status | None, *, new_check: bool = False
) -> tuple[Change, str]:
    """How one check moved between the baseline and this run, with a short reason. Pure."""
    if after is None:
        return (Change.NOT_EVALUATED, "not in this run") if before in EVALUATED else _SAME
    if before is None and new_check:
        return Change.NEW_CHECK, "not in the baseline"
    if before == after:
        return _SAME
    if after in FINDINGS:
        if before is Status.FAIL:
            return Change.IMPROVED, ""
        return Change.REGRESSED, "worse" if before is Status.WARN else "new finding"
    if after is Status.PASS:
        return (Change.FIXED, "") if before in FINDINGS else (Change.NOW_EVALUATED, "")
    return (Change.NOT_EVALUATED, "") if before in EVALUATED else _SAME


_SAME: tuple[Change, str] = (Change.UNCHANGED, "")


def restrict(snapshot: Snapshot, project_id: str, cluster: str | None) -> Snapshot:
    """The part of a baseline a run of ``project_id`` can be compared with: one ``cluster``, or
    the whole project when ``cluster`` is None. Raises ``BaselineError`` when it is not covered,
    which the CLI checks before any API call."""
    if snapshot.project_id != project_id:
        raise BaselineError(
            f"baseline is for project {snapshot.project_id}, this run is for project {project_id}"
        )
    if cluster is None:
        if snapshot.project is None:
            raise BaselineError(
                f"baseline scored cluster {snapshot.reports[0].scope.cluster} only; compare an "
                "--all-clusters run with an --all-clusters baseline"
            )
        return snapshot
    kept = tuple(rep for rep in snapshot.reports if rep.scope.cluster == cluster)
    if not kept:
        covered = ", ".join(rep.scope.cluster for rep in snapshot.reports)
        raise BaselineError(f"baseline has no cluster {cluster} (it covers {covered})")
    return replace(snapshot, reports=kept, project=None)


def compare(baseline: Baseline, current: Snapshot) -> Comparison:
    """Every check of ``current`` against the same cluster and id in ``baseline``. Pure."""
    cluster = None if current.project else current.reports[0].scope.cluster
    before = restrict(baseline.snapshot, current.project_id, cluster)
    base_auto, cur_auto = before.auto_by_cluster(), current.auto_by_cluster()
    known = frozenset(r.id for r in before.results())
    diffs = (
        *(
            d
            for name, rows in cur_auto.items()
            for d in _diff(name, base_auto.get(name), rows, known)
        ),
        *_diff("", before.discuss(), current.discuss(), known),
    )
    moved = tuple(
        sorted(
            (d for d in diffs if d.change is not Change.UNCHANGED), key=lambda d: _ORDER[d.change]
        )
    )
    pillars_before = score_by_pillar(before.results())
    pillars_after = score_by_pillar(current.results())
    removed = tuple(name for name in base_auto if name not in cur_auto)
    return Comparison(
        baseline_path=baseline.path,
        baseline_sha256=baseline.sha256,
        baseline_generated_at=before.generated_at,
        changes=moved,
        unchanged=len(diffs) - len(moved),
        total=ScoreChange(score(before.results()), score(current.results())),
        by_pillar={p: ScoreChange(pillars_before[p], pillars_after[p]) for p in Pillar},
        by_cluster={
            name: ScoreChange(_score_of(base_auto.get(name)), _score_of(cur_auto.get(name)))
            for name in (*cur_auto, *removed)
        },
        clusters_added=tuple(name for name in cur_auto if name not in base_auto),
        clusters_removed=removed,
        notes=_notes(before, current),
    )


def _score_of(results: Sequence[CheckResult] | None) -> Score | None:
    return score(results) if results is not None else None


def _diff(
    cluster: str,
    before: Sequence[CheckResult] | None,
    after: Sequence[CheckResult],
    known: frozenset[str],
) -> Iterator[CheckChange]:
    """Pair two result lists by id. ``before is None`` means the cluster is new to the project:
    only its findings are reported, as regressions."""
    if before is None:
        yield from (
            CheckChange(cluster, r, None, r.status, Change.REGRESSED, "new cluster")
            for r in after
            if r.status in FINDINGS
        )
        return
    old = {r.id: r for r in before}
    for r in after:
        prior = old.get(r.id)
        was = prior.status if prior else None
        change, reason = classify(was, r.status, new_check=r.id not in known)
        yield CheckChange(cluster, r, was, r.status, change, reason)
    present = {r.id for r in after}
    for r in before:
        if r.id not in present:
            change, reason = classify(r.status, None)
            yield CheckChange(cluster, r, r.status, None, change, reason)


def _notes(before: Snapshot, current: Snapshot) -> tuple[str, ...]:
    """Why a delta may not be like for like: a different catalog or a different policy."""
    catalog = (
        (
            f"catalog changed from {before.catalog or 'unknown'} to {current.catalog}: checks it "
            "added are listed as new checks, never as regressions",
        )
        if before.catalog != current.catalog
        else ()
    )
    caveat = "a status change may come from the policy rather than from Atlas"
    if before.policy_profile != current.policy_profile:
        policy: tuple[str, ...] = (
            f"policy profile changed from {before.policy_profile or 'defaults'} to "
            f"{current.policy_profile or 'defaults'}: {caveat}",
        )
    elif (
        before.policy_fingerprint
        and current.policy_fingerprint
        and before.policy_fingerprint != current.policy_fingerprint
    ):
        policy = (
            f"policy {current.policy_profile or 'defaults'} changed since the baseline "
            f"(fingerprint {before.policy_fingerprint} to {current.policy_fingerprint}): {caveat}",
        )
    else:
        policy = ()
    return catalog + policy
