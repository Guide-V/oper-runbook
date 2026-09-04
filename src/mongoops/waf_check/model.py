"""Data model for the WAF readiness scorecard.

Vocabulary:

* ``CheckSpec``: one entry of the catalog. Product-neutral (id, pillar, title, kind, default
  severity, documentation link). ``auto`` checks are evaluated from Atlas facts, ``discuss``
  checks are people/process items the tool cannot see and only lists for the workshop.
* ``Outcome``: what an evaluator says about the facts, before policy is applied
  (``ok`` / not ok / not applicable / could not evaluate).
* ``CheckResult``: ``Outcome`` after the policy decided how bad "not ok" is.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class Pillar(StrEnum):
    """The five Atlas Well-Architected Framework pillars."""

    OPERATIONAL_EFFICIENCY = "operational_efficiency"
    SECURITY = "security"
    RELIABILITY = "reliability"
    PERFORMANCE = "performance"
    COST_OPTIMIZATION = "cost_optimization"


PILLAR_LABEL: Mapping[Pillar, str] = {
    Pillar.OPERATIONAL_EFFICIENCY: "Operational efficiency",
    Pillar.SECURITY: "Security",
    Pillar.RELIABILITY: "Reliability",
    Pillar.PERFORMANCE: "Performance",
    Pillar.COST_OPTIMIZATION: "Cost optimization",
}


class Kind(StrEnum):
    AUTO = "auto"
    DISCUSS = "discuss"


class Severity(StrEnum):
    """How a failed ``auto`` check is reported. Configurable per check in the policy file."""

    FAIL = "fail"
    WARN = "warn"
    OFF = "off"


class Status(StrEnum):
    FAIL = "FAIL"
    WARN = "WARN"
    UNKNOWN = "UNKNOWN"  # fact unavailable (role, tier, API error); never counted as a failure
    PASS = "PASS"
    NA = "NA"  # not applicable to this cluster or not required by the policy
    SKIPPED = "SKIPPED"  # severity ``off`` in the policy
    DISCUSS = "DISCUSS"  # people/process item, listed for the workshop


# Worst first, for sorting and for the "action needed" section.
STATUS_ORDER: Mapping[Status, int] = {
    Status.FAIL: 0,
    Status.WARN: 1,
    Status.UNKNOWN: 2,
    Status.PASS: 3,
    Status.NA: 4,
    Status.SKIPPED: 5,
    Status.DISCUSS: 6,
}


@dataclass(frozen=True, slots=True)
class CheckSpec:
    id: str
    pillar: Pillar
    title: str
    kind: Kind
    default_severity: Severity
    doc: str
    """Architecture Center / docs page that justifies the check."""
    what: str
    """One sentence: what evidence is used (auto) or what to settle (discuss)."""


@dataclass(frozen=True, slots=True)
class Outcome:
    """Result of an evaluator, before policy. Exactly one of the shapes below applies:

    * ``ok=True``: passes.
    * ``ok=False``: does not pass; policy decides FAIL / WARN / SKIPPED.
    * ``ok=None, unavailable=<reason>``: could not evaluate (UNKNOWN).
    * ``ok=None, not_applicable=<reason>``: does not apply (NA).
    """

    ok: bool | None
    message: str
    evidence: Mapping[str, Any] = field(default_factory=dict)
    remedy: str = ""
    unavailable: str = ""
    not_applicable: str = ""


@dataclass(frozen=True, slots=True)
class CheckResult:
    id: str
    pillar: Pillar
    title: str
    kind: Kind
    status: Status
    severity: Severity
    message: str
    evidence: Mapping[str, Any]
    remedy: str
    doc: str

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["evidence"] = dict(self.evidence)
        return d


def resolve(spec: CheckSpec, outcome: Outcome, severity: Severity) -> CheckResult:
    """Combine an evaluator outcome with the policy severity into a final result. Pure."""
    if severity is Severity.OFF:
        status = Status.SKIPPED
    elif outcome.unavailable:
        status = Status.UNKNOWN
    elif outcome.not_applicable:
        status = Status.NA
    elif outcome.ok:
        status = Status.PASS
    else:
        status = Status.FAIL if severity is Severity.FAIL else Status.WARN
    message = (
        outcome.unavailable
        if status is Status.UNKNOWN
        else outcome.not_applicable
        if status is Status.NA
        else outcome.message
    )
    return CheckResult(
        id=spec.id,
        pillar=spec.pillar,
        title=spec.title,
        kind=spec.kind,
        status=status,
        severity=severity,
        message=message,
        evidence=dict(outcome.evidence),
        remedy=outcome.remedy if status in (Status.FAIL, Status.WARN) else "",
        doc=spec.doc,
    )


def discussion(spec: CheckSpec) -> CheckResult:
    """A ``discuss`` catalog entry rendered as a result so every renderer handles one type."""
    return CheckResult(
        id=spec.id,
        pillar=spec.pillar,
        title=spec.title,
        kind=Kind.DISCUSS,
        status=Status.DISCUSS,
        severity=Severity.OFF,
        message=spec.what,
        evidence={},
        remedy="",
        doc=spec.doc,
    )
