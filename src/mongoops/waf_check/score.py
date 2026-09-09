"""Readiness score out of 10. Pure functions over ``CheckResult`` sequences.

Why a score at all: counts of FAIL / WARN / PASS do not compare well between clusters with a
different number of applicable checks, and they give the team nothing to aim for. A single
number out of 10 with a named tier does both, as long as every digit can be traced back to
the checks that produced it. Rules:

* Only checks that were actually evaluated count: PASS, WARN and FAIL. UNKNOWN (missing role),
  NA (not applicable), SKIPPED (severity ``off``) and open DISCUSS items are left out of both
  the numerator and the denominator, so a narrow API key never lowers the score.
* Attested discussion items count once attested (their status becomes PASS / WARN / FAIL), so
  settling the workshop items moves the score.
* Weight is 2 for a check the policy treats as ``fail`` and 1 for ``warn``; a passing check
  earns its weight, a failing one earns nothing. Fixing a FAIL is therefore worth twice a WARN.
* ``score = 10 * earned / possible`` rounded to one decimal. No randomness, no decay.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from mongoops.waf_check.model import STATUS_ORDER, CheckResult, Pillar, Severity, Status

SCORED_STATUSES = frozenset({Status.PASS, Status.WARN, Status.FAIL})
MAX_SCORE = 10.0


@dataclass(frozen=True, slots=True)
class Tier:
    label: str
    floor: float
    css: str
    """Presentation class: ok / good / warn / bad."""


# Highest first. Boundaries apply to the rounded score so what is displayed is what is tiered.
TIERS: tuple[Tier, ...] = (
    Tier("Well-architected", 9.0, "ok"),
    Tier("Ready with gaps", 7.0, "good"),
    Tier("Needs work", 5.0, "warn"),
    Tier("At risk", 0.0, "bad"),
)


@dataclass(frozen=True, slots=True)
class Score:
    earned: int
    possible: int
    passed: int
    scored: int

    @property
    def value(self) -> float | None:
        """0.0 to 10.0, or None when nothing could be scored."""
        if not self.possible:
            return None
        return round(MAX_SCORE * self.earned / self.possible, 1)

    @property
    def tier(self) -> Tier | None:
        return tier_for(self.value)

    def to_dict(self) -> dict[str, Any]:
        t = self.tier
        return {
            "value": self.value,
            "max": MAX_SCORE,
            "earned": self.earned,
            "possible": self.possible,
            "passed": self.passed,
            "scored": self.scored,
            "tier": t.label if t else None,
        }


def tier_for(value: float | None) -> Tier | None:
    if value is None:
        return None
    return next(t for t in TIERS if value >= t.floor)


def is_scored(r: CheckResult) -> bool:
    return r.status in SCORED_STATUSES


def weight(r: CheckResult) -> int:
    """2 for a fail-severity check (or an item attested FAIL), 1 otherwise."""
    return 2 if r.severity is Severity.FAIL or r.status is Status.FAIL else 1


def score(results: Sequence[CheckResult]) -> Score:
    scored = tuple(r for r in results if is_scored(r))
    passed = tuple(r for r in scored if r.status is Status.PASS)
    return Score(
        earned=sum(weight(r) for r in passed),
        possible=sum(weight(r) for r in scored),
        passed=len(passed),
        scored=len(scored),
    )


def score_by_pillar(results: Sequence[CheckResult]) -> Mapping[Pillar, Score]:
    return {p: score(tuple(r for r in results if r.pillar is p)) for p in Pillar}


@dataclass(frozen=True, slots=True)
class QuickWin:
    result: CheckResult
    """Representative result (the first occurrence)."""
    gain: float
    """Points added to the score once every occurrence passes."""
    occurrences: int
    """How many clusters fail this check; a project-wide setting fails once per cluster."""


def quick_wins(results: Sequence[CheckResult], *, limit: int = 3) -> tuple[QuickWin, ...]:
    """The failing checks worth the most points, grouped by check id so a project-wide setting
    that fails on every cluster shows once with the combined gain. Highest gain first, then
    worst status, then catalog order."""
    total = score(results)
    if not total.possible:
        return ()
    groups: dict[str, list[CheckResult]] = {}
    for r in results:
        if r.status in (Status.FAIL, Status.WARN):
            groups.setdefault(r.id, []).append(r)
    wins = tuple(
        QuickWin(
            result=rows[0],
            gain=round(MAX_SCORE * sum(weight(r) for r in rows) / total.possible, 1),
            occurrences=len(rows),
        )
        for rows in groups.values()
    )
    ranked = sorted(wins, key=lambda w: (-w.gain, STATUS_ORDER[w.result.status]))
    return tuple(ranked[:limit])


def fixes_to_next_tier(results: Sequence[CheckResult]) -> tuple[Tier, int] | None:
    """Smallest number of fixes (highest weight first) that reaches the next tier, or None
    when already at the top or nothing can be scored."""
    total = score(results)
    current = total.tier
    if total.value is None or current is None or current is TIERS[0]:
        return None
    target = TIERS[TIERS.index(current) - 1]
    weights = sorted(
        (weight(r) for r in results if r.status in (Status.FAIL, Status.WARN)), reverse=True
    )
    earned = total.earned
    for n, w in enumerate(weights, start=1):
        earned += w
        if round(MAX_SCORE * earned / total.possible, 1) >= target.floor:
            return target, n
    return None
