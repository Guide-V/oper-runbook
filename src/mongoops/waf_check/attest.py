"""Attestations: the recorded outcome of the ``discuss`` items the API cannot see.

The landing-zone workshop settles each people/process item; this file is where the answer
lives so the scorecard stops listing it as an open question. ``waf-check attest-init`` writes
the template (every discussion item, ``status: open``), the team fills it in, commits it next to
the policy, and passes it with ``waf-check atlas --attest FILE``.

An attested item takes the attested status (PASS / FAIL / WARN / NA) with owner, date and note
as evidence, so it counts in the pillar totals and trips ``--fail-on`` like any auto check.
Attestations expire (``valid_days``, default 365): an expired one is listed as DISCUSS again with
the old answer shown, because a yearly re-confirmation is the point of the exercise.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import date
from pathlib import Path
from typing import Any

import yaml

from mongoops.waf_check.catalog import BY_ID, DISCUSS_CHECKS
from mongoops.waf_check.model import CheckResult, Kind, Status

OPEN = "open"
ATTESTED_STATUS: Mapping[str, Status] = {
    "pass": Status.PASS,
    "fail": Status.FAIL,
    "warn": Status.WARN,
    "na": Status.NA,
}
DEFAULT_VALID_DAYS = 365


class AttestationError(ValueError):
    """Malformed attestation file; the message points at the offending key."""


@dataclass(frozen=True, slots=True)
class Attestation:
    check_id: str
    status: Status
    owner: str
    on: date
    note: str = ""


@dataclass(frozen=True, slots=True)
class Attestations:
    items: Mapping[str, Attestation] = field(default_factory=dict)
    valid_days: int = DEFAULT_VALID_DAYS
    path: str = ""

    def expired(self, attestation: Attestation, today: date) -> bool:
        return (today - attestation.on).days > self.valid_days


NO_ATTESTATIONS = Attestations()


def load_attestations(path: Path) -> Attestations:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise AttestationError(f"attestation file not found: {path}") from None
    except yaml.YAMLError as exc:
        raise AttestationError(f"{path}: not valid YAML: {exc}") from None
    return replace(attestations_from_mapping(data if data is not None else {}), path=str(path))


def attestations_from_mapping(data: Any) -> Attestations:
    """Validate a parsed YAML document. ``status: open`` entries are kept out of ``items``."""
    if not isinstance(data, Mapping):
        raise AttestationError("expected a mapping at the top level")
    unknown = set(data) - {"valid_days", "attestations"}
    if unknown:
        raise AttestationError(f"unknown top-level key(s): {', '.join(sorted(unknown))}")
    valid_days = data.get("valid_days", DEFAULT_VALID_DAYS)
    if isinstance(valid_days, bool) or not isinstance(valid_days, int) or valid_days <= 0:
        raise AttestationError(f"valid_days: expected a positive integer, got {valid_days!r}")
    entries = data.get("attestations") or {}
    if not isinstance(entries, Mapping):
        raise AttestationError("attestations: expected a mapping of check id -> entry")
    items = {
        check_id: parsed
        for check_id, entry in entries.items()
        if (parsed := _attestation(str(check_id), entry)) is not None
    }
    return Attestations(items=items, valid_days=valid_days)


def _attestation(check_id: str, entry: Any) -> Attestation | None:
    spec = BY_ID.get(check_id)
    if spec is None or spec.kind is not Kind.DISCUSS:
        raise AttestationError(f"attestations.{check_id}: not a discussion item")
    if not isinstance(entry, Mapping):
        raise AttestationError(f"attestations.{check_id}: expected status/owner/date/note")
    unknown = set(entry) - {"status", "owner", "date", "note"}
    if unknown:
        raise AttestationError(f"attestations.{check_id}: unknown key(s) {sorted(unknown)}")
    status = str(entry.get("status", OPEN) or OPEN).lower()
    if status == OPEN:
        return None
    if status not in ATTESTED_STATUS:
        raise AttestationError(
            f"attestations.{check_id}.status: expected open, pass, fail, warn or na, got {status!r}"
        )
    owner = str(entry.get("owner") or "").strip()
    if not owner:
        raise AttestationError(f"attestations.{check_id}.owner: required once attested")
    return Attestation(
        check_id=check_id,
        status=ATTESTED_STATUS[status],
        owner=owner,
        on=_date(entry.get("date"), f"attestations.{check_id}.date"),
        note=str(entry.get("note") or "").strip(),
    )


def _date(value: Any, where: str) -> date:
    if isinstance(value, date):
        return value
    try:
        return date.fromisoformat(str(value))
    except (TypeError, ValueError):
        raise AttestationError(f"{where}: expected YYYY-MM-DD, got {value!r}") from None


def apply_attestations(
    results: Sequence[CheckResult], attestations: Attestations, *, today: date | None = None
) -> tuple[CheckResult, ...]:
    """Replace DISCUSS results that have a current attestation with the attested status. Pure."""
    current = today or date.today()
    return tuple(_apply_one(r, attestations, current) for r in results)


def _apply_one(result: CheckResult, attestations: Attestations, today: date) -> CheckResult:
    a = attestations.items.get(result.id)
    if result.kind is not Kind.DISCUSS or a is None:
        return result
    evidence = {"owner": a.owner, "date": a.on.isoformat(), "note": a.note, "attested": a.status}
    if attestations.expired(a, today):
        return replace(
            result,
            message=f"attestation from {a.on.isoformat()} ({a.status.value}, {a.owner}) is older "
            f"than {attestations.valid_days} days; re-confirm. {result.message}",
            evidence={**evidence, "expired": True},
        )
    return replace(
        result,
        status=a.status,
        message=a.note or f"attested {a.status.value} by {a.owner} on {a.on.isoformat()}",
        evidence=evidence,
        remedy=result.message if a.status in (Status.FAIL, Status.WARN) else "",
    )


def render_attestations_yaml(attestations: Attestations = NO_ATTESTATIONS) -> str:
    """A commented template listing every discussion item, grouped by pillar."""
    lines = [
        '# waf-check attestations: outcomes of the "discuss these" items.',
        "# Fill in after the landing-zone workshop and pass with `waf-check atlas --attest FILE`.",
        "#   status: open | pass | fail | warn | na   (open = not settled yet, stays DISCUSS)",
        "#   owner:  team or person accountable      (required once status is not open)",
        "#   date:   YYYY-MM-DD of the decision       (entries older than valid_days expire)",
        "#   note:   the decision itself, or a link to it",
        f"valid_days: {attestations.valid_days}",
        "",
        "attestations:",
    ]
    for spec in DISCUSS_CHECKS:
        a = attestations.items.get(spec.id)
        lines.append(f"  # {spec.title}")
        lines.append(f"  {spec.id}:")
        if a is None:
            lines += [f"    status: {OPEN}", "    owner:", "    date:", "    note:"]
        else:
            lines += [
                f"    status: {a.status.value.lower()}",
                f"    owner: {_yaml_str(a.owner)}",
                f"    date: {a.on.isoformat()}",
                f"    note: {_yaml_str(a.note)}",
            ]
    return "\n".join(lines) + "\n"


def _yaml_str(text: str) -> str:
    return yaml.safe_dump(text, default_style='"').strip().removesuffix("\n...").strip()
