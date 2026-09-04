"""Small pure helpers for the ``--since`` / ``--duration`` style options."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

_DURATION = re.compile(r"^(?P<n>\d+)\s*(?P<u>ms|s|m|h|d|w)$")
_UNIT_MS = {"ms": 1, "s": 1_000, "m": 60_000, "h": 3_600_000, "d": 86_400_000, "w": 604_800_000}


def parse_duration_ms(text: str) -> int:
    """``"24h"`` -> 86_400_000. Accepts ms, s, m, h, d, w."""
    m = _DURATION.match(text.strip().lower())
    if not m:
        raise ValueError(f"invalid duration {text!r}; use e.g. 30m, 24h, 7d")
    return int(m.group("n")) * _UNIT_MS[m.group("u")]


def parse_since_ms(text: str, *, now: datetime | None = None) -> int:
    """Epoch ms for either a relative duration ("24h" = 24h ago) or an ISO-8601 instant."""
    current = now or datetime.now(UTC)
    if _DURATION.match(text.strip().lower()):
        return to_epoch_ms(current - timedelta(milliseconds=parse_duration_ms(text)))
    parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return to_epoch_ms(parsed)


def to_epoch_ms(dt: datetime) -> int:
    return int(dt.timestamp() * 1000)
