"""Pure helpers for the time-window options and for showing times in the operator's zone.

Flags: ``--since`` / ``--until`` / ``--duration`` (a range), ``--at`` / ``--around`` (an incident
moment +- a margin) and ``--tz`` (how to read a date/time typed without an offset, and how to
display times). Machine-readable outputs stay in UTC; only human-facing text uses ``--tz``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone, tzinfo
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

_DURATION = re.compile(r"^(?P<n>\d+)\s*(?P<u>ms|s|m|h|d|w)$")
_UNIT_MS = {"ms": 1, "s": 1_000, "m": 60_000, "h": 3_600_000, "d": 86_400_000, "w": 604_800_000}
_OFFSET = re.compile(r"^(?P<sign>[+-])(?P<h>\d{2}):?(?P<m>\d{2})$")
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)

DEFAULT_AROUND = "30m"


def parse_duration_ms(text: str) -> int:
    """``"24h"`` -> 86_400_000. Accepts ms, s, m, h, d, w."""
    m = _DURATION.match(text.strip().lower())
    if not m:
        raise ValueError(f"invalid duration {text!r}; use e.g. 30m, 24h, 7d")
    return int(m.group("n")) * _UNIT_MS[m.group("u")]


def is_relative(text: str) -> bool:
    """``"24h"`` style (an age relative to now) rather than an absolute date/time."""
    return _DURATION.match(text.strip().lower()) is not None


def is_naive(text: str) -> bool:
    """True for an absolute date/time typed without a UTC offset, whose zone is ambiguous."""
    return not is_relative(text) and _parse_iso(text).tzinfo is None


def parse_instant_ms(text: str, *, tz: tzinfo = UTC, now: datetime | None = None) -> int:
    """Epoch ms for a relative age ("24h" = 24h ago) or an ISO-8601 date/time.

    A date/time without an offset is read in ``tz``; one with an offset keeps it.
    """
    if is_relative(text):
        return to_epoch_ms(
            (now or datetime.now(UTC)) - timedelta(milliseconds=parse_duration_ms(text))
        )
    parsed = _parse_iso(text)
    return to_epoch_ms(parsed if parsed.tzinfo else parsed.replace(tzinfo=tz))


def parse_since_ms(text: str, *, now: datetime | None = None) -> int:
    """Start of a window that only takes ``--since`` (naive date/times are UTC)."""
    return parse_instant_ms(text, now=now)


def to_epoch_ms(dt: datetime) -> int:
    return (dt - _EPOCH) // timedelta(milliseconds=1)


def _parse_iso(text: str) -> datetime:
    try:
        return datetime.fromisoformat(text.strip())
    except ValueError:
        raise ValueError(
            f"invalid date/time {text!r}; use e.g. 24h, 2026-10-07T14:00 or 2026-10-07T14:00+07:00"
        ) from None


# --- zones -------------------------------------------------------------------------------------


def parse_zone(name: str) -> tzinfo:
    """``UTC``, ``local`` (this machine), an IANA name (``Asia/Bangkok``) or ``+07:00``."""
    key = name.strip()
    if key.upper() in {"UTC", "Z"}:
        return UTC
    if key.lower() == "local":
        return local_zone()
    if m := _OFFSET.match(key):
        sign = -1 if m.group("sign") == "-" else 1
        return timezone(sign * timedelta(hours=int(m.group("h")), minutes=int(m.group("m"))))
    try:
        return ZoneInfo(key)
    except (ZoneInfoNotFoundError, ValueError):
        raise ValueError(
            f"unknown time zone {name!r}; use UTC, local, an IANA name such as Asia/Bangkok "
            "or an offset such as +07:00"
        ) from None


def local_zone() -> tzinfo:
    """This machine's current zone (reads the OS setting; the only impure helper here)."""
    return datetime.now().astimezone().tzinfo or UTC


def is_utc(tz: tzinfo, at: datetime | None = None) -> bool:
    return (at or datetime.now(UTC)).astimezone(tz).utcoffset() == timedelta(0)


def zone_label(dt: datetime) -> str:
    """``UTC`` or ``+07:00`` for an aware datetime."""
    offset = dt.utcoffset() or timedelta(0)
    if offset == timedelta(0):
        return "UTC"
    text = dt.strftime("%z")
    return f"{text[:3]}:{text[3:]}"


# --- windows -----------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class WindowSpec:
    """The time-window flags exactly as typed; ``None`` means "not given"."""

    since: str | None = None
    until: str | None = None
    duration: str | None = None
    at: str | None = None
    around: str | None = None

    def typed_instants(self) -> tuple[str, ...]:
        """The values that name a moment (as opposed to a length)."""
        return tuple(t for t in (self.since, self.until, self.at) if t)


@dataclass(frozen=True, slots=True)
class TimeWindow:
    """Resolved half-open window ``[start, end)`` in epoch ms; ``None`` = unbounded side."""

    start_ms: int | None = None
    end_ms: int | None = None

    @property
    def bounded(self) -> bool:
        return self.start_ms is not None or self.end_ms is not None

    @property
    def duration_ms(self) -> int | None:
        if self.start_ms is None or self.end_ms is None:
            return None
        return self.end_ms - self.start_ms

    def contains(self, epoch_ms: int) -> bool:
        return (self.start_ms is None or epoch_ms >= self.start_ms) and (
            self.end_ms is None or epoch_ms < self.end_ms
        )


NO_WINDOW = TimeWindow()


def validate_window(spec: WindowSpec) -> None:
    """Reject flag combinations that do not describe exactly one window."""
    if spec.at and (spec.since or spec.until or spec.duration):
        raise ValueError("--at cannot be combined with --since, --until or --duration")
    if spec.around and not spec.at:
        raise ValueError("--around needs --at")
    if spec.since and spec.until and spec.duration:
        raise ValueError("give two of --since, --until and --duration, not all three")
    if spec.until and not (spec.since or spec.duration):
        raise ValueError("--until needs --since (or --duration for a window ending then)")


def resolve_window(
    spec: WindowSpec, *, tz: tzinfo = UTC, now: datetime | None = None
) -> TimeWindow:
    """Turn the flags into absolute bounds. Pure given ``now``."""
    validate_window(spec)
    current = now or datetime.now(UTC)

    def instant(text: str) -> int:
        return parse_instant_ms(text, tz=tz, now=current)

    if spec.at:
        centre, half = instant(spec.at), parse_duration_ms(spec.around or DEFAULT_AROUND)
        return _ordered(TimeWindow(centre - half, centre + half))
    length = parse_duration_ms(spec.duration) if spec.duration else None
    if spec.since:
        start = instant(spec.since)
        end = instant(spec.until) if spec.until else (start + length if length else None)
        return _ordered(TimeWindow(start, end))
    if spec.until and length:
        end = instant(spec.until)
        return _ordered(TimeWindow(end - length, end))
    if length:
        return TimeWindow(to_epoch_ms(current) - length, None)
    return TimeWindow()


def _ordered(window: TimeWindow) -> TimeWindow:
    if window.duration_ms is not None and window.duration_ms <= 0:
        raise ValueError("the window ends before it starts; check --since / --until")
    return window


# --- display -----------------------------------------------------------------------------------


def format_instant(epoch_ms: int, tz: tzinfo = UTC, *, seconds: bool = False) -> str:
    """``2026-10-07 14:00 +07:00`` (or ``... UTC``)."""
    dt = datetime.fromtimestamp(epoch_ms / 1000, tz)
    return f"{dt.strftime('%Y-%m-%d %H:%M:%S' if seconds else '%Y-%m-%d %H:%M')} {zone_label(dt)}"


def describe_window(window: TimeWindow, tz: tzinfo = UTC) -> str:
    """Human description in ``tz``, with the UTC equivalent when ``tz`` is not UTC."""
    if not window.bounded:
        return ""
    local = _span(window, tz)
    anchor = window.start_ms if window.start_ms is not None else window.end_ms
    if anchor is None or is_utc(tz, datetime.fromtimestamp(anchor / 1000, UTC)):
        return local
    return f"{local} ({_span(window, UTC)})"


def _span(window: TimeWindow, tz: tzinfo) -> str:
    if window.start_ms is None and window.end_ms is not None:
        return f"until {format_instant(window.end_ms, tz)}"
    assert window.start_ms is not None
    start = datetime.fromtimestamp(window.start_ms / 1000, tz)
    if window.end_ms is None:
        return f"{start:%Y-%m-%d %H:%M} {zone_label(start)} to now"
    end = datetime.fromtimestamp(window.end_ms / 1000, tz)
    end_text = f"{end:%H:%M}" if end.date() == start.date() else f"{end:%Y-%m-%d %H:%M}"
    return f"{start:%Y-%m-%d %H:%M} to {end_text} {zone_label(end)}"


def format_duration_ms(ms: float) -> str:
    """``640 ms``, ``12.7 s``, ``3.2 min``, ``1.5 h``."""
    if ms < 1_000:
        return f"{ms:,.0f} ms"
    if ms < 60_000:
        return f"{ms / 1_000:,.1f} s"
    if ms < 3_600_000:
        return f"{ms / 60_000:,.1f} min"
    return f"{ms / 3_600_000:,.1f} h"


def timestamp_ms(text: str | None) -> int | None:
    """Epoch ms of a mongod log timestamp (``...+00:00``, legacy ``...+0000``); None if invalid."""
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.strip())
    except ValueError:
        return None
    return to_epoch_ms(parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC))


def display_timestamp(text: str | None, tz: tzinfo = UTC) -> str:
    """A log timestamp shown in ``tz`` to the second; the raw text when it cannot be parsed."""
    ms = timestamp_ms(text)
    return format_instant(ms, tz, seconds=True) if ms is not None else (text or "")
