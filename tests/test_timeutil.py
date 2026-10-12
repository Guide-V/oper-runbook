"""Time windows (--since/--until/--duration/--at/--around) and zone handling (--tz)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest

from mongoops.common.timeutil import (
    TimeWindow,
    WindowSpec,
    describe_window,
    display_timestamp,
    format_duration_ms,
    is_naive,
    parse_zone,
    resolve_window,
    timestamp_ms,
    to_epoch_ms,
)

NOW = datetime(2026, 10, 8, 12, 0, tzinfo=UTC)
BANGKOK = timezone(timedelta(hours=7))


def ms(*args: int, tz: timezone = UTC) -> int:
    return to_epoch_ms(datetime(*args, tzinfo=tz))  # type: ignore[misc]


class TestResolveWindow:
    def test_since_until_is_an_explicit_range(self) -> None:
        w = resolve_window(WindowSpec(since="2026-10-07T07:00Z", until="2026-10-07T09:00Z"))
        assert w == TimeWindow(ms(2026, 10, 7, 7), ms(2026, 10, 7, 9))
        assert w.duration_ms == 2 * 3_600_000

    def test_since_plus_duration_and_until_minus_duration(self) -> None:
        start = resolve_window(WindowSpec(since="2026-10-07T07:00Z", duration="2h"))
        end = resolve_window(WindowSpec(until="2026-10-07T09:00Z", duration="2h"))
        assert start == end == TimeWindow(ms(2026, 10, 7, 7), ms(2026, 10, 7, 9))

    def test_relative_values_count_back_from_now(self) -> None:
        assert resolve_window(WindowSpec(since="3h", until="1h"), now=NOW) == TimeWindow(
            ms(2026, 10, 8, 9), ms(2026, 10, 8, 11)
        )
        assert resolve_window(WindowSpec(duration="6h"), now=NOW) == TimeWindow(
            ms(2026, 10, 8, 6), None
        )
        assert resolve_window(WindowSpec(since="24h"), now=NOW).end_ms is None

    def test_at_around_is_an_incident_window(self) -> None:
        assert resolve_window(WindowSpec(at="2026-10-07T14:30+07:00")) == TimeWindow(
            ms(2026, 10, 7, 7, 0), ms(2026, 10, 7, 8, 0)
        )  # default +-30m
        assert resolve_window(WindowSpec(at="2026-10-07T07:30Z", around="5m")) == TimeWindow(
            ms(2026, 10, 7, 7, 25), ms(2026, 10, 7, 7, 35)
        )

    def test_naive_input_is_read_in_the_given_zone_offsets_are_kept(self) -> None:
        naive = WindowSpec(since="2026-10-07 14:00", until="2026-10-07 16:00")
        assert resolve_window(naive).start_ms == ms(2026, 10, 7, 14)  # UTC by default
        assert resolve_window(naive, tz=BANGKOK).start_ms == ms(2026, 10, 7, 7)
        explicit = WindowSpec(since="2026-10-07T14:00+07:00", duration="1h")
        assert resolve_window(explicit, tz=parse_zone("America/New_York")).start_ms == ms(
            2026, 10, 7, 7
        )

    def test_empty_spec_means_no_bounds(self) -> None:
        assert not resolve_window(WindowSpec()).bounded

    @pytest.mark.parametrize(
        ("spec", "message"),
        [
            (WindowSpec(at="2026-10-07", since="1h"), "--at cannot be combined"),
            (WindowSpec(around="10m"), "--around needs --at"),
            (WindowSpec(since="3h", until="1h", duration="2h"), "not all three"),
            (WindowSpec(until="1h"), "--until needs --since"),
            (WindowSpec(since="1h", until="3h"), "ends before it starts"),
            (WindowSpec(since="yesterday"), "invalid date/time"),
            (WindowSpec(at="2026-10-07", around="soon"), "invalid duration"),
        ],
    )
    def test_rejects_ambiguous_or_broken_flags(self, spec: WindowSpec, message: str) -> None:
        with pytest.raises(ValueError, match=message):
            resolve_window(spec, now=NOW)

    def test_contains_is_half_open(self) -> None:
        w = TimeWindow(10, 20)
        assert (w.contains(9), w.contains(10), w.contains(19), w.contains(20)) == (
            False,
            True,
            True,
            False,
        )


class TestZones:
    def test_naive_detection(self) -> None:
        assert is_naive("2026-10-07 14:00") and is_naive("2026-10-07")
        assert not is_naive("2026-10-07T14:00Z") and not is_naive("2026-10-07T14:00+07:00")
        assert not is_naive("24h")

    @pytest.mark.parametrize(
        ("name", "offset_h"), [("UTC", 0), ("Asia/Bangkok", 7), ("+07:00", 7), ("-0330", -3.5)]
    )
    def test_parse_zone(self, name: str, offset_h: float) -> None:
        assert NOW.astimezone(parse_zone(name)).utcoffset() == timedelta(hours=offset_h)

    def test_unknown_zone_is_a_usage_error(self) -> None:
        with pytest.raises(ValueError, match="unknown time zone 'Mars/Base'"):
            parse_zone("Mars/Base")


class TestDisplay:
    def test_window_in_utc_and_in_a_local_zone(self) -> None:
        w = TimeWindow(ms(2026, 10, 7, 7), ms(2026, 10, 7, 9))
        assert describe_window(w) == "2026-10-07 07:00 to 09:00 UTC"
        assert describe_window(w, BANGKOK) == (
            "2026-10-07 14:00 to 16:00 +07:00 (2026-10-07 07:00 to 09:00 UTC)"
        )
        assert describe_window(TimeWindow(ms(2026, 10, 6, 22), ms(2026, 10, 7, 2))) == (
            "2026-10-06 22:00 to 2026-10-07 02:00 UTC"
        )
        assert describe_window(TimeWindow(ms(2026, 10, 7, 7), None)) == (
            "2026-10-07 07:00 UTC to now"
        )
        assert describe_window(TimeWindow()) == ""

    def test_log_timestamps_json_and_legacy(self) -> None:
        assert timestamp_ms("2026-09-04T03:21:24.365+00:00") == ms(2026, 9, 4, 3, 21, 24) + 365
        assert timestamp_ms("2019-11-20T10:15:33.447+0000") == ms(2019, 11, 20, 10, 15, 33) + 447
        assert timestamp_ms("not a time") is None and timestamp_ms(None) is None
        assert display_timestamp("2026-09-04T03:21:24.365+00:00", BANGKOK) == (
            "2026-09-04 10:21:24 +07:00"
        )
        assert display_timestamp("garbage") == "garbage"

    @pytest.mark.parametrize(
        ("value", "text"),
        [(0, "0 ms"), (640, "640 ms"), (12_700, "12.7 s"), (192_000, "3.2 min"), (5.4e6, "1.5 h")],
    )
    def test_durations_read_naturally(self, value: float, text: str) -> None:
        assert format_duration_ms(value) == text
