from __future__ import annotations

import gzip
import json
from datetime import timedelta, timezone
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mongoops.cli import app
from mongoops.common.timeutil import WindowSpec, resolve_window
from mongoops.regex_finder import cli as regex_cli
from tests.conftest import FIXTURES

runner = CliRunner()
FIXTURE = str(FIXTURES / "atlas_local_slow_queries.jsonl")
BANGKOK = timezone(timedelta(hours=7))


def test_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.stdout.startswith("mongoops ")


def test_no_args_prints_help() -> None:
    result = runner.invoke(app, [])
    assert result.exit_code == 0
    assert "regex-finder" in result.stdout


def test_logfile_table() -> None:
    result = runner.invoke(app, ["regex-finder", "logfile", FIXTURE])
    assert result.exit_code == 0, result.output
    assert "$regex usage summary" in result.stdout
    assert "case_insensitive" in result.stdout


def test_logfile_json_to_file_with_filters(tmp_path: Path) -> None:
    out = tmp_path / "out" / "r.json"
    result = runner.invoke(
        app,
        [
            "regex-finder",
            "logfile",
            FIXTURE,
            "-f",
            "json",
            "--view",
            "details",
            "-o",
            str(out),
            "--include-getmore",
            "-n",
            "mongoops_test.customers",
            "--min-ms",
            "1",
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(out.read_text())
    assert set(payload) == {"findings"}
    assert all(f["duration_ms"] >= 1 for f in payload["findings"])
    assert (
        any(f["command"] == "getMore" for f in payload["findings"]) is False
    )  # getMores were 0 ms


def test_logfile_fail_on_gates_on_remedy() -> None:
    base = ["regex-finder", "logfile", FIXTURE, "-f", "json"]
    clean = runner.invoke(app, [*base, "--fail-on", "search"])  # local fixture: no Search shape
    assert clean.exit_code == 0, clean.output
    remedies = {r["remedy"] for r in json.loads(clean.stdout)["summary"]}
    assert remedies and "search" not in remedies, remedies
    gated = runner.invoke(app, [*base, "--fail-on", ",".join(sorted(remedies))])
    assert gated.exit_code == 1, gated.output
    assert "blocking:" in gated.output
    assert json.loads(gated.stdout)["summary"]  # the report is still written before exiting 1
    typo = runner.invoke(app, [*base, "--fail-on", "search,shrug"])
    assert typo.exit_code == 2
    assert "unknown remedy shrug" in typo.output


def test_logfile_gzip_and_stdin(tmp_path: Path) -> None:
    gz = tmp_path / "mongod.log.gz"
    with gzip.open(gz, "wt") as fh:
        fh.write(Path(FIXTURE).read_text())
    result = runner.invoke(app, ["regex-finder", "logfile", str(gz), "-f", "csv"])
    assert result.exit_code == 0, result.output
    assert result.stdout.count("\n") == 17  # header + 16 findings

    piped = runner.invoke(
        app, ["regex-finder", "logfile", "-", "-f", "csv"], input=Path(FIXTURE).read_text()
    )
    assert piped.exit_code == 0, piped.output
    assert piped.stdout.count("\n") == 17


def test_logfile_missing_file() -> None:
    result = runner.invoke(app, ["regex-finder", "logfile", "/nope/none.log"])
    assert result.exit_code == 2
    assert "file not found" in result.output


def test_atlas_requires_cluster_or_process() -> None:
    result = runner.invoke(app, ["regex-finder", "atlas", "--project-id", "a" * 24])
    assert result.exit_code == 2
    assert "--cluster" in result.output


def test_atlas_without_credentials_fails_cleanly(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    for var in (
        "MONGODB_ATLAS_PUBLIC_API_KEY",
        "MONGODB_ATLAS_PRIVATE_API_KEY",
        "MONGODB_ATLAS_CLIENT_ID",
        "MONGODB_ATLAS_CLIENT_SECRET",
    ):
        monkeypatch.delenv(var, raising=False)
    result = runner.invoke(
        app,
        [
            "--env-file",
            "/nonexistent.env",
            "regex-finder",
            "atlas",
            "-p",
            "a" * 24,
            "-c",
            "Cluster0",
        ],
    )
    assert result.exit_code == 2
    assert "credentials missing" in result.output


class TestTimeWindowFlags:
    """Golden path for "show me the cluster at this date and time"."""

    BASE = ("regex-finder", "logfile", FIXTURE, "-f", "json", "--view", "details")
    # 4 regex usages in the fixture fall in [03:21:24.540, 03:21:24.549) UTC
    WINDOW_UTC = ("--since", "2026-09-04T03:21:24.540Z", "--until", "2026-09-04T03:21:24.549Z")

    @pytest.fixture(autouse=True)
    def _bangkok_machine(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("MONGOOPS_TZ", raising=False)
        monkeypatch.setattr(regex_cli, "local_zone", lambda: BANGKOK)
        monkeypatch.setattr(regex_cli, "_interactive", lambda: False)

    def _timestamps(self, *args: str, stdin: str | None = None) -> list[str]:
        result = runner.invoke(app, [*self.BASE, *args], input=stdin)
        assert result.exit_code == 0, result.output
        return [f["timestamp"] for f in json.loads(result.stdout)["findings"]]

    def test_since_until_filters_on_the_log_timestamp(self) -> None:
        stamps = self._timestamps(*self.WINDOW_UTC)
        assert len(stamps) == 4
        assert all("03:21:24.54" in s for s in stamps)

    def test_resolved_window_is_echoed_on_stderr(self) -> None:
        result = runner.invoke(app, [*self.BASE, *self.WINDOW_UTC, "--tz", "+07:00"])
        assert result.exit_code == 0, result.output
        assert "4 regex usage(s) found, window 2026-09-04 10:21 to 10:21 +07:00" in result.stderr

    def test_at_around_gives_the_same_incident_window(self) -> None:
        at = ("--at", "2026-09-04T03:21:24.545Z", "--around", "4ms")
        assert self._timestamps(*at) == self._timestamps(*self.WINDOW_UTC)

    def test_tz_reads_naive_input_in_that_zone(self) -> None:
        local = ("--since", "2026-09-04 10:21:24.540", "--until", "2026-09-04 10:21:24.549")
        assert self._timestamps(*local, "--tz", "Asia/Bangkok") == self._timestamps(
            *self.WINDOW_UTC
        )

    def test_naive_input_without_a_terminal_is_utc_and_says_so(self) -> None:
        local = ("--since", "2026-09-04 10:21:24.540", "--until", "2026-09-04 10:21:24.549")
        result = runner.invoke(app, [*self.BASE, *local])
        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["findings"] == []  # 10:21 UTC is after the fixture
        assert "read as UTC; pass --tz" in result.output

    def test_interactive_prompt_can_switch_to_the_local_zone(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(regex_cli, "_interactive", lambda: True)
        local = ("--since", "2026-09-04 10:21:24.540", "--until", "2026-09-04 10:21:24.549")
        result = runner.invoke(app, [*self.BASE, *local], input="l\n")
        assert result.exit_code == 0, result.output
        assert "has no time zone" in result.output
        assert "this machine  2026-09-04 10:21 +07:00" in result.output
        # CliRunner echoes typed input to stdout (a real terminal does not), so skip past it
        payload = json.loads(result.stdout[result.stdout.index("{") :])
        assert len(payload["findings"]) == 4

    def test_display_zone_reaches_table_and_dashboard(self, tmp_path: Path) -> None:
        dash = tmp_path / "d.html"
        result = runner.invoke(
            app,
            [
                "regex-finder",
                "logfile",
                FIXTURE,
                *self.WINDOW_UTC,
                "--tz",
                "Asia/Bangkok",
                "--view",
                "details",
                "--html",
                str(dash),
            ],
        )
        assert result.exit_code == 0, result.output
        assert "2026-09-04 10:21:24 +07:00" in result.stdout
        html = dash.read_text(encoding="utf-8")
        assert "<b>window</b>2026-09-04 10:21 to 10:21 +07:00 (2026-09-04 03:21 to 03:21 UTC)" in (
            html
        )

    @pytest.mark.parametrize(
        ("args", "message"),
        [
            (("--at", "2026-09-04", "--since", "1h"), "--at cannot be combined"),
            (("--until", "1h"), "--until needs --since"),
            (("--since", "1h", "--tz", "Mars/Base"), "unknown time zone"),
            (("--since", "tuesday"), "invalid date/time"),
        ],
    )
    def test_bad_flags_are_usage_errors(self, args: tuple[str, ...], message: str) -> None:
        result = runner.invoke(app, [*self.BASE, *args])
        assert result.exit_code == 2
        assert message in result.output


def test_api_window_passes_absolute_bounds_to_performance_advisor() -> None:
    window = resolve_window(WindowSpec(at="2026-10-07T14:30+07:00", around="15m"))
    params = regex_cli._api_window(window, ["shop.orders"], 500).as_params()
    assert params == {
        "nLogs": 500,
        "since": window.start_ms,
        "duration": 30 * 60_000,
        "namespaces": ["shop.orders"],
    }
    assert "since" not in regex_cli._api_window(resolve_window(WindowSpec()), None, 9).as_params()


def test_progress_flags_nodes_that_hit_the_line_cap() -> None:
    warnings: list[str] = []
    report = regex_cli._progress(100, warnings)
    report("node-a:27017", 99)
    report("node-b:27017", 100)
    assert len(warnings) == 1 and warnings[0].startswith("node-b:27017 returned 100 lines")


def test_logfile_hotspots_csv() -> None:
    result = runner.invoke(
        app, ["regex-finder", "logfile", FIXTURE, "-f", "csv", "--view", "hotspots"]
    )
    assert result.exit_code == 0, result.output
    header, row = result.stdout.splitlines()
    assert header.startswith("namespace,database,collection,ops,total_ms,share_pct")
    assert row.startswith("mongoops_test.customers,mongoops_test,customers,14,")


def test_live_unreachable_fails_cleanly() -> None:
    result = runner.invoke(
        app,
        [
            "regex-finder",
            "live",
            "--uri",
            "mongodb://127.0.0.1:1/?serverSelectionTimeoutMS=200&directConnection=true",
        ],
    )
    assert result.exit_code == 2
    assert "error" in result.output
