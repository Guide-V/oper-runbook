from __future__ import annotations

import gzip
import json
from pathlib import Path

from typer.testing import CliRunner

from mongoops.cli import app
from tests.conftest import FIXTURES

runner = CliRunner()
FIXTURE = str(FIXTURES / "atlas_local_slow_queries.jsonl")


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
