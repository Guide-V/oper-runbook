from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from mongoops.cli import app
from mongoops.regex_finder.analyze import AnalyzeOptions, Finding, SourceLine, analyze_lines
from mongoops.regex_finder.detector import RegexCategory
from mongoops.regex_finder.report import ReportMeta, render, summarize
from tests.conftest import FIXTURES

FIXTURE = str(FIXTURES / "atlas_local_slow_queries.jsonl")
META = ReportMeta(
    source="atlas",
    target="cluster-free (project abc)",
    window="since 24h",
    filters=("namespace mongoops_test.customers",),
    generated_at="2026-09-04 05:00:00 UTC",
)


def _findings(lines: tuple[str, ...]) -> tuple[Finding, ...]:
    return tuple(analyze_lines([SourceLine(line=ln, origin="t") for ln in lines], AnalyzeOptions()))


class TestRenderHtml:
    def test_is_self_contained_document_with_header_metadata(
        self, atlas_local_lines: tuple[str, ...]
    ) -> None:
        html = render(_findings(atlas_local_lines), fmt="html", view="both", meta=META)
        assert html.startswith("<!doctype html>")
        assert html.rstrip().endswith("</html>")
        for needle in (
            "cluster-free (project abc)",
            "since 24h",
            "mongoops_test.customers",
            "2026-09-04 05:00:00 UTC",
        ):
            assert needle in html
        # No external assets: everything must work offline.
        assert "http://" not in html and "https://" not in html
        assert '<link rel="stylesheet"' not in html and "<script src=" not in html

    def test_kpis_and_sections_reflect_the_data(self, atlas_local_lines: tuple[str, ...]) -> None:
        findings = _findings(atlas_local_lines)
        summary = summarize(findings)
        html = render(findings, fmt="html", view="both", meta=META)
        assert f"Shapes ({len(summary)})" in html
        assert f"Findings ({len(findings)})" in html
        collscans = sum(1 for f in findings if "COLLSCAN" in (f.plan_summary or ""))
        assert f'<div class="v">{collscans}</div><div class="l">COLLSCAN operations</div>' in html
        bad = sum(
            1 for r in summary if r.category not in (RegexCategory.PREFIX, RegexCategory.ANCHORED)
        )
        assert f'<div class="v">{bad}</div><div class="l">index-defeating shapes</div>' in html
        for cat in {f.category for f in findings}:
            assert f'class="badge {"ok" if cat is RegexCategory.PREFIX else "bad"}">{cat}<' in html
        assert 'class="plan-collscan">COLLSCAN' in html

    def test_escapes_untrusted_log_content(self) -> None:
        line = json.dumps(
            {
                "t": {"$date": "2026-01-01T00:00:00.000+00:00"},
                "msg": "Slow query",
                "attr": {
                    "type": "command",
                    "ns": "db.c",
                    "appName": "<script>alert(1)</script>",
                    "command": {"find": "c", "filter": {"x": {"$regex": "<b>&</b>"}}},
                    "durationMillis": 5,
                },
            }
        )
        findings = tuple(analyze_lines([SourceLine(line=line, origin="o")], AnalyzeOptions()))
        html = render(findings, fmt="html", view="both", meta=META)
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
        assert "<code>&lt;b&gt;&amp;&lt;/b&gt;</code>" in html

    def test_empty_state(self) -> None:
        html = render((), fmt="html", view="both", meta=META)
        assert "No <code>$regex</code> usage found" in html
        assert 'id="findings"' not in html

    def test_default_meta_when_none_given(self, atlas_local_lines: tuple[str, ...]) -> None:
        html = render(_findings(atlas_local_lines), fmt="html", view="both")
        assert "<b>source</b>unknown" in html


class TestCliDashboard:
    def test_html_flag_writes_dashboard_and_keeps_stdout(self, tmp_path: Path) -> None:
        dash = tmp_path / "reports" / "d.html"
        result = CliRunner().invoke(
            app,
            [
                "regex-finder",
                "logfile",
                FIXTURE,
                "--view",
                "summary",
                "--html",
                str(dash),
                "-n",
                "mongoops_test.customers",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "$regex usage summary" in result.stdout  # terminal output unchanged
        html = dash.read_text(encoding="utf-8")
        assert "<b>source</b>logfile" in html
        assert "<b>filter</b>namespace mongoops_test.customers" in html
        assert "Findings (16)" in html  # --html always renders both views
        assert dash.as_uri() in result.output

    def test_format_html_to_stdout(self) -> None:
        result = CliRunner().invoke(app, ["regex-finder", "logfile", FIXTURE, "-f", "html"])
        assert result.exit_code == 0, result.output
        assert result.stdout.startswith("<!doctype html>")

    def test_live_uri_is_redacted_in_dashboard(self, tmp_path: Path) -> None:
        from mongoops.regex_finder.cli import _redact_uri

        # Placeholder host on a reserved TLD so secret scanners do not mistake this for a
        # real Atlas connection string.
        assert (
            _redact_uri("mongodb+srv://user:p%40ss@cluster0.example.invalid/db")
            == "mongodb+srv://***@cluster0.example.invalid/db"
        )
        assert _redact_uri("mongodb://localhost:27099/?directConnection=true") == (
            "mongodb://localhost:27099/?directConnection=true"
        )
