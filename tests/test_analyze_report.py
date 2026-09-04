from __future__ import annotations

import csv
import io
import json

from mongoops.regex_finder.analyze import AnalyzeOptions, SourceLine, analyze_lines
from mongoops.regex_finder.detector import RegexCategory
from mongoops.regex_finder.report import render, summarize


def _lines(raw: tuple[str, ...], origin: str = "test") -> list[SourceLine]:
    return [SourceLine(line=line, origin=origin) for line in raw]


class TestAnalyzeAtlasLocal:
    """Golden path: real MongoDB 8.0 slow-query lines -> findings."""

    def test_finds_every_seeded_regex_shape(self, atlas_local_lines: tuple[str, ...]) -> None:
        findings = tuple(analyze_lines(_lines(atlas_local_lines), AnalyzeOptions()))
        # 13 seeded ops; $in -> 2 hits, aggregate -> 2 hits, update & delete logged twice each = 16
        assert len(findings) == 16
        assert {f.namespace for f in findings} == {"mongoops_test.customers"}
        assert all(f.log_format == "json" for f in findings)
        by_pattern = {(f.pattern, f.options): f for f in findings}
        assert by_pattern[("^som", "i")].category == RegexCategory.CASE_INSENSITIVE
        assert by_pattern[("^6681", "")].category == RegexCategory.PREFIX
        assert by_pattern[("^6681", "")].plan_summary == "IXSCAN { msisdn: 1 }"
        assert by_pattern[("^.*2222$", "")].category == RegexCategory.LEADING_WILDCARD
        assert by_pattern[("^Anan", "")].category == RegexCategory.NEGATED
        assert by_pattern[("^S", "i")].operator == "$regexMatch"
        assert by_pattern[("@(.*)\\.", "")].operator == "$regexFind"
        assert by_pattern[("example", "i")].plan_summary == "COLLSCAN"

    def test_getmore_excluded_by_default_included_on_request(
        self, atlas_local_lines: tuple[str, ...]
    ) -> None:
        default = tuple(analyze_lines(_lines(atlas_local_lines), AnalyzeOptions()))
        assert not any(f.command == "getMore" for f in default)
        with_getmore = tuple(
            analyze_lines(_lines(atlas_local_lines), AnalyzeOptions(include_getmore=True))
        )
        getmores = [f for f in with_getmore if f.command == "getMore"]
        assert len(getmores) == 3
        assert all(f.pattern == "a" for f in getmores)

    def test_namespace_and_min_duration_filters(self, atlas_local_lines: tuple[str, ...]) -> None:
        assert (
            tuple(
                analyze_lines(
                    _lines(atlas_local_lines), AnalyzeOptions(namespaces=frozenset({"x.y"}))
                )
            )
            == ()
        )
        slow = tuple(analyze_lines(_lines(atlas_local_lines), AnalyzeOptions(min_duration_ms=3)))
        assert slow and all((f.duration_ms or 0) >= 3 for f in slow)

    def test_namespace_hint_used_for_filtering(self) -> None:
        line = json.dumps(
            {
                "t": {"$date": "x"},
                "msg": "Slow query",
                "attr": {
                    "type": "command",
                    "command": {"find": "c", "filter": {"a": {"$regex": "b"}}},
                },
            }
        )
        src = [SourceLine(line=line, origin="o", namespace_hint="db.c")]
        assert len(tuple(analyze_lines(src, AnalyzeOptions(namespaces=frozenset({"db.c"}))))) == 1
        assert tuple(analyze_lines(src, AnalyzeOptions(namespaces=frozenset({"db.other"})))) == ()


class TestAnalyzeLegacy:
    def test_legacy_lines(self, legacy_lines: tuple[str, ...]) -> None:
        findings = tuple(analyze_lines(_lines(legacy_lines), AnalyzeOptions()))
        assert [(f.field, f.pattern, f.category) for f in findings] == [
            ("emails", "^tocde", RegexCategory.CASE_INSENSITIVE),
            ("name", "^Som", RegexCategory.CASE_INSENSITIVE),
            ("tags", "^vip", RegexCategory.PREFIX),
            ("tags", "^gold", RegexCategory.PREFIX),
            ("name", "^Test", RegexCategory.NEGATED),
            ("email", "\\.net$", RegexCategory.UNANCHORED),
        ]
        assert findings[1].duration_ms == 1834
        assert findings[1].plan_summary == "COLLSCAN"
        assert findings[-1].command == "update"


class TestReport:
    def test_summary_groups_and_orders_worst_first(
        self, atlas_local_lines: tuple[str, ...]
    ) -> None:
        findings = tuple(analyze_lines(_lines(atlas_local_lines), AnalyzeOptions()))
        rows = summarize(findings)
        assert sum(r.count for r in rows) == len(findings)
        assert rows[0].category == RegexCategory.CASE_INSENSITIVE
        assert rows[-1].category == RegexCategory.PREFIX
        update_row = next(r for r in rows if r.command == "update")
        assert (update_row.count, update_row.collscan_count, update_row.max_duration_ms) == (
            2,
            1,
            8,
        )
        in_row = next(
            r
            for r in rows
            if r.command == "find" and r.category == RegexCategory.PREFIX and r.field == "name"
        )
        assert in_row.count == 2  # both $in members

    def test_csv_details_round_trip(self, atlas_local_lines: tuple[str, ...]) -> None:
        findings = tuple(analyze_lines(_lines(atlas_local_lines), AnalyzeOptions()))
        out = render(findings, fmt="csv", view="details")
        rows = list(csv.DictReader(io.StringIO(out)))
        assert len(rows) == len(findings)
        assert rows[0]["category"] == "case_insensitive"
        assert set(rows[0]) >= {
            "namespace",
            "field",
            "pattern",
            "options",
            "category",
            "plan_summary",
            "duration_ms",
        }

    def test_csv_summary(self, atlas_local_lines: tuple[str, ...]) -> None:
        findings = tuple(analyze_lines(_lines(atlas_local_lines), AnalyzeOptions()))
        rows = list(csv.DictReader(io.StringIO(render(findings, fmt="csv", view="summary"))))
        assert len(rows) == len(summarize(findings))
        assert rows[0]["advice"].startswith("Case-insensitive")

    def test_json_both(self, atlas_local_lines: tuple[str, ...]) -> None:
        findings = tuple(analyze_lines(_lines(atlas_local_lines), AnalyzeOptions()))
        payload = json.loads(render(findings, fmt="json", view="both"))
        assert set(payload) == {"summary", "findings"}
        assert len(payload["findings"]) == len(findings)
        assert payload["findings"][0]["category"] == "case_insensitive"

    def test_table_limits_detail_rows_and_handles_empty(
        self, atlas_local_lines: tuple[str, ...]
    ) -> None:
        findings = tuple(analyze_lines(_lines(atlas_local_lines), AnalyzeOptions()))
        text = render(findings, fmt="table", view="both", max_detail_rows=5)
        assert "showing first 5" in text
        assert "$regex usage summary" in text
        assert "No $regex usage found" in render((), fmt="table", view="both")
