"""Rule table for remedies. Each test is one row of the decision table in spec.md."""

from __future__ import annotations

import pytest

from mongoops.regex_finder.analyze import AnalyzeOptions, SourceLine, analyze_lines
from mongoops.regex_finder.detector import RegexCategory as C
from mongoops.regex_finder.remedy import Remedy, literal_body, recommend, with_field

HEAVY = dict(
    plan_summary="IXSCAN { name: 1 }", keys_examined=300_000, docs_examined=22, nreturned=22
)
TINY = dict(plan_summary="COLLSCAN", keys_examined=0, docs_examined=3, nreturned=3)
COLLSCAN_BIG = dict(plan_summary="COLLSCAN", keys_examined=0, docs_examined=300_000, nreturned=1)


def rec(
    category: C, pattern: str, *, command: str = "find", options: str = "", **stats: object
) -> Remedy:
    return recommend(
        category=category,
        command=command,
        pattern=pattern,
        options=options,
        **{**HEAVY, **stats},  # type: ignore[arg-type]
    ).remedy


class TestLiteralBody:
    @pytest.mark.parametrize(
        ("pattern", "expected"),
        [
            ("^som", "som"),
            ("^.*99999$", "99999"),
            ("Rakdee 1234", "Rakdee 1234"),
            (r"\.net$", ".net"),
            (r"example\.org$", "example.org"),
            (r"user1234\d@example\.net$", ""),  # \d is a class, not literal
            ("^S", "S"),
            ("@(.*)\\.", ""),
            ("^[A-Z]", ""),
        ],
    )
    def test_strips_anchors_and_detects_metacharacters(self, pattern: str, expected: str) -> None:
        assert literal_body(pattern) == expected


class TestRules:
    def test_case_sensitive_prefix_needs_nothing(self) -> None:
        assert rec(C.PREFIX, "^6681") is Remedy.NONE

    def test_prefix_on_collscan_wants_a_btree_index(self) -> None:
        assert rec(C.PREFIX, "^post", **COLLSCAN_BIG) is Remedy.BTREE_INDEX
        assert rec(C.PREFIX, "^post", **TINY) is Remedy.BTREE_INDEX  # cheap, do it anyway

    def test_negated_is_always_a_rewrite(self) -> None:
        assert rec(C.NEGATED, "^S", command="aggregate") is Remedy.REWRITE
        assert rec(C.NEGATED, "^S", command="update", **TINY) is Remedy.REWRITE

    def test_case_insensitive_prefix_is_a_collation_index_even_on_writes(self) -> None:
        assert rec(C.CASE_INSENSITIVE, "^som", options="i") is Remedy.COLLATION_INDEX
        assert (
            rec(C.CASE_INSENSITIVE, "^som", options="i", command="update") is Remedy.COLLATION_INDEX
        )
        how = recommend(
            category=C.CASE_INSENSITIVE,
            command="find",
            pattern="^som",
            options="i",
            **HEAVY,  # type: ignore[arg-type]
        ).how
        assert "strength: 2" in how and "^som" in how

    def test_case_insensitive_unanchored_goes_to_search_when_heavy(self) -> None:
        assert rec(C.CASE_INSENSITIVE, "example", options="i") is Remedy.SEARCH
        assert rec(C.CASE_INSENSITIVE, "example", options="i", **TINY) is Remedy.MONITOR

    def test_identifier_suffix_is_a_reversed_field(self) -> None:
        assert rec(C.LEADING_WILDCARD, "^.*99999$") is Remedy.REVERSED_FIELD
        assert (
            rec(C.UNANCHORED, "99999$", command="update") is Remedy.REVERSED_FIELD
        )  # works on writes
        how = recommend(
            category=C.LEADING_WILDCARD,
            command="find",
            pattern="^.*99999$",
            options="",
            **HEAVY,  # type: ignore[arg-type]
        )
        assert (
            "/^99999/" in with_field(how, "msisdn").how
            and "msisdn_rev" in with_field(how, "msisdn").how
        )

    def test_text_suffix_is_not_an_identifier(self) -> None:
        assert rec(C.UNANCHORED, r"example\.org$") is Remedy.SEARCH
        assert rec(C.UNANCHORED, "Jaidee$", **COLLSCAN_BIG) is Remedy.SEARCH

    def test_write_path_never_gets_search(self) -> None:
        for cmd in ("update", "delete", "remove", "findAndModify"):
            assert rec(C.UNANCHORED, r"user\d+@example\.net$", command=cmd) is Remedy.FIX_FILTER
        assert (
            "$search cannot be used in a update filter"
            in recommend(
                category=C.UNANCHORED,
                command="update",
                pattern="x",
                options="",
                **HEAVY,  # type: ignore[arg-type]
            ).how
        )

    def test_search_requires_scan_evidence(self) -> None:
        assert rec(C.UNANCHORED, "Rakdee 1234") is Remedy.SEARCH  # 300k keys
        assert rec(C.UNANCHORED, "Rakdee 1234", **COLLSCAN_BIG) is Remedy.SEARCH
        assert rec(C.UNANCHORED, "Rakdee 1234", **TINY) is Remedy.MONITOR
        # COLLSCAN with poor selectivity counts even below the absolute threshold
        assert (
            rec(
                C.UNANCHORED,
                "x",
                plan_summary="COLLSCAN",
                keys_examined=0,
                docs_examined=500,
                nreturned=2,
            )
            is Remedy.SEARCH
        )

    def test_search_operator_advice_matches_shape(self) -> None:
        def how(cat: C, pattern: str, options: str = "") -> str:
            return recommend(
                category=cat, command="find", pattern=pattern, options=options, **HEAVY
            ).how  # type: ignore[arg-type]

        assert "wildcard/regex operator" in how(C.LEADING_WILDCARD, "^.*smith$")
        assert "standard analyzer" in how(C.UNANCHORED, "Rakdee 1234")
        assert "text or phrase operator" in how(C.UNANCHORED, "Rakdee")
        assert "$search as the first aggregation stage" in how(C.UNANCHORED, "Rakdee")

    def test_expression_operator_outside_a_filter_has_no_index_implication(self) -> None:
        r = recommend(
            category=C.CASE_INSENSITIVE,
            command="aggregate",
            pattern="^S",
            options="i",
            operator="$regexMatch",
            path="pipeline[1].$project.isVip.$regexMatch.regex",
            **HEAVY,  # type: ignore[arg-type]
        )
        assert r.remedy is Remedy.NONE and "projection/expression" in r.how

    def test_expression_operator_in_expr_prefix_should_become_a_plain_predicate(self) -> None:
        r = recommend(
            category=C.CASE_INSENSITIVE,
            command="find",
            pattern="^som",
            options="i",
            operator="$regexMatch",
            path="filter.$expr.$regexMatch.regex",
            **HEAVY,  # type: ignore[arg-type]
        )
        assert r.remedy is Remedy.REWRITE
        assert "/^som/i" in r.how and "collation index" in r.how

    def test_expression_operator_in_expr_unanchored_falls_through_to_search(self) -> None:
        assert (
            recommend(
                category=C.UNANCHORED,
                command="find",
                pattern="record 12345$",
                options="",
                operator="$regexFind",
                path="filter.$expr.$ne[0].$regexFind.regex",
                **COLLSCAN_BIG,  # type: ignore[arg-type]
            ).remedy
            is Remedy.SEARCH
        )


class TestEndToEnd:
    def test_fixture_remedies(self, atlas_local_lines: tuple[str, ...]) -> None:
        findings = tuple(
            analyze_lines(
                [SourceLine(line=ln, origin="t") for ln in atlas_local_lines], AnalyzeOptions()
            )
        )
        by = {(f.field, f.pattern, f.command): f.remedy for f in findings}
        assert by[("msisdn", "^.*2222$", "find")] is Remedy.REVERSED_FIELD
        assert by[("name", "^som", "find")] is Remedy.COLLATION_INDEX
        assert by[("name", "^Anan", "find")] is Remedy.REWRITE
        assert by[("email", "\\.net$", "update")] is Remedy.FIX_FILTER
        assert by[("name", "^S", "aggregate")] is Remedy.NONE  # $regexMatch in $project
        assert by[("msisdn", "^6681", "find")] is Remedy.NONE
        # a 3-document collection must not be told to buy Search
        assert Remedy.SEARCH not in by.values()
        assert by[("email", "example", "find")] is Remedy.MONITOR
        assert all(f.remedy_how and "<field>" not in f.remedy_how for f in findings)

    def test_legacy_fixture_remedies(self, legacy_lines: tuple[str, ...]) -> None:
        findings = tuple(
            analyze_lines(
                [SourceLine(line=ln, origin="t") for ln in legacy_lines], AnalyzeOptions()
            )
        )
        remedies = [f.remedy for f in findings]
        assert remedies == [
            Remedy.COLLATION_INDEX,  # ^tocde i
            Remedy.COLLATION_INDEX,  # ^Som i, 120k docs
            Remedy.NONE,  # ^vip
            Remedy.NONE,  # ^gold
            Remedy.REWRITE,  # $not ^Test
            Remedy.FIX_FILTER,  # update \.net$
        ]
