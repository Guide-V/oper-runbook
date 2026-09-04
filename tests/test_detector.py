from __future__ import annotations

import pytest

from mongoops.regex_finder.detector import (
    RegexCategory,
    classify,
    find_regex_usages,
    find_regex_usages_legacy,
    literal_prefix,
)


def lit(pattern: str, options: str = "") -> dict[str, dict[str, str]]:
    return {"$regularExpression": {"pattern": pattern, "options": options}}


class TestClassify:
    @pytest.mark.parametrize(
        ("pattern", "options", "expected"),
        [
            ("^6681", "", RegexCategory.PREFIX),
            ("^abc.*", "", RegexCategory.PREFIX),
            ("^som", "i", RegexCategory.CASE_INSENSITIVE),
            ("(?i)^som", "", RegexCategory.CASE_INSENSITIVE),
            ("^.*2222$", "", RegexCategory.LEADING_WILDCARD),
            (".*foo", "", RegexCategory.LEADING_WILDCARD),
            ("^(a|b)", "", RegexCategory.ANCHORED),
            ("^\\d+", "", RegexCategory.ANCHORED),
            ("^[A-Z]", "", RegexCategory.ANCHORED),
            ("example", "", RegexCategory.UNANCHORED),
            ("\\.org$", "", RegexCategory.UNANCHORED),
            ("", "", RegexCategory.UNANCHORED),
        ],
    )
    def test_shapes(self, pattern: str, options: str, expected: RegexCategory) -> None:
        assert classify(pattern, options) == expected

    def test_negation_wins_over_prefix(self) -> None:
        assert classify("^abc", "", negated=True) == RegexCategory.NEGATED

    def test_case_insensitive_wins_over_prefix(self) -> None:
        assert classify("^abc", "im") == RegexCategory.CASE_INSENSITIVE


@pytest.mark.parametrize(
    ("pattern", "expected"),
    [("^6681", "6681"), ("^abc.*", "abc"), ("^\\d", ""), ("^", ""), ("abc", ""), ("^a\\.b", "a")],
)
def test_literal_prefix(pattern: str, expected: str) -> None:
    assert literal_prefix(pattern) == expected


class TestFindRegexUsages:
    def test_explicit_operator_with_options(self) -> None:
        cmd = {"find": "c", "filter": {"name": {"$regex": "^som", "$options": "i"}}}
        (hit,) = find_regex_usages(cmd)
        assert (hit.field, hit.pattern, hit.options, hit.operator) == (
            "name",
            "^som",
            "i",
            "$regex",
        )
        assert hit.path == "filter.name.$regex"
        assert hit.category == RegexCategory.CASE_INSENSITIVE

    def test_regex_literal(self) -> None:
        (hit,) = find_regex_usages({"find": "c", "filter": {"msisdn": lit("^6681")}})
        assert (hit.field, hit.pattern, hit.operator) == ("msisdn", "^6681", "$regularExpression")
        assert hit.path == "filter.msisdn"
        assert hit.category == RegexCategory.PREFIX

    def test_operator_with_literal_operand_is_reported_once(self) -> None:
        hits = find_regex_usages({"filter": {"a": {"$regex": lit("x", "s"), "$options": "i"}}})
        assert [(h.pattern, h.options, h.operator) for h in hits] == [("x", "i", "$regex")]

    def test_in_array_keeps_owning_field(self) -> None:
        hits = find_regex_usages({"filter": {"name": {"$in": [lit("^Som"), lit("^Sud"), "plain"]}}})
        assert [h.field for h in hits] == ["name", "name"]
        assert [h.path for h in hits] == ["filter.name.$in[0]", "filter.name.$in[1]"]
        assert {h.category for h in hits} == {RegexCategory.PREFIX}

    @pytest.mark.parametrize("op", ["$not", "$nin"])
    def test_negating_operators(self, op: str) -> None:
        operand = lit("^Anan") if op == "$not" else [lit("^Anan")]
        (hit,) = find_regex_usages({"filter": {"name": {op: operand}}})
        assert hit.field == "name"
        assert hit.category == RegexCategory.NEGATED

    def test_or_and_nested_fields(self) -> None:
        cmd = {
            "filter": {
                "$or": [{"address.city": lit("Bang")}, {"x": {"$elemMatch": {"y": lit("^z")}}}]
            }
        }
        hits = find_regex_usages(cmd)
        assert [(h.field, h.path) for h in hits] == [
            ("address.city", "filter.$or[0].address.city"),
            ("y", "filter.$or[1].x.$elemMatch.y"),
        ]

    def test_aggregation_match_and_regex_match_expression(self) -> None:
        cmd = {
            "aggregate": "c",
            "pipeline": [
                {"$match": {"email": {"$regex": "\\.org$"}}},
                {
                    "$project": {
                        "isVip": {
                            "$regexMatch": {"input": "$name", "regex": lit("^S"), "options": "i"}
                        }
                    }
                },
            ],
        }
        hits = find_regex_usages(cmd)
        assert [(h.field, h.pattern, h.options, h.operator) for h in hits] == [
            ("email", "\\.org$", "", "$regex"),
            ("name", "^S", "i", "$regexMatch"),
        ]
        assert hits[1].path == "pipeline[1].$project.isVip.$regexMatch.regex"

    def test_regex_find_inside_expr_with_string_regex(self) -> None:
        cmd = {
            "filter": {
                "$expr": {"$ne": [{"$regexFind": {"input": "$email", "regex": "@(.*)\\."}}, None]}
            }
        }
        (hit,) = find_regex_usages(cmd)
        assert (hit.field, hit.pattern, hit.operator) == ("email", "@(.*)\\.", "$regexFind")

    def test_expression_negation_does_not_apply(self) -> None:
        cmd = {"filter": {"$expr": {"$not": [{"$regexMatch": {"input": "$a", "regex": "^x"}}]}}}
        (hit,) = find_regex_usages(cmd)
        assert hit.category == RegexCategory.PREFIX

    def test_batched_update_and_individual_write(self) -> None:
        batch = {
            "update": "c",
            "updates": [{"q": {"email": lit("\\.net$")}, "u": {"$set": {"f": 1}}}],
        }
        single = {"q": {"email": lit("\\.net$")}, "u": {"$set": {"f": 1}}, "multi": True}
        assert find_regex_usages(batch)[0].path == "updates[0].q.email"
        assert find_regex_usages(single)[0].path == "q.email"

    def test_no_regex(self) -> None:
        assert find_regex_usages({"find": "c", "filter": {"msisdn": "66812345678"}}) == ()
        assert find_regex_usages(None) == ()
        assert find_regex_usages("$regex") == ()

    def test_regex_looking_string_values_are_ignored(self) -> None:
        assert (
            find_regex_usages({"filter": {"note": "use $regex here", "k": "$regularExpression"}})
            == ()
        )


class TestLegacy:
    def test_literal_with_options(self) -> None:
        (hit,) = find_regex_usages_legacy('{ find: "users", filter: { emails: /^tocde/i } }')
        assert (hit.field, hit.pattern, hit.options, hit.operator) == (
            "emails",
            "^tocde",
            "i",
            "legacy-literal",
        )
        assert hit.category == RegexCategory.CASE_INSENSITIVE

    def test_operator_string_with_sibling_options(self) -> None:
        text = '{ filter: { name: { $regex: "^Som", $options: "i" }, status: "active" } }'
        (hit,) = find_regex_usages_legacy(text)
        assert (hit.field, hit.pattern, hit.options, hit.operator) == (
            "name",
            "^Som",
            "i",
            "legacy-$regex",
        )

    def test_operator_literal_operand(self) -> None:
        (hit,) = find_regex_usages_legacy("{ filter: { name: { $regex: /^Som/ } } }")
        assert (hit.field, hit.pattern, hit.operator) == ("name", "^Som", "legacy-$regex")

    def test_in_array_and_not(self) -> None:
        text = "{ filter: { tags: { $in: [ /^vip/, /^gold/ ] }, name: { $not: /^Test/ } } }"
        hits = find_regex_usages_legacy(text)
        assert [(h.field, h.pattern, h.category) for h in hits] == [
            ("tags", "^vip", RegexCategory.PREFIX),
            ("tags", "^gold", RegexCategory.PREFIX),
            ("name", "^Test", RegexCategory.NEGATED),
        ]

    def test_url_string_is_not_a_regex(self) -> None:
        assert find_regex_usages_legacy('{ filter: { url: "http://example.com/a/b" } }') == ()

    def test_escaped_slash_in_pattern(self) -> None:
        (hit,) = find_regex_usages_legacy(r"{ q: { path: /^\/api\/v1/ } }")
        assert hit.pattern == r"^\/api\/v1"
