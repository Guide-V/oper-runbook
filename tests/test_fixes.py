"""Copy-paste mongosh snippets per remedy: right target, right shape, nothing dangerous."""

from __future__ import annotations

import pytest

from mongoops.regex_finder.detector import RegexCategory as C
from mongoops.regex_finder.fixes import fix_snippet, split_namespace
from mongoops.regex_finder.remedy import Remedy, literal_body, recommend, search_operator

COLL = 'db.getSiblingDB("shop").getCollection("orders")'


def snip(
    remedy: Remedy,
    pattern: str,
    *,
    category: C = C.UNANCHORED,
    options: str = "",
    command: str = "find",
    field: str = "name",
    namespace: str = "shop.orders",
) -> str:
    return fix_snippet(
        remedy=remedy,
        namespace=namespace,
        field=field,
        command=command,
        category=category,
        pattern=pattern,
        options=options,
    )


def test_split_namespace_keeps_dots_in_the_collection() -> None:
    assert split_namespace("shop.orders.v2") == ("shop", "orders.v2")
    assert split_namespace("?") == ("?", "?")


def test_btree_index() -> None:
    assert f"{COLL}.createIndex({{ name: 1 }})" in snip(
        Remedy.BTREE_INDEX, "^post", category=C.PREFIX
    )


def test_collation_index_turns_the_regex_into_an_equality() -> None:
    s = snip(Remedy.COLLATION_INDEX, "^somchai$", category=C.CASE_INSENSITIVE, options="i")
    assert '{ collation: { locale: "en", strength: 2 } }' in s
    assert f'{COLL}.find({{ name: "somchai" }}).collation({{ locale: "en", strength: 2 }})' in s


def test_normalized_field_backfills_indexes_and_queries_lower_case() -> None:
    s = snip(
        Remedy.NORMALIZED_FIELD,
        "^Som",
        category=C.CASE_INSENSITIVE,
        options="i",
        command="aggregate",
    )
    assert '[{ $set: { name_lower: { $toLower: "$name" } } }]' in s
    assert f"{COLL}.createIndex({{ name_lower: 1 }})" in s
    assert f"{COLL}.aggregate([{{ $match: {{ name_lower: /^som/ }} }}])" in s


def test_reversed_field_reverses_the_literal_and_escapes_it() -> None:
    s = snip(Remedy.REVERSED_FIELD, "^.*99\\.1$", category=C.LEADING_WILDCARD, field="msisdn")
    assert "$reduce" in s and "msisdn_rev" in s
    assert f"{COLL}.find({{ msisdn_rev: /^1\\.99/ }})" in s


@pytest.mark.parametrize(
    ("pattern", "category", "options", "operator"),
    [
        ("record 12345$", C.UNANCHORED, "", "phrase: {"),
        ("example", C.CASE_INSENSITIVE, "i", "text: {"),
        ("^.*smith$", C.LEADING_WILDCARD, "", 'wildcard: { query: "*smith"'),
        (r"user\d+@x\.net$", C.UNANCHORED, "", 'regex: { query: ".*user\\\\d+@x\\\\.net"'),
    ],
)
def test_search_picks_an_operator_for_the_shape(
    pattern: str, category: C, options: str, operator: str
) -> None:
    s = snip(Remedy.SEARCH, pattern, category=category, options=options)
    assert f'{COLL}.createSearchIndex("orders_name_search", {{ mappings: {{ dynamic: false' in s
    assert '.aggregate([{ $search: { index: "orders_name_search", ' in s
    assert operator in s


@pytest.mark.parametrize(
    ("pattern", "category", "options"),
    [
        ("record 12345$", C.UNANCHORED, ""),
        ("Rakdee", C.UNANCHORED, ""),
        ("rakdee 1234", C.CASE_INSENSITIVE, "i"),
        ("^.*smith$", C.LEADING_WILDCARD, ""),
        (r"user\d+$", C.UNANCHORED, ""),
    ],
)
def test_search_sentence_and_snippet_name_the_same_operator(
    pattern: str, category: C, options: str
) -> None:
    how = recommend(
        category=category,
        command="find",
        pattern=pattern,
        options=options,
        plan_summary="COLLSCAN",
        keys_examined=0,
        docs_examined=300_000,
        nreturned=1,
    ).how
    operator = search_operator(category, options, literal_body(pattern))
    assert f"the {operator} operator" in how
    assert f"{operator}: {{ query: " in snip(
        Remedy.SEARCH, pattern, category=category, options=options
    )


def test_search_maps_dotted_fields_as_documents() -> None:
    s = snip(Remedy.SEARCH, "late fee", field="billing.memo")
    assert 'fields: { billing: { type: "document", fields: { memo: { type: "string"' in s
    assert 'path: "billing.memo"' in s


def test_write_path_fix_keeps_the_write_and_names_placeholders() -> None:
    s = snip(Remedy.FIX_FILTER, r"\.net$", command="update", field="email")
    assert (
        f'{COLL}.updateMany({{ "<indexed field>": <value>, email: /\\.net$/ }}, <your update>)' in s
    )
    assert "deleteMany" in snip(Remedy.FIX_FILTER, "x", command="delete")


def test_negated_rewrite_precomputes_an_indexed_flag() -> None:
    s = snip(Remedy.REWRITE, "^S", category=C.NEGATED)
    assert '{ $regexMatch: { input: "$name", regex: /^S/ } }' in s
    assert f"{COLL}.find({{ name_matches: false }})" in s


def test_expr_rewrite_becomes_a_plain_predicate() -> None:
    assert f"{COLL}.find({{ name: /^som/ }})" in snip(Remedy.REWRITE, "^som", category=C.PREFIX)
    assert "name_lower: /^som/" in snip(
        Remedy.REWRITE, "^Som", category=C.CASE_INSENSITIVE, options="i"
    )


def test_slashes_are_escaped_and_odd_names_quoted() -> None:
    s = snip(Remedy.FIX_FILTER, "a/b", command="update", field="first-name")
    assert '"first-name": /a\\/b/' in s


def test_no_snippet_when_nothing_to_do_and_never_a_match_all_prefix() -> None:
    assert snip(Remedy.NONE, "^ok", category=C.PREFIX) == ""
    assert snip(Remedy.MONITOR, "x") == ""
    s = snip(Remedy.REVERSED_FIELD, "^.*[0-9]$", category=C.LEADING_WILDCARD)
    assert "/^/" not in s and "/^<prefix>/" in s
