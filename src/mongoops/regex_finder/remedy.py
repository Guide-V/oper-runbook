"""Turn one regex finding into a concrete remedy.

The rules are deliberately conservative: the cheapest fix that works wins, MongoDB Search is
only recommended when the operation is on the read path *and* the log shows a real scan, and
write-path regexes are never sent to Search because ``$search`` is an aggregation-only stage.
Everything here is pure and depends only on values already in the slow-query line.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from mongoops.regex_finder.detector import RegexCategory


class Remedy(StrEnum):
    NONE = "none"  # index-friendly already
    BTREE_INDEX = "btree_index"  # prefix regex but no index on the field
    COLLATION_INDEX = "collation_index"  # case-insensitive prefix / exact -> collation
    REVERSED_FIELD = "reversed_field"  # suffix match on an identifier -> reversed copy
    SEARCH = "search"  # MongoDB Search (Atlas or self-managed mongot)
    FIX_FILTER = "fix_filter"  # write-path regex: Search not applicable
    REWRITE = "rewrite"  # negated regex: change the predicate / add a flag field
    MONITOR = "monitor"  # scan too small to justify anything yet


@dataclass(frozen=True, slots=True)
class Recommendation:
    remedy: Remedy
    how: str  # one concrete sentence an operator can act on


REMEDY_LABEL: dict[Remedy, str] = {
    Remedy.NONE: "No action",
    Remedy.BTREE_INDEX: "Add a regular index",
    Remedy.COLLATION_INDEX: "Collation index",
    Remedy.REVERSED_FIELD: "Reversed field + prefix index",
    Remedy.SEARCH: "MongoDB Search",
    Remedy.FIX_FILTER: "Fix the write filter",
    Remedy.REWRITE: "Rewrite the predicate",
    Remedy.MONITOR: "Monitor",
}

# Roughly "cheaper first"; used for ordering in reports.
REMEDY_ORDER: dict[Remedy, int] = {
    Remedy.NONE: 0,
    Remedy.MONITOR: 1,
    Remedy.BTREE_INDEX: 2,
    Remedy.COLLATION_INDEX: 3,
    Remedy.REVERSED_FIELD: 4,
    Remedy.REWRITE: 5,
    Remedy.FIX_FILTER: 6,
    Remedy.SEARCH: 7,
}

SEARCH_DEPLOYMENT_NOTE = (
    "MongoDB Search needs Atlas M10+ (optionally dedicated Search Nodes) or, self-managed, "
    "the paid Enterprise Advanced add-on on MongoDB 8.2+ with mongot deployed via the Kubernetes "
    "operator. It is eventually consistent, so keep validation and uniqueness checks on B-tree "
    "indexes."
)

# Commands whose filter runs on the write path (or cannot start with $search at all).
_WRITE_PATH = frozenset({"update", "delete", "remove", "findAndModify", "findandmodify", "insert"})

# Aggregation *expression* operators: evaluated per document, never index-bounded.
_EXPRESSION_OPS = frozenset({"$regexMatch", "$regexFind", "$regexFindAll"})

# Evidence that the regex really scans: either an outright large scan or a bad selectivity ratio.
_MIN_SCANNED = 1_000
_MIN_SCAN_RATIO = 100

_META = re.compile(r"[.*+?()\[\]{}|\\^$]")
_IDENTIFIER = re.compile(r"^[0-9A-Za-z_\-+]+$")


def recommend(
    *,
    category: RegexCategory,
    command: str | None,
    pattern: str,
    options: str,
    plan_summary: str | None,
    keys_examined: int | None,
    docs_examined: int | None,
    nreturned: int | None,
    operator: str = "$regex",
    path: str = "",
) -> Recommendation:
    """Pick the remedy for one regex usage. Pure."""
    field_hint = "<field>"
    write_path = (command or "") in _WRITE_PATH
    collscan = "COLLSCAN" in (plan_summary or "")
    scanned = max(keys_examined or 0, docs_examined or 0)
    heavy = _heavy_scan(scanned, nreturned, collscan)
    literal = literal_body(pattern)

    if operator in _EXPRESSION_OPS:
        if "$expr" not in path:
            return Recommendation(
                Remedy.NONE,
                f"{operator} here is a projection/expression evaluated on documents already "
                "selected by earlier stages; it has no index implication. The cost, if any, is "
                "in the preceding filter.",
            )
        if _is_prefix_shape(pattern) and literal and not write_path:
            return Recommendation(
                Remedy.REWRITE,
                f"{operator} inside $expr can never use an index. Move it to a plain predicate "
                f"{{ {field_hint}: /^{literal}/{options} }}"
                + (" with a collation index" if "i" in options else "")
                + " so the prefix becomes an index range scan.",
            )
        # Unanchored inside $expr: same options as a plain unanchored regex (below), the
        # instruction to leave $expr is implied by every remedy.

    if category is RegexCategory.NEGATED:
        return Recommendation(
            Remedy.REWRITE,
            "A negated regex ($not/$nin) has no index bounds. Invert the predicate or precompute a "
            f"flag/enum field on {field_hint} and query that with equality.",
        )

    if category is RegexCategory.PREFIX:
        if collscan:
            return Recommendation(
                Remedy.BTREE_INDEX,
                f"The prefix regex is index-friendly but ran as COLLSCAN: create an index on "
                f"{field_hint} and it becomes a range scan.",
            )
        return Recommendation(Remedy.NONE, "Case-sensitive prefix regex range-scans the index.")

    if category is RegexCategory.CASE_INSENSITIVE and _is_prefix_shape(pattern) and literal:
        return Recommendation(
            Remedy.COLLATION_INDEX,
            "Case-insensitive prefix/exact match: create a collation index "
            f'({{ {field_hint}: 1 }}, {{ collation: {{ locale: "en", strength: 2 }} }}) and query '
            f'with the same collation using a case-sensitive prefix (^{literal}) instead of "i".',
        )

    if _is_suffix_shape(pattern) and literal and _looks_like_identifier(literal):
        return Recommendation(
            Remedy.REVERSED_FIELD,
            f"Suffix match on an identifier: store a reversed copy ({field_hint}_rev), index it, "
            f"and query {{ {field_hint}_rev: /^{literal[::-1]}/ }} which range-scans the index.",
        )

    if write_path:
        return Recommendation(
            Remedy.FIX_FILTER,
            f"$search cannot be used in a {command} filter. Narrow the filter with an equality or "
            "case-sensitive prefix on an indexed field, or run $search first to collect _ids and "
            f"then {command} by _id.",
        )

    if heavy:
        return Recommendation(Remedy.SEARCH, _search_how(category, options, literal, field_hint))

    return Recommendation(
        Remedy.MONITOR,
        f"The regex scans ({scanned} keys/docs for {nreturned or 0} returned) but the collection "
        "is small; no action now, recheck as it grows (Search or a reversed field are the "
        "eventual fixes).",
    )


def with_field(rec: Recommendation, field: str) -> Recommendation:
    """Substitute the real field name into the instruction."""
    return Recommendation(rec.remedy, rec.how.replace("<field>", field or "<field>"))


# --- pattern shape helpers (pure) --------------------------------------------------------------


def literal_body(pattern: str) -> str:
    """The literal text of a pattern once anchors / catch-all wildcards are stripped.

    Returns "" when what remains still contains regex metacharacters (so it is not a literal).
    Escaped dots (``\\.``) are accepted and unescaped, since they are common in e-mail/domain
    patterns and still denote a literal.
    """
    body = re.sub(r"^\^?(\.\*)?", "", pattern)
    body = re.sub(r"(\.\*)?\$?$", "", body)
    body = body.replace(r"\.", "\x00")
    if _META.search(body):
        return ""
    return body.replace("\x00", ".")


def _is_prefix_shape(pattern: str) -> bool:
    return pattern.startswith("^") and not pattern.startswith("^.*")


def _is_suffix_shape(pattern: str) -> bool:
    return (
        pattern.endswith("$")
        and not pattern.endswith(".*$")
        and (pattern.startswith("^.*") or not pattern.startswith("^"))
    )


def _looks_like_identifier(literal: str) -> bool:
    """Digit-heavy token without spaces: MSISDN, account or order numbers, hex ids."""
    if len(literal) < 3 or not _IDENTIFIER.match(literal):
        return False
    digits = sum(ch.isdigit() for ch in literal)
    return digits * 2 >= len(literal)


def _heavy_scan(scanned: int, nreturned: int | None, collscan: bool) -> bool:
    if scanned >= _MIN_SCANNED:
        return True
    ratio = scanned / max(nreturned or 0, 1)
    return collscan and ratio >= _MIN_SCAN_RATIO


def _search_how(category: RegexCategory, options: str, literal: str, field: str) -> str:
    if category is RegexCategory.LEADING_WILDCARD or not literal:
        operator = (
            "the wildcard/regex operator over a keyword-analyzed field "
            "(or autocomplete with an nGram tokenizer for type-ahead)"
        )
    elif "i" in options or " " in literal:
        operator = (
            "the text operator with the standard analyzer (case-insensitive word matching), "
            "or autocomplete for type-ahead"
        )
    else:
        operator = "the text or phrase operator (standard analyzer), or autocomplete for type-ahead"
    return (
        f"Unanchored matching on free text scans every key. Create a MongoDB Search index on "
        f"{field} and query it with $search as the first aggregation stage using {operator}."
    )
