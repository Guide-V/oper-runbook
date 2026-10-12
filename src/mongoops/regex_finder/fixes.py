"""Copy-paste ``mongosh`` snippets for each remedy, so the action plan is something to run.

Snippets are starting points written for the shape that was seen in the log (namespace, field,
command, sample pattern); they still need a review and an ``explain()`` before production.
Documents are built as Python data and printed as mongosh literals by ``_lit``. Pure.
"""

from __future__ import annotations

import json
import re
from typing import Any

from mongoops.regex_finder.detector import RegexCategory
from mongoops.regex_finder.remedy import Remedy, SearchOperator, literal_body, search_operator

_COLLATION: dict[str, Any] = {"locale": "en", "strength": 2}
_WRITE_COMMANDS = frozenset({"update", "findAndModify", "findandmodify"})
_DELETE_COMMANDS = frozenset({"delete", "remove"})
_REGEX_META = re.compile(r"([.*+?()\[\]{}|\\^$/])")
_UNESCAPED_SLASH = re.compile(r"(?<!\\)/")
_INDEX_NAME_UNSAFE = re.compile(r"[^A-Za-z0-9_-]+")
_BARE_KEY = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*$")
_SYNC_NOTE = "keep it in sync on every write (large collection: batch it, off-peak)"


class Raw(str):
    """Printed verbatim: regex literals and ``<placeholders>``."""

    __slots__ = ()


def split_namespace(namespace: str) -> tuple[str, str]:
    """``"shop.orders.v2"`` -> ``("shop", "orders.v2")``: database names cannot contain dots."""
    db, _, coll = namespace.partition(".")
    return db or "?", coll or "?"


def fix_snippet(
    *,
    remedy: Remedy,
    namespace: str,
    field: str,
    command: str,
    category: RegexCategory,
    pattern: str,
    options: str,
) -> str:
    """The commands that apply ``remedy`` to this shape ("" when there is nothing to run)."""
    db, coll = split_namespace(namespace)
    c = f"db.getSiblingDB({_lit(db)}).getCollection({_lit(coll)})"
    regex = Raw(_regex(pattern, options))
    literal = literal_body(pattern)
    before = _lit({field: regex})

    if remedy is Remedy.BTREE_INDEX:
        return _lines(
            "// the prefix regex is index-friendly once the field is indexed",
            f"{c}.createIndex({_lit({field: 1})})",
        )
    if remedy is Remedy.COLLATION_INDEX:
        return _lines(
            f"{c}.createIndex({_lit({field: 1})}, {_lit({'collation': _COLLATION})})",
            f"// replace {before} with an equality under the same collation",
            _query(c, command, {field: literal}, collation=True),
        )
    if remedy is Remedy.NORMALIZED_FIELD:
        return _lower_copy(c, command, field, literal, before)
    if remedy is Remedy.REVERSED_FIELD:
        return _derived_field(
            c,
            command,
            before=before,
            field=f"{field}_rev",
            expression=_reverse_expression(field),
            note="add a reversed copy",
            match=_prefix_regex(literal[::-1]),
        )
    if remedy is Remedy.SEARCH:
        return _search(c, coll, command, field, category, pattern, options, before)
    if remedy is Remedy.FIX_FILTER:
        return _lines(
            f"// before (scans every key): {before}",
            "// after: lead with an equality or case-sensitive prefix on an indexed field",
            _query(c, command, {"<indexed field>": Raw("<value>"), field: regex}),
        )
    if remedy is Remedy.REWRITE:
        return _rewrite(c, command, field, category, options, regex, literal)
    return ""


# --- per-remedy builders -----------------------------------------------------------------------


def _derived_field(
    c: str,
    command: str,
    *,
    before: str,
    field: str,
    expression: dict[str, Any],
    note: str,
    match: Any,
) -> str:
    return _lines(
        f"// 1. {note}; {_SYNC_NOTE}",
        f"{c}.updateMany({{}}, {_lit([{'$set': {field: expression}}])})",
        f"{c}.createIndex({_lit({field: 1})})",
        f"// 2. replace {before} with",
        _query(c, command, {field: match}),
    )


def _lower_copy(c: str, command: str, field: str, literal: str, before: str) -> str:
    return _derived_field(
        c,
        command,
        before=before,
        field=f"{field}_lower",
        expression={"$toLower": f"${field}"},
        note="add a lower-cased copy ($toLower is exact for ASCII)",
        match=_prefix_regex(literal.lower()),
    )


def _reverse_expression(field: str) -> dict[str, Any]:
    """Aggregation expression that reverses a string field code point by code point."""
    return {
        "$reduce": {
            "input": {"$range": [0, {"$strLenCP": f"${field}"}]},
            "initialValue": "",
            "in": {"$concat": [{"$substrCP": [f"${field}", "$$this", 1]}, "$$value"]},
        }
    }


def _search(
    c: str,
    coll: str,
    command: str,
    field: str,
    category: RegexCategory,
    pattern: str,
    options: str,
    before: str,
) -> str:
    literal = literal_body(pattern)
    index = _INDEX_NAME_UNSAFE.sub("_", f"{coll}_{field}_search")
    kind = search_operator(category, options, literal)
    analyzer = "lucene.keyword" if kind in ("wildcard", "regex") else "lucene.standard"
    operator, notes = _search_operator(kind, field, pattern, literal)
    first_stage = (
        "// $search must be the first stage of the pipeline"
        if command == "aggregate"
        else "// find() becomes an aggregation"
    )
    return _lines(
        "// needs Atlas M10+ or Enterprise Advanced with mongot; results are eventually consistent",
        f"{c}.createSearchIndex({_lit(index)}, {_lit(_search_mapping(field, analyzer))})",
        f"// replace {before} with",
        first_stage,
        *notes,
        f"{c}.aggregate({_lit([{'$search': {'index': index, **operator}}])})",
    )


def _search_operator(
    kind: SearchOperator, field: str, pattern: str, literal: str
) -> tuple[dict[str, Any], tuple[str, ...]]:
    if kind == "wildcard":
        query = f"*{literal}" if pattern.endswith("$") else f"*{literal}*"
        return {"wildcard": {"query": query, "path": field, "allowAnalyzedField": True}}, ()
    if kind == "regex":
        spec = {"query": _lucene_regex(pattern), "path": field, "allowAnalyzedField": True}
        return {"regex": spec}, (
            "// Lucene regex matches the whole value and differs from PCRE: review the pattern",
        )
    notes = ("// Search matches words, not substrings: compare results before switching",)
    return {kind: {"query": literal, "path": field}}, notes


def _search_mapping(field: str, analyzer: str) -> dict[str, Any]:
    """Static mapping for one (possibly dotted) field."""
    *parents, name = field.split(".")
    node: dict[str, Any] = {name: {"type": "string", "analyzer": analyzer}}
    for parent in reversed(parents):
        node = {parent: {"type": "document", "fields": node}}
    return {"mappings": {"dynamic": False, "fields": node}}


def _lucene_regex(pattern: str) -> str:
    """PCRE-ish pattern -> Lucene's whole-value form: drop anchors, pad unanchored ends."""
    anchored_end = pattern.endswith("$") and not pattern.endswith("\\$")
    body = pattern.removeprefix("^")
    body = body[:-1] if anchored_end else body
    return f"{'' if pattern.startswith('^') else '.*'}{body}{'' if anchored_end else '.*'}"


def _rewrite(
    c: str,
    command: str,
    field: str,
    category: RegexCategory,
    options: str,
    regex: Raw,
    literal: str,
) -> str:
    if category is RegexCategory.NEGATED:
        flag = f"{field}_matches"
        return _lines(
            "// 1. precompute the match once per write and index the flag",
            f"{c}.updateMany({{}}, "
            f"{_lit([{'$set': {flag: {'$regexMatch': {'input': f'${field}', 'regex': regex}}}}])})",
            f"{c}.createIndex({_lit({flag: 1})})",
            f"// 2. replace {_lit({field: {'$not': regex}})} with",
            _query(c, command, {flag: False}),
        )
    before = _lit({"$expr": {"$regexMatch": {"input": f"${field}", "regex": regex}}})
    if "i" in options:
        return _lower_copy(c, command, field, literal, before)
    return _lines(
        f"// replace {before} with a plain predicate the planner can bound",
        _query(c, command, {field: _prefix_regex(literal)}),
    )


# --- small helpers -----------------------------------------------------------------------------


def _query(c: str, command: str, filt: dict[str, Any], *, collation: bool = False) -> str:
    opts = f", {_lit({'collation': _COLLATION})}" if collation else ""
    if command == "aggregate":
        return f"{c}.aggregate({_lit([{'$match': filt}])}{opts})"
    if command in _WRITE_COMMANDS:
        return f"{c}.updateMany({_lit(filt)}, <your update>{opts})"
    if command in _DELETE_COMMANDS:
        return f"{c}.deleteMany({_lit(filt)}{opts})"
    return f"{c}.find({_lit(filt)})" + (f".collation({_lit(_COLLATION)})" if collation else "")


def _lit(value: Any) -> str:
    """A mongosh literal: bare keys where JavaScript allows them, ``Raw`` printed verbatim."""
    if isinstance(value, Raw):
        return str(value)
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return str(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, dict):
        items = ", ".join(f"{_key(k)}: {_lit(v)}" for k, v in value.items())
        return f"{{ {items} }}" if items else "{}"
    if isinstance(value, list | tuple):
        return f"[{', '.join(_lit(v) for v in value)}]"
    raise TypeError(f"cannot print {type(value).__name__} as a mongosh literal")


def _key(key: str) -> str:
    return key if _BARE_KEY.match(key) else json.dumps(key, ensure_ascii=False)


def _lines(*lines: str) -> str:
    return "\n".join(lines)


def _regex(pattern: str, options: str) -> str:
    body = _UNESCAPED_SLASH.sub(r"\\/", pattern)
    return f"/{body}/{options}"


def _prefix_regex(literal: str) -> Raw:
    """``/^literal/``; a placeholder when there is no literal, since ``/^/`` matches everything."""
    return Raw(f"/^{_escape(literal)}/" if literal else "/^<prefix>/")


def _escape(literal: str) -> str:
    return _REGEX_META.sub(r"\\\1", literal)
