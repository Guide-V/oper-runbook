"""Pure functions that locate regular-expression usage inside a MongoDB command document.

Shapes recognised (all as they appear in mongod JSON logs, i.e. relaxed extended JSON):

* ``{field: {"$regex": "pat", "$options": "i"}}``            - explicit operator
* ``{field: {"$regularExpression": {"pattern", "options"}}}`` - BSON regex literal (``/pat/i``)
* ``{field: {"$in": [<regex literal>, ...]}}`` / ``{"$not": <regex literal>}`` / ``$nin`` / ``$all``
* ``{"$regexMatch" | "$regexFind" | "$regexFindAll": {"input", "regex", "options"}}`` - aggregation
  expressions, e.g. inside ``$expr`` or ``$project``.

Each hit is classified for index-friendliness following the MongoDB docs on ``$regex`` index use:
a case-sensitive *prefix expression* (``^literal``) can be turned into an index range scan; any
other regex has to be evaluated against every key in the index (or every document); a
case-insensitive regex cannot use a regular index efficiently at all.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

REGEX_EXPRESSION_OPERATORS: frozenset[str] = frozenset(
    {"$regexMatch", "$regexFind", "$regexFindAll"}
)
_REGEX_META = frozenset(".^$*+?()[]{}|\\")
_INLINE_CASE_INSENSITIVE = re.compile(r"^\(\?[a-z]*i[a-z]*\)")


class RegexCategory(StrEnum):
    """Index-friendliness of a regex, most to least efficient."""

    PREFIX = "prefix"
    """``^literal...`` and case-sensitive: index range scan possible."""
    ANCHORED = "anchored"
    """Starts with ``^`` but the first token is a meta character: full index scan."""
    UNANCHORED = "unanchored"
    """No leading ``^``: full index scan or collection scan."""
    LEADING_WILDCARD = "leading_wildcard"
    """``^.*`` or ``.*...``: anti-pattern; anchor is useless."""
    CASE_INSENSITIVE = "case_insensitive"
    """``i`` option (or ``(?i)``): cannot use a regular index efficiently regardless of shape."""
    NEGATED = "negated"
    """Under ``$not`` / ``$nin``: no index bounds can be derived, every key or doc is checked."""


_NEGATING_OPERATORS: frozenset[str] = frozenset({"$not", "$nin"})


@dataclass(frozen=True, slots=True)
class RegexUsage:
    field: str
    """Document field the regex applies to (``$``-stripped expression input for ``$regexMatch``)."""
    path: str
    """Dotted location inside the command, e.g. ``filter.name.$regex``."""
    pattern: str
    options: str
    operator: str
    """``$regex`` | ``$regularExpression`` | ``$regexMatch`` | ``$regexFind`` | ``$regexFindAll``
    | ``legacy-literal`` | ``legacy-$regex``."""
    category: RegexCategory


def classify(pattern: str, options: str, *, negated: bool = False) -> RegexCategory:
    """Classify a regex for index-friendliness. Pure."""
    if negated:
        return RegexCategory.NEGATED
    if "i" in options or _INLINE_CASE_INSENSITIVE.match(pattern):
        return RegexCategory.CASE_INSENSITIVE
    if pattern.startswith(".*") or pattern.startswith("^.*"):
        return RegexCategory.LEADING_WILDCARD
    if not pattern.startswith("^"):
        return RegexCategory.UNANCHORED
    return RegexCategory.PREFIX if literal_prefix(pattern) else RegexCategory.ANCHORED


def literal_prefix(pattern: str) -> str:
    """Return the literal characters following ``^`` up to the first meta character ("" if none)."""
    if not pattern.startswith("^"):
        return ""
    body = pattern[1:]
    end = next((i for i, ch in enumerate(body) if ch in _REGEX_META), len(body))
    return body[:end]


@dataclass(frozen=True, slots=True)
class _Ctx:
    """Immutable walk context; a new instance is derived at each level."""

    path: str = ""
    field: str = ""
    negated: bool = False

    def child(self, key: str) -> _Ctx:
        return _Ctx(
            path=f"{self.path}.{key}" if self.path else key,
            field=self.field if key.startswith("$") else key,
            negated=self.negated or key in _NEGATING_OPERATORS,
        )

    def index(self, i: int) -> _Ctx:
        return _Ctx(path=f"{self.path}[{i}]", field=self.field, negated=self.negated)


def find_regex_usages(doc: Any) -> tuple[RegexUsage, ...]:
    """Walk a parsed command document and return every regex usage found (deterministic order)."""
    return tuple(_walk(doc, _Ctx()))


def _walk(node: Any, ctx: _Ctx) -> Iterator[RegexUsage]:
    if isinstance(node, Mapping):
        yield from _walk_mapping(node, ctx)
    elif isinstance(node, Sequence) and not isinstance(node, str | bytes):
        for i, item in enumerate(node):
            yield from _walk(item, ctx.index(i))


def _walk_mapping(node: Mapping[str, Any], ctx: _Ctx) -> Iterator[RegexUsage]:
    literal = _as_regex_literal(node)
    if literal is not None:
        pattern, options = literal
        yield _usage(ctx, ctx.path, pattern, options, "$regularExpression")
        return

    for key, value in node.items():
        child = ctx.child(key)
        if key == "$options":
            continue  # consumed together with $regex
        if key == "$regex":
            pattern, literal_opts = _pattern_and_options(value)
            options = _str(node.get("$options")) or literal_opts
            yield _usage(ctx, child.path, pattern, options, "$regex")
            continue
        if key in REGEX_EXPRESSION_OPERATORS and isinstance(value, Mapping):
            yield from _walk_regex_expression(key, value, child)
            continue
        yield from _walk(value, child)


def _walk_regex_expression(
    operator: str, spec: Mapping[str, Any], ctx: _Ctx
) -> Iterator[RegexUsage]:
    pattern, literal_opts = _pattern_and_options(spec.get("regex"))
    options = _str(spec.get("options")) or literal_opts
    input_expr = spec.get("input")
    target = (
        input_expr[1:] if isinstance(input_expr, str) and input_expr.startswith("$") else ctx.field
    )
    # Expression operators evaluate per document; index bounds never apply, so negation is moot.
    yield _usage(
        _Ctx(ctx.path, target or "<expr>", False), f"{ctx.path}.regex", pattern, options, operator
    )
    # ``input`` may itself be an expression containing regexes; ``regex``/``options`` are consumed.
    yield from _walk(input_expr, ctx.child("input"))


def _as_regex_literal(node: Mapping[str, Any]) -> tuple[str, str] | None:
    inner = node.get("$regularExpression")
    if len(node) == 1 and isinstance(inner, Mapping):
        return _str(inner.get("pattern")), _str(inner.get("options"))
    return None


def _pattern_and_options(value: Any) -> tuple[str, str]:
    """Normalise a ``$regex`` / ``regex`` operand (string or literal) to (pattern, options)."""
    if isinstance(value, Mapping):
        literal = _as_regex_literal(value)
        if literal is not None:
            return literal
    return _str(value), ""


def _str(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _usage(ctx: _Ctx, path: str, pattern: str, options: str, operator: str) -> RegexUsage:
    return RegexUsage(
        field=ctx.field or "<unknown>",
        path=path,
        pattern=pattern,
        options=options,
        operator=operator,
        category=classify(pattern, options, negated=ctx.negated),
    )


# --- Legacy (pre-4.4) text log support --------------------------------------------------------

# A regex literal in value position: after ``:`` ``[`` or ``,`` and before ``,`` ``}`` or ``]``.
_LEGACY_LITERAL = re.compile(
    r"(?<=[:\[,])\s*/(?P<pat>(?:\\.|[^/])*)/(?P<opts>[imxs]*)(?=\s*[,}\]])"
)
_LEGACY_REGEX_STRING = re.compile(r'\$regex:\s*"(?P<pat>(?:\\.|[^"])*)"')
_LEGACY_OPTIONS = re.compile(r'\$options:\s*"(?P<opts>[^"]*)"')
_KEY_BEFORE = re.compile(r"([\w.$]+):\s*$")


def find_regex_usages_legacy(command_text: str) -> tuple[RegexUsage, ...]:
    """Best-effort regex extraction from a legacy (non-JSON) command body.

    Covers ``field: /pat/opts`` literals (also inside ``$in`` / ``$not`` / ``$nin`` / ``$all``) and
    ``field: { $regex: "pat", $options: "i" }``. The owning field is resolved by walking outwards
    to the nearest non-``$`` key. Strings containing braces may confuse this; it is a fallback for
    MongoDB <= 4.2 only.
    """
    literal_hits = tuple(
        _legacy_literal_usage(command_text, m) for m in _LEGACY_LITERAL.finditer(command_text)
    )
    string_hits = tuple(
        _legacy_usage(
            command_text,
            m.start(),
            m.group("pat"),
            _sibling_options(command_text, m.start()),
            "legacy-$regex",
        )
        for m in _LEGACY_REGEX_STRING.finditer(command_text)
    )
    return literal_hits + string_hits


def _legacy_literal_usage(text: str, m: re.Match[str]) -> RegexUsage:
    key = _key_before(text, m.start())
    if key == "$regex":
        options = m.group("opts") or _sibling_options(text, m.start())
        return _legacy_usage(text, m.start(), m.group("pat"), options, "legacy-$regex")
    return _legacy_usage(text, m.start(), m.group("pat"), m.group("opts"), "legacy-literal")


def _legacy_usage(text: str, pos: int, pattern: str, options: str, operator: str) -> RegexUsage:
    key = _key_before(text, pos)
    direct = key if key and not key.startswith("$") else None
    field = direct or _enclosing_field(text, pos)
    negated = any(k in _NEGATING_OPERATORS for k in _enclosing_operator_keys(text, pos))
    ctx = _Ctx(path=field, field=field, negated=negated)
    path = f"{field}.$regex" if operator == "legacy-$regex" else field
    return _usage(ctx, path, pattern, options, operator)


def _key_before(text: str, pos: int) -> str | None:
    m = _KEY_BEFORE.search(text[:pos])
    return m.group(1) if m else None


def _container_start(text: str, pos: int) -> int | None:
    """Index of the ``{`` or ``[`` opening the innermost container that contains ``pos``."""
    depth = 0
    for i in range(pos - 1, -1, -1):
        ch = text[i]
        if ch in "}]":
            depth += 1
        elif ch in "{[":
            if depth == 0:
                return i
            depth -= 1
    return None


def _container_end(text: str, start: int) -> int:
    depth = 0
    for i in range(start, len(text)):
        if text[i] in "{[":
            depth += 1
        elif text[i] in "}]":
            depth -= 1
            if depth == 0:
                return i + 1
    return len(text)


def _enclosing_keys(text: str, pos: int) -> Iterator[str]:
    """Keys owning each container around ``pos``, innermost first (also the key right before it)."""
    direct = _key_before(text, pos)
    if direct:
        yield direct
    start = _container_start(text, pos)
    while start is not None:
        key = _key_before(text, start)
        if key:
            yield key
        start = _container_start(text, start)


def _enclosing_field(text: str, pos: int) -> str:
    return next((k for k in _enclosing_keys(text, pos) if not k.startswith("$")), "<unknown>")


def _enclosing_operator_keys(text: str, pos: int) -> tuple[str, ...]:
    """``$``-keys between ``pos`` and its owning field: ``("$not",)`` for ``a: {$not: /x/}``."""
    keys: list[str] = []
    for k in _enclosing_keys(text, pos):
        if not k.startswith("$"):
            break
        keys.append(k)
    return tuple(keys)


def _sibling_options(text: str, pos: int) -> str:
    start = _container_start(text, pos)
    if start is None:
        return ""
    m = _LEGACY_OPTIONS.search(text, start, _container_end(text, start))
    return m.group("opts") if m else ""
