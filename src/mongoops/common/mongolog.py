"""Parse mongod slow-query log lines into an immutable `SlowQuery` record.

Two on-disk formats are supported:

* **JSON (MongoDB >= 4.4)** - one JSON object per line, ``msg == "Slow query"``. This is what
  Atlas / Ops Manager Performance Advisor return in ``slowQueries[].line`` and what ``getLog``
  returns for modern servers.
* **Legacy text (MongoDB <= 4.2)** - ``<ts> I COMMAND [connN] command db.coll ... command: {...}
  planSummary: COLLSCAN keysExamined:0 ... 123ms``. The command body is not JSON, so only the
  raw text is kept; regex detection on it is best effort (see ``regex_finder.detector``).

All functions are pure; nothing here performs I/O.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal

LogFormat = Literal["json", "legacy"]

_LEGACY_LINE = re.compile(
    r"^(?P<ts>\S+)\s+(?P<sev>[IWEF])\s+(?P<comp>[A-Z]+)\s+\[(?P<ctx>[^\]]+)\]\s+"
    r"(?P<op>command|query|update|remove|getmore|insert)\s+(?P<ns>\S+)\s+(?P<rest>.*?)\s+(?P<ms>\d+)ms$"
)
_LEGACY_INT = {
    "keysExamined": re.compile(r"\bkeysExamined:(\d+)"),
    "docsExamined": re.compile(r"\bdocsExamined:(\d+)"),
    "nreturned": re.compile(r"\bnreturned:(\d+)"),
}
# e.g. ``COLLSCAN`` or ``IXSCAN { a: 1 }, IXSCAN { b: 1 }``
_LEGACY_PLAN = re.compile(
    r"\bplanSummary:\s*(?P<plan>[A-Z_]+(?:\s*\{[^}]*\})?(?:,\s*[A-Z_]+(?:\s*\{[^}]*\})?)*)"
)
_LEGACY_APP = re.compile(r'\bappName:\s*"([^"]*)"')
_LEGACY_QUERY_HASH = re.compile(r"\bqueryHash:([0-9A-Fa-f]+)")


@dataclass(frozen=True, slots=True)
class SlowQuery:
    """One slow operation as recorded by mongod."""

    raw: str
    log_format: LogFormat
    timestamp: str | None
    namespace: str | None
    op_type: str | None
    """``attr.type``: ``command`` | ``update`` | ``remove`` | ``query`` | ``getmore`` | ..."""
    command_name: str | None
    """Top-level command (``find``, ``aggregate``, ``getMore``, ``update`` ...)."""
    command: Mapping[str, Any] | None
    """Parsed ``attr.command`` (JSON format only)."""
    originating_command: Mapping[str, Any] | None
    """``attr.originatingCommand`` for getMore lines (JSON format only)."""
    command_text: str | None
    """Unparsed command body for legacy lines."""
    app_name: str | None
    plan_summary: str | None
    duration_ms: int | None
    keys_examined: int | None
    docs_examined: int | None
    nreturned: int | None
    query_hash: str | None
    truncated: bool


def parse_log_line(line: str) -> SlowQuery | None:
    """Return a `SlowQuery` if ``line`` is a slow-query log line, else ``None``."""
    stripped = line.strip()
    if not stripped:
        return None
    if stripped.startswith("{"):
        return _parse_json(stripped)
    return _parse_legacy(stripped)


def is_slow_query_line(line: str) -> bool:
    """Cheap pre-filter so callers can skip obviously irrelevant lines before JSON parsing."""
    return '"Slow query"' in line or _LEGACY_LINE.match(line.strip()) is not None


# --- JSON format ---------------------------------------------------------------------------


def _parse_json(line: str) -> SlowQuery | None:
    try:
        doc = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(doc, dict) or doc.get("msg") != "Slow query":
        return None
    attr = doc.get("attr") or {}
    if not isinstance(attr, dict):
        return None

    command = attr.get("command") if isinstance(attr.get("command"), dict) else None
    originating = (
        attr.get("originatingCommand") if isinstance(attr.get("originatingCommand"), dict) else None
    )
    op_type = attr.get("type")
    return SlowQuery(
        raw=line,
        log_format="json",
        timestamp=_json_timestamp(doc.get("t")),
        namespace=_resolve_namespace(attr.get("ns"), command),
        op_type=op_type,
        command_name=_command_name(op_type, command),
        command=command,
        originating_command=originating,
        command_text=None,
        app_name=attr.get("appName"),
        plan_summary=attr.get("planSummary"),
        duration_ms=_as_int(attr.get("durationMillis")),
        keys_examined=_as_int(attr.get("keysExamined")),
        docs_examined=_as_int(attr.get("docsExamined")),
        nreturned=_as_int(attr.get("nreturned")),
        query_hash=attr.get("queryShapeHash") or attr.get("queryHash"),
        truncated="truncated" in attr,
    )


def _resolve_namespace(ns: Any, command: Mapping[str, Any] | None) -> str | None:
    """Batched writes are logged against ``db.$cmd``; recover ``db.<collection>`` from the command.

    The first key of a command names it and its value is normally the collection
    (``{"update": "customers", ...}``).
    """
    if not isinstance(ns, str):
        return None
    if not ns.endswith(".$cmd") or not command:
        return ns
    collection = next(iter(command.values()), None)
    db = command.get("$db") if isinstance(command.get("$db"), str) else ns.rsplit(".", 1)[0]
    return f"{db}.{collection}" if isinstance(collection, str) else ns


def _json_timestamp(t: Any) -> str | None:
    if isinstance(t, dict):
        value = t.get("$date")
        return value if isinstance(value, str) else None
    return t if isinstance(t, str) else None


def _command_name(op_type: str | None, command: Mapping[str, Any] | None) -> str | None:
    """Derive the human-readable command name.

    For ``type: command`` the first key of the command document is the command name. For
    individual write ops (``type: update`` / ``remove``) mongod logs ``{q, u, ...}`` so the
    op type itself is the best name.
    """
    if op_type in {"update", "remove", "insert", "query", "getmore"}:
        return "getMore" if op_type == "getmore" else op_type
    if command:
        first = next(iter(command), None)
        return first if isinstance(first, str) else None
    return op_type


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, dict):  # {"$numberLong": "123"}
        inner = value.get("$numberLong") or value.get("$numberInt")
        return int(inner) if isinstance(inner, str) and inner.lstrip("-").isdigit() else None
    return None


# --- Legacy text format ---------------------------------------------------------------------


def _parse_legacy(line: str) -> SlowQuery | None:
    m = _LEGACY_LINE.match(line)
    if not m:
        return None
    rest = m.group("rest")
    op = m.group("op")
    command_word, command_text = _legacy_command_body(rest)
    plan = _LEGACY_PLAN.search(rest)
    app = _LEGACY_APP.search(rest)
    qh = _LEGACY_QUERY_HASH.search(rest)
    ints = {k: _legacy_int(rx, rest) for k, rx in _LEGACY_INT.items()}
    return SlowQuery(
        raw=line,
        log_format="legacy",
        timestamp=m.group("ts"),
        namespace=m.group("ns"),
        op_type=op,
        command_name=_legacy_command_name(op, command_word, command_text),
        command=None,
        originating_command=None,
        command_text=command_text,
        app_name=app.group(1) if app else None,
        plan_summary=plan.group("plan").strip() if plan else None,
        duration_ms=int(m.group("ms")),
        keys_examined=ints["keysExamined"],
        docs_examined=ints["docsExamined"],
        nreturned=ints["nreturned"],
        query_hash=qh.group(1) if qh else None,
        truncated=False,
    )


def _legacy_int(rx: re.Pattern[str], text: str) -> int | None:
    m = rx.search(text)
    return int(m.group(1)) if m else None


_LEGACY_BODY_START = re.compile(r"\b(?:command|query):\s*(?P<name>\w+)?\s*\{")


def _legacy_command_body(rest: str) -> tuple[str | None, str | None]:
    """Return ``(command word, balanced {...})`` after ``command:`` / ``query:``.

    4.2 writes ``command: find { find: "users", ... }`` for commands and ``command: { q: ... }``
    for individual writes, so the command word is optional.
    """
    m = _LEGACY_BODY_START.search(rest)
    if not m:
        return None, None
    return m.group("name"), _balanced_braces(rest, m.end() - 1)


def _balanced_braces(text: str, start: int) -> str | None:
    depth = 0
    in_string = False
    escape = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return None


def _legacy_command_name(op: str, command_word: str | None, command_text: str | None) -> str:
    if op != "command":
        return "getMore" if op == "getmore" else op
    if command_word:
        return command_word
    m = re.match(r"\{\s*(\w+)\s*:", command_text or "")
    return m.group(1) if m else op
