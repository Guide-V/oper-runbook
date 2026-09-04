from __future__ import annotations

import json

from mongoops.common.mongolog import is_slow_query_line, parse_log_line


def _json_line(attr: dict, ts: str = "2026-09-04T03:21:24.497+00:00") -> str:
    return json.dumps(
        {
            "t": {"$date": ts},
            "s": "I",
            "c": "COMMAND",
            "id": 51803,
            "ctx": "conn1",
            "msg": "Slow query",
            "attr": attr,
        }
    )


class TestJsonFormat:
    def test_find_command(self) -> None:
        line = _json_line(
            {
                "type": "command",
                "ns": "db.coll",
                "appName": "mongosh 2.5.6",
                "command": {"find": "coll", "filter": {"a": 1}, "$db": "db"},
                "planSummary": "IXSCAN { a: 1 }",
                "keysExamined": 3,
                "docsExamined": 1,
                "nreturned": 1,
                "queryShapeHash": "ABC",
                "durationMillis": 12,
            }
        )
        sq = parse_log_line(line)
        assert sq is not None
        assert sq.log_format == "json"
        assert sq.timestamp == "2026-09-04T03:21:24.497+00:00"
        assert (sq.namespace, sq.op_type, sq.command_name) == ("db.coll", "command", "find")
        assert (sq.plan_summary, sq.duration_ms) == ("IXSCAN { a: 1 }", 12)
        assert (sq.keys_examined, sq.docs_examined, sq.nreturned) == (3, 1, 1)
        assert sq.query_hash == "ABC"
        assert sq.app_name == "mongosh 2.5.6"
        assert sq.truncated is False

    def test_batched_write_namespace_resolved_from_command(self) -> None:
        line = _json_line(
            {
                "type": "command",
                "ns": "db.$cmd",
                "command": {"update": "customers", "updates": [], "$db": "db"},
            }
        )
        sq = parse_log_line(line)
        assert sq is not None
        assert (sq.namespace, sq.command_name) == ("db.customers", "update")

    def test_individual_write_uses_op_type_as_command_name(self) -> None:
        line = _json_line(
            {"type": "update", "ns": "db.c", "command": {"q": {}, "u": {}}, "durationMillis": 3}
        )
        sq = parse_log_line(line)
        assert sq is not None
        assert sq.command_name == "update"

    def test_getmore_keeps_originating_command(self) -> None:
        line = _json_line(
            {
                "type": "command",
                "ns": "db.c",
                "command": {"getMore": 1, "collection": "c"},
                "originatingCommand": {"find": "c", "filter": {"x": 1}},
            }
        )
        sq = parse_log_line(line)
        assert sq is not None
        assert sq.command_name == "getMore"
        assert sq.originating_command == {"find": "c", "filter": {"x": 1}}

    def test_legacy_query_hash_and_numberlong(self) -> None:
        line = _json_line(
            {
                "type": "command",
                "ns": "db.c",
                "command": {"find": "c"},
                "queryHash": "F1CEA260",
                "durationMillis": {"$numberLong": "42"},
            }
        )
        sq = parse_log_line(line)
        assert sq is not None
        assert (sq.query_hash, sq.duration_ms) == ("F1CEA260", 42)

    def test_truncated_flag(self) -> None:
        line = _json_line(
            {
                "type": "command",
                "ns": "db.c",
                "command": {"find": "c"},
                "truncated": {"command": {}},
            }
        )
        sq = parse_log_line(line)
        assert sq is not None and sq.truncated is True

    def test_non_slow_query_json_is_ignored(self) -> None:
        other = json.dumps({"t": {"$date": "x"}, "msg": "Connection accepted", "attr": {}})
        assert parse_log_line(other) is None
        assert parse_log_line("{not json") is None
        assert parse_log_line("") is None

    def test_real_atlas_local_lines_all_parse(self, atlas_local_lines: tuple[str, ...]) -> None:
        parsed = [parse_log_line(line) for line in atlas_local_lines]
        assert all(p is not None for p in parsed)
        assert all(p.namespace == "mongoops_test.customers" for p in parsed if p)
        names = {p.command_name for p in parsed if p}
        assert {
            "find",
            "aggregate",
            "update",
            "remove",
            "delete",
            "getMore",
            "createIndexes",
        } <= names


class TestLegacyFormat:
    def test_command_line(self, legacy_lines: tuple[str, ...]) -> None:
        sq = parse_log_line(legacy_lines[1])
        assert sq is not None
        assert sq.log_format == "legacy"
        assert (sq.namespace, sq.op_type, sq.command_name) == ("myDb.users", "command", "find")
        assert sq.duration_ms == 512
        assert sq.plan_summary == "IXSCAN { emails: 1 }"
        assert (sq.keys_examined, sq.docs_examined, sq.nreturned) == (5000, 3, 3)
        assert sq.app_name == "MongoDB Shell"
        assert sq.query_hash == "2B9F1E4C"
        assert sq.command_text is not None and sq.command_text.startswith('{ find: "users"')
        assert sq.command_text.endswith("}")

    def test_write_line(self, legacy_lines: tuple[str, ...]) -> None:
        sq = parse_log_line(legacy_lines[4])
        assert sq is not None
        assert (sq.op_type, sq.command_name, sq.duration_ms) == ("update", "update", 2201)
        assert sq.plan_summary == "COLLSCAN"
        assert (
            sq.command_text
            == "{ q: { email: /\\.net$/ }, u: { $set: { flagged: true } }, multi: true, upsert: false }"
        )

    def test_noise_lines_ignored(self, legacy_lines: tuple[str, ...]) -> None:
        assert parse_log_line(legacy_lines[0]) is None
        assert is_slow_query_line(legacy_lines[0]) is False
        assert is_slow_query_line(legacy_lines[1]) is True
