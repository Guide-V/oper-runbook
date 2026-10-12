"""Synthetic slow-query lines shaped like the live ``cluster-free`` probe (300k-document scans).

The atlas-local fixture is too small to rank anything (every op is 0-8 ms), so ranking, roll-up
and headline tests use this workload instead. Two databases; one ``$or`` with two regexes per
operation, so per-operation totals can be told apart from per-usage counts.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

from mongoops.regex_finder.analyze import AnalyzeOptions, Finding, SourceLine, analyze_lines

START = datetime(2026, 10, 7, 7, 0, tzinfo=UTC)


def slow_line(
    minute: int,
    ns: str,
    filt: dict[str, Any],
    *,
    ms: int,
    plan: str,
    keys: int,
    docs: int,
    ret: int,
    app: str = "orders-api",
) -> str:
    db, coll = ns.split(".", 1)
    ts = (START + timedelta(minutes=minute)).isoformat(timespec="milliseconds")
    return json.dumps(
        {
            "t": {"$date": ts},
            "msg": "Slow query",
            "attr": {
                "type": "command",
                "ns": ns,
                "appName": app,
                "command": {"find": coll, "filter": filt, "$db": db},
                "planSummary": plan,
                "keysExamined": keys,
                "docsExamined": docs,
                "nreturned": ret,
                "durationMillis": ms,
            },
        }
    )


def _rx(pattern: str, options: str = "") -> dict[str, Any]:
    return {"$regularExpression": {"pattern": pattern, "options": options}}


def workload_lines() -> tuple[str, ...]:
    note = tuple(
        slow_line(
            i,
            "aisops.customers",
            {"note": _rx("record 12345$")},
            ms=905,
            plan="COLLSCAN",
            keys=0,
            docs=300_000,
            ret=1,
        )
        for i in range(6)
    )
    names = tuple(
        slow_line(
            10 + i,
            "aisops.customers",
            {"$or": [{"name": _rx("Rakdee 1234")}, {"name": _rx("Meesuk 5678")}]},
            ms=289,
            plan="IXSCAN { name: 1 }",
            keys=300_000,
            docs=22,
            ret=22,
        )
        for i in range(6)
    )
    prefix_i = tuple(
        slow_line(
            20 + i,
            "aisops.customers",
            {"name": _rx("^som", "i")},
            ms=144,
            plan="IXSCAN { name: 1 }",
            keys=187_505,
            docs=5,
            ret=5,
            app="crm-ui",
        )
        for i in range(6)
    )
    invoices = tuple(
        slow_line(
            30 + i,
            "billing.invoices",
            {"ref": _rx("^INV-2026")},
            ms=50,
            plan="COLLSCAN",
            keys=0,
            docs=2_000,
            ret=10,
            app="billing-batch",
        )
        for i in range(2)
    )
    memo = (
        slow_line(
            40,
            "billing.invoices",
            {"memo": _rx("late")},
            ms=2,
            plan="IXSCAN { memo: 1 }",
            keys=10,
            docs=1,
            ret=1,
            app="billing-batch",
        ),
    )
    return note + names + prefix_i + invoices + memo


def workload_findings() -> tuple[Finding, ...]:
    return tuple(
        analyze_lines(
            (SourceLine(line=ln, origin="node-0") for ln in workload_lines()), AnalyzeOptions()
        )
    )
