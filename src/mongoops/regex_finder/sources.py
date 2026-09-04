"""Source adapters: each yields `SourceLine`s from somewhere slow-query log lines live.

* Atlas Performance Advisor        (`atlas_lines`)
* Ops Manager Performance Advisor  (`ops_manager_lines`)   - Enterprise Advanced
* mongod log file / stdin          (`file_lines`)           - EA without Ops Manager, exported logs
* live server ``getLog`` command   (`getlog_lines`)         - quick check, atlas-local testing

Adapters are the only place with I/O; everything downstream is pure.
"""

from __future__ import annotations

import gzip
import sys
from collections.abc import Callable, Iterable, Iterator
from pathlib import Path
from typing import Any

import httpx
from pymongo import MongoClient

from mongoops.common import atlas_api, ops_manager_api
from mongoops.common.mongolog import is_slow_query_line
from mongoops.common.perf_advisor import SlowQueryLog, SlowQueryWindow
from mongoops.regex_finder.analyze import SourceLine

ProgressFn = Callable[[str, int], None]
"""Callback ``(origin, line_count)`` invoked after each origin is fetched."""


def _no_progress(_origin: str, _count: int) -> None:
    return None


def atlas_lines(
    client: httpx.Client,
    group_id: str,
    processes: Iterable[atlas_api.AtlasProcess],
    window: SlowQueryWindow,
    progress: ProgressFn = _no_progress,
) -> Iterator[SourceLine]:
    for process in processes:
        logs = atlas_api.slow_query_logs(client, group_id, process.id, window)
        progress(process.id, len(logs))
        yield from _from_perf_advisor(logs, origin=process.user_alias or process.id)


def ops_manager_lines(
    client: httpx.Client,
    group_id: str,
    hosts: Iterable[ops_manager_api.OpsManagerHost],
    window: SlowQueryWindow,
    progress: ProgressFn = _no_progress,
) -> Iterator[SourceLine]:
    for host in hosts:
        logs = ops_manager_api.slow_query_logs(client, group_id, host.id, window)
        origin = f"{host.hostname}:{host.port}"
        progress(origin, len(logs))
        yield from _from_perf_advisor(logs, origin=origin)


def _from_perf_advisor(logs: Iterable[SlowQueryLog], *, origin: str) -> Iterator[SourceLine]:
    return (SourceLine(line=log.line, origin=origin, namespace_hint=log.namespace) for log in logs)


def file_lines(path: str) -> Iterator[SourceLine]:
    """Read a mongod log (plain or ``.gz``), or stdin when ``path == "-"``."""
    if path == "-":
        yield from _filtered(sys.stdin, origin="stdin")
        return
    p = Path(path)
    opener = gzip.open if p.suffix == ".gz" else open
    with opener(p, "rt", encoding="utf-8", errors="replace") as fh:
        yield from _filtered(fh, origin=p.name)


def _filtered(lines: Iterable[str], *, origin: str) -> Iterator[SourceLine]:
    return (SourceLine(line=line, origin=origin) for line in lines if is_slow_query_line(line))


def getlog_lines(uri: str) -> Iterator[SourceLine]:
    """Pull the in-memory ``getLog: "global"`` ring buffer (last ~1024 lines) from one server.

    Requires the ``clusterMonitor`` role (or ``hostManager``). On a replica-set URI this hits the
    primary only; pass ``directConnection=true`` to target a specific node.
    """
    # One-shot CLI: a single thread issues a single admin command, so a pool of one connection is
    # enough and short timeouts make failures visible immediately instead of hanging the operator.
    client: MongoClient[dict[str, Any]] = MongoClient(
        uri,
        appname="mongoops-regex-finder",
        maxPoolSize=1,
        serverSelectionTimeoutMS=5_000,
        connectTimeoutMS=5_000,
        socketTimeoutMS=30_000,
    )
    with client:
        result = client.admin.command("getLog", "global")
        origin = f"{client.address[0]}:{client.address[1]}" if client.address else uri
        yield from _filtered(result.get("log", []), origin=origin)
