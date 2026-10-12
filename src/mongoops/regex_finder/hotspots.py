"""Roll findings up to database -> collection, and say in one sentence where to start.

Answers "which database / collection hurts most?" before anyone reads a shape table. Totals are
per distinct operation (see ``summary.distinct_ops``) so an operation with several regexes is
counted once. Pure.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from typing import Any

from mongoops.common.timeutil import format_duration_ms
from mongoops.regex_finder.analyze import Finding
from mongoops.regex_finder.fixes import split_namespace
from mongoops.regex_finder.remedy import NO_ACTION, REMEDY_LABEL, Remedy
from mongoops.regex_finder.summary import SummaryRow, distinct_ops, share_pct, total_ms


@dataclass(frozen=True, slots=True)
class CollectionSpot:
    namespace: str
    database: str
    collection: str
    ops: int
    total_ms: int
    share_pct: float
    shapes: int
    to_fix: int
    """Shapes whose remedy is real work (not none / monitor)."""
    collscan_ops: int
    main_remedy: Remedy
    """Remedy of the costliest shape that needs work (``none`` if nothing does)."""

    def to_dict(self) -> dict[str, Any]:
        return {**asdict(self), "main_remedy": str(self.main_remedy)}


@dataclass(frozen=True, slots=True)
class DatabaseSpot:
    database: str
    ops: int
    total_ms: int
    share_pct: float
    shapes: int
    to_fix: int
    collections: tuple[CollectionSpot, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            **{k: v for k, v in asdict(self).items() if k != "collections"},
            "collections": [c.to_dict() for c in self.collections],
        }


def hotspots(
    findings: Sequence[Finding], summary: Sequence[SummaryRow]
) -> tuple[DatabaseSpot, ...]:
    """Databases (costliest first), each with its collections (costliest first)."""
    all_ops = distinct_ops(findings)
    totals = (total_ms(all_ops), len(all_ops))
    by_ns: dict[str, list[Finding]] = defaultdict(list)
    for f in all_ops:
        by_ns[f.namespace or "?"].append(f)
    rows_by_ns: dict[str, list[SummaryRow]] = defaultdict(list)
    for r in summary:
        rows_by_ns[r.namespace].append(r)

    collections = tuple(_collection(ns, ops, rows_by_ns[ns], totals) for ns, ops in by_ns.items())
    by_db: dict[str, list[CollectionSpot]] = defaultdict(list)
    for c in _costliest_first(collections):
        by_db[c.database].append(c)
    return _costliest_first(tuple(_database(db, colls, totals) for db, colls in by_db.items()))


def flat_collections(spots: Sequence[DatabaseSpot]) -> tuple[CollectionSpot, ...]:
    """Every collection across databases, costliest first."""
    return _costliest_first(tuple(c for d in spots for c in d.collections))


def headline(
    findings: Sequence[Finding], summary: Sequence[SummaryRow], spots: Sequence[DatabaseSpot]
) -> str:
    """One plain sentence (two at most): how much, where, and the first thing to do."""
    if not findings:
        return "No $regex usage found in the analysed slow queries."
    ops = distinct_ops(findings)
    colls = flat_collections(spots)
    top = colls[0]
    where = (
        f"All of it is in {top.namespace}."
        if len(colls) == 1
        else f"{top.namespace} accounts for {top.share_pct:.0f}% of it."
    )
    head = (
        f"{len(ops)} slow operation(s) used $regex, {format_duration_ms(total_ms(ops))} in total "
        f"across {len(colls)} collection(s). {where}"
    )
    win = next((r for r in summary if r.remedy not in NO_ACTION), None)
    if win is None:
        return f"{head} Nothing to fix: every shape is index-friendly or too small to matter yet."
    return (
        f"{head} Biggest win: {REMEDY_LABEL[win.remedy]} for {win.field} on {win.namespace} "
        f"({win.share_pct:.0f}% of regex time)."
    )


# --- helpers -----------------------------------------------------------------------------------


def _collection(
    namespace: str, ops: list[Finding], rows: list[SummaryRow], totals: tuple[int, int]
) -> CollectionSpot:
    database, collection = split_namespace(namespace)
    spent = sum(f.duration_ms or 0 for f in ops)
    work = tuple(r for r in rows if r.remedy not in NO_ACTION)
    return CollectionSpot(
        namespace=namespace,
        database=database,
        collection=collection,
        ops=len(ops),
        total_ms=spent,
        share_pct=share_pct(spent, len(ops), *totals),
        shapes=len(rows),
        to_fix=len(work),
        collscan_ops=sum(1 for f in ops if "COLLSCAN" in (f.plan_summary or "")),
        main_remedy=work[0].remedy if work else Remedy.NONE,
    )


def _database(database: str, colls: list[CollectionSpot], totals: tuple[int, int]) -> DatabaseSpot:
    spent, ops = sum(c.total_ms for c in colls), sum(c.ops for c in colls)
    return DatabaseSpot(
        database=database,
        ops=ops,
        total_ms=spent,
        share_pct=share_pct(spent, ops, *totals),
        shapes=sum(c.shapes for c in colls),
        to_fix=sum(c.to_fix for c in colls),
        collections=tuple(colls),
    )


def _costliest_first[T: (CollectionSpot, DatabaseSpot)](items: tuple[T, ...]) -> tuple[T, ...]:
    return tuple(sorted(items, key=lambda s: (-s.total_ms, -s.ops, _name(s))))


def _name(spot: CollectionSpot | DatabaseSpot) -> str:
    return spot.namespace if isinstance(spot, CollectionSpot) else spot.database
