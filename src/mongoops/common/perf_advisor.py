"""Performance Advisor "slow query logs" access shared by Atlas and Ops Manager.

Both products expose the same resource shape::

    GET .../performanceAdvisor/slowQueryLogs
        ?since=<epoch ms>&duration=<ms>&namespaces=db.coll&nLogs=N
    -> {"slowQueries": [{"line": "<raw mongod log line>", "namespace": "db.coll"}, ...]}

Only the URL prefix and authentication differ, so the fetch logic lives here once.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from typing import Any

import httpx

MAX_N_LOGS = 20_000


class ApiError(RuntimeError):
    """HTTP error from Atlas / Ops Manager with the response body preserved for the operator."""

    def __init__(self, response: httpx.Response) -> None:
        detail = response.text[:500]
        super().__init__(
            f"{response.request.method} {response.request.url} -> {response.status_code}: {detail}"
        )
        self.status_code = response.status_code


@dataclass(frozen=True, slots=True)
class SlowQueryLog:
    line: str
    namespace: str | None


@dataclass(frozen=True, slots=True)
class SlowQueryWindow:
    """Time window / filters for a slowQueryLogs request. ``None`` means "use API default"."""

    since_ms: int | None = None
    duration_ms: int | None = None
    namespaces: tuple[str, ...] = ()
    n_logs: int = MAX_N_LOGS

    def as_params(self) -> dict[str, Any]:
        params: dict[str, Any] = {"nLogs": min(self.n_logs, MAX_N_LOGS)}
        if self.since_ms is not None:
            params["since"] = self.since_ms
        if self.duration_ms is not None:
            params["duration"] = self.duration_ms
        if self.namespaces:
            params["namespaces"] = list(self.namespaces)
        return params


def get_json(client: httpx.Client, url: str, params: dict[str, Any] | None = None) -> Any:
    response = client.get(url, params=params)
    if response.is_error:
        raise ApiError(response)
    return response.json()


def paginate(
    client: httpx.Client, url: str, *, items_per_page: int = 500
) -> Iterator[dict[str, Any]]:
    """Iterate ``results`` across ``pageNum`` pages for list endpoints (Atlas and Ops Manager)."""
    page = 1
    seen = 0
    while True:
        body = get_json(client, url, {"itemsPerPage": items_per_page, "pageNum": page})
        results: Sequence[dict[str, Any]] = body.get("results") or []
        yield from results
        seen += len(results)
        total = body.get("totalCount")
        if not results or (isinstance(total, int) and seen >= total):
            return
        page += 1


def fetch_slow_query_logs(
    client: httpx.Client, url: str, window: SlowQueryWindow
) -> tuple[SlowQueryLog, ...]:
    body = get_json(client, url, window.as_params())
    return tuple(
        SlowQueryLog(line=str(item.get("line", "")), namespace=item.get("namespace"))
        for item in body.get("slowQueries") or []
        if isinstance(item, dict)
    )
