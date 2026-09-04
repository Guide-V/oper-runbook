"""Minimal MongoDB Atlas Administration API v2 client (only what the scripts need).

Authentication mirrors the Atlas CLI environment variables:

* ``MONGODB_ATLAS_PUBLIC_API_KEY`` / ``MONGODB_ATLAS_PRIVATE_API_KEY`` -> HTTP digest
* ``MONGODB_ATLAS_CLIENT_ID`` / ``MONGODB_ATLAS_CLIENT_SECRET``        -> service account (OAuth2)
"""

from __future__ import annotations

import base64
import os
import re
import time
from collections.abc import Generator, Sequence
from dataclasses import dataclass

import httpx

from mongoops.common.perf_advisor import (
    SlowQueryLog,
    SlowQueryWindow,
    fetch_slow_query_logs,
    get_json,
    paginate,
)

DEFAULT_BASE_URL = "https://cloud.mongodb.com"
ATLAS_ACCEPT = "application/vnd.atlas.2023-01-01+json"


@dataclass(frozen=True, slots=True)
class AtlasAuth:
    public_key: str = ""
    private_key: str = ""
    client_id: str = ""
    client_secret: str = ""

    @property
    def kind(self) -> str:
        if self.public_key and self.private_key:
            return "api-key"
        if self.client_id and self.client_secret:
            return "service-account"
        return "none"


@dataclass(frozen=True, slots=True)
class AtlasProcess:
    id: str
    """``hostname:port`` - the ``processId`` path parameter."""
    hostname: str
    port: int
    type_name: str
    replica_set_name: str | None
    user_alias: str | None
    """Cluster-facing hostname, e.g. ``cluster0-shard-00-00.abcde.mongodb.net``."""


def auth_from_env(env: dict[str, str] | None = None) -> AtlasAuth:
    e = env if env is not None else dict(os.environ)
    return AtlasAuth(
        public_key=e.get("MONGODB_ATLAS_PUBLIC_API_KEY", ""),
        private_key=e.get("MONGODB_ATLAS_PRIVATE_API_KEY", ""),
        client_id=e.get("MONGODB_ATLAS_CLIENT_ID", ""),
        client_secret=e.get("MONGODB_ATLAS_CLIENT_SECRET", ""),
    )


class ServiceAccountAuth(httpx.Auth):
    """OAuth2 client-credentials flow for Atlas service accounts, refreshed when expired."""

    requires_response_body = True

    def __init__(self, client_id: str, client_secret: str, base_url: str) -> None:
        self._client_id = client_id
        self._client_secret = client_secret
        self._token_url = f"{base_url.rstrip('/')}/api/oauth/token"
        self._token: str | None = None
        self._expires_at = 0.0

    def auth_flow(self, request: httpx.Request) -> Generator[httpx.Request, httpx.Response, None]:
        if self._token is None or time.time() >= self._expires_at:
            token_response = yield self._token_request()
            self._store(token_response)
        request.headers["Authorization"] = f"Bearer {self._token}"
        response = yield request
        if response.status_code == 401:
            token_response = yield self._token_request()
            self._store(token_response)
            request.headers["Authorization"] = f"Bearer {self._token}"
            yield request

    def _token_request(self) -> httpx.Request:
        basic = base64.b64encode(f"{self._client_id}:{self._client_secret}".encode()).decode()
        return httpx.Request(
            "POST",
            self._token_url,
            headers={"Accept": "application/json", "Authorization": f"Basic {basic}"},
            data={"grant_type": "client_credentials"},
        )

    def _store(self, response: httpx.Response) -> None:
        response.read()
        if response.is_error:
            raise RuntimeError(
                f"service account token request failed: {response.status_code} "
                f"{response.text[:300]}"
            )
        body = response.json()
        self._token = body["access_token"]
        self._expires_at = time.time() + int(body.get("expires_in", 3600)) - 60


def atlas_client(
    auth: AtlasAuth, *, base_url: str = DEFAULT_BASE_URL, timeout: float = 60.0
) -> httpx.Client:
    """Build an authenticated httpx client rooted at ``{base_url}/api/atlas/v2``."""
    if auth.kind == "api-key":
        http_auth: httpx.Auth = httpx.DigestAuth(auth.public_key, auth.private_key)
    elif auth.kind == "service-account":
        http_auth = ServiceAccountAuth(auth.client_id, auth.client_secret, base_url)
    else:
        raise ValueError(
            "Atlas credentials missing: set MONGODB_ATLAS_PUBLIC_API_KEY / "
            "MONGODB_ATLAS_PRIVATE_API_KEY or MONGODB_ATLAS_CLIENT_ID / MONGODB_ATLAS_CLIENT_SECRET"
        )
    return httpx.Client(
        base_url=f"{base_url.rstrip('/')}/api/atlas/v2",
        auth=http_auth,
        headers={"Accept": ATLAS_ACCEPT, "User-Agent": "mongoops"},
        timeout=timeout,
    )


def list_processes(client: httpx.Client, group_id: str) -> tuple[AtlasProcess, ...]:
    return tuple(
        AtlasProcess(
            id=str(p.get("id") or f"{p.get('hostname')}:{p.get('port')}"),
            hostname=str(p.get("hostname", "")),
            port=int(p.get("port", 27017)),
            type_name=str(p.get("typeName", "")),
            replica_set_name=p.get("replicaSetName"),
            user_alias=p.get("userAlias"),
        )
        for p in paginate(client, f"/groups/{group_id}/processes")
    )


_HOSTPORT = re.compile(r"([A-Za-z0-9.-]+):(\d+)")


def cluster_hosts(client: httpx.Client, group_id: str, cluster_name: str) -> frozenset[str]:
    """Hostnames (no port) of a cluster, taken from its ``connectionStrings.standard``.

    Process hostnames/aliases are not derived from the cluster name (e.g. ``Cluster0`` runs on
    ``ac-qwe456-shard-00-00.<hash>.mongodb.net``), so the cluster resource is the only reliable
    link between a cluster name and its processes. For sharded clusters the standard string lists
    the mongos hosts, which are co-located with the shard mongods.
    """
    body = get_json(client, f"/groups/{group_id}/clusters/{cluster_name}")
    standard = (body.get("connectionStrings") or {}).get("standard") or ""
    return frozenset(host.lower() for host, _port in _HOSTPORT.findall(standard))


def select_processes(
    processes: Sequence[AtlasProcess],
    *,
    hosts: frozenset[str] | None = None,
    process_ids: Sequence[str] = (),
) -> tuple[AtlasProcess, ...]:
    """Filter processes by explicit ids and/or a set of hostnames (matched on hostname or alias).

    Both filters are ANDed; passing neither returns every process. Pure.
    """
    wanted_ids = set(process_ids)
    return tuple(
        p
        for p in processes
        if (not wanted_ids or p.id in wanted_ids)
        and (hosts is None or p.hostname.lower() in hosts or (p.user_alias or "").lower() in hosts)
    )


def slow_query_logs(
    client: httpx.Client, group_id: str, process_id: str, window: SlowQueryWindow
) -> tuple[SlowQueryLog, ...]:
    url = f"/groups/{group_id}/processes/{process_id}/performanceAdvisor/slowQueryLogs"
    return fetch_slow_query_logs(client, url, window)
