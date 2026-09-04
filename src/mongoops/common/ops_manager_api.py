"""Minimal Ops Manager / Cloud Manager public API v1.0 client for Enterprise Advanced deployments.

Environment variable names follow ``mongocli``:

* ``MONGODB_OPS_MANAGER_URL``               e.g. ``https://opsmanager.example.internal:8443``
* ``MONGODB_OPS_MANAGER_PUBLIC_API_KEY`` / ``MONGODB_OPS_MANAGER_PRIVATE_API_KEY`` (HTTP digest)
* ``MONGODB_OPS_MANAGER_CA_FILE``           optional CA bundle for self-signed TLS
"""

from __future__ import annotations

import os
from collections.abc import Sequence
from dataclasses import dataclass

import httpx

from mongoops.common.perf_advisor import (
    SlowQueryLog,
    SlowQueryWindow,
    fetch_slow_query_logs,
    paginate,
)


@dataclass(frozen=True, slots=True)
class OpsManagerConfig:
    base_url: str
    public_key: str
    private_key: str
    ca_file: str | None = None
    verify_tls: bool = True

    @property
    def configured(self) -> bool:
        return bool(self.base_url and self.public_key and self.private_key)


@dataclass(frozen=True, slots=True)
class OpsManagerHost:
    id: str
    """Ops Manager host id - the ``hostId`` path parameter."""
    hostname: str
    port: int
    type_name: str
    replica_set_name: str | None
    cluster_id: str | None


def config_from_env(env: dict[str, str] | None = None) -> OpsManagerConfig:
    e = env if env is not None else dict(os.environ)
    return OpsManagerConfig(
        base_url=e.get("MONGODB_OPS_MANAGER_URL", ""),
        public_key=e.get("MONGODB_OPS_MANAGER_PUBLIC_API_KEY", ""),
        private_key=e.get("MONGODB_OPS_MANAGER_PRIVATE_API_KEY", ""),
        ca_file=e.get("MONGODB_OPS_MANAGER_CA_FILE") or None,
    )


def ops_manager_client(config: OpsManagerConfig, *, timeout: float = 60.0) -> httpx.Client:
    if not config.configured:
        raise ValueError(
            "Ops Manager settings missing: set MONGODB_OPS_MANAGER_URL, "
            "MONGODB_OPS_MANAGER_PUBLIC_API_KEY and MONGODB_OPS_MANAGER_PRIVATE_API_KEY"
        )
    verify: bool | str = config.ca_file if config.ca_file else config.verify_tls
    return httpx.Client(
        base_url=f"{config.base_url.rstrip('/')}/api/public/v1.0",
        auth=httpx.DigestAuth(config.public_key, config.private_key),
        headers={"Accept": "application/json", "User-Agent": "mongoops"},
        timeout=timeout,
        verify=verify,
    )


def list_hosts(client: httpx.Client, group_id: str) -> tuple[OpsManagerHost, ...]:
    return tuple(
        OpsManagerHost(
            id=str(h.get("id", "")),
            hostname=str(h.get("hostname", "")),
            port=int(h.get("port", 27017)),
            type_name=str(h.get("typeName", "")),
            replica_set_name=h.get("replicaSetName"),
            cluster_id=h.get("clusterId"),
        )
        for h in paginate(client, f"/groups/{group_id}/hosts")
    )


def select_hosts(
    hosts: Sequence[OpsManagerHost],
    *,
    host_ids: Sequence[str] = (),
    replica_set: str | None = None,
    cluster_id: str | None = None,
    hostname_prefix: str | None = None,
) -> tuple[OpsManagerHost, ...]:
    """Filter hosts; every supplied criterion must match (AND). No criteria = all hosts."""
    wanted = set(host_ids)
    prefix = hostname_prefix.lower() if hostname_prefix else None
    return tuple(
        h
        for h in hosts
        if (not wanted or h.id in wanted)
        and (replica_set is None or h.replica_set_name == replica_set)
        and (cluster_id is None or h.cluster_id == cluster_id)
        and (prefix is None or h.hostname.lower().startswith(prefix))
    )


def slow_query_logs(
    client: httpx.Client, group_id: str, host_id: str, window: SlowQueryWindow
) -> tuple[SlowQueryLog, ...]:
    url = f"/groups/{group_id}/hosts/{host_id}/performanceAdvisor/slowQueryLogs"
    return fetch_slow_query_logs(client, url, window)
