"""Atlas facts for one cluster: the raw Admin API documents the checks are evaluated against.

Every fact is fetched on its own and wrapped in ``Fact`` so a single 401/403 (the key lacks the
role that endpoint needs) or a tier limitation (no ``processArgs`` on shared tiers) turns into
``UNKNOWN`` for the checks that need it instead of aborting the run or, worse, a false ``FAIL``.

Read-only: only GET requests. Roles: Project Read Only covers most endpoints; ``auditLog`` and
``integrations`` need Project Owner, ``suggestedIndexes`` needs Project Data Access Read Only.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

import httpx

from mongoops.common.perf_advisor import ApiError, paginate

ACCEPT_2024 = "application/vnd.atlas.2024-08-05+json"

# Endpoint suffix -> role the docs list, shown in UNKNOWN messages so the fix is obvious.
_ROLE_HINTS: Mapping[str, str] = {
    "/auditLog": "Project Owner",
    "/integrations": "Project Owner",
    "/backupCompliancePolicy": "Project Owner",
    "/performanceAdvisor/suggestedIndexes": "Project Data Access Read Only",
}

Progress = Callable[[str, str], None]


@dataclass(frozen=True, slots=True)
class Fact:
    value: Any = None
    error: str = ""

    @property
    def available(self) -> bool:
        return not self.error


@dataclass(frozen=True, slots=True)
class Facts:
    group_id: str
    cluster_name: str
    cluster: Mapping[str, Any]
    process_args: Fact = field(default_factory=Fact)
    backup_schedule: Fact = field(default_factory=Fact)
    compliance_policy: Fact = field(default_factory=Fact)
    access_list: Fact = field(default_factory=Fact)
    peers: Fact = field(default_factory=Fact)
    audit: Fact = field(default_factory=Fact)
    maintenance_window: Fact = field(default_factory=Fact)
    alert_configs: Fact = field(default_factory=Fact)
    integrations: Fact = field(default_factory=Fact)
    database_users: Fact = field(default_factory=Fact)
    project_settings: Fact = field(default_factory=Fact)
    suggested_indexes: Fact = field(default_factory=Fact)

    @property
    def provider(self) -> str:
        """Cloud provider of the first region config (``AWS`` / ``AZURE`` / ``GCP``)."""
        for rc in region_configs(self.cluster):
            name = str(rc.get("backingProviderName") or rc.get("providerName") or "")
            if name and name not in ("TENANT", "FLEX", "SERVERLESS"):
                return name
        return "AWS"

    @property
    def shared_tier(self) -> bool:
        """M0/M2/M5/Flex/Serverless: many project- and cluster-level controls do not apply."""
        return any(
            str(rc.get("providerName", "")) in ("TENANT", "FLEX", "SERVERLESS")
            for rc in region_configs(self.cluster)
        )


def region_configs(cluster: Mapping[str, Any]) -> tuple[Mapping[str, Any], ...]:
    """Flatten ``replicationSpecs[].regionConfigs[]`` (pure)."""
    return tuple(
        rc
        for spec in cluster.get("replicationSpecs") or []
        for rc in (spec.get("regionConfigs") or [])
        if isinstance(rc, Mapping)
    )


# --- collection -----------------------------------------------------------------------------------


def collect_atlas(
    client: httpx.Client, group_id: str, cluster_name: str, progress: Progress | None = None
) -> Facts:
    """Fetch every fact for one cluster. Raises ``ApiError`` only if the cluster itself is
    unreadable; everything else degrades to ``Fact(error=...)``."""
    base = f"/groups/{group_id}"
    cl = f"{base}/clusters/{cluster_name}"
    note = progress or (lambda _name, _state: None)

    response = client.get(cl, headers={"Accept": ACCEPT_2024})
    if response.is_error:  # includes 404: a wrong cluster name is a usage error, not a finding
        raise ApiError(response)
    cluster: Mapping[str, Any] = response.json()
    facts = Facts(group_id=group_id, cluster_name=cluster_name, cluster=cluster)
    note("cluster", "ok")

    fetches: tuple[tuple[str, Callable[[], Fact]], ...] = (
        ("process_args", lambda: _get(client, f"{cl}/processArgs", accept=ACCEPT_2024)),
        ("backup_schedule", lambda: _get(client, f"{cl}/backup/schedule", accept=ACCEPT_2024)),
        ("compliance_policy", lambda: _get(client, f"{base}/backupCompliancePolicy")),
        ("access_list", lambda: _list(client, f"{base}/accessList")),
        ("peers", lambda: _list(client, f"{base}/peers", {"providerName": facts.provider})),
        ("audit", lambda: _get(client, f"{base}/auditLog")),
        ("maintenance_window", lambda: _get(client, f"{base}/maintenanceWindow")),
        ("alert_configs", lambda: _list(client, f"{base}/alertConfigs")),
        ("integrations", lambda: _list(client, f"{base}/integrations")),
        ("database_users", lambda: _list(client, f"{base}/databaseUsers")),
        ("project_settings", lambda: _get(client, f"{base}/settings")),
        (
            "suggested_indexes",
            lambda: _get(client, f"{cl}/performanceAdvisor/suggestedIndexes", accept=ACCEPT_2024),
        ),
    )
    collected: dict[str, Fact] = {}
    for name, fetch in fetches:
        fact = fetch()
        collected[name] = fact
        note(name, "ok" if fact.available else fact.error)
    return Facts(group_id=group_id, cluster_name=cluster_name, cluster=cluster, **collected)


def _get(client: httpx.Client, url: str, *, accept: str | None = None) -> Fact:
    headers = {"Accept": accept} if accept else None
    try:
        response = client.get(url, headers=headers)
    except httpx.HTTPError as exc:
        return Fact(error=f"{type(exc).__name__} on GET {url}")
    if response.status_code == 404:
        return Fact(value=None)
    if response.is_error:
        return Fact(error=_describe(response, url))
    return Fact(value=response.json())


def _list(client: httpx.Client, url: str, params: Mapping[str, Any] | None = None) -> Fact:
    try:
        if params:
            response = client.get(url, params={**params, "itemsPerPage": 500})
            if response.status_code == 404:
                return Fact(value=())
            if response.is_error:
                return Fact(error=_describe(response, url))
            return Fact(value=tuple(response.json().get("results") or []))
        return Fact(value=tuple(paginate(client, url)))
    except ApiError as exc:
        return Fact(error=_describe_api_error(exc, url))
    except httpx.HTTPError as exc:
        return Fact(error=f"{type(exc).__name__} on GET {url}")


def _describe(response: httpx.Response, url: str) -> str:
    return _describe_status(response.status_code, url, response.text[:200])


def _describe_api_error(exc: ApiError, url: str) -> str:
    return _describe_status(exc.status_code, url, str(exc)[-200:])


def _describe_status(status: int, url: str, detail: str) -> str:
    tail = url.rsplit("/groups/", 1)[-1]
    if status in (401, 403):
        hint = next((role for suffix, role in _ROLE_HINTS.items() if url.endswith(suffix)), "")
        role = f"; this endpoint needs {hint}" if hint else ""
        return f"HTTP {status} reading {tail}: the API key lacks the required role{role}"
    return f"HTTP {status} reading {tail}: {detail}"
