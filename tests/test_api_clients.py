"""Atlas / Ops Manager clients against an in-memory httpx transport (no network)."""

from __future__ import annotations

import json
from collections.abc import Callable
from urllib.parse import parse_qs

import httpx
import pytest

from mongoops.common import atlas_api, ops_manager_api
from mongoops.common.perf_advisor import ApiError, SlowQueryWindow, paginate
from mongoops.common.timeutil import parse_duration_ms, parse_since_ms
from mongoops.regex_finder import sources
from mongoops.regex_finder.analyze import AnalyzeOptions, analyze_lines

Handler = Callable[[httpx.Request], httpx.Response]

SLOW_LINE = json.dumps(
    {
        "t": {"$date": "2026-09-04T00:00:00.000+00:00"},
        "msg": "Slow query",
        "attr": {
            "type": "command",
            "ns": "shop.orders",
            "command": {"find": "orders", "filter": {"sku": {"$regex": "^AB", "$options": "i"}}},
            "planSummary": "COLLSCAN",
            "durationMillis": 250,
        },
    }
)

# Shapes as observed on a real project: hostnames and aliases carry no trace of the cluster name.
ATLAS_PROCESSES = {
    "results": [
        {
            "id": "atlas-abc123-shard-00-00.xyz789.mongodb.net:27017",
            "hostname": "atlas-abc123-shard-00-00.xyz789.mongodb.net",
            "port": 27017,
            "typeName": "REPLICA_SECONDARY",
            "replicaSetName": "atlas-abc123-shard-0",
            "userAlias": "ac-qwe456-shard-00-00.xyz789.mongodb.net",
        },
        {
            "id": "atlas-abc123-shard-00-01.xyz789.mongodb.net:27017",
            "hostname": "atlas-abc123-shard-00-01.xyz789.mongodb.net",
            "port": 27017,
            "typeName": "REPLICA_PRIMARY",
            "replicaSetName": "atlas-abc123-shard-0",
            "userAlias": "ac-qwe456-shard-00-01.xyz789.mongodb.net",
        },
        {
            "id": "atlas-wwhvwv-shard-00-00.mhacthk.mongodb.net:27017",
            "hostname": "atlas-wwhvwv-shard-00-00.mhacthk.mongodb.net",
            "port": 27017,
            "typeName": "REPLICA_PRIMARY",
            "replicaSetName": "atlas-wwhvwv-shard-0",
            "userAlias": "ac-s2cgwm9-shard-00-00.mhacthk.mongodb.net",
        },
    ],
    "totalCount": 3,
}
ATLAS_CLUSTER = {
    "name": "Cluster0",
    "connectionStrings": {
        "standard": "mongodb://ac-qwe456-shard-00-00.xyz789.mongodb.net:27017,"
        "ac-qwe456-shard-00-01.xyz789.mongodb.net:27017/?ssl=true&authSource=admin"
        "&replicaSet=atlas-abc123-shard-0",
        "standardSrv": "mongodb+srv://cluster0.xyz789.mongodb.net",
    },
}


def _client(handler: Handler, base: str) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler), base_url=base)


class TestAtlas:
    def test_auth_kind_and_client_construction(self) -> None:
        assert atlas_api.AtlasAuth("pub", "priv").kind == "api-key"
        assert atlas_api.AtlasAuth(client_id="id", client_secret="s").kind == "service-account"
        assert atlas_api.AtlasAuth().kind == "none"
        with pytest.raises(ValueError, match="credentials missing"):
            atlas_api.atlas_client(atlas_api.AtlasAuth())
        c = atlas_api.atlas_client(atlas_api.AtlasAuth("pub", "priv"))
        assert str(c.base_url) == "https://cloud.mongodb.com/api/atlas/v2/"
        assert c.headers["Accept"] == atlas_api.ATLAS_ACCEPT
        assert isinstance(c.auth, httpx.DigestAuth)

    def test_auth_from_env(self) -> None:
        auth = atlas_api.auth_from_env(
            {"MONGODB_ATLAS_PUBLIC_API_KEY": "a", "MONGODB_ATLAS_PRIVATE_API_KEY": "b"}
        )
        assert (auth.public_key, auth.private_key, auth.kind) == ("a", "b", "api-key")

    def test_cluster_hosts_and_select_processes(self) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            if req.url.path == "/api/atlas/v2/groups/gid/processes":
                return httpx.Response(200, json=ATLAS_PROCESSES)
            assert req.url.path == "/api/atlas/v2/groups/gid/clusters/Cluster0"
            return httpx.Response(200, json=ATLAS_CLUSTER)

        with _client(handler, "https://cloud.mongodb.com/api/atlas/v2") as c:
            processes = atlas_api.list_processes(c, "gid")
            hosts = atlas_api.cluster_hosts(c, "gid", "Cluster0")
        assert len(processes) == 3
        assert hosts == {
            "ac-qwe456-shard-00-00.xyz789.mongodb.net",
            "ac-qwe456-shard-00-01.xyz789.mongodb.net",
        }
        selected = atlas_api.select_processes(processes, hosts=hosts)
        assert [p.id for p in selected] == [
            "atlas-abc123-shard-00-00.xyz789.mongodb.net:27017",
            "atlas-abc123-shard-00-01.xyz789.mongodb.net:27017",
        ]
        only = atlas_api.select_processes(processes, process_ids=[processes[1].id])
        assert only == (processes[1],)
        assert atlas_api.select_processes(processes, hosts=frozenset()) == ()
        assert atlas_api.select_processes(processes) == processes

    def test_cluster_hosts_matches_hostname_too(self) -> None:
        processes = (
            atlas_api.AtlasProcess(
                "h1:27017", "H1.x.mongodb.net", 27017, "SHARD_MONGOS", None, None
            ),
        )
        assert (
            atlas_api.select_processes(processes, hosts=frozenset({"h1.x.mongodb.net"}))
            == processes
        )

    def test_slow_query_logs_params_and_pipeline(self) -> None:
        seen: list[httpx.Request] = []

        def handler(req: httpx.Request) -> httpx.Response:
            seen.append(req)
            return httpx.Response(
                200, json={"slowQueries": [{"line": SLOW_LINE, "namespace": "shop.orders"}]}
            )

        window = SlowQueryWindow(
            since_ms=1000, duration_ms=2000, namespaces=("shop.orders", "a.b"), n_logs=99
        )
        with _client(handler, "https://cloud.mongodb.com/api/atlas/v2") as c:
            logs = atlas_api.slow_query_logs(c, "gid", "host:27017", window)
            process = atlas_api.AtlasProcess(
                "host:27017", "host", 27017, "REPLICA_PRIMARY", None, "alias"
            )
            findings = tuple(
                analyze_lines(sources.atlas_lines(c, "gid", [process], window), AnalyzeOptions())
            )

        assert logs[0].namespace == "shop.orders"
        req = seen[0]
        assert (
            req.url.path
            == "/api/atlas/v2/groups/gid/processes/host:27017/performanceAdvisor/slowQueryLogs"
        )
        qs = parse_qs(req.url.query.decode())
        assert qs == {
            "nLogs": ["99"],
            "since": ["1000"],
            "duration": ["2000"],
            "namespaces": ["shop.orders", "a.b"],
        }
        assert len(findings) == 1
        assert (findings[0].origin, findings[0].field, findings[0].pattern) == (
            "alias",
            "sku",
            "^AB",
        )

    def test_api_error_surfaces_body(self) -> None:
        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(
                401, json={"errorCode": "USER_UNAUTHORIZED", "reason": "Unauthorized"}
            )

        with (
            _client(handler, "https://cloud.mongodb.com/api/atlas/v2") as c,
            pytest.raises(ApiError) as e,
        ):
            atlas_api.list_processes(c, "gid")
        assert e.value.status_code == 401
        assert "USER_UNAUTHORIZED" in str(e.value)

    def test_service_account_token_flow(self) -> None:
        calls: list[str] = []

        def handler(req: httpx.Request) -> httpx.Response:
            calls.append(req.url.path)
            if req.url.path == "/api/oauth/token":
                assert req.headers["Authorization"].startswith("Basic ")
                assert b"grant_type=client_credentials" in req.content
                return httpx.Response(200, json={"access_token": "tok", "expires_in": 3600})
            assert req.headers["Authorization"] == "Bearer tok"
            return httpx.Response(200, json={"results": [], "totalCount": 0})

        auth = atlas_api.ServiceAccountAuth("id", "secret", "https://cloud.mongodb.com")
        with httpx.Client(
            transport=httpx.MockTransport(handler),
            auth=auth,
            base_url="https://cloud.mongodb.com/api/atlas/v2",
        ) as c:
            assert atlas_api.list_processes(c, "gid") == ()
            atlas_api.list_processes(c, "gid")  # token cached
        assert calls.count("/api/oauth/token") == 1


class TestOpsManager:
    def test_config_and_client(self) -> None:
        cfg = ops_manager_api.config_from_env(
            {
                "MONGODB_OPS_MANAGER_URL": "https://om.local:8443/",
                "MONGODB_OPS_MANAGER_PUBLIC_API_KEY": "pub",
                "MONGODB_OPS_MANAGER_PRIVATE_API_KEY": "priv",
            }
        )
        assert cfg.configured
        c = ops_manager_api.ops_manager_client(cfg)
        assert str(c.base_url) == "https://om.local:8443/api/public/v1.0/"
        with pytest.raises(ValueError, match="settings missing"):
            ops_manager_api.ops_manager_client(ops_manager_api.OpsManagerConfig("", "", ""))

    def test_hosts_pagination_selection_and_slow_queries(self) -> None:
        page1 = {
            "results": [
                {
                    "id": "h1",
                    "hostname": "db1.example.local",
                    "port": 27017,
                    "typeName": "REPLICA_PRIMARY",
                    "replicaSetName": "rs0",
                    "clusterId": "c1",
                },
            ],
            "totalCount": 2,
        }
        page2 = {
            "results": [
                {
                    "id": "h2",
                    "hostname": "db2.example.local",
                    "port": 27017,
                    "typeName": "REPLICA_SECONDARY",
                    "replicaSetName": "rs1",
                    "clusterId": "c1",
                },
            ],
            "totalCount": 2,
        }

        def handler(req: httpx.Request) -> httpx.Response:
            if req.url.path.endswith("/hosts"):
                page = parse_qs(req.url.query.decode())["pageNum"][0]
                return httpx.Response(200, json=page1 if page == "1" else page2)
            assert (
                req.url.path
                == "/api/public/v1.0/groups/gid/hosts/h1/performanceAdvisor/slowQueryLogs"
            )
            return httpx.Response(
                200, json={"slowQueries": [{"line": SLOW_LINE, "namespace": "shop.orders"}]}
            )

        with _client(handler, "https://om.local/api/public/v1.0") as c:
            hosts = ops_manager_api.list_hosts(c, "gid")
            assert [h.id for h in hosts] == ["h1", "h2"]
            assert ops_manager_api.select_hosts(hosts, replica_set="rs0") == (hosts[0],)
            assert ops_manager_api.select_hosts(hosts, cluster_id="c1") == hosts
            assert ops_manager_api.select_hosts(hosts, hostname_prefix="DB2") == (hosts[1],)
            assert ops_manager_api.select_hosts(hosts, host_ids=["h2"], replica_set="rs0") == ()
            findings = tuple(
                analyze_lines(
                    sources.ops_manager_lines(c, "gid", hosts[:1], SlowQueryWindow()),
                    AnalyzeOptions(),
                )
            )
        assert len(findings) == 1
        assert findings[0].origin == "db1.example.local:27017"


def test_paginate_stops_on_empty_page_without_total() -> None:
    pages = iter([{"results": [{"a": 1}]}, {"results": []}])

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=next(pages))

    with _client(handler, "https://x") as c:
        assert list(paginate(c, "/things")) == [{"a": 1}]


class TestTimeUtil:
    def test_durations(self) -> None:
        assert parse_duration_ms("24h") == 86_400_000
        assert parse_duration_ms("30 m") == 1_800_000
        assert parse_duration_ms("7d") == 604_800_000
        with pytest.raises(ValueError, match="invalid duration"):
            parse_duration_ms("yesterday")

    def test_since(self) -> None:
        from datetime import UTC, datetime

        now = datetime(2026, 9, 4, 12, 0, tzinfo=UTC)
        assert parse_since_ms("1h", now=now) == int(
            datetime(2026, 9, 4, 11, 0, tzinfo=UTC).timestamp() * 1000
        )
        assert parse_since_ms("2026-09-04T00:00:00Z") == int(
            datetime(2026, 9, 4, tzinfo=UTC).timestamp() * 1000
        )
        assert parse_since_ms("2026-09-04") == int(
            datetime(2026, 9, 4, tzinfo=UTC).timestamp() * 1000
        )
