"""Atlas Admin API documents shaped like real responses, for the waf-check tests."""

from __future__ import annotations

from typing import Any

from mongoops.waf_check.facts import Fact, Facts

GOOD_CLUSTER: dict[str, Any] = {
    "name": "prod-orders",
    "mongoDBVersion": "8.0.4",
    "mongoDBMajorVersion": "8.0",
    "clusterType": "REPLICASET",
    "backupEnabled": True,
    "pitEnabled": True,
    "terminationProtectionEnabled": True,
    "encryptionAtRestProvider": "AWS",
    "tags": [
        {"key": "application", "value": "orders"},
        {"key": "Environment", "value": "prod"},
        {"key": "contact", "value": "ops@example.co.th"},
        {"key": "criticality", "value": "high"},
    ],
    "connectionStrings": {
        "standard": "mongodb://a.example.net:27017/?ssl=true",
        "privateEndpoint": [{"connectionString": "mongodb://pl-0-a.example.net:1024/"}],
    },
    "replicationSpecs": [
        {
            "regionConfigs": [
                {
                    "providerName": "AWS",
                    "regionName": "AP_SOUTHEAST_1",
                    "electableSpecs": {"instanceSize": "M30", "nodeCount": 3},
                    "autoScaling": {"compute": {"enabled": True}, "diskGB": {"enabled": True}},
                }
            ]
        }
    ],
}

BAD_CLUSTER: dict[str, Any] = {
    "name": "dev-scratch",
    "mongoDBVersion": "6.0.19",
    "mongoDBMajorVersion": "6.0",
    "backupEnabled": False,
    "pitEnabled": False,
    "terminationProtectionEnabled": False,
    "encryptionAtRestProvider": "NONE",
    "tags": [{"key": "application", "value": "<script>alert(1)</script>"}],
    "connectionStrings": {"standard": "mongodb://b.example.net:27017/?ssl=true"},
    "replicationSpecs": [
        {
            "regionConfigs": [
                {
                    "providerName": "AWS",
                    "regionName": "AP_SOUTHEAST_1",
                    "electableSpecs": {"instanceSize": "M10", "nodeCount": 1},
                    "autoScaling": {"compute": {"enabled": False}, "diskGB": {"enabled": False}},
                }
            ]
        }
    ],
}

SHARED_CLUSTER: dict[str, Any] = {
    "name": "cluster-free",
    "mongoDBVersion": "8.0.4",
    "backupEnabled": True,
    "terminationProtectionEnabled": True,
    "tags": GOOD_CLUSTER["tags"],
    "connectionStrings": {"standard": "mongodb://c.example.net:27017/?ssl=true"},
    "replicationSpecs": [
        {
            "regionConfigs": [
                {
                    "providerName": "TENANT",
                    "backingProviderName": "AWS",
                    "regionName": "AP_SOUTHEAST_1",
                    "electableSpecs": {"instanceSize": "M0", "nodeCount": 3},
                }
            ]
        }
    ],
}

PROCESS_ARGS = {
    "minimumEnabledTlsProtocol": "TLS1_2",
    "javascriptEnabled": False,
    "defaultMaxTimeMS": 5000,
}
BACKUP_SCHEDULE = {
    "restoreWindowDays": 7,
    "policies": [
        {
            "policyItems": [
                {"frequencyType": "daily", "retentionUnit": "days", "retentionValue": 7},
                {"frequencyType": "weekly", "retentionUnit": "weeks", "retentionValue": 4},
                {"frequencyType": "monthly", "retentionUnit": "months", "retentionValue": 12},
            ]
        }
    ],
    "copySettings": [{"regionName": "AP_SOUTHEAST_2", "cloudProvider": "AWS"}],
}
ACCESS_LIST_GOOD = ({"cidrBlock": "10.0.0.0/24", "comment": "app subnet"},)
ACCESS_LIST_BAD = (
    {"cidrBlock": "0.0.0.0/0", "comment": "temp"},
    {"cidrBlock": "10.0.0.0/8"},
    {"ipAddress": "203.0.113.10"},
)
AUDIT_ON = {"enabled": True, "configurationType": "FILTER_JSON", "auditAuthorizationSuccess": False}
MAINTENANCE = {
    "dayOfWeek": 1,
    "hourOfDay": 3,
    "timeZoneId": "Asia/Bangkok",
    "protectedHours": {"startHourOfDay": 9, "endHourOfDay": 18},
}


def alert(event: str, metric: str = "", enabled: bool = True) -> dict[str, Any]:
    cfg: dict[str, Any] = {"eventTypeName": event, "enabled": enabled}
    if metric:
        cfg["metricThreshold"] = {"metricName": metric}
    return cfg


ALERTS_ALL = (
    alert("OUTSIDE_METRIC_THRESHOLD", "CONNECTIONS_PERCENT"),
    alert("OUTSIDE_METRIC_THRESHOLD", "NORMALIZED_SYSTEM_CPU_USER"),
    alert("OUTSIDE_METRIC_THRESHOLD", "DISK_PARTITION_SPACE_USED_DATA"),
    alert("OUTSIDE_METRIC_THRESHOLD", "DISK_PARTITION_IOPS_TOTAL_DATA"),
    alert("OUTSIDE_METRIC_THRESHOLD", "QUERY_TARGETING_SCANNED_OBJECTS_PER_RETURNED"),
    alert("OUTSIDE_METRIC_THRESHOLD", "OPLOG_SLAVE_LAG_MASTER_TIME"),
    alert("REPLICATION_OPLOG_WINDOW_RUNNING_OUT"),
    alert("NO_PRIMARY"),
    alert("HOST_DOWN"),
)
USERS_FEDERATED = (
    {"username": "arn:aws:iam::1:role/app", "databaseName": "$external", "awsIAMType": "ROLE"},
    {"username": "CN=ops", "databaseName": "$external", "x509Type": "CUSTOMER", "scopes": []},
)
USERS_MIXED = (
    *USERS_FEDERATED,
    {"username": "legacy-app", "databaseName": "admin", "awsIAMType": "NONE", "scopes": []},
    {
        "username": "other-cluster-only",
        "databaseName": "admin",
        "scopes": [{"type": "CLUSTER", "name": "somewhere-else"}],
    },
)
SETTINGS_ON = {
    "isPerformanceAdvisorEnabled": True,
    "isSchemaAdvisorEnabled": True,
    "isRealtimePerformancePanelEnabled": True,
}


def good_facts(**overrides: Any) -> Facts:
    base: dict[str, Any] = {
        "group_id": "5f1a" + "0" * 20,
        "cluster_name": "prod-orders",
        "cluster": GOOD_CLUSTER,
        "process_args": Fact(PROCESS_ARGS),
        "backup_schedule": Fact(BACKUP_SCHEDULE),
        "compliance_policy": Fact({"state": "ACTIVE"}),
        "access_list": Fact(ACCESS_LIST_GOOD),
        "peers": Fact(()),
        "audit": Fact(AUDIT_ON),
        "maintenance_window": Fact(MAINTENANCE),
        "alert_configs": Fact(ALERTS_ALL),
        "integrations": Fact(({"type": "DATADOG"},)),
        "database_users": Fact(USERS_FEDERATED),
        "project_settings": Fact(SETTINGS_ON),
        "suggested_indexes": Fact({"suggestedIndexes": [], "shapes": []}),
    }
    return Facts(**{**base, **overrides})


def bad_facts() -> Facts:
    return good_facts(
        cluster_name="dev-scratch",
        cluster=BAD_CLUSTER,
        process_args=Fact({"minimumEnabledTlsProtocol": "TLS1_1", "javascriptEnabled": True}),
        backup_schedule=Fact(None),
        compliance_policy=Fact(None),
        access_list=Fact(ACCESS_LIST_BAD),
        audit=Fact(
            error="HTTP 403 reading gid/auditLog: the API key lacks the required role; "
            "this endpoint needs Project Owner"
        ),
        maintenance_window=Fact({}),
        alert_configs=Fact(ALERTS_ALL[:3]),
        integrations=Fact(()),
        database_users=Fact(USERS_MIXED),
        project_settings=Fact({**SETTINGS_ON, "isSchemaAdvisorEnabled": False}),
        suggested_indexes=Fact({"suggestedIndexes": [{"namespace": "shop.orders"}]}),
    )
