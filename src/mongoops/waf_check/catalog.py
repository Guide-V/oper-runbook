"""The check catalog: MongoDB's operational-readiness checklist mapped to stable check ids.

Baseline: https://www.mongodb.com/docs/atlas/architecture/current/operational-readiness-checklist/
Ids are ``<pillar prefix>.<area>.<check>`` and are the keys a landing-zone policy uses to set
severity. Keep ids stable; change titles and docs freely.

Default severity rule of thumb: ``fail`` when the gap can lose data or expose the cluster
(open network, no backup, no audit, single node), ``warn`` for governance and recommendations
the landing zone may legitimately decide differently (tags, autoscaling, snapshot copies).
"""

from __future__ import annotations

from collections.abc import Mapping

from mongoops.waf_check.model import CheckSpec, Kind, Pillar, Severity

CATALOG_VERSION = "operational-readiness-2026-09"

_ARCH = "https://www.mongodb.com/docs/atlas/architecture/current/"
DOC_CHECKLIST = _ARCH + "operational-readiness-checklist/"
DOC_LANDING_ZONE = _ARCH + "landing-zone/"
DOC_HIERARCHY = _ARCH + "hierarchy/"
DOC_TAGS = _ARCH + "resource-tags/"
DOC_AUTOMATION = _ARCH + "automation/"
DOC_MONITORING = _ARCH + "monitoring-alerts/"
DOC_NETWORK = _ARCH + "network-security/"
DOC_AUTH = _ARCH + "auth/"
DOC_ENCRYPTION = _ARCH + "data-encryption/"
DOC_AUDIT = _ARCH + "auditing-logging/"
DOC_COMPLIANCE = _ARCH + "compliance/"
DOC_HA = _ARCH + "high-availability/"
DOC_BACKUPS = _ARCH + "backups/"
DOC_DR = _ARCH + "disaster-recovery/"
DOC_SCALABILITY = _ARCH + "scalability/"
DOC_COST = _ARCH + "cost-saving-config/"
DOC_BILLING = _ARCH + "billing-data/"
DOC_MAINTENANCE = "https://www.mongodb.com/docs/atlas/tutorial/cluster-maintenance-window/"
DOC_PERF_ADVISOR = "https://www.mongodb.com/docs/atlas/performance-advisor/"
DOC_SERVER_JS = "https://www.mongodb.com/docs/atlas/cluster-additional-settings/"
DOC_CSFLE = "https://www.mongodb.com/docs/manual/core/csfle/"
DOC_ONLINE_ARCHIVE = "https://www.mongodb.com/docs/atlas/online-archive/overview/"
DOC_TEST_FAILOVER = "https://www.mongodb.com/docs/atlas/tutorial/test-resilience/"
DOC_CA = (
    "https://www.mongodb.com/docs/atlas/reference/faq/security/#hard-coded-certificate-authority"
)
DOC_MAX_TIME = "https://www.mongodb.com/docs/manual/reference/command/setDefaultRWConcern/"


def _auto(
    id: str, pillar: Pillar, title: str, severity: Severity, doc: str, what: str
) -> CheckSpec:
    return CheckSpec(id, pillar, title, Kind.AUTO, severity, doc, what)


def _discuss(id: str, pillar: Pillar, title: str, doc: str, what: str) -> CheckSpec:
    return CheckSpec(id, pillar, title, Kind.DISCUSS, Severity.OFF, doc, what)


S, OE, R, P, C = (
    Pillar.SECURITY,
    Pillar.OPERATIONAL_EFFICIENCY,
    Pillar.RELIABILITY,
    Pillar.PERFORMANCE,
    Pillar.COST_OPTIMIZATION,
)
FAIL, WARN = Severity.FAIL, Severity.WARN

AUTO_CHECKS: tuple[CheckSpec, ...] = (
    # --- security -----------------------------------------------------------------------------
    _auto(
        "sec.network.no-open-access",
        S,
        "No 0.0.0.0/0 entry in the project IP access list",
        FAIL,
        DOC_NETWORK,
        "Project access list entries.",
    ),
    _auto(
        "sec.network.private-connectivity",
        S,
        "Cluster reachable through the connectivity the landing zone mandates",
        WARN,
        DOC_NETWORK,
        "Private endpoint / peering connection strings on the cluster vs policy network.mode.",
    ),
    _auto(
        "sec.network.access-list-scoped",
        S,
        "IP access list entries are narrower than the policy CIDR floor",
        WARN,
        DOC_NETWORK,
        "CIDR prefix length of every access list entry vs policy network.min_cidr_prefix.",
    ),
    _auto(
        "sec.tls.minimum-version",
        S,
        "Minimum TLS protocol meets the policy",
        FAIL,
        DOC_NETWORK,
        "Cluster advanced configuration minimumEnabledTlsProtocol.",
    ),
    _auto(
        "sec.auth.no-password-users",
        S,
        "No SCRAM (password) database users in scope of this cluster",
        WARN,
        DOC_AUTH,
        "Database users whose scope includes the cluster; Atlas has no password rotation, "
        "federated / workload identity (OIDC, AWS IAM, X.509) is recommended.",
    ),
    _auto(
        "sec.encryption.customer-managed-keys",
        S,
        "Encryption at rest uses customer-managed keys (BYOK)",
        WARN,
        DOC_ENCRYPTION,
        "Cluster encryptionAtRestProvider vs policy encryption.require_customer_managed_keys.",
    ),
    _auto(
        "sec.audit.enabled",
        S,
        "Database auditing enabled for the project",
        FAIL,
        DOC_AUDIT,
        "Project auditing configuration (needs Project Owner to read).",
    ),
    _auto(
        "sec.hardening.server-side-javascript-disabled",
        S,
        "Server-side JavaScript disabled",
        WARN,
        DOC_SERVER_JS,
        "Cluster advanced configuration javascriptEnabled.",
    ),
    # --- reliability --------------------------------------------------------------------------
    _auto(
        "rel.ha.electable-nodes",
        R,
        "Every shard has at least the policy minimum of electable nodes",
        FAIL,
        DOC_HA,
        "Sum of electableSpecs.nodeCount per replication spec vs policy ha.min_electable_nodes.",
    ),
    _auto(
        "rel.ha.regions",
        R,
        "Cluster spans at least the policy minimum of regions",
        WARN,
        DOC_HA,
        "Distinct regions in replicationSpecs vs policy ha.min_regions.",
    ),
    _auto(
        "rel.protection.termination-protection",
        R,
        "Termination protection enabled",
        FAIL,
        DOC_HA,
        "Cluster terminationProtectionEnabled.",
    ),
    _auto(
        "rel.backup.enabled",
        R,
        "Cloud Backup enabled",
        FAIL,
        DOC_BACKUPS,
        "Cluster backupEnabled.",
    ),
    _auto(
        "rel.backup.continuous",
        R,
        "Continuous Cloud Backup (point-in-time restore) enabled",
        FAIL,
        DOC_BACKUPS,
        "Cluster pitEnabled.",
    ),
    _auto(
        "rel.backup.restore-window",
        R,
        "Point-in-time restore window meets the policy RPO",
        WARN,
        DOC_BACKUPS,
        "Backup schedule restoreWindowDays vs policy backup.restore_window_days.",
    ),
    _auto(
        "rel.backup.schedule",
        R,
        "Snapshot schedule covers the policy frequencies",
        WARN,
        DOC_BACKUPS,
        "Backup schedule policy item frequency types vs policy backup.required_frequencies.",
    ),
    _auto(
        "rel.backup.snapshot-copy",
        R,
        "Snapshots copied to another region",
        WARN,
        DOC_DR,
        "Backup schedule copySettings vs policy backup.require_snapshot_copy.",
    ),
    _auto(
        "rel.backup.compliance-policy",
        R,
        "Backup Compliance Policy active",
        WARN,
        DOC_BACKUPS,
        "Project backup compliance policy state vs policy backup.require_compliance_policy.",
    ),
    _auto(
        "rel.maintenance.window",
        R,
        "Maintenance window defined",
        WARN,
        DOC_MAINTENANCE,
        "Project maintenanceWindow dayOfWeek / hourOfDay.",
    ),
    _auto(
        "rel.maintenance.protected-hours",
        R,
        "Protected hours defined",
        WARN,
        DOC_MAINTENANCE,
        "Project maintenanceWindow protectedHours.",
    ),
    _auto(
        "rel.version.minimum",
        R,
        "MongoDB major version at or above the policy floor",
        WARN,
        DOC_HA,
        "Cluster mongoDBMajorVersion vs policy cluster.min_mongodb_major.",
    ),
    # --- operational efficiency ---------------------------------------------------------------
    _auto(
        "ops.tags.required",
        OE,
        "Cluster carries every required tag",
        WARN,
        DOC_TAGS,
        "Cluster tags vs policy tags.required (application, environment, contact, criticality).",
    ),
    _auto(
        "ops.alerts.recommended",
        OE,
        "Recommended alerts configured and enabled",
        WARN,
        DOC_MONITORING,
        "Project alert configurations vs policy alerts.required.",
    ),
    _auto(
        "ops.integrations.observability",
        OE,
        "Metrics exported to the observability stack",
        WARN,
        DOC_MONITORING,
        "Project third-party integrations vs policy integrations.required.",
    ),
    _auto(
        "ops.project.advisors-enabled",
        OE,
        "Performance Advisor, Schema Advisor and Real-Time Performance Panel enabled",
        WARN,
        DOC_PERF_ADVISOR,
        "Project settings isPerformanceAdvisorEnabled / isSchemaAdvisorEnabled / "
        "isRealtimePerformancePanelEnabled.",
    ),
    # --- performance --------------------------------------------------------------------------
    _auto(
        "perf.autoscaling.compute",
        P,
        "Compute autoscaling enabled",
        WARN,
        DOC_SCALABILITY,
        "regionConfigs autoScaling.compute.enabled vs policy "
        "performance.require_compute_autoscaling.",
    ),
    _auto(
        "perf.autoscaling.disk",
        P,
        "Storage autoscaling enabled",
        WARN,
        DOC_SCALABILITY,
        "regionConfigs autoScaling.diskGB.enabled vs policy performance.require_disk_autoscaling.",
    ),
    _auto(
        "perf.advisor.suggested-indexes",
        P,
        "Performance Advisor has no outstanding index suggestions",
        WARN,
        DOC_PERF_ADVISOR,
        "Cluster performanceAdvisor/suggestedIndexes count vs policy "
        "performance.max_suggested_indexes (needs Project Data Access Read Only).",
    ),
    _auto(
        "perf.config.default-max-time-ms",
        P,
        "Cluster-level default query timeout set",
        WARN,
        DOC_MAX_TIME,
        "Cluster advanced configuration defaultMaxTimeMS vs policy "
        "performance.require_default_max_time_ms.",
    ),
    # --- cost optimization --------------------------------------------------------------------
    _auto(
        "cost.backup.retention",
        C,
        "Snapshot retention within the policy ceiling",
        WARN,
        DOC_COST,
        "Longest backup policy item retention vs policy cost.max_snapshot_retention_days.",
    ),
)

DISCUSS_CHECKS: tuple[CheckSpec, ...] = (
    _discuss(
        "ops.discuss.org-structure",
        OE,
        "Organization / project layout and prod vs non-prod isolation",
        DOC_HIERARCHY,
        "Agree how projects map to business unit, application or environment, and that "
        "production and non-production never share a project.",
    ),
    _discuss(
        "ops.discuss.infrastructure-as-code",
        OE,
        "Clusters, tags and alert rules provisioned through Terraform",
        DOC_AUTOMATION,
        "Confirm the cluster, its tags, alert configurations and maintenance window are managed "
        "as code and drift is detected.",
    ),
    _discuss(
        "ops.discuss.roles-and-change-control",
        OE,
        "Roles, responsibilities and change control for Atlas",
        DOC_CHECKLIST,
        "Who owns the org, projects, keys and clusters; how changes are approved and audited.",
    ),
    _discuss(
        "ops.discuss.support-and-training",
        OE,
        "MongoDB Support engagement process and team training",
        DOC_CHECKLIST,
        "How production issues reach MongoDB Support; which team members have completed Atlas "
        "fundamentals and security training.",
    ),
    _discuss(
        "ops.discuss.developer-access",
        OE,
        "Developer tooling and access model",
        DOC_CHECKLIST,
        "How developers connect (Compass, mongosh, Atlas CLI, MCP Server) and with which roles.",
    ),
    _discuss(
        "sec.discuss.federated-authentication",
        S,
        "Federated authentication for the Atlas UI and database access",
        DOC_AUTH,
        "Plan for workforce identity (SAML/OIDC) on the control plane and workload identity "
        "(OIDC, AWS IAM, X.509) on the data plane; Atlas does not rotate passwords.",
    ),
    _discuss(
        "sec.discuss.field-level-encryption",
        S,
        "Client-Side Field Level Encryption / Queryable Encryption for sensitive fields",
        DOC_CSFLE,
        "Which fields need CSFLE or Queryable Encryption, where keys live, and that exports of "
        "encrypted data must go through a driver-based application (mongoexport and Atlas Data "
        "Federation cannot decrypt).",
    ),
    _discuss(
        "sec.discuss.certificate-authority",
        S,
        "No pinned or hard-coded certificate authority in applications",
        DOC_CA,
        "Atlas rotates certificates; confirm drivers rely on the system trust store.",
    ),
    _discuss(
        "sec.discuss.compliance-standards",
        S,
        "Applicable compliance standards identified",
        DOC_COMPLIANCE,
        "ISO/IEC 27001, PCI DSS, GDPR, local regulation: which apply and what evidence is needed.",
    ),
    _discuss(
        "rel.discuss.rpo-rto",
        R,
        "RPO and RTO documented per application",
        DOC_DR,
        "Recovery objectives drive backup frequency, restore window and multi-region choices.",
    ),
    _discuss(
        "rel.discuss.dr-runbook-and-drill",
        R,
        "Disaster recovery runbook written and restore drill performed",
        DOC_DR,
        "A snapshot restore and a point-in-time restore have been rehearsed and timed.",
    ),
    _discuss(
        "rel.discuss.failover-and-retryable-writes",
        R,
        "Applications survive a primary failover",
        DOC_TEST_FAILOVER,
        "Retryable writes and reads enabled in drivers; Test Failover run against the cluster.",
    ),
    _discuss(
        "perf.discuss.schema-and-index-review",
        P,
        "Schema and index review cadence",
        DOC_PERF_ADVISOR,
        "Query Profiler, Explain Plans and Performance Advisor reviewed before major releases; "
        "the regex-finder gate in CI covers index-hostile $regex.",
    ),
    _discuss(
        "perf.discuss.read-locality-and-sharding",
        P,
        "Read preference locality and sharding strategy",
        DOC_SCALABILITY,
        "Whether reads should target the nearest region and when the workload needs sharding.",
    ),
    _discuss(
        "cost.discuss.idle-and-oversized",
        C,
        "Idle and oversized clusters reviewed",
        DOC_COST,
        "Pause or scale down unused non-production clusters; review tier vs actual utilisation.",
    ),
    _discuss(
        "cost.discuss.data-lifecycle",
        C,
        "Data lifecycle: TTL indexes and Online Archive",
        DOC_ONLINE_ARCHIVE,
        "Archival decisions belong to the application team; confirm they exist.",
    ),
    _discuss(
        "cost.discuss.billing-visibility",
        C,
        "Billing data and cost allocation by tag",
        DOC_BILLING,
        "Invoices or billing exports broken down by the tags this report requires.",
    ),
)

CATALOG: tuple[CheckSpec, ...] = AUTO_CHECKS + DISCUSS_CHECKS
BY_ID: Mapping[str, CheckSpec] = {spec.id: spec for spec in CATALOG}
