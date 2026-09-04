"""Landing-zone policy: what "good" means for this organisation.

The catalog says *what* to check; the policy says *how strict*. Defaults are MongoDB's published
recommendations (Architecture Center). A customer file only overrides what differs, and every
``auto`` check can be set to ``fail``, ``warn`` or ``off``.

One flat file per environment (``landing-zone.prod.yaml``, ``landing-zone.nonprod.yaml``) is
deliberately simpler than nested environment blocks: the report is per cluster, so the caller
already knows which environment it is scoring.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

import yaml

from mongoops.waf_check.catalog import AUTO_CHECKS, BY_ID
from mongoops.waf_check.model import Kind, Severity

NETWORK_MODES = ("private_endpoint", "peering", "ip_allowlist")
TLS_VERSIONS = ("TLS1_0", "TLS1_1", "TLS1_2", "TLS1_3")
FREQUENCIES = ("hourly", "daily", "weekly", "monthly", "yearly")


class PolicyError(ValueError):
    """Malformed or inconsistent policy file; message is meant for the operator."""


@dataclass(frozen=True, slots=True)
class AlertRequirement:
    event: str
    metric: str = ""

    def matches(self, config: Mapping[str, Any]) -> bool:
        if not config.get("enabled", False) or config.get("eventTypeName") != self.event:
            return False
        if not self.metric:
            return True
        metric = (config.get("metricThreshold") or {}).get("metricName", "")
        return str(metric) == self.metric

    @property
    def label(self) -> str:
        return f"{self.event}/{self.metric}" if self.metric else self.event


# Recommended alerts (Architecture Center, monitoring guidance) plus the metrics the customer
# named as key monitoring areas. Names are Atlas alert metric names; a wrong name simply shows
# up as "missing", so the list is safe to tune.
DEFAULT_ALERTS: tuple[AlertRequirement, ...] = (
    AlertRequirement("OUTSIDE_METRIC_THRESHOLD", "CONNECTIONS_PERCENT"),
    AlertRequirement("OUTSIDE_METRIC_THRESHOLD", "NORMALIZED_SYSTEM_CPU_USER"),
    AlertRequirement("OUTSIDE_METRIC_THRESHOLD", "DISK_PARTITION_SPACE_USED_DATA"),
    AlertRequirement("OUTSIDE_METRIC_THRESHOLD", "DISK_PARTITION_IOPS_TOTAL_DATA"),
    AlertRequirement("OUTSIDE_METRIC_THRESHOLD", "QUERY_TARGETING_SCANNED_OBJECTS_PER_RETURNED"),
    AlertRequirement("OUTSIDE_METRIC_THRESHOLD", "OPLOG_SLAVE_LAG_MASTER_TIME"),
    AlertRequirement("REPLICATION_OPLOG_WINDOW_RUNNING_OUT"),
    AlertRequirement("NO_PRIMARY"),
    AlertRequirement("HOST_DOWN"),
)


@dataclass(frozen=True, slots=True)
class Policy:
    profile: str = "mongodb-defaults"
    network_mode: str = "private_endpoint"
    network_min_cidr_prefix: int = 24
    tls_minimum: str = "TLS1_2"
    auth_allow_password_users: bool = False
    encryption_require_customer_managed_keys: bool = True
    ha_min_electable_nodes: int = 3
    ha_min_regions: int = 1
    backup_restore_window_days: int = 7
    backup_required_frequencies: tuple[str, ...] = ("daily", "weekly", "monthly")
    backup_require_snapshot_copy: bool = False
    backup_require_compliance_policy: bool = False
    cluster_min_mongodb_major: str = "7.0"
    tags_required: tuple[str, ...] = ("application", "environment", "contact", "criticality")
    alerts_required: tuple[AlertRequirement, ...] = DEFAULT_ALERTS
    integrations_required: tuple[str, ...] = ()
    performance_require_compute_autoscaling: bool = True
    performance_require_disk_autoscaling: bool = True
    performance_max_suggested_indexes: int = 0
    performance_require_default_max_time_ms: bool = False
    cost_max_snapshot_retention_days: int = 365
    severities: Mapping[str, Severity] = field(
        default_factory=lambda: {c.id: c.default_severity for c in AUTO_CHECKS}
    )

    def severity(self, check_id: str) -> Severity:
        return self.severities.get(check_id, BY_ID[check_id].default_severity)


DEFAULT_POLICY = Policy()


# --- loading ------------------------------------------------------------------------------------

_SECTIONS = (
    "profile",
    "network",
    "tls",
    "auth",
    "encryption",
    "ha",
    "backup",
    "cluster",
    "tags",
    "alerts",
    "integrations",
    "performance",
    "cost",
    "checks",
)


def load_policy(path: Path) -> Policy:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise PolicyError(f"cannot read policy {path}: {exc}") from exc
    return policy_from_mapping(raw if raw is not None else {})


def policy_from_mapping(data: Any) -> Policy:
    """Build a ``Policy`` from a parsed YAML/JSON document, validating keys and values. Pure."""
    if not isinstance(data, Mapping):
        raise PolicyError("policy must be a mapping at the top level")
    unknown = sorted(set(data) - set(_SECTIONS))
    if unknown:
        raise PolicyError(f"unknown policy section(s): {', '.join(unknown)}")

    d = DEFAULT_POLICY
    network = _section(data, "network")
    tls = _section(data, "tls")
    auth = _section(data, "auth")
    enc = _section(data, "encryption")
    ha = _section(data, "ha")
    backup = _section(data, "backup")
    cluster = _section(data, "cluster")
    tags = _section(data, "tags")
    alerts = _section(data, "alerts")
    integrations = _section(data, "integrations")
    perf = _section(data, "performance")
    cost = _section(data, "cost")

    policy = replace(
        d,
        profile=str(data.get("profile", d.profile)),
        network_mode=_choice(network.get("mode", d.network_mode), NETWORK_MODES, "network.mode"),
        network_min_cidr_prefix=_int(
            network.get("min_cidr_prefix", d.network_min_cidr_prefix), "network.min_cidr_prefix"
        ),
        tls_minimum=_choice(tls.get("minimum", d.tls_minimum), TLS_VERSIONS, "tls.minimum"),
        auth_allow_password_users=_bool(
            auth.get("allow_password_users", d.auth_allow_password_users),
            "auth.allow_password_users",
        ),
        encryption_require_customer_managed_keys=_bool(
            enc.get("require_customer_managed_keys", d.encryption_require_customer_managed_keys),
            "encryption.require_customer_managed_keys",
        ),
        ha_min_electable_nodes=_int(
            ha.get("min_electable_nodes", d.ha_min_electable_nodes), "ha.min_electable_nodes"
        ),
        ha_min_regions=_int(ha.get("min_regions", d.ha_min_regions), "ha.min_regions"),
        backup_restore_window_days=_int(
            backup.get("restore_window_days", d.backup_restore_window_days),
            "backup.restore_window_days",
        ),
        backup_required_frequencies=tuple(
            _choice(f, FREQUENCIES, "backup.required_frequencies")
            for f in _list(
                backup.get("required_frequencies", d.backup_required_frequencies),
                "backup.required_frequencies",
            )
        ),
        backup_require_snapshot_copy=_bool(
            backup.get("require_snapshot_copy", d.backup_require_snapshot_copy),
            "backup.require_snapshot_copy",
        ),
        backup_require_compliance_policy=_bool(
            backup.get("require_compliance_policy", d.backup_require_compliance_policy),
            "backup.require_compliance_policy",
        ),
        cluster_min_mongodb_major=str(
            cluster.get("min_mongodb_major", d.cluster_min_mongodb_major)
        ),
        tags_required=tuple(
            str(t).lower() for t in _list(tags.get("required", d.tags_required), "tags.required")
        ),
        alerts_required=tuple(
            _alert(item) for item in _list(alerts.get("required", None), "alerts.required")
        )
        if "required" in alerts
        else d.alerts_required,
        integrations_required=tuple(
            str(i).upper()
            for i in _list(
                integrations.get("required", d.integrations_required), "integrations.required"
            )
        ),
        performance_require_compute_autoscaling=_bool(
            perf.get("require_compute_autoscaling", d.performance_require_compute_autoscaling),
            "performance.require_compute_autoscaling",
        ),
        performance_require_disk_autoscaling=_bool(
            perf.get("require_disk_autoscaling", d.performance_require_disk_autoscaling),
            "performance.require_disk_autoscaling",
        ),
        performance_max_suggested_indexes=_int(
            perf.get("max_suggested_indexes", d.performance_max_suggested_indexes),
            "performance.max_suggested_indexes",
        ),
        performance_require_default_max_time_ms=_bool(
            perf.get("require_default_max_time_ms", d.performance_require_default_max_time_ms),
            "performance.require_default_max_time_ms",
        ),
        cost_max_snapshot_retention_days=_int(
            cost.get("max_snapshot_retention_days", d.cost_max_snapshot_retention_days),
            "cost.max_snapshot_retention_days",
        ),
        severities=_severities(_section(data, "checks")),
    )
    _parse_version(policy.cluster_min_mongodb_major, "cluster.min_mongodb_major")
    return policy


def _section(data: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    value = data.get(key)
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise PolicyError(f"{key} must be a mapping")
    return value


def _choice(value: Any, allowed: Sequence[str], where: str) -> str:
    text = str(value)
    if text not in allowed:
        raise PolicyError(f"{where}: {text!r} is not one of {', '.join(allowed)}")
    return text


def _int(value: Any, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise PolicyError(f"{where}: expected a non-negative integer, got {value!r}")
    return value


def _bool(value: Any, where: str) -> bool:
    if not isinstance(value, bool):
        raise PolicyError(f"{where}: expected true/false, got {value!r}")
    return value


def _list(value: Any, where: str) -> Sequence[Any]:
    if value is None:
        return ()
    if isinstance(value, str | Mapping):
        raise PolicyError(f"{where}: expected a list")
    return tuple(value)


def _alert(item: Any) -> AlertRequirement:
    if isinstance(item, str):
        event, _, metric = item.partition("/")
        return AlertRequirement(event, metric)
    if isinstance(item, Mapping) and "event" in item:
        return AlertRequirement(str(item["event"]), str(item.get("metric", "")))
    raise PolicyError(
        f"alerts.required: expected 'EVENT' / 'EVENT/METRIC' or {{event, metric}}, got {item!r}"
    )


def _severities(overrides: Mapping[str, Any]) -> dict[str, Severity]:
    result = {c.id: c.default_severity for c in AUTO_CHECKS}
    for check_id, value in overrides.items():
        spec = BY_ID.get(str(check_id))
        if spec is None or spec.kind is not Kind.AUTO:
            raise PolicyError(
                f"checks: {check_id!r} is not an auto check; run `mongoops waf-check checks`"
            )
        # YAML 1.1 reads a bare `off` as boolean false; people will type it, so accept it.
        text = "off" if value is False else str(value).lower()
        try:
            result[spec.id] = Severity(text)
        except ValueError as exc:
            raise PolicyError(f"checks.{check_id}: severity must be fail, warn or off") from exc
    return result


def _parse_version(text: str, where: str) -> tuple[int, ...]:
    try:
        return tuple(int(part) for part in text.split("."))
    except ValueError as exc:
        raise PolicyError(f"{where}: expected a version like 7.0, got {text!r}") from exc


def version_tuple(text: str) -> tuple[int, ...]:
    """``"8.0"`` -> ``(8, 0)``; tolerant of trailing junk like ``"8.0.4-ent"``."""
    parts: list[int] = []
    for piece in text.split("."):
        digits = "".join(ch for ch in piece if ch.isdigit())
        if not digits:
            break
        parts.append(int(digits))
    return tuple(parts)


# --- writing ------------------------------------------------------------------------------------


def render_policy_yaml(policy: Policy = DEFAULT_POLICY) -> str:
    """Commented landing-zone file. Every knob is listed so the customer can see what to tune."""
    y = _yaml_scalar
    freqs = ", ".join(policy.backup_required_frequencies)
    tags = ", ".join(policy.tags_required)
    integrations = ", ".join(policy.integrations_required)
    alerts = "\n".join(f"    - {a.label}" for a in policy.alerts_required)
    checks = "\n".join(
        f"  {spec.id}: {policy.severity(spec.id).value}"
        + (
            ""
            if policy.severity(spec.id) is spec.default_severity
            else "  # default: " + spec.default_severity.value
        )
        for spec in AUTO_CHECKS
    )
    return f"""# mongoops waf-check landing-zone policy
# Baseline: MongoDB Atlas operational-readiness checklist and Architecture Center defaults.
# Edit what differs for your landing zone; delete nothing you do not care about, defaults apply.
# One file per environment is the intended pattern (e.g. landing-zone.prod.yaml).
profile: {y(policy.profile)}

network:
  # private_endpoint: cluster must have a private endpoint attached
  # peering:          private endpoint or VPC/VNet peering is acceptable
  # ip_allowlist:     public access list only (0.0.0.0/0 is still a failure)
  mode: {policy.network_mode}
  # access list entries broader than this prefix length are reported (24 = /24)
  min_cidr_prefix: {policy.network_min_cidr_prefix}

tls:
  minimum: {policy.tls_minimum}          # TLS1_2 or TLS1_3

auth:
  # Atlas does not rotate database passwords; false means SCRAM users are reported.
  allow_password_users: {y(policy.auth_allow_password_users)}

encryption:
  # BYOK via AWS KMS / Azure Key Vault / GCP KMS
  require_customer_managed_keys: {y(policy.encryption_require_customer_managed_keys)}

ha:
  min_electable_nodes: {policy.ha_min_electable_nodes}
  min_regions: {policy.ha_min_regions}            # 2+ for multi-region resilience

backup:
  restore_window_days: {policy.backup_restore_window_days}   # point-in-time window, from RPO
  required_frequencies: [{freqs}]
  require_snapshot_copy: {y(policy.backup_require_snapshot_copy)}   # copies to another region
  # Backup Compliance Policy (irreversible once enabled)
  require_compliance_policy: {y(policy.backup_require_compliance_policy)}

cluster:
  min_mongodb_major: "{policy.cluster_min_mongodb_major}"

tags:
  required: [{tags}]

alerts:
  # EVENT or EVENT/METRIC as shown in the Atlas alert configuration
  required:
{alerts}

integrations:
  # e.g. [DATADOG, PROMETHEUS, PAGER_DUTY]; empty list = not checked
  required: [{integrations}]

performance:
  require_compute_autoscaling: {y(policy.performance_require_compute_autoscaling)}
  require_disk_autoscaling: {y(policy.performance_require_disk_autoscaling)}
  max_suggested_indexes: {policy.performance_max_suggested_indexes}
  require_default_max_time_ms: {y(policy.performance_require_default_max_time_ms)}

cost:
  max_snapshot_retention_days: {policy.cost_max_snapshot_retention_days}

# Severity of every automatic check when it does not pass: fail, warn or off
# (write "off" with quotes if your YAML tooling complains; bare off is accepted too).
checks:
{checks}
"""


def _yaml_scalar(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    text = str(value)
    return text if text.replace("-", "").replace("_", "").isalnum() else f'"{text}"'
