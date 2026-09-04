"""Evaluators: ``Facts`` x ``Policy`` -> ``Outcome`` per auto check. Pure, one function per id.

Conventions:

* A fact that could not be read yields ``unavailable`` (UNKNOWN), never a failure.
* Controls that do not exist on shared tiers (M0/M2/M5/Flex) yield ``not_applicable``.
* Checks the policy switched off by value (e.g. ``require_snapshot_copy: false``) also yield
  ``not_applicable`` so the report shows *why* nothing was evaluated.
* ``evidence`` carries the raw values used, so a reader can verify without opening Atlas.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from mongoops.waf_check.catalog import AUTO_CHECKS, DISCUSS_CHECKS
from mongoops.waf_check.facts import Fact, Facts, region_configs
from mongoops.waf_check.model import CheckResult, Outcome, discussion, resolve
from mongoops.waf_check.policy import Policy, version_tuple

Evaluator = Callable[[Facts, Policy], Outcome]


def evaluate(facts: Facts, policy: Policy) -> tuple[CheckResult, ...]:
    """Run every catalog check. Auto checks first (in catalog order), then discussion items."""
    auto = tuple(
        resolve(spec, EVALUATORS[spec.id](facts, policy), policy.severity(spec.id))
        for spec in AUTO_CHECKS
    )
    return auto + tuple(discussion(spec) for spec in DISCUSS_CHECKS)


# --- helpers ------------------------------------------------------------------------------------


def _unavailable(fact: Fact) -> Outcome:
    return Outcome(None, "", unavailable=fact.error)


def _na(reason: str, **evidence: Any) -> Outcome:
    return Outcome(None, "", evidence=evidence, not_applicable=reason)


def _shared(facts: Facts, control: str) -> Outcome | None:
    if facts.shared_tier:
        return _na(f"{control} is not available on shared / Flex tiers")
    return None


def _tags(cluster: Mapping[str, Any]) -> dict[str, str]:
    return {
        str(t.get("key", "")).lower(): str(t.get("value", ""))
        for t in cluster.get("tags") or []
        if isinstance(t, Mapping)
    }


def _electable_per_spec(cluster: Mapping[str, Any]) -> tuple[int, ...]:
    return tuple(
        sum(
            int((rc.get("electableSpecs") or {}).get("nodeCount") or 0)
            for rc in (spec.get("regionConfigs") or [])
        )
        for spec in cluster.get("replicationSpecs") or []
    )


def _autoscaling(cluster: Mapping[str, Any], key: str) -> tuple[bool, ...]:
    return tuple(
        bool(((rc.get("autoScaling") or {}).get(key) or {}).get("enabled", False))
        for rc in region_configs(cluster)
        if int((rc.get("electableSpecs") or {}).get("nodeCount") or 0) > 0
    )


def _cidr(entry: Mapping[str, Any]) -> str:
    return str(
        entry.get("cidrBlock") or (f"{entry['ipAddress']}/32" if entry.get("ipAddress") else "")
    )


def _user_in_scope(user: Mapping[str, Any], cluster_name: str) -> bool:
    scopes = user.get("scopes") or []
    return not scopes or any(
        s.get("type") == "CLUSTER" and s.get("name") == cluster_name for s in scopes
    )


def _is_password_user(user: Mapping[str, Any]) -> bool:
    if user.get("databaseName") != "admin":
        return False  # $external: X.509, LDAP, OIDC or AWS IAM
    return all(
        str(user.get(k, "NONE")) in ("NONE", "")
        for k in ("awsIAMType", "ldapAuthType", "oidcAuthType", "x509Type")
    )


# --- security -----------------------------------------------------------------------------------


def no_open_access(facts: Facts, _: Policy) -> Outcome:
    if not facts.access_list.available:
        return _unavailable(facts.access_list)
    entries = tuple(_cidr(e) for e in facts.access_list.value)
    open_entries = tuple(c for c in entries if c in ("0.0.0.0/0", "::/0"))
    return Outcome(
        ok=not open_entries,
        message=(
            f"{len(open_entries)} entry(ies) allow the whole internet"
            if open_entries
            else f"{len(entries)} access list entry(ies), none open"
        ),
        evidence={"open_entries": open_entries, "entry_count": len(entries)},
        remedy="Remove 0.0.0.0/0 from Network Access and use Private Endpoints or explicit CIDRs.",
    )


def private_connectivity(facts: Facts, policy: Policy) -> Outcome:
    strings = facts.cluster.get("connectionStrings") or {}
    private_endpoints = tuple(strings.get("privateEndpoint") or ())
    peering = bool(strings.get("private") or strings.get("privateSrv"))
    evidence = {
        "private_endpoints": len(private_endpoints),
        "peering_connection_string": peering,
        "policy_mode": policy.network_mode,
    }
    if policy.network_mode == "ip_allowlist":
        return _na("policy network.mode is ip_allowlist", **evidence)
    if facts.shared_tier:
        return _na("private connectivity is not available on shared / Flex tiers", **evidence)
    ok = bool(private_endpoints) or (policy.network_mode == "peering" and peering)
    return Outcome(
        ok=ok,
        message=(
            "private endpoint attached"
            if private_endpoints
            else "VPC/VNet peering in place"
            if ok
            else "cluster is only reachable over the public access list"
        ),
        evidence=evidence,
        remedy=(
            "Create a Private Endpoint (AWS PrivateLink / Azure Private Link / GCP PSC) and attach "
            "it to the project."
            if policy.network_mode == "private_endpoint"
            else "Set up a Private Endpoint or VPC/VNet peering for the cluster's region."
        ),
    )


def access_list_scoped(facts: Facts, policy: Policy) -> Outcome:
    if not facts.access_list.available:
        return _unavailable(facts.access_list)
    broad = tuple(
        c
        for c in (_cidr(e) for e in facts.access_list.value)
        if c and c not in ("0.0.0.0/0", "::/0") and _prefix(c) < policy.network_min_cidr_prefix
    )
    return Outcome(
        ok=not broad,
        message=(
            f"{len(broad)} entry(ies) broader than /{policy.network_min_cidr_prefix}"
            if broad
            else f"all entries at /{policy.network_min_cidr_prefix} or narrower"
        ),
        evidence={"broad_entries": broad, "min_prefix": policy.network_min_cidr_prefix},
        remedy="Replace wide ranges with the specific application subnets or a Private Endpoint.",
    )


def _prefix(cidr: str) -> int:
    try:
        return int(ipaddress.ip_network(cidr, strict=False).prefixlen)
    except ValueError:
        return 128


def tls_minimum(facts: Facts, policy: Policy) -> Outcome:
    if (na := _shared(facts, "advanced configuration")) is not None:
        return na
    if not facts.process_args.available:
        return _unavailable(facts.process_args)
    current = str((facts.process_args.value or {}).get("minimumEnabledTlsProtocol") or "TLS1_2")
    ok = _tls_rank(current) >= _tls_rank(policy.tls_minimum)
    return Outcome(
        ok=ok,
        message=f"minimum TLS is {current}",
        evidence={"minimumEnabledTlsProtocol": current, "policy": policy.tls_minimum},
        remedy=f"Set the minimum TLS protocol to {policy.tls_minimum} in Additional Settings.",
    )


def _tls_rank(name: str) -> int:
    return {"TLS1_0": 0, "TLS1_1": 1, "TLS1_2": 2, "TLS1_3": 3}.get(name, 2)


def no_password_users(facts: Facts, policy: Policy) -> Outcome:
    if not facts.database_users.available:
        return _unavailable(facts.database_users)
    users = tuple(u for u in facts.database_users.value if _user_in_scope(u, facts.cluster_name))
    scram = tuple(str(u.get("username")) for u in users if _is_password_user(u))
    evidence = {"users_in_scope": len(users), "password_users": scram}
    if policy.auth_allow_password_users:
        return _na("policy auth.allow_password_users is true", **evidence)
    return Outcome(
        ok=not scram,
        message=(
            f"{len(scram)} of {len(users)} user(s) authenticate with a password"
            if scram
            else f"{len(users)} user(s) in scope, none password-based"
        ),
        evidence=evidence,
        remedy=(
            "Move applications to workload identity (OIDC, AWS IAM or X.509) and people to "
            "federated login; Atlas cannot rotate or expire SCRAM passwords."
        ),
    )


def customer_managed_keys(facts: Facts, policy: Policy) -> Outcome:
    provider = str(facts.cluster.get("encryptionAtRestProvider") or "NONE")
    evidence = {"encryptionAtRestProvider": provider}
    if not policy.encryption_require_customer_managed_keys:
        return _na("policy encryption.require_customer_managed_keys is false", **evidence)
    if (na := _shared(facts, "customer key management")) is not None:
        return na
    return Outcome(
        ok=provider != "NONE",
        message=(
            f"customer-managed keys via {provider}"
            if provider != "NONE"
            else "Atlas-managed disk encryption only"
        ),
        evidence=evidence,
        remedy="Enable Encryption at Rest using Customer Key Management (AWS KMS, Azure Key "
        "Vault or GCP KMS) on the project, then on the cluster.",
    )


def audit_enabled(facts: Facts, _: Policy) -> Outcome:
    if (na := _shared(facts, "database auditing")) is not None:
        return na
    if not facts.audit.available:
        return _unavailable(facts.audit)
    audit = facts.audit.value or {}
    enabled = bool(audit.get("enabled", False))
    return Outcome(
        ok=enabled,
        message="auditing enabled" if enabled else "auditing disabled for the project",
        evidence={
            "enabled": enabled,
            "configurationType": audit.get("configurationType"),
            "auditAuthorizationSuccess": audit.get("auditAuthorizationSuccess"),
        },
        remedy="Enable Database Auditing in Project Settings and define an audit filter.",
    )


def server_side_js_disabled(facts: Facts, _: Policy) -> Outcome:
    if (na := _shared(facts, "advanced configuration")) is not None:
        return na
    if not facts.process_args.available:
        return _unavailable(facts.process_args)
    enabled = bool((facts.process_args.value or {}).get("javascriptEnabled", True))
    return Outcome(
        ok=not enabled,
        message="server-side JavaScript enabled" if enabled else "server-side JavaScript disabled",
        evidence={"javascriptEnabled": enabled},
        remedy="Disable server-side JavaScript in Additional Settings unless $where / $function "
        "is required.",
    )


# --- reliability --------------------------------------------------------------------------------


def electable_nodes(facts: Facts, policy: Policy) -> Outcome:
    counts = _electable_per_spec(facts.cluster)
    if not counts:
        return Outcome(None, "", unavailable="cluster document has no replicationSpecs")
    low = tuple(c for c in counts if c < policy.ha_min_electable_nodes)
    return Outcome(
        ok=not low,
        message=f"electable nodes per shard: {', '.join(map(str, counts))}",
        evidence={"electable_per_spec": counts, "minimum": policy.ha_min_electable_nodes},
        remedy=f"Raise electable nodes to at least {policy.ha_min_electable_nodes} per shard.",
    )


def regions(facts: Facts, policy: Policy) -> Outcome:
    names = tuple(
        sorted(
            {
                str(rc.get("regionName"))
                for rc in region_configs(facts.cluster)
                if int((rc.get("electableSpecs") or {}).get("nodeCount") or 0) > 0
            }
        )
    )
    return Outcome(
        ok=len(names) >= policy.ha_min_regions,
        message=f"{len(names)} region(s) with electable nodes: {', '.join(names)}",
        evidence={"regions": names, "minimum": policy.ha_min_regions},
        remedy="Add electable nodes in another region to survive a regional outage.",
    )


def termination_protection(facts: Facts, _: Policy) -> Outcome:
    enabled = bool(facts.cluster.get("terminationProtectionEnabled", False))
    return Outcome(
        ok=enabled,
        message="termination protection on" if enabled else "cluster can be deleted in one click",
        evidence={"terminationProtectionEnabled": enabled},
        remedy="Enable Termination Protection on the cluster (Project Owner).",
    )


def backup_enabled(facts: Facts, _: Policy) -> Outcome:
    enabled = bool(facts.cluster.get("backupEnabled", False))
    return Outcome(
        ok=enabled,
        message="Cloud Backup enabled" if enabled else "backups are off",
        evidence={"backupEnabled": enabled},
        remedy="Turn on Cloud Backup for the cluster.",
    )


def backup_continuous(facts: Facts, _: Policy) -> Outcome:
    if (na := _shared(facts, "continuous cloud backup")) is not None:
        return na
    if not facts.cluster.get("backupEnabled", False):
        return _na("backups are off (see rel.backup.enabled)")
    enabled = bool(facts.cluster.get("pitEnabled", False))
    return Outcome(
        ok=enabled,
        message="point-in-time restore available" if enabled else "no point-in-time restore",
        evidence={"pitEnabled": enabled},
        remedy="Enable Continuous Cloud Backup on the cluster.",
    )


def restore_window(facts: Facts, policy: Policy) -> Outcome:
    if (na := _shared(facts, "continuous cloud backup")) is not None:
        return na
    if not facts.cluster.get("pitEnabled", False):
        return _na("continuous backup is off (see rel.backup.continuous)")
    if not facts.backup_schedule.available:
        return _unavailable(facts.backup_schedule)
    days = int((facts.backup_schedule.value or {}).get("restoreWindowDays") or 0)
    return Outcome(
        ok=days >= policy.backup_restore_window_days,
        message=f"restore window {days} day(s)",
        evidence={"restoreWindowDays": days, "policy_days": policy.backup_restore_window_days},
        remedy=f"Set the restore window to {policy.backup_restore_window_days} days or more.",
    )


def _policy_items(schedule: Mapping[str, Any] | None) -> tuple[Mapping[str, Any], ...]:
    return tuple(
        item
        for pol in (schedule or {}).get("policies") or []
        for item in (pol.get("policyItems") or [])
        if isinstance(item, Mapping)
    )


def backup_schedule(facts: Facts, policy: Policy) -> Outcome:
    if (na := _shared(facts, "snapshot schedules")) is not None:
        return na
    if not facts.cluster.get("backupEnabled", False):
        return _na("backups are off (see rel.backup.enabled)")
    if not facts.backup_schedule.available:
        return _unavailable(facts.backup_schedule)
    present = tuple(
        sorted(
            {
                str(i.get("frequencyType", "")).lower()
                for i in _policy_items(facts.backup_schedule.value)
            }
        )
    )
    missing = tuple(f for f in policy.backup_required_frequencies if f not in present)
    return Outcome(
        ok=not missing,
        message=f"snapshot frequencies: {', '.join(present) or 'none'}",
        evidence={"present": present, "missing": missing},
        remedy=f"Add {', '.join(missing)} snapshot policy item(s) with a retention that matches "
        "the business continuity requirement.",
    )


def snapshot_copy(facts: Facts, policy: Policy) -> Outcome:
    if not policy.backup_require_snapshot_copy:
        return _na("policy backup.require_snapshot_copy is false")
    if (na := _shared(facts, "snapshot distribution")) is not None:
        return na
    if not facts.backup_schedule.available:
        return _unavailable(facts.backup_schedule)
    schedule = facts.backup_schedule.value or {}
    copies = tuple(
        str(c.get("regionName", ""))
        for c in schedule.get("copySettings") or []
        if isinstance(c, Mapping)
    )
    return Outcome(
        ok=bool(copies),
        message=f"snapshots copied to {', '.join(copies)}" if copies else "no snapshot copies",
        evidence={"copy_regions": copies},
        remedy="Add a copy setting to a second region in the backup policy.",
    )


def compliance_policy(facts: Facts, policy: Policy) -> Outcome:
    if not policy.backup_require_compliance_policy:
        return _na("policy backup.require_compliance_policy is false")
    if not facts.compliance_policy.available:
        return _unavailable(facts.compliance_policy)
    state = str((facts.compliance_policy.value or {}).get("state") or "NONE")
    return Outcome(
        ok=state == "ACTIVE",
        message=f"backup compliance policy state {state}",
        evidence={"state": state},
        remedy="Enable the Backup Compliance Policy (irreversible; requires MongoDB Support to "
        "lift).",
    )


def maintenance_window(facts: Facts, _: Policy) -> Outcome:
    if not facts.maintenance_window.available:
        return _unavailable(facts.maintenance_window)
    mw = facts.maintenance_window.value or {}
    day, hour = mw.get("dayOfWeek"), mw.get("hourOfDay")
    defined = isinstance(day, int) and day > 0
    return Outcome(
        ok=defined,
        message=(
            f"maintenance window day {day} hour {hour} ({mw.get('timeZoneId') or 'UTC'})"
            if defined
            else "no maintenance window; Atlas picks the time"
        ),
        evidence={"dayOfWeek": day, "hourOfDay": hour, "timeZoneId": mw.get("timeZoneId")},
        remedy="Define a maintenance window outside business-critical hours.",
    )


def protected_hours(facts: Facts, _: Policy) -> Outcome:
    if not facts.maintenance_window.available:
        return _unavailable(facts.maintenance_window)
    ph = (facts.maintenance_window.value or {}).get("protectedHours") or {}
    defined = "startHourOfDay" in ph and "endHourOfDay" in ph
    return Outcome(
        ok=defined,
        message=(
            f"protected hours {ph.get('startHourOfDay')}-{ph.get('endHourOfDay')}"
            if defined
            else "no protected hours"
        ),
        evidence={"protectedHours": dict(ph)},
        remedy="Set protected hours so standard updates cannot start during peak traffic.",
    )


def version_minimum(facts: Facts, policy: Policy) -> Outcome:
    version = str(
        facts.cluster.get("mongoDBMajorVersion") or facts.cluster.get("mongoDBVersion") or ""
    )
    if not version:
        return Outcome(None, "", unavailable="cluster document has no MongoDB version")
    return Outcome(
        ok=version_tuple(version) >= version_tuple(policy.cluster_min_mongodb_major),
        message=f"MongoDB {version}",
        evidence={"version": version, "minimum": policy.cluster_min_mongodb_major},
        remedy=f"Plan the upgrade to MongoDB {policy.cluster_min_mongodb_major}+ within a "
        "maintenance window.",
    )


# --- operational efficiency ---------------------------------------------------------------------


def tags_required(facts: Facts, policy: Policy) -> Outcome:
    tags = _tags(facts.cluster)
    missing = tuple(t for t in policy.tags_required if t not in tags)
    return Outcome(
        ok=not missing,
        message=f"tags present: {', '.join(sorted(tags)) or 'none'}",
        evidence={"tags": tags, "missing": missing},
        remedy=f"Add tag(s) {', '.join(missing)} (ideally through Terraform so they cannot drift).",
    )


def alerts_recommended(facts: Facts, policy: Policy) -> Outcome:
    if not facts.alert_configs.available:
        return _unavailable(facts.alert_configs)
    configs: Sequence[Mapping[str, Any]] = facts.alert_configs.value
    missing = tuple(
        a.label for a in policy.alerts_required if not any(a.matches(c) for c in configs)
    )
    return Outcome(
        ok=not missing,
        message=(
            f"{len(missing)} of {len(policy.alerts_required)} recommended alert(s) missing"
            if missing
            else f"all {len(policy.alerts_required)} recommended alerts configured"
        ),
        evidence={"missing": missing, "configured": len(configs)},
        remedy="Create the missing alerts (Terraform mongodbatlas_alert_configuration) with "
        "notifications routed to the on-call tool.",
    )


def integrations_observability(facts: Facts, policy: Policy) -> Outcome:
    if not policy.integrations_required:
        return _na("policy integrations.required is empty")
    if not facts.integrations.available:
        return _unavailable(facts.integrations)
    present = tuple(sorted({str(i.get("type", "")).upper() for i in facts.integrations.value}))
    ok = any(t in present for t in policy.integrations_required)
    return Outcome(
        ok=ok,
        message=f"integrations: {', '.join(present) or 'none'}",
        evidence={"present": present, "required_any_of": policy.integrations_required},
        remedy=f"Configure one of {', '.join(policy.integrations_required)} under Project "
        "Integrations so Atlas metrics reach the observability stack.",
    )


def advisors_enabled(facts: Facts, _: Policy) -> Outcome:
    if not facts.project_settings.available:
        return _unavailable(facts.project_settings)
    settings = facts.project_settings.value or {}
    keys = (
        "isPerformanceAdvisorEnabled",
        "isSchemaAdvisorEnabled",
        "isRealtimePerformancePanelEnabled",
    )
    disabled = tuple(k for k in keys if not settings.get(k, True))
    return Outcome(
        ok=not disabled,
        message="all advisors enabled" if not disabled else f"disabled: {', '.join(disabled)}",
        evidence={k: settings.get(k) for k in keys},
        remedy="Re-enable the advisors in Project Settings; they are free and read-only.",
    )


# --- performance --------------------------------------------------------------------------------


def autoscaling_compute(facts: Facts, policy: Policy) -> Outcome:
    if not policy.performance_require_compute_autoscaling:
        return _na("policy performance.require_compute_autoscaling is false")
    if (na := _shared(facts, "autoscaling")) is not None:
        return na
    flags = _autoscaling(facts.cluster, "compute")
    return Outcome(
        ok=bool(flags) and all(flags),
        message="compute autoscaling on" if flags and all(flags) else "compute autoscaling off",
        evidence={"per_region": flags},
        remedy="Enable compute autoscaling with a max tier that fits the budget.",
    )


def autoscaling_disk(facts: Facts, policy: Policy) -> Outcome:
    if not policy.performance_require_disk_autoscaling:
        return _na("policy performance.require_disk_autoscaling is false")
    if (na := _shared(facts, "autoscaling")) is not None:
        return na
    flags = _autoscaling(facts.cluster, "diskGB")
    return Outcome(
        ok=bool(flags) and all(flags),
        message="storage autoscaling on" if flags and all(flags) else "storage autoscaling off",
        evidence={"per_region": flags},
        remedy="Enable storage autoscaling so a full disk does not become an outage.",
    )


def suggested_indexes(facts: Facts, policy: Policy) -> Outcome:
    if (na := _shared(facts, "Performance Advisor")) is not None:
        return na
    if not facts.suggested_indexes.available:
        return _unavailable(facts.suggested_indexes)
    body = facts.suggested_indexes.value or {}
    suggestions = tuple(body.get("suggestedIndexes") or [])
    namespaces = tuple(sorted({str(s.get("namespace", "")) for s in suggestions}))
    return Outcome(
        ok=len(suggestions) <= policy.performance_max_suggested_indexes,
        message=f"{len(suggestions)} suggested index(es)",
        evidence={"count": len(suggestions), "namespaces": namespaces},
        remedy="Review the suggestions in Performance Advisor and create the indexes through the "
        "release process (or record why not).",
    )


def default_max_time_ms(facts: Facts, policy: Policy) -> Outcome:
    if not policy.performance_require_default_max_time_ms:
        return _na("policy performance.require_default_max_time_ms is false")
    if (na := _shared(facts, "advanced configuration")) is not None:
        return na
    if not facts.process_args.available:
        return _unavailable(facts.process_args)
    value = (facts.process_args.value or {}).get("defaultMaxTimeMS")
    return Outcome(
        ok=isinstance(value, int) and value > 0,
        message=f"defaultMaxTimeMS {value}" if value else "no cluster-level query timeout",
        evidence={"defaultMaxTimeMS": value},
        remedy="Set defaultMaxTimeMS (MongoDB 8.0+) or enforce maxTimeMS in the drivers.",
    )


# --- cost ---------------------------------------------------------------------------------------


def backup_retention(facts: Facts, policy: Policy) -> Outcome:
    if (na := _shared(facts, "snapshot schedules")) is not None:
        return na
    if not facts.cluster.get("backupEnabled", False):
        return _na("backups are off (see rel.backup.enabled)")
    if not facts.backup_schedule.available:
        return _unavailable(facts.backup_schedule)
    items = _policy_items(facts.backup_schedule.value)
    days = tuple(_retention_days(i) for i in items)
    longest = max(days, default=0)
    return Outcome(
        ok=longest <= policy.cost_max_snapshot_retention_days,
        message=f"longest retention {longest} day(s)",
        evidence={
            "retention_days": days,
            "ceiling": policy.cost_max_snapshot_retention_days,
        },
        remedy="Shorten retention on the longest policy item or raise the policy ceiling if "
        "compliance really needs it.",
    )


def _retention_days(item: Mapping[str, Any]) -> int:
    unit = str(item.get("retentionUnit", "days")).lower()
    value = int(item.get("retentionValue") or 0)
    return value * {"days": 1, "weeks": 7, "months": 30, "years": 365}.get(unit, 1)


EVALUATORS: Mapping[str, Evaluator] = {
    "sec.network.no-open-access": no_open_access,
    "sec.network.private-connectivity": private_connectivity,
    "sec.network.access-list-scoped": access_list_scoped,
    "sec.tls.minimum-version": tls_minimum,
    "sec.auth.no-password-users": no_password_users,
    "sec.encryption.customer-managed-keys": customer_managed_keys,
    "sec.audit.enabled": audit_enabled,
    "sec.hardening.server-side-javascript-disabled": server_side_js_disabled,
    "rel.ha.electable-nodes": electable_nodes,
    "rel.ha.regions": regions,
    "rel.protection.termination-protection": termination_protection,
    "rel.backup.enabled": backup_enabled,
    "rel.backup.continuous": backup_continuous,
    "rel.backup.restore-window": restore_window,
    "rel.backup.schedule": backup_schedule,
    "rel.backup.snapshot-copy": snapshot_copy,
    "rel.backup.compliance-policy": compliance_policy,
    "rel.maintenance.window": maintenance_window,
    "rel.maintenance.protected-hours": protected_hours,
    "rel.version.minimum": version_minimum,
    "ops.tags.required": tags_required,
    "ops.alerts.recommended": alerts_recommended,
    "ops.integrations.observability": integrations_observability,
    "ops.project.advisors-enabled": advisors_enabled,
    "perf.autoscaling.compute": autoscaling_compute,
    "perf.autoscaling.disk": autoscaling_disk,
    "perf.advisor.suggested-indexes": suggested_indexes,
    "perf.config.default-max-time-ms": default_max_time_ms,
    "cost.backup.retention": backup_retention,
}
