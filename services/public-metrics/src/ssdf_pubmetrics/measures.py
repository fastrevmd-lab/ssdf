"""Declarative measure catalog + pure SQL builders (return (sql, params); no I/O).

Catalog is extensible: M13 health signals append as enabled entries with no
redesign. M7c ships only measures derivable from today's ssdf.events.
"""

from __future__ import annotations

from dataclasses import dataclass

DENY_ACTIONS = ["deny", "drop", "block", "reject"]

# Per-entity series are keyed by the source IP (mapped to a 'host' surrogate).
INDEX_METRICS: set[str] = {"deny_rate_index", "ips_volume_index"}

AGG_VALUE_EXPR: dict[str, str] = {
    # network_bytes is Nullable in ssdf.events (detection/audit sources carry no
    # bytes); ifNull keeps sum() from returning NULL for an all-NULL group, which
    # would otherwise surface as a None value the resolver can't float().
    "bytes": "sum(ifNull(network_bytes, 0))",
    "flows": "count()",
    "connections": ("uniqExact((source_ip, source_port, destination_ip, "
                    "destination_port, network_transport))"),
}


@dataclass(frozen=True)
class Measure:
    metric: str
    enabled: bool
    per_entity: bool  # also emit top-N entity_series rows
    kind: str         # 'aggregate' | 'index'


CATALOG: list[Measure] = [
    # Tier 1 — shareable volume/activity. Only `bytes` carries a per-entity
    # (top-N talker) breakdown; flows/connections are aggregate-only. Every
    # measure still emits its aggregate metric_timeseries series regardless.
    Measure("bytes", True, True, "aggregate"),
    Measure("flows", True, False, "aggregate"),
    Measure("connections", True, False, "aggregate"),
    # Tier 2 — normalized stance indices (ratio-to-baseline only)
    Measure("deny_rate_index", True, False, "index"),
    Measure("ips_volume_index", True, False, "index"),
    # Tier 3 — operational health (disabled placeholders). M13a now lands the
    # source data in ssdf.health_metrics (NOT ssdf.events); flipping these to
    # enabled + adding a health-table AGG_VALUE_EXPR branch + the pseudonym
    # pipeline is the M13a -> public-metrics follow-on, deliberately deferred.
    Measure("mem_util_pct", False, False, "aggregate"),
    Measure("cpu_util_pct", False, False, "aggregate"),
    Measure("iface_error_rate", False, False, "aggregate"),
    Measure("port_flap_count", False, False, "aggregate"),
    Measure("proto_flap_count", False, False, "aggregate"),
]


def enabled_measures() -> list[Measure]:
    """The catalog entries whose source data exists today."""
    return [m for m in CATALOG if m.enabled]


def ratio_to_baseline(current_rate: float, baseline_rate: float) -> float:
    """current / baseline, guarding a zero baseline (no history yet) as 0.0."""
    if baseline_rate == 0:
        return 0.0
    return current_rate / baseline_rate


def build_aggregate_sql(metric: str, since_iso: str, bucket_secs: int,
                        tenant: str) -> tuple[str, dict]:
    expr = AGG_VALUE_EXPR[metric]
    sql = (
        f"SELECT toStartOfInterval(timestamp, INTERVAL {int(bucket_secs)} SECOND) "
        f"AS bucket_start, toFloat64({expr}) AS value FROM ssdf.events "
        "WHERE tenant_id = {tenant:String} "
        "AND timestamp >= parseDateTimeBestEffort({since:String}) "
        "GROUP BY bucket_start ORDER BY bucket_start"
    )
    return sql, {"tenant": tenant, "since": since_iso}


def build_entity_bucket_sql(metric: str, since_iso: str, bucket_secs: int,
                            tenant: str) -> tuple[str, dict]:
    expr = AGG_VALUE_EXPR[metric]
    sql = (
        f"SELECT toStartOfInterval(timestamp, INTERVAL {int(bucket_secs)} SECOND) "
        f"AS bucket_start, toString(source_ip) AS ip, toFloat64({expr}) AS value "
        "FROM ssdf.events "
        "WHERE tenant_id = {tenant:String} AND source_ip IS NOT NULL "
        "AND timestamp >= parseDateTimeBestEffort({since:String}) "
        "GROUP BY bucket_start, ip ORDER BY bucket_start"
    )
    return sql, {"tenant": tenant, "since": since_iso}


def build_deny_counts_sql(since_iso: str, tenant: str) -> tuple[str, dict]:
    sql = (
        "SELECT toFloat64(countIf(event_action IN {deny:Array(String)})) AS deny, "
        "toFloat64(count()) AS total FROM ssdf.events "
        "WHERE tenant_id = {tenant:String} "
        "AND event_provider IN ('paloalto', 'juniper') "
        "AND timestamp >= parseDateTimeBestEffort({since:String})"
    )
    return sql, {"tenant": tenant, "since": since_iso, "deny": DENY_ACTIONS}


def build_alert_count_sql(since_iso: str, tenant: str) -> tuple[str, dict]:
    sql = (
        "SELECT toFloat64(count()) AS c FROM ssdf.events "
        "WHERE tenant_id = {tenant:String} AND event_provider = 'unifi' "
        "AND event_kind = 'alert' "
        "AND timestamp >= parseDateTimeBestEffort({since:String})"
    )
    return sql, {"tenant": tenant, "since": since_iso}
