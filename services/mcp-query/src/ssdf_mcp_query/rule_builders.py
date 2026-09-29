# src/ssdf_mcp_query/rule_builders.py
"""Pure SQL builders for the rule usage/history tools (MEC-566). Return (sql, params); no I/O."""

from __future__ import annotations

from .timeparse import parse_time

HISTORY_MAX_LIMIT = 500


def _window_params(since, until) -> dict:
    since_dt = parse_time(since) if since else parse_time("now-24h")
    until_dt = parse_time(until) if until else parse_time("now")
    return {"since": since_dt.isoformat(), "until": until_dt.isoformat()}


def build_rule_usage_sql(device_name: str, rule_name: str, since=None, until=None):
    """Hourly usage buckets for one (device, rule) over a time window.

    Reads ssdf.rule_usage_hourly FINAL: the table is a ReplacingMergeTree keyed
    through bucket_start, and FINAL collapses a bucket the rollup job re-emitted
    (late-arriving events) to its latest write before summing.
    """
    params = _window_params(since, until)
    params["device"] = device_name
    params["rule"] = rule_name
    sql = (
        "SELECT bucket_start, provider, observer_hostname, rule_name, "
        "sum(sessions) AS sessions, sum(bytes) AS bytes "
        "FROM ssdf.rule_usage_hourly FINAL "
        "WHERE observer_hostname = {device:String} AND rule_name = {rule:String} "
        "AND bucket_start >= parseDateTimeBestEffort({since:String}) "
        "AND bucket_start < parseDateTimeBestEffort({until:String}) "
        "GROUP BY bucket_start, provider, observer_hostname, rule_name "
        "ORDER BY bucket_start"
    )
    return sql, params


def build_device_log_coverage_sql(device_name: str, since, until):
    """Whether ssdf.events has ANY row for this device in the window (log
    ingest coverage, independent of any one rule) -- unused_rules' "was this
    device even logging" signal."""
    params = _window_params(since, until)
    params["device"] = device_name
    sql = (
        "SELECT count() AS c FROM ssdf.events "
        "WHERE observer_hostname = {device:String} "
        "AND timestamp >= parseDateTimeBestEffort({since:String}) "
        "AND timestamp < parseDateTimeBestEffort({until:String})"
    )
    return sql, params


def build_rule_history_sql(device_name: str, rule_name: str, limit: int = 50):
    limit = max(1, min(int(limit), HISTORY_MAX_LIMIT))
    params = {"device": device_name, "rule": rule_name}
    sql = (
        "SELECT toString(valid_from) AS valid_from, content_hash, action, "
        "from_zone, to_zone, enabled, position "
        "FROM ssdf.policy_versions "
        "WHERE device_name = {device:String} AND rule_name = {rule:String} "
        f"ORDER BY valid_from DESC LIMIT {limit}"
    )
    return sql, params
