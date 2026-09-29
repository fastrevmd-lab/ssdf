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
    """Bounds of the rule-usage rollup's coverage for this device in the window
    (log ingest coverage, independent of any one rule) -- unused_rules' "did the
    aggregation job actually roll up this device across the whole window, not
    just find one stray bucket" signal.

    Deliberately reads ssdf.rule_usage_hourly (the rollup unused_rules itself
    queries per-rule), not ssdf.events directly: a device can have raw events
    while the hourly rollup job is stalled or has never covered this window,
    and a per-rule usage query would then silently read as "0 sessions" --
    indistinguishable from a genuinely unused rule. Callers compare
    min_bucket/max_bucket against the window edges (see rule_tools._log_coverage)
    rather than trusting `c > 0` alone, since a handful of buckets clustered at
    one end of a week-long window is not "covered".
    """
    params = _window_params(since, until)
    params["device"] = device_name
    sql = (
        "SELECT min(bucket_start) AS min_bucket, max(bucket_start) AS max_bucket, "
        "count() AS c FROM ssdf.rule_usage_hourly FINAL "
        "WHERE observer_hostname = {device:String} "
        "AND bucket_start >= parseDateTimeBestEffort({since:String}) "
        "AND bucket_start < parseDateTimeBestEffort({until:String})"
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
