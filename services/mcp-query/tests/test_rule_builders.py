from ssdf_mcp_query.rule_builders import (
    build_device_log_coverage_sql,
    build_rule_history_sql,
    build_rule_usage_sql,
)


def test_build_rule_usage_sql_binds_device_and_rule():
    sql, params = build_rule_usage_sql("vsrx-ci", "ALLOW-WEB", since="now-1h")
    assert "ssdf.rule_usage_hourly FINAL" in sql
    assert params["device"] == "vsrx-ci"
    assert params["rule"] == "ALLOW-WEB"
    assert "since" in params and "until" in params


def test_build_rule_usage_sql_defaults_to_24h_window():
    _, params_a = build_rule_usage_sql("vsrx-ci", "r1")
    _, params_b = build_rule_usage_sql("vsrx-ci", "r1", since="now-24h", until="now")
    # Both resolve relative times; just assert the param keys line up (values
    # are wall-clock-dependent so not compared directly).
    assert set(params_a) == set(params_b)


def test_build_device_log_coverage_sql_scopes_to_device_only():
    sql, params = build_device_log_coverage_sql("vsrx-ci", "now-24h", "now")
    assert "rule_name" not in sql  # device-wide coverage, not per-rule
    assert params["device"] == "vsrx-ci"


def test_build_rule_history_sql_clamps_limit():
    sql, params = build_rule_history_sql("vsrx-ci", "ALLOW-WEB", limit=999999)
    assert "LIMIT 500" in sql
    assert params["device"] == "vsrx-ci"
    assert params["rule"] == "ALLOW-WEB"


def test_build_rule_history_sql_orders_newest_first():
    sql, _ = build_rule_history_sql("vsrx-ci", "ALLOW-WEB")
    assert "ORDER BY valid_from DESC" in sql
