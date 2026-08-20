from ssdf_pubmetrics.measures import (
    CATALOG,
    INDEX_METRICS,
    VOLUME_METRICS,
    enabled_measures,
    ratio_to_baseline,
    build_aggregate_sql,
    build_entity_bucket_sql,
    build_deny_counts_sql,
    build_alert_count_sql,
    AGG_VALUE_EXPR,
)


def test_catalog_has_tier1_and_tier2_enabled():
    ids = {m.metric for m in enabled_measures()}
    assert {"bytes", "flows", "connections", "deny_rate_index", "ips_volume_index"} <= ids


def test_tier3_health_measures_present_but_disabled():
    by_id = {m.metric: m for m in CATALOG}
    for mid in (
        "mem_util_pct",
        "cpu_util_pct",
        "iface_error_rate",
        "port_flap_count",
        "proto_flap_count",
    ):
        assert by_id[mid].enabled is False


def test_index_metrics_set():
    assert INDEX_METRICS == {"deny_rate_index", "ips_volume_index"}


def test_ratio_to_baseline_zero_guard():
    assert ratio_to_baseline(0.5, 0.0) == 0.0
    assert ratio_to_baseline(0.4, 0.2) == 2.0


def test_aggregate_sql_uses_bucket_and_expr():
    sql, params = build_aggregate_sql("bytes", "2026-06-19T00:00:00+00:00", 300, "t_main")
    assert "toStartOfInterval(timestamp, INTERVAL 300 SECOND)" in sql
    assert AGG_VALUE_EXPR["bytes"] in sql
    assert params["tenant"] == "t_main"


def test_entity_bucket_sql_groups_by_ip():
    sql, params = build_entity_bucket_sql("flows", "2026-06-19T00:00:00+00:00", 300, "t_main")
    assert "toString(source_ip) AS ip" in sql
    assert "source_ip IS NOT NULL" in sql
    assert "GROUP BY bucket_start, ip" in sql


def test_deny_counts_sql_selects_deny_and_total():
    sql, params = build_deny_counts_sql("2026-06-19T00:00:00+00:00", "t_main")
    assert "countIf(event_action IN" in sql
    assert "AS deny" in sql and "AS total" in sql
    assert params["deny"] == ["deny", "drop", "block", "reject"]


def test_alert_count_sql_filters_unifi_alert():
    sql, params = build_alert_count_sql("2026-06-19T00:00:00+00:00", "t_main")
    assert "event_provider = 'unifi'" in sql
    assert "event_kind = 'alert'" in sql


def test_volume_metrics_set():
    assert VOLUME_METRICS == {"bytes", "flows", "connections"}


def test_aggregate_sql_volume_metrics_scoped_to_flows():
    for metric in VOLUME_METRICS:
        sql, params = build_aggregate_sql(metric, "2026-07-05T00:00:00+00:00", 300, "t_main")
        assert "event_action LIKE 'flow_%'" in sql


def test_entity_bucket_sql_volume_metrics_scoped_to_flows():
    for metric in VOLUME_METRICS:
        sql, params = build_entity_bucket_sql(metric, "2026-07-05T00:00:00+00:00", 300, "t_main")
        assert "event_action LIKE 'flow_%'" in sql


def test_deny_counts_sql_scoped_to_flows():
    sql, params = build_deny_counts_sql("2026-07-05T00:00:00+00:00", "t_main")
    assert "event_action LIKE 'flow_%'" in sql
