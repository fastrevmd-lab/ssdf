# tests/test_builders.py
import pytest
from ssdf_mcp_query.builders import (
    build_query_flows, build_top_talkers, FLOW_COLUMNS, BuilderError,
)

def test_query_flows_no_filters_has_window_and_limit():
    sql, params = build_query_flows(limit=100)
    assert "FROM ssdf.events" in sql
    assert "ORDER BY timestamp DESC" in sql
    assert "LIMIT 100" in sql
    assert "since" in params and "until" in params  # default window bound

def test_query_flows_filters_bind_params_not_interpolated():
    sql, params = build_query_flows(src_ip="10.64.0.1", action="flow_session_deny", dst_port=443)
    assert "10.64.0.1" not in sql            # value is bound, never inlined
    assert params["src_ip"] == "10.64.0.1"
    assert params["action"] == "flow_session_deny"
    assert params["dst_port"] == 443
    assert "{src_ip:String}" in sql
    assert "{dst_port:UInt16}" in sql

def test_query_flows_zone_matches_either_side():
    sql, _ = build_query_flows(zone="trust")
    assert "observer_ingress_zone" in sql and "observer_egress_zone" in sql

def test_query_flows_limit_clamped():
    sql, _ = build_query_flows(limit=10_000)
    assert "LIMIT 1000" in sql

def test_query_flows_selects_expected_columns():
    sql, _ = build_query_flows()
    for col in FLOW_COLUMNS:
        assert col in sql

def test_top_talkers_by_bytes_src():
    sql, params = build_top_talkers(by="bytes", side="src", limit=5)
    assert "source_ip" in sql
    assert "sum(network_bytes)" in sql
    assert "LIMIT 5" in sql

def test_top_talkers_by_flows_dst():
    sql, _ = build_top_talkers(by="flows", side="dst")
    assert "destination_ip" in sql
    assert "count()" in sql

def test_top_talkers_invalid_args_raise():
    with pytest.raises(BuilderError):
        build_top_talkers(by="nope", side="src")
    with pytest.raises(BuilderError):
        build_top_talkers(by="bytes", side="nope")
