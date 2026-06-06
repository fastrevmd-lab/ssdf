# tests/test_clickhouse.py
import datetime as dt
import ipaddress
from ssdf_mcp_query.clickhouse import jsonify

def test_jsonify_datetime_to_iso():
    value = dt.datetime(2026, 6, 6, 12, 0, 0, tzinfo=dt.timezone.utc)
    assert jsonify(value) == "2026-06-06T12:00:00+00:00"

def test_jsonify_ipv4_to_str():
    assert jsonify(ipaddress.IPv4Address("10.65.1.10")) == "10.65.1.10"

def test_jsonify_passthrough_and_none():
    assert jsonify(None) is None
    assert jsonify(443) == 443
    assert jsonify("x") == "x"

def test_jsonify_nested_collections():
    assert jsonify({"a": ipaddress.IPv4Address("1.2.3.4")}) == {"a": "1.2.3.4"}
    assert jsonify([dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)]) == ["2026-01-01T00:00:00+00:00"]
