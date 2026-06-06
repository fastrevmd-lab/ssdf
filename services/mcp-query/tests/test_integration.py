# tests/test_integration.py
"""Integration tests against a live ClickHouse. Run with CH_* env set; skipped otherwise."""

import os
import pytest

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def tools():
    if not os.environ.get("CH_PASSWORD"):
        pytest.skip("no live ClickHouse configured (set CH_HOST/CH_USER/CH_PASSWORD)")
    from ssdf_mcp_query.config import load_config
    from ssdf_mcp_query.clickhouse import ClickHouseClient
    from ssdf_mcp_query.tools import Tools
    os.environ.setdefault("MCP_AUTH_TOKEN", "test")   # config needs a token to load
    return Tools(ClickHouseClient(load_config()))


def test_describe_schema_live(tools):
    out = tools.describe_schema()
    assert "error" not in out
    names = {c["name"] for c in out["columns"]}
    assert {"timestamp", "event_action", "source_ip"} <= names
    assert out["row_count"] >= 0


def test_query_flows_live_returns_typed_rows(tools):
    out = tools.query_flows(since="now-7d", limit=5)
    assert "error" not in out
    assert isinstance(out["rows"], list)
    assert out["row_count"] <= 5


def test_query_flows_deny_acceptance(tools):
    # M1 acceptance question, now answered through MCP
    out = tools.query_flows(action="flow_session_deny", since="now-30d", limit=50)
    assert "error" not in out


def test_run_sql_guarded_live(tools):
    out = tools.run_sql("SELECT event_action, count() AS c FROM ssdf.events GROUP BY event_action")
    assert "error" not in out
    assert out["row_count"] >= 0


def test_run_sql_write_blocked_live(tools):
    out = tools.run_sql("INSERT INTO ssdf.events(event_id) VALUES ('x')")
    assert out["error"] == "validation"
