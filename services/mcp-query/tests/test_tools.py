# tests/test_tools.py
import pytest
from ssdf_mcp_query.tools import Tools

class FakeClient:
    def __init__(self, rows=None, columns=None, raise_exc=None):
        self._rows = rows or []
        self._columns = columns or []
        self._raise = raise_exc
        self.last_sql = None
        self.last_params = None

    def run(self, sql, params=None):
        self.last_sql = sql
        self.last_params = params
        if self._raise:
            raise self._raise
        return {"columns": self._columns, "rows": self._rows, "row_count": len(self._rows)}

def test_query_flows_returns_rows_and_metadata():
    fake = FakeClient(rows=[{"source_ip": "10.64.0.1"}], columns=["source_ip"])
    tools = Tools(fake, max_rows=1000)
    out = tools.query_flows(action="flow_session_deny", since="now-1h")
    assert out["row_count"] == 1
    assert out["rows"][0]["source_ip"] == "10.64.0.1"
    assert out["truncated"] is False
    assert "elapsed_ms" in out
    assert fake.last_params["action"] == "flow_session_deny"

def test_query_flows_truncated_flag():
    rows = [{"x": i} for i in range(1000)]
    tools = Tools(FakeClient(rows=rows, columns=["x"]), max_rows=1000)
    out = tools.query_flows(limit=1000)
    assert out["truncated"] is True          # hit the cap

def test_run_sql_rejected_returns_validation_error():
    tools = Tools(FakeClient(), max_rows=1000)
    out = tools.run_sql("DROP TABLE ssdf.events")
    assert out["error"] == "validation"

def test_run_sql_allowed_executes_guarded_sql():
    fake = FakeClient(rows=[{"n": 1}], columns=["n"])
    tools = Tools(fake, max_rows=1000)
    out = tools.run_sql("SELECT count() AS n FROM ssdf.events")
    assert out["row_count"] == 1
    assert "limit" in fake.last_sql.lower()   # guard injected a LIMIT

def test_upstream_error_is_caught():
    tools = Tools(FakeClient(raise_exc=RuntimeError("ch down")), max_rows=1000)
    out = tools.query_flows()
    assert out["error"] == "upstream"

def test_top_talkers_invalid_arg_is_validation_error():
    tools = Tools(FakeClient(), max_rows=1000)
    out = tools.top_talkers(by="bogus")
    assert out["error"] == "validation"
