from ssdf_mcp_query.wrapper import audited_tool, row_count_of
from ssdf_mcp_query.audit import Auditor


class _Recorder:
    def __init__(self):
        self.calls = []

    def record(self, **fields):
        self.calls.append(fields)


def test_row_count_from_row_count_field():
    assert row_count_of({"row_count": 5, "rows": [1, 2]}) == 5


def test_row_count_from_rows_len():
    assert row_count_of({"rows": [1, 2, 3]}) == 3


def test_row_count_default_zero():
    assert row_count_of({"error": "x"}) == 0
    assert row_count_of("not-a-dict") == 0


def test_allowed_tool_runs_and_audits_allow():
    rec = _Recorder()
    fn = lambda dst_port=None: {"rows": [1, 2], "row_count": 2}
    wrapped = audited_tool("query_flows", fn, rec, caller=lambda: ("p", None))
    assert wrapped(dst_port=443) == {"rows": [1, 2], "row_count": 2}
    assert len(rec.calls) == 1
    call = rec.calls[0]
    assert call["decision"] == "allow"
    assert call["tool"] == "query_flows"
    assert call["principal"] == "p"
    assert call["data_classes"] == ["security_log"]
    assert call["row_count"] == 2
    assert call["args"] == {"dst_port": 443}


def test_disallowed_tool_denied_and_not_invoked():
    rec = _Recorder()
    invoked = {"hit": False}

    def fn(**kwargs):
        invoked["hit"] = True
        return {"rows": []}

    wrapped = audited_tool("run_sql", fn, rec, caller=lambda: ("p", frozenset({"query_flows"})))
    result = wrapped(query="SELECT 1")
    assert result["error"] == "forbidden"
    assert invoked["hit"] is False
    assert rec.calls[0]["decision"] == "deny"
    assert rec.calls[0]["row_count"] == 0


def test_tool_error_result_audits_allow_with_error():
    rec = _Recorder()
    fn = lambda query=None: {"error": "bad_sql", "detail": "nope"}
    wrapped = audited_tool("run_sql", fn, rec, caller=lambda: ("p", None))
    result = wrapped(query="DROP")
    assert result["error"] == "bad_sql"
    assert rec.calls[0]["decision"] == "allow"
    assert rec.calls[0]["error"] == "bad_sql"
    assert rec.calls[0]["row_count"] == 0


def test_audit_write_failure_does_not_break_tool():
    def boom(_row):
        raise RuntimeError("ch down")

    fn = lambda: {"rows": [1]}
    wrapped = audited_tool("describe_schema", fn, Auditor(boom), caller=lambda: ("p", None))
    assert wrapped() == {"rows": [1]}  # tool result still returned


def test_unexpired_token_runs(monkeypatch):
    import datetime as dt

    rec = _Recorder()
    future = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=1)
    fn = lambda: {"rows": [1]}
    wrapped = audited_tool("query_flows", fn, rec, caller=lambda: ("p", None, future))
    assert wrapped() == {"rows": [1]}
    assert rec.calls[0]["decision"] == "allow"


def test_no_expiry_token_runs(monkeypatch):
    rec = _Recorder()
    fn = lambda: {"rows": [1]}
    wrapped = audited_tool("query_flows", fn, rec, caller=lambda: ("p", None, None))
    assert wrapped() == {"rows": [1]}
    assert rec.calls[0]["decision"] == "allow"


def test_expired_token_denied_and_not_invoked():
    import datetime as dt

    rec = _Recorder()
    invoked = {"hit": False}

    def fn(**kwargs):
        invoked["hit"] = True
        return {"rows": []}

    past = dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=1)
    wrapped = audited_tool("query_flows", fn, rec, caller=lambda: ("p", None, past))
    result = wrapped(dst_port=443)
    assert result["error"] == "forbidden"
    assert invoked["hit"] is False
    assert len(rec.calls) == 1
    assert rec.calls[0]["decision"] == "deny"
    assert rec.calls[0]["row_count"] == 0
    assert rec.calls[0]["principal"] == "p"


def test_two_tuple_caller_backward_compat():
    """Legacy (principal, allowed) callers keep working — no expiry implied."""
    rec = _Recorder()
    fn = lambda: {"rows": [1]}
    wrapped = audited_tool("query_flows", fn, rec, caller=lambda: ("p", None))
    assert wrapped() == {"rows": [1]}
    assert rec.calls[0]["decision"] == "allow"


def test_wrapped_preserves_signature_and_doc():
    import inspect

    def query_flows(dst_port: int | None = None) -> dict:
        """Real docstring."""
        return {"rows": []}

    wrapped = audited_tool("query_flows", query_flows, _Recorder(), caller=lambda: ("p", None))
    assert wrapped.__doc__ == "Real docstring."
    assert list(inspect.signature(wrapped).parameters) == ["dst_port"]
