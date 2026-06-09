import datetime as dt
import json
from ssdf_mcp_query.audit import build_audit_row, Auditor, AUDIT_COLUMNS


def test_build_audit_row_shapes_all_columns():
    row = build_audit_row(
        principal="triage-agent", tier="sovereign", tool="query_flows",
        args={"dst_port": 443}, data_classes=["security_log"],
        decision="allow", row_count=7, error="",
    )
    assert set(row) == set(AUDIT_COLUMNS)
    assert row["principal"] == "triage-agent"
    assert row["tier"] == "sovereign"
    assert row["tool"] == "query_flows"
    assert json.loads(row["args"]) == {"dst_port": 443}
    assert row["data_classes"] == ["security_log"]
    assert row["decision"] == "allow"
    assert row["row_count"] == 7
    assert row["error"] == ""
    assert isinstance(row["ts"], dt.datetime)


def test_build_audit_row_serializes_non_json_args():
    row = build_audit_row(
        principal="p", tier="sovereign", tool="run_sql",
        args={"since": dt.datetime(2026, 6, 9)}, data_classes=["security_log"],
        decision="allow", row_count=0, error=None,
    )
    assert "2026-06-09" in row["args"]
    assert row["error"] == ""


def test_auditor_record_calls_insert():
    captured = []
    Auditor(captured.append).record(
        principal="p", tier="sovereign", tool="locate", args={"identifier": "x"},
        data_classes=["topology"], decision="allow", row_count=1, error="",
    )
    assert len(captured) == 1
    assert captured[0]["tool"] == "locate"


def test_auditor_swallows_insert_failure(capsys):
    def boom(_row):
        raise RuntimeError("ch down")

    Auditor(boom).record(
        principal="p", tier="sovereign", tool="locate", args={},
        data_classes=["topology"], decision="allow", row_count=0, error="",
    )  # must NOT raise
    assert "audit" in capsys.readouterr().err.lower()
