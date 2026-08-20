import datetime as dt
import json
import threading
from ssdf_mcp_query.audit import build_audit_row, Auditor, AUDIT_COLUMNS, AUDIT_BASE_COLUMNS
from ssdf_mcp_query.audit_chain import compute_row_hash


def test_build_audit_row_shapes_all_columns():
    row = build_audit_row(
        principal="triage-agent",
        tier="sovereign",
        tool="query_flows",
        args={"dst_port": 443},
        data_classes=["security_log"],
        decision="allow",
        row_count=7,
        error="",
    )
    assert set(row) == set(AUDIT_BASE_COLUMNS)
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
        principal="p",
        tier="sovereign",
        tool="run_sql",
        args={"since": dt.datetime(2026, 6, 9)},
        data_classes=["security_log"],
        decision="allow",
        row_count=0,
        error=None,
    )
    assert "2026-06-09" in row["args"]
    assert row["error"] == ""


def test_auditor_record_calls_insert():
    captured = []
    Auditor(captured.append).record(
        principal="p",
        tier="sovereign",
        tool="locate",
        args={"identifier": "x"},
        data_classes=["topology"],
        decision="allow",
        row_count=1,
        error="",
    )
    assert len(captured) == 1
    assert captured[0]["tool"] == "locate"


def test_auditor_swallows_insert_failure(capsys):
    def boom(_row):
        raise RuntimeError("ch down")

    Auditor(boom).record(
        principal="p",
        tier="sovereign",
        tool="locate",
        args={},
        data_classes=["topology"],
        decision="allow",
        row_count=0,
        error="",
    )  # must NOT raise
    assert "audit" in capsys.readouterr().err.lower()


def test_audit_columns_extend_base_with_hash_cols():
    assert AUDIT_COLUMNS == AUDIT_BASE_COLUMNS + ["prev_hash", "row_hash"]


def test_build_audit_row_shapes_base_columns():
    row = build_audit_row(
        principal="p",
        tier="sovereign",
        tool="locate",
        args={},
        data_classes=["topology"],
        decision="allow",
        row_count=0,
        error="",
    )
    assert set(row) == set(AUDIT_BASE_COLUMNS)


def test_record_chains_hashes_across_calls():
    captured = []
    aud = Auditor(captured.append, last_hash="")
    common = dict(
        principal="p",
        tier="sovereign",
        data_classes=["topology"],
        decision="allow",
        row_count=0,
        error="",
    )
    aud.record(tool="a", args={}, **common)
    aud.record(tool="b", args={}, **common)
    assert captured[0]["prev_hash"] == ""
    assert captured[1]["prev_hash"] == captured[0]["row_hash"]
    assert captured[1]["row_hash"] == compute_row_hash(captured[1]["prev_hash"], captured[1])


def test_record_does_not_advance_chain_on_insert_failure():
    captured = []
    state = {"fail_next": False}

    def insert(row):
        if state["fail_next"]:
            raise RuntimeError("ch down")
        captured.append(row)

    aud = Auditor(insert, last_hash="")
    common = dict(
        principal="p",
        tier="sovereign",
        data_classes=["topology"],
        decision="allow",
        row_count=0,
        error="",
    )
    aud.record(tool="a", args={}, **common)
    first_hash = captured[0]["row_hash"]
    state["fail_next"] = True
    aud.record(tool="b", args={}, **common)
    state["fail_next"] = False
    aud.record(tool="c", args={}, **common)
    assert captured[-1]["prev_hash"] == first_hash


def test_record_concurrent_calls_form_valid_chain():
    captured = []
    lock = threading.Lock()

    def insert(row):
        with lock:
            captured.append(row)

    aud = Auditor(insert, last_hash="")
    common = dict(
        principal="p",
        tier="sovereign",
        data_classes=["topology"],
        decision="allow",
        row_count=0,
        error="",
    )

    def worker(n):
        aud.record(tool=f"t{n}", args={}, **common)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    by_hash = {r["row_hash"]: r for r in captured}
    genesis = [r for r in captured if r["prev_hash"] == ""]
    assert len(genesis) == 1
    for r in captured:
        if r["prev_hash"] != "":
            assert r["prev_hash"] in by_hash
