from __future__ import annotations

import datetime as dt
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import checkpoint_audit  # noqa: E402
from ssdf_mcp_query.audit_chain import compute_row_hash  # noqa: E402


class _FakeResult:
    def __init__(self, result_rows):
        self.result_rows = result_rows


class _FakeClient:
    def __init__(self, audit_rows=(), checkpoint_rows=()):
        self._audit_rows = list(audit_rows)
        self._checkpoint_rows = list(checkpoint_rows)
        self.inserted: list[tuple[str, list, list]] = []

    def query(self, sql, parameters=None):
        if "FROM ssdf.audit " in sql or sql.rstrip().endswith("ssdf.audit"):
            return _FakeResult(list(self._audit_rows))
        if "audit_checkpoints" in sql:
            return _FakeResult(list(self._checkpoint_rows))
        raise AssertionError(f"unexpected query: {sql}")

    def insert(self, table, data, column_names):
        self.inserted.append((table, data, column_names))


def _audit_row(i: int, tier: str, prev_hash: str, args: str = "{}") -> tuple:
    row = {
        "ts": dt.datetime(2026, 6, 10, tzinfo=dt.timezone.utc),
        "principal": "agent",
        "tier": tier,
        "tool": f"t{i}",
        "args": args,
        "data_classes": [],
        "decision": "allow",
        "row_count": i,
        "error": "",
        "prev_hash": prev_hash,
    }
    row["row_hash"] = compute_row_hash(prev_hash, row)
    return (row["tier"], row["args"], row["prev_hash"], row["row_hash"]), row["row_hash"]


def test_fetch_rows_by_chain_groups_by_tier_and_server_id():
    sovereign_row, _ = _audit_row(0, "sovereign", "")
    evidence_args = json.dumps({"server_id": "junos-1"})
    ev_row, _ = _audit_row(1, "evidence", "", args=evidence_args)
    client = _FakeClient(audit_rows=[sovereign_row, ev_row])

    by_chain = checkpoint_audit.fetch_rows_by_chain(client)

    assert ("sovereign", "") in by_chain
    assert ("evidence", "junos-1") in by_chain
    assert len(by_chain[("sovereign", "")]) == 1
    assert len(by_chain[("evidence", "junos-1")]) == 1


def test_fetch_previous_checkpoints_keeps_latest_per_chain():
    rows = [
        ("sovereign", "", 4, "h1", "2026-09-01T00:00:00.000Z", "sig1", "k1"),
        ("sovereign", "", 7, "h2", "2026-09-02T00:00:00.000Z", "sig2", "k2"),
    ]
    client = _FakeClient(checkpoint_rows=rows)

    latest = checkpoint_audit.fetch_previous_checkpoints(client)

    assert latest[("sovereign", "")]["row_count"] == 7
    assert latest[("sovereign", "")]["head_row_hash"] == "h2"


def test_format_checkpoint_ts_is_millisecond_precision_utc():
    now = dt.datetime(2026, 9, 28, 0, 0, 0, 123456, tzinfo=dt.timezone.utc)
    assert checkpoint_audit.format_checkpoint_ts(now) == "2026-09-28T00:00:00.123Z"


def test_format_checkpoint_ts_converts_naive_to_utc():
    now = dt.datetime(2026, 9, 28, 0, 0, 0)
    assert checkpoint_audit.format_checkpoint_ts(now) == "2026-09-28T00:00:00.000Z"


def test_sign_checkpoint_raises_on_nonzero_exit(monkeypatch):
    class _Proc:
        returncode = 1
        stdout = ""
        stderr = "bad key"

    monkeypatch.setattr(checkpoint_audit.subprocess, "run", lambda *a, **k: _Proc())
    with pytest.raises(RuntimeError, match="bad key"):
        checkpoint_audit.sign_checkpoint("binary", "key", {"tier": "sovereign"})


def test_sign_checkpoint_raises_on_invalid_json(monkeypatch):
    class _Proc:
        returncode = 0
        stdout = "not json"
        stderr = ""

    monkeypatch.setattr(checkpoint_audit.subprocess, "run", lambda *a, **k: _Proc())
    with pytest.raises(RuntimeError, match="invalid JSON"):
        checkpoint_audit.sign_checkpoint("binary", "key", {"tier": "sovereign"})


def test_sign_checkpoint_raises_on_missing_fields(monkeypatch):
    class _Proc:
        returncode = 0
        stdout = json.dumps({"tier": "sovereign"})
        stderr = ""

    monkeypatch.setattr(checkpoint_audit.subprocess, "run", lambda *a, **k: _Proc())
    with pytest.raises(RuntimeError, match="missing field"):
        checkpoint_audit.sign_checkpoint("binary", "key", {"tier": "sovereign"})


def test_sign_checkpoint_returns_parsed_output(monkeypatch):
    signed = {c: "x" for c in checkpoint_audit._CHECKPOINT_COLUMNS}

    class _Proc:
        returncode = 0
        stdout = json.dumps(signed)
        stderr = ""

    captured = {}

    def fake_run(cmd, input, capture_output, text, timeout):
        captured["cmd"] = cmd
        captured["input"] = input
        return _Proc()

    monkeypatch.setattr(checkpoint_audit.subprocess, "run", fake_run)
    out = checkpoint_audit.sign_checkpoint("the-binary", "the-key", {"tier": "sovereign"})

    assert out == signed
    assert captured["cmd"] == ["the-binary", "the-key"]
    assert json.loads(captured["input"]) == {"tier": "sovereign"}


def test_run_checkpoints_a_fresh_chain_and_inserts_it(monkeypatch):
    (row_tuple, row_hash) = _audit_row(0, "sovereign", "")
    client = _FakeClient(audit_rows=[row_tuple], checkpoint_rows=[])

    signed = {
        "tier": "sovereign",
        "server_id": "",
        "row_count": 1,
        "head_row_hash": row_hash,
        "checkpoint_ts": "2026-06-10T00:00:00.000Z",
        "signature": "sig",
        "key_id": "k1",
    }
    monkeypatch.setattr(checkpoint_audit, "sign_checkpoint", lambda *a, **k: signed)

    inserted = checkpoint_audit.run(client, "binary", "key")

    assert inserted == [signed]
    assert len(client.inserted) == 1
    table, data, columns = client.inserted[0]
    assert table == "ssdf.audit_checkpoints"
    assert columns == checkpoint_audit._CHECKPOINT_COLUMNS
    assert data == [[signed[c] for c in checkpoint_audit._CHECKPOINT_COLUMNS]]


def test_run_skips_chains_with_nothing_new(monkeypatch):
    (row_tuple, row_hash) = _audit_row(0, "sovereign", "")
    checkpoint_row = (
        "sovereign",
        "",
        1,
        row_hash,
        "2026-06-10T00:00:00.000Z",
        "sig",
        "k1",
    )
    client = _FakeClient(audit_rows=[row_tuple], checkpoint_rows=[checkpoint_row])

    def fail_sign(*args, **kwargs):
        raise AssertionError("should not sign an unchanged chain")

    monkeypatch.setattr(checkpoint_audit, "sign_checkpoint", fail_sign)

    inserted = checkpoint_audit.run(client, "binary", "key")

    assert inserted == []
    assert client.inserted == []
