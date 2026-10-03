from __future__ import annotations

import datetime as dt

from ssdf_mcp_query.audit_chain import compute_row_hash
from ssdf_mcp_query.checkpoint_orchestrator import compute_next_checkpoint


def _chain(n, tier="sovereign", first_prev=""):
    rows = []
    prev = first_prev
    for i in range(n):
        row = dict(
            ts=dt.datetime(2026, 6, 10, 12, 0, i, 0, tzinfo=dt.timezone.utc),
            principal="agent",
            tier=tier,
            tool=f"t{i}",
            args="{}",
            data_classes=["topology"],
            decision="allow",
            row_count=i,
            error="",
        )
        row["prev_hash"] = prev
        row["row_hash"] = compute_row_hash(prev, row)
        prev = row["row_hash"]
        rows.append(row)
    return rows


def test_no_rows_yields_no_checkpoint():
    assert compute_next_checkpoint([], previous=None) is None


def test_first_checkpoint_walks_from_genesis():
    rows = _chain(4)
    cp = compute_next_checkpoint(rows, previous=None)
    assert cp is not None
    assert cp.tier == "sovereign"
    assert cp.server_id == ""
    assert cp.row_count == 4
    assert cp.head_row_hash == rows[-1]["row_hash"]


def test_second_checkpoint_counts_only_new_rows_since_the_last_one():
    first_run = _chain(4)
    previous = {"row_count": 4, "head_row_hash": first_run[-1]["row_hash"]}

    second_run = _chain(3, first_prev=first_run[-1]["row_hash"])
    # Simulate the earliest rows of first_run having expired out of ssdf.audit
    # by only passing the still-live tail plus the new rows.
    still_live = [first_run[-1]] + second_run

    cp = compute_next_checkpoint(still_live, previous)
    assert cp is not None
    assert cp.row_count == 4 + 3  # base + 3 new rows, NOT len(still_live)
    assert cp.head_row_hash == second_run[-1]["row_hash"]


def test_no_new_rows_since_previous_checkpoint_yields_none():
    rows = _chain(4)
    previous = {"row_count": 4, "head_row_hash": rows[-1]["row_hash"]}
    # Only the already-checkpointed tip survives; nothing new appended.
    cp = compute_next_checkpoint([rows[-1]], previous)
    assert cp is None


def test_previous_checkpoint_head_fully_expired_yields_none_not_a_guess():
    """If the previous checkpoint's head row itself has expired out of
    ssdf.audit and no later row chains from it either, there is nothing this
    run can honestly extend -- it must not guess at a row_count."""
    rows = _chain(3, first_prev="deadbeef-stale-checkpoint-head")
    previous = {"row_count": 10, "head_row_hash": "deadbeef-stale-checkpoint-head-does-not-match"}
    assert compute_next_checkpoint(rows, previous) is None


def test_evidence_chain_carries_its_writer_id():
    row = dict(
        ts=dt.datetime(2026, 8, 20, 12, 0, 0, 0, tzinfo=dt.timezone.utc),
        principal="agent:mecmcp",
        tier="evidence",
        tool="evidence:proposal",
        args='{"server_id":"rustsdcmcp-606","run_id":"run-1","segment_seq":0}',
        data_classes=["device:vsrx-ci"],
        decision="",
        row_count=1,
        error="",
        prev_hash="",
    )
    row["row_hash"] = compute_row_hash("", row)
    cp = compute_next_checkpoint([row], previous=None)
    assert cp.tier == "evidence"
    assert cp.server_id == "rustsdcmcp-606"
    assert cp.row_count == 1
