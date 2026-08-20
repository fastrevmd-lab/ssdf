import datetime as dt
from ssdf_mcp_query.audit_chain import compute_row_hash
from ssdf_mcp_query.verify_audit import verify_tier


def _chain(n, tier="sovereign"):
    """Build n correctly-chained rows for one tier."""
    rows = []
    prev = ""
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


def test_clean_chain_has_no_issues():
    assert verify_tier(_chain(4)) == []


def test_detects_content_edit():
    rows = _chain(4)
    rows[2]["tool"] = "TAMPERED"  # stored row_hash no longer matches recomputed
    issues = verify_tier(rows)
    assert any(i["type"] == "content_edit" for i in issues)


def test_detects_deletion_of_predecessor():
    rows = _chain(4)
    del rows[1]  # row[2].prev_hash now names a missing row_hash
    issues = verify_tier(rows)
    assert any(i["type"] == "missing_predecessor" for i in issues)


def test_legacy_unhashed_rows_are_not_issues():
    """Rows written before migration 009 have prev_hash='' / row_hash='' (column
    DEFAULT). The first *hashed* row per tier is that tier's chain start; legacy
    rows must not be flagged."""
    legacy = dict(
        ts=dt.datetime(2026, 6, 9, 12, 0, 0, 0, tzinfo=dt.timezone.utc),
        principal="agent",
        tier="sovereign",
        tool="old",
        args="{}",
        data_classes=["topology"],
        decision="allow",
        row_count=0,
        error="",
        prev_hash="",
        row_hash="",
    )
    rows = [legacy] + _chain(3)
    assert verify_tier(rows) == []


def test_detects_unreachable_orphan():
    rows = _chain(3)
    orphan = dict(
        ts=dt.datetime(2026, 6, 10, 13, 0, 0, 0, tzinfo=dt.timezone.utc),
        principal="agent",
        tier="sovereign",
        tool="x",
        args="{}",
        data_classes=["topology"],
        decision="allow",
        row_count=0,
        error="",
        prev_hash="deadbeef",
        row_hash="feedface",
    )
    rows.append(orphan)
    issues = verify_tier(rows)
    assert any(i["type"] in ("unreachable", "missing_predecessor") for i in issues)


def _evidence_chain(n, server_id, first_prev=""):
    """Build n correctly-chained evidence rows for one writer."""
    rows = []
    prev = first_prev
    for i in range(n):
        row = dict(
            ts=dt.datetime(2026, 8, 20, 12, 0, i, 0, tzinfo=dt.timezone.utc),
            principal="agent:mecmcp",
            tier="evidence",
            tool="evidence:proposal",
            args=('{"server_id":"' + server_id + '","run_id":"run-1","segment_seq":0}'),
            data_classes=["device:vsrx-ci"],
            decision="",
            row_count=1,
            error="",
        )
        row["prev_hash"] = prev
        row["row_hash"] = compute_row_hash(prev, row)
        prev = row["row_hash"]
        rows.append(row)
    return rows


def test_two_writers_are_verified_as_separate_chains():
    """The evidence tier has many writers; one chain per tier cannot work.

    Fifteen MCP servers write ``tier='evidence'``. Chaining per tier would need
    every writer to serialise against a shared head — there is no such lock, so
    each seeds ``prev_hash=""`` and the tier acquires one accepted root per
    server. Grouping by writer gives each exactly one root, which is what makes
    a deleted run detectable (ssdf#47).
    """
    from ssdf_mcp_query.verify_audit import group_key

    rows = _evidence_chain(3, "mecmcp-950") + _evidence_chain(3, "mecmcp-960")

    keys = {group_key(r) for r in rows}
    assert keys == {
        ("evidence", "mecmcp-950"),
        ("evidence", "mecmcp-960"),
    }, "each writer must be its own chain"

    for key in keys:
        subset = [r for r in rows if group_key(r) == key]
        assert verify_tier(subset) == [], f"{key} must verify clean on its own"


def test_a_deleted_run_leaves_a_missing_predecessor():
    """The failure this whole mechanism exists to catch.

    A run that continues its writer's chain (``resume_from``) means deleting
    that run outright breaks the link its successor names — rather than removing
    an entire independent root, which leaves nothing to notice.
    """
    first_run = _evidence_chain(2, "mecmcp-950")
    second_run = _evidence_chain(2, "mecmcp-950", first_prev=first_run[-1]["row_hash"])

    surviving = second_run  # the first run is deleted wholesale

    issues = verify_tier(surviving)
    assert any(i["type"] == "missing_predecessor" for i in issues), (
        "deleting a whole run must be visible; it is only visible because the "
        "later run chained onto the earlier one"
    )


def test_rows_without_a_server_id_group_by_tier_alone():
    """Sovereign rows carry no server_id and must keep verifying as they did."""
    from ssdf_mcp_query.verify_audit import group_key

    assert group_key(_chain(1)[0]) == ("sovereign", "")


def test_an_evidence_row_without_a_writer_is_a_violation():
    """An evidence row must name the chain it belongs to.

    Grouping such a row under the tier alone is not a harmless default: several
    malformed writers land in one bucket, each contributes its own root, and the
    result verifies as clean. That is the deletion blind spot the per-writer
    grouping exists to close, reached from the other side — so an evidence row
    with no usable ``server_id`` has to be an issue, not a fallback.
    """
    from ssdf_mcp_query.verify_audit import writer_issue

    assert writer_issue({"tier": "evidence", "args": "", "row_hash": "sha256:a"})
    assert writer_issue({"tier": "evidence", "args": "not json", "row_hash": "sha256:b"})
    assert writer_issue({"tier": "evidence", "args": '{"server_id": 7}', "row_hash": "sha256:c"})
    assert writer_issue({"tier": "evidence", "args": '{"server_id": ""}', "row_hash": "sha256:d"})
    assert not writer_issue(
        {"tier": "evidence", "args": '{"server_id": "junos-950"}', "row_hash": "sha256:e"}
    )


def test_a_sovereign_row_without_a_writer_is_not_a_violation():
    """The 20,193 existing sovereign rows name no writer and never did.

    Requiring one of them would turn every historical row into an issue, which
    is a rule about a different tier applied where it was never promised.
    """
    from ssdf_mcp_query.verify_audit import writer_issue

    assert not writer_issue({"tier": "sovereign", "args": "", "row_hash": "sha256:f"})
