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
            principal="agent", tier=tier, tool=f"t{i}", args="{}",
            data_classes=["topology"], decision="allow", row_count=i, error="",
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


def test_detects_unreachable_orphan():
    rows = _chain(3)
    orphan = dict(
        ts=dt.datetime(2026, 6, 10, 13, 0, 0, 0, tzinfo=dt.timezone.utc),
        principal="agent", tier="sovereign", tool="x", args="{}",
        data_classes=["topology"], decision="allow", row_count=0, error="",
        prev_hash="deadbeef", row_hash="feedface",
    )
    rows.append(orphan)
    issues = verify_tier(rows)
    assert any(i["type"] in ("unreachable", "missing_predecessor") for i in issues)
