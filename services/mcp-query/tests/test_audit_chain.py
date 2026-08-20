import datetime as dt
from ssdf_mcp_query.audit_chain import ts_ms_iso, canonical, compute_row_hash


def _row(**over):
    base = dict(
        ts=dt.datetime(2026, 6, 10, 12, 0, 0, 123000, tzinfo=dt.timezone.utc),
        principal="agent",
        tier="sovereign",
        tool="locate",
        args='{"x":1}',
        data_classes=["topology"],
        decision="allow",
        row_count=1,
        error="",
    )
    base.update(over)
    return base


def test_ts_ms_iso_millisecond_precision():
    ts = dt.datetime(2026, 6, 10, 12, 0, 0, 123999, tzinfo=dt.timezone.utc)
    assert ts_ms_iso(ts) == "2026-06-10T12:00:00.123Z"


def test_ts_ms_iso_assumes_utc_when_naive():
    ts = dt.datetime(2026, 6, 10, 12, 0, 0, 0)
    assert ts_ms_iso(ts) == "2026-06-10T12:00:00.000Z"


def test_canonical_is_deterministic():
    assert canonical(_row()) == canonical(_row())


def test_row_hash_changes_when_any_field_changes():
    base = compute_row_hash("", _row())
    assert compute_row_hash("", _row(tool="run_sql")) != base
    assert compute_row_hash("", _row(row_count=2)) != base
    assert compute_row_hash("prevX", _row()) != base  # prev_hash participates


def test_row_hash_is_sha256_hex():
    h = compute_row_hash("", _row())
    assert len(h) == 64 and all(c in "0123456789abcdef" for c in h)
