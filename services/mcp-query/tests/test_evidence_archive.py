from __future__ import annotations

import datetime as dt

from ssdf_mcp_query.evidence_archive import rows_due_for_archiving

NOW = dt.datetime(2026, 10, 3, 0, 0, 0, tzinfo=dt.timezone.utc)


def _row(days_old, row_hash=""):
    return {
        "ts": NOW - dt.timedelta(days=days_old),
        "principal": "agent",
        "tool": "t",
        "row_hash": row_hash,
    }


def test_recent_row_is_not_due():
    assert rows_due_for_archiving([_row(10)], NOW) == []


def test_old_row_is_due():
    rows = [_row(80)]
    assert rows_due_for_archiving(rows, NOW) == rows


def test_boundary_is_inclusive_of_the_threshold_day():
    due = _row(75)
    not_due = _row(74)
    result = rows_due_for_archiving([due, not_due], NOW, archive_after_days=75)
    assert due in result
    assert not_due not in result


def test_already_archived_row_is_skipped():
    row = _row(80, row_hash="abc123")
    assert rows_due_for_archiving([row], NOW, already_archived=frozenset({"abc123"})) == []


def test_legacy_unhashed_row_is_never_treated_as_already_archived():
    """Legacy rows all share row_hash=='' -- that must never match an entry in
    ``already_archived`` (which also would not contain '' for a real row), or
    one legacy row being archived would make every other legacy row look
    already-copied and get silently skipped."""
    row = _row(80, row_hash="")
    assert rows_due_for_archiving([row], NOW, already_archived=frozenset({""})) == [row]


def test_custom_threshold_is_respected():
    rows = [_row(50)]
    assert rows_due_for_archiving(rows, NOW, archive_after_days=75) == []
    assert rows_due_for_archiving(rows, NOW, archive_after_days=40) == rows


def test_naive_datetimes_are_treated_as_utc():
    naive_now = dt.datetime(2026, 10, 3, 0, 0, 0)
    naive_row = {"ts": dt.datetime(2026, 7, 1, 0, 0, 0), "row_hash": ""}
    assert rows_due_for_archiving([naive_row], naive_now, archive_after_days=75) == [naive_row]
