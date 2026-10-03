#!/usr/bin/env python3
"""Archive ssdf.audit rows into the retention-safe ssdf.audit_evidence tier (MEC-565).

I/O shell around `ssdf_mcp_query.evidence_archive.rows_due_for_archiving`
(pure decision logic, unit-tested on its own): reads rows from `ssdf.audit`
older than the archive threshold plus the set of row_hash values already
present in `ssdf.audit_evidence`, as the `ssdf_archiver` identity
(023_audit_evidence.sql), asks the pure function which rows are still due,
and inserts them verbatim (same column shape, hash-chain fields included) so
an archived row still verifies against the row_hash it had in `ssdf.audit`.

Idempotent by design: re-running after a partial failure only re-inserts rows
not already found in `ssdf.audit_evidence` (by row_hash) -- see
`rows_due_for_archiving`'s docstring for the legacy-row caveat (empty
row_hash is never treated as "already archived").

Run periodically (e.g. daily), well ahead of `ssdf.audit`'s 90-day TTL
(DEFAULT_ARCHIVE_AFTER_DAYS leaves ten days of margin against a missed run).

Usage (from services/mcp-query, where the package is installed):
    export CH_HOST=... CH_ARCHIVER_PASSWORD=...
    uv run python scripts/archive_audit.py [--archive-after-days 75]
"""

from __future__ import annotations

import argparse
import datetime as dt
import os
import sys

from ssdf_common.config import ConfigError, require_tls_or_loopback
from ssdf_mcp_query.evidence_archive import DEFAULT_ARCHIVE_AFTER_DAYS, rows_due_for_archiving

_AUDIT_COLUMNS = [
    "ts",
    "principal",
    "tier",
    "tool",
    "args",
    "data_classes",
    "decision",
    "row_count",
    "error",
    "client_name",
    "model_id",
    "actor_type",
    "prev_hash",
    "row_hash",
]


def fetch_candidate_rows(client, cutoff: dt.datetime) -> list[dict]:
    """Rows old enough to be worth considering for archiving.

    Filters by ``ts <= cutoff`` in SQL purely to limit how much of
    `ssdf.audit` is pulled across the wire; the exact due/not-due and
    already-archived decisions still belong to `rows_due_for_archiving`.
    """
    res = client.query(
        f"SELECT {', '.join(_AUDIT_COLUMNS)} FROM ssdf.audit WHERE ts <= {{cutoff:DateTime64(3)}}",
        parameters={"cutoff": cutoff},
    )
    rows = [dict(zip(_AUDIT_COLUMNS, row)) for row in res.result_rows]
    # clickhouse-connect returns a DateTime64(_, 'UTC') value as a NAIVE
    # datetime (the column's own timezone already pins its meaning). Attaching
    # UTC explicitly here, before this value is ever written anywhere else,
    # heads off a real bug confirmed by a live run: handing that naive value
    # straight to a later `client.insert(...)` makes clickhouse-connect
    # reinterpret it as wall-clock time in *this process's* local timezone and
    # convert accordingly, silently shifting `ts` by the host's UTC offset on
    # any machine not already running in UTC -- a correctness bug in archived
    # audit timestamps, not merely a display quirk.
    for row in rows:
        if row["ts"].tzinfo is None:
            row["ts"] = row["ts"].replace(tzinfo=dt.timezone.utc)
    return rows


def fetch_already_archived(client) -> frozenset[str]:
    """``row_hash`` values already present in ``ssdf.audit_evidence``.

    Excludes the empty-string legacy sentinel: it is never a meaningful
    "already archived" marker (see `rows_due_for_archiving`'s docstring), and
    returning it here would be harmless on its own only because that
    function already guards against it -- this still leaves it out so the
    guard is not the only thing standing between two call sites.
    """
    res = client.query("SELECT DISTINCT row_hash FROM ssdf.audit_evidence WHERE row_hash != ''")
    return frozenset(row[0] for row in res.result_rows)


def insert_evidence_rows(client, rows: list[dict]) -> None:
    client.insert(
        "ssdf.audit_evidence",
        [[row[c] for c in _AUDIT_COLUMNS] for row in rows],
        column_names=_AUDIT_COLUMNS,
    )


def run(
    client,
    archive_after_days: int = DEFAULT_ARCHIVE_AFTER_DAYS,
    now: dt.datetime | None = None,
) -> list[dict]:
    """Archive every row due for it. Returns the rows that were inserted."""
    now = now or dt.datetime.now(dt.timezone.utc)
    cutoff = now - dt.timedelta(days=archive_after_days)
    candidates = fetch_candidate_rows(client, cutoff)
    already_archived = fetch_already_archived(client)
    due = rows_due_for_archiving(
        candidates, now, archive_after_days=archive_after_days, already_archived=already_archived
    )
    if due:
        insert_evidence_rows(client, due)
    return due


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--archive-after-days",
        type=int,
        default=int(os.environ.get("ARCHIVE_AFTER_DAYS", str(DEFAULT_ARCHIVE_AFTER_DAYS))),
    )
    args = parser.parse_args()

    password = os.environ.get("CH_ARCHIVER_PASSWORD")
    if not password:
        print("CH_ARCHIVER_PASSWORD is required", file=sys.stderr)
        return 2

    host = os.environ.get("CH_HOST", "127.0.0.1")
    secure = os.environ.get("CH_SECURE", "").strip().lower() in ("1", "true")
    try:
        require_tls_or_loopback(host, secure)
    except ConfigError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    import clickhouse_connect

    kwargs: dict = {}
    if secure:
        kwargs["interface"] = "https"
        ca_file = os.environ.get("CH_CA_FILE")
        if ca_file:
            kwargs["ca_cert"] = ca_file

    client = clickhouse_connect.get_client(
        host=host,
        port=int(os.environ.get("CH_PORT", "8123")),
        username="ssdf_archiver",
        password=password,
        database="ssdf",
        **kwargs,
    )

    archived = run(client, archive_after_days=args.archive_after_days)
    print(f"archived {len(archived)} row(s) into ssdf.audit_evidence")
    return 0


if __name__ == "__main__":
    sys.exit(main())
