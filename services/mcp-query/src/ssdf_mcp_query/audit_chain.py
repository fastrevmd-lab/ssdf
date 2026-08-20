"""Pure helpers for the per-tier audit hash chain (M3).

No I/O. The same functions are used by the write path (audit.py) and the offline
verifier (verify_audit.py), so a chain written by one is reproducible by the other.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json


def ts_ms_iso(ts: _dt.datetime) -> str:
    """UTC ISO-8601 truncated to milliseconds, matching a ClickHouse DateTime64(3,'UTC')
    round-trip. Naive datetimes are assumed UTC."""
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=_dt.timezone.utc)
    ts = ts.astimezone(_dt.timezone.utc)
    return ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z"


def canonical(row: dict) -> str:
    """Deterministic serialization of a row's nine non-hash fields, in fixed order."""
    return json.dumps(
        [
            ts_ms_iso(row["ts"]),
            row["principal"],
            row["tier"],
            row["tool"],
            row["args"],
            list(row["data_classes"]),
            row["decision"],
            int(row["row_count"]),
            row["error"],
        ],
        separators=(",", ":"),
        ensure_ascii=False,
    )


def compute_row_hash(prev_hash: str, row: dict) -> str:
    """row_hash = SHA-256( prev_hash + '\\n' + canonical(row) ), hex digest."""
    return hashlib.sha256((prev_hash + "\n" + canonical(row)).encode("utf-8")).hexdigest()


def dedup_token(server_id: str, run_id: str, segment_seq: int) -> str:
    """ClickHouse ``insert_deduplication_token`` for one evidence segment.

    Canonical definition for this repository. It must stay byte-identical to
    the Rust sink's ``dedup_token`` (mecmcp-audit) and to the copy in
    ``scripts/verify_evidence_contract.py``, which cannot import this module --
    the known-answer vectors in the tests pin all three together.

    Two properties matter, and both have already been got wrong once:

    - **Byte lengths, not character counts.** Python's ``len()`` counts code
      points while Rust's ``str::len()`` counts UTF-8 bytes. They agree for
      ASCII, which is how the divergence hides, and disagree for anything else
      -- so a retry issued by the other implementation would carry a different
      token, ClickHouse would see a new block, and the duplicate would land.
    - **Length-prefixed, not merely separated.** Identifiers are free-form, so
      joining on ``:`` alone is not injective: ``("a:b", "c", 1)`` and
      ``("a", "b:c", 1)`` both give ``a:b:c:1``, and two segments sharing a
      token means one is dropped while its writer is told it succeeded.
    """
    return (
        f"{len(server_id.encode('utf-8'))}:{server_id}:"
        f"{len(run_id.encode('utf-8'))}:{run_id}:{segment_seq}"
    )
