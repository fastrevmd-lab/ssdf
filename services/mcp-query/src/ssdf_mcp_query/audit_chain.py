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
    return hashlib.sha256(
        (prev_hash + "\n" + canonical(row)).encode("utf-8")
    ).hexdigest()
