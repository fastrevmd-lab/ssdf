"""Append-only audit of MCP tool calls (M7a) with a per-tier hash chain (M3).

Best-effort by design: an audit write failure is logged to stderr and never fails
the tool call. Rows are inserted by a dedicated INSERT-only ``ssdf_audit`` CH user
on a connection separate from the ``ssdf_ro`` query path. Each row carries
``prev_hash``/``row_hash`` linking it to the previous row of the SAME tier written
by this process, so tampering (edits, deletions, reorders) is later detectable by
``verify_audit``. The chain head is kept in-process and seeded at startup via the
read-only ``ssdf_audit_verify`` identity; the insert path itself never reads.
"""

from __future__ import annotations

import datetime as _dt
import json
import sys
import threading
from typing import Any, Callable, Iterable

from .audit_chain import compute_row_hash
from .config import ch_tls_kwargs

# The nine stored business fields (what build_audit_row produces).
AUDIT_BASE_COLUMNS: list[str] = [
    "ts",
    "principal",
    "tier",
    "tool",
    "args",
    "data_classes",
    "decision",
    "row_count",
    "error",
]
# Attribution (issue #9, migration 017). Listed separately from the base nine
# because audit_chain.canonical() treats them as a conditional tail, not as
# part of the original fixed form.
AUDIT_ATTRIBUTION_COLUMNS: list[str] = ["client_name", "model_id", "actor_type"]
# Full insert column order MUST match infra/clickhouse/007_audit.sql +
# 009_audit_hash_chain.sql + 017_audit_attribution.sql.
AUDIT_COLUMNS: list[str] = (
    AUDIT_BASE_COLUMNS + AUDIT_ATTRIBUTION_COLUMNS + ["prev_hash", "row_hash"]
)


def build_audit_row(
    *,
    principal: str,
    tier: str,
    tool: str,
    args: Any,
    data_classes: Iterable[str],
    decision: str,
    row_count: int,
    error: Any,
    ts: _dt.datetime | None = None,
    client_name: str = "",
    model_id: str = "",
    actor_type: str = "",
) -> dict:
    """Build the business fields of an audit row (pure; no hashes, no I/O).

    The three attribution fields (issue #9) default to empty, which is what an
    unattributed call genuinely is -- and what keeps such a row hashing exactly
    as it did before the columns existed.
    """
    return {
        "ts": ts or _dt.datetime.now(_dt.timezone.utc),
        "principal": principal,
        "tier": tier,
        "tool": tool,
        "args": json.dumps(args, default=str, sort_keys=True),
        "data_classes": list(data_classes),
        "decision": decision,
        "row_count": int(row_count),
        "error": str(error or ""),
        "client_name": str(client_name or ""),
        "model_id": str(model_id or ""),
        "actor_type": str(actor_type or ""),
    }


class Auditor:
    """Wraps a row-insert callable; chains hashes per process and swallows failures."""

    def __init__(self, insert: Callable[[dict], None], last_hash: str = ""):
        self._insert = insert
        self._last_hash = last_hash
        self._lock = threading.Lock()

    def record(self, **fields: Any) -> None:
        """Build, hash-chain, and insert one audit row; never raises."""
        row = build_audit_row(**fields)
        with self._lock:
            prev = self._last_hash
            row_hash = compute_row_hash(prev, row)
            row["prev_hash"] = prev
            row["row_hash"] = row_hash
            try:
                self._insert(row)
            except Exception as exc:  # best-effort: audit must not block a tool call
                print(f"[audit] insert failed: {exc}", file=sys.stderr)
                return
            self._last_hash = row_hash  # advance only after a successful insert


def _noop_insert(_row: dict) -> None:
    return None


def _seed_last_hash(config, tier: str) -> str:
    """Seed the chain head from the latest row of this tier (read-only identity)."""
    if not config.ch_audit_verify_password:
        print(
            "[audit] CH_AUDIT_VERIFY_PASSWORD unset; chain starts fresh (not seeded from history)",
            file=sys.stderr,
        )
        return ""
    import clickhouse_connect

    verify_client = clickhouse_connect.get_client(
        host=config.ch_host,
        port=config.ch_port,
        username="ssdf_audit_verify",
        password=config.ch_audit_verify_password,
        database=config.ch_database,
        **ch_tls_kwargs(config),
    )
    res = verify_client.query(
        "SELECT row_hash FROM ssdf.audit WHERE tier = {tier:String} ORDER BY ts DESC LIMIT 1",
        parameters={"tier": tier},
    )
    if res.result_rows:
        return res.result_rows[0][0]
    return ""


def make_ch_auditor(config, tier: str = "sovereign") -> Auditor:
    """Build a CH-backed Auditor, or a no-op one when no audit password is set."""
    if not config.ch_audit_password:
        print("[audit] CH_AUDIT_PASSWORD unset; audit disabled (no-op)", file=sys.stderr)
        return Auditor(_noop_insert)
    import clickhouse_connect

    client = clickhouse_connect.get_client(
        host=config.ch_host,
        port=config.ch_port,
        username=config.ch_audit_user,
        password=config.ch_audit_password,
        database=config.ch_database,
        **ch_tls_kwargs(config),
    )

    def insert(row: dict) -> None:
        client.insert(
            "ssdf.audit",
            [[row[col] for col in AUDIT_COLUMNS]],
            column_names=AUDIT_COLUMNS,
        )

    last_hash = _seed_last_hash(config, tier)
    return Auditor(insert, last_hash=last_hash)
