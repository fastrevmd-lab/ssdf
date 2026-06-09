"""Append-only audit of MCP tool calls (M7a).

Best-effort by design: an audit write failure is logged to stderr but must never
fail the tool call. Rows are inserted by a dedicated INSERT-only ``ssdf_audit``
CH user on a connection separate from the ``ssdf_ro`` query path.
"""

from __future__ import annotations

import datetime as _dt
import json
import sys
from typing import Any, Callable, Iterable

# Column order MUST match infra/clickhouse/007_audit.sql.
AUDIT_COLUMNS: list[str] = [
    "ts", "principal", "tier", "tool", "args",
    "data_classes", "decision", "row_count", "error",
]


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
) -> dict:
    """Build a fully-shaped audit row dict (pure; no I/O)."""
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
    }


class Auditor:
    """Wraps a row-insert callable, swallowing (and logging) insert failures."""

    def __init__(self, insert: Callable[[dict], None]):
        self._insert = insert

    def record(self, **fields: Any) -> None:
        """Build and insert one audit row; never raises."""
        row = build_audit_row(**fields)
        try:
            self._insert(row)
        except Exception as exc:  # best-effort: audit must not block a tool call
            print(f"[audit] insert failed: {exc}", file=sys.stderr)


def _noop_insert(_row: dict) -> None:
    return None


def make_ch_auditor(config) -> Auditor:
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
    )

    def insert(row: dict) -> None:
        client.insert(
            "ssdf.audit",
            [[row[col] for col in AUDIT_COLUMNS]],
            column_names=AUDIT_COLUMNS,
        )

    return Auditor(insert)
