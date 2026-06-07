# src/ssdf_mcp_query/clickhouse.py
"""Read-only ClickHouse access (the swappable storage seam)."""

from __future__ import annotations

import datetime as _dt
import ipaddress as _ip
from typing import Any

import clickhouse_connect

from .config import Config


def jsonify(value: Any) -> Any:
    """Convert ClickHouse-returned values into JSON-serializable Python primitives."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, _dt.datetime):
        return value.isoformat()
    if isinstance(value, (_ip.IPv4Address, _ip.IPv6Address)):
        return str(value)
    if isinstance(value, dict):
        return {k: jsonify(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [jsonify(v) for v in value]
    return str(value)


class ClickHouseClient:
    """Thin read-only client. All queries run as the configured (read-only) CH user."""

    def __init__(self, config: Config):
        self._config = config
        self._client = clickhouse_connect.get_client(
            host=config.ch_host,
            port=config.ch_port,
            username=config.ch_user,
            password=config.ch_password,
            database=config.ch_database,
        )

    def run(self, sql: str, params: dict | None = None) -> dict:
        """Execute a read query; return {columns, rows, row_count}. Rows are dicts."""
        result = self._client.query(sql, parameters=params or {})
        columns = list(result.column_names)
        rows = [
            {col: jsonify(val) for col, val in zip(columns, row)}
            for row in result.result_rows
        ]
        return {"columns": columns, "rows": rows, "row_count": len(rows)}
