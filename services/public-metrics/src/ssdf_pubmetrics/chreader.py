"""Read seam: aggregate ssdf.events + load the current pseudonym map."""

from __future__ import annotations

from typing import Any

import clickhouse_connect

from ssdf_common.clickhouse import client_kwargs as _client_kwargs
from .config import Config
from .measures import (
    build_aggregate_sql,
    build_entity_bucket_sql,
    build_deny_counts_sql,
    build_alert_count_sql,
)


def client_kwargs(config: Config) -> dict[str, Any]:
    return _client_kwargs(
        host=config.ch_host,
        port=config.ch_port,
        user=config.ch_user,
        password=config.ch_password,
        database=config.ch_database,
        secure=config.ch_secure,
        ca_file=config.ch_ca_file,
    )


class EventsReader:
    """Reads ssdf.events for aggregation and loads the sovereign pseudonym map."""

    def __init__(self, config: Config):
        self._client = clickhouse_connect.get_client(**client_kwargs(config))
        self._tenant = config.tenant_id

    def _rows(self, sql: str, params: dict) -> list[dict]:
        result = self._client.query(sql, parameters=params)
        cols = list(result.column_names)
        return [dict(zip(cols, row)) for row in result.result_rows]

    def aggregate_series(self, metric: str, since_iso: str, bucket_secs: int) -> list[dict]:
        sql, params = build_aggregate_sql(metric, since_iso, bucket_secs, self._tenant)
        return self._rows(sql, params)

    def entity_bucket_series(self, metric: str, since_iso: str, bucket_secs: int) -> list[dict]:
        sql, params = build_entity_bucket_sql(metric, since_iso, bucket_secs, self._tenant)
        return self._rows(sql, params)

    def deny_counts(self, since_iso: str) -> dict:
        sql, params = build_deny_counts_sql(since_iso, self._tenant)
        rows = self._rows(sql, params)
        return rows[0] if rows else {"deny": 0.0, "total": 0.0}

    def alert_count(self, since_iso: str) -> float:
        sql, params = build_alert_count_sql(since_iso, self._tenant)
        rows = self._rows(sql, params)
        return float(rows[0]["c"]) if rows else 0.0

    def load_pseudonym_map(self, kinds: list[str]) -> dict[tuple[str, str], str]:
        if not kinds:
            return {}
        sql = (
            "SELECT kind, real_value, surrogate FROM ssdf.pseudonym_map FINAL "
            "WHERE kind IN {kinds:Array(String)}"
        )
        rows = self._rows(sql, {"kinds": kinds})
        return {(r["kind"], r["real_value"]): r["surrogate"] for r in rows}
