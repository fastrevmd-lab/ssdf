"""Write seam: insert the three M7c tables."""

from __future__ import annotations

from datetime import datetime
from typing import Iterable

import clickhouse_connect

from .chreader import client_kwargs
from .config import Config

METRIC_COLUMNS = ["bucket_start", "metric", "dim", "value", "tenant_id"]
ENTITY_COLUMNS = ["bucket_start", "surrogate", "metric", "value", "tenant_id"]
MAP_COLUMNS = ["kind", "real_value", "surrogate", "key_version", "first_seen", "last_seen"]

# DateTime/DateTime64 columns: clickhouse_connect's insert serializer calls
# value.timestamp(), so ISO strings (the resolver's index + map rows) must be
# parsed to datetime first. Values read back from ClickHouse are already
# datetime objects and pass through untouched.
_DATETIME_COLUMNS = {"bucket_start", "first_seen", "last_seen"}


def _coerce(column: str, value):
    if column in _DATETIME_COLUMNS and isinstance(value, str):
        return datetime.fromisoformat(value)
    return value


def _rows(items: Iterable[dict], columns: list[str]) -> list[list]:
    return [[_coerce(c, item[c]) for c in columns] for item in items]


class MetricsWriter:
    def __init__(self, config: Config):
        self._client = clickhouse_connect.get_client(**client_kwargs(config))

    def write_metric_timeseries(self, items: list[dict]) -> int:
        if not items:
            return 0
        self._client.insert("ssdf_public.metric_timeseries",
                            _rows(items, METRIC_COLUMNS), column_names=METRIC_COLUMNS)
        return len(items)

    def write_entity_series(self, items: list[dict]) -> int:
        if not items:
            return 0
        self._client.insert("ssdf_public.entity_series",
                            _rows(items, ENTITY_COLUMNS), column_names=ENTITY_COLUMNS)
        return len(items)

    def write_pseudonym_map(self, items: list[dict]) -> int:
        if not items:
            return 0
        self._client.insert("ssdf.pseudonym_map",
                            _rows(items, MAP_COLUMNS), column_names=MAP_COLUMNS)
        return len(items)
