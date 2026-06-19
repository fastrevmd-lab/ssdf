"""Write seam: insert the three M7c tables."""

from __future__ import annotations

from typing import Iterable

import clickhouse_connect

from .chreader import client_kwargs
from .config import Config

METRIC_COLUMNS = ["bucket_start", "metric", "dim", "value", "tenant_id"]
ENTITY_COLUMNS = ["bucket_start", "surrogate", "metric", "value", "tenant_id"]
MAP_COLUMNS = ["kind", "real_value", "surrogate", "key_version", "first_seen", "last_seen"]


def _rows(items: Iterable[dict], columns: list[str]) -> list[list]:
    return [[item[c] for c in columns] for item in items]


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
