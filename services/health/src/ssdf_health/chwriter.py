"""ClickHouse writer for health gauges (the storage seam, write side)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Iterable

import clickhouse_connect

from .config import Config
from .gauge import Gauge

HEALTH_COLUMNS = [
    "timestamp", "tenant_id", "provider", "device", "scope",
    "metric_class", "sensor", "metric_name", "metric_value", "unit", "raw",
]


def client_kwargs(config: Config) -> dict[str, Any]:
    """get_client kwargs from config; adds TLS (interface/ca_cert) when ch_secure."""
    kwargs: dict[str, Any] = dict(
        host=config.ch_host, port=config.ch_port, username=config.ch_user,
        password=config.ch_password, database=config.ch_database,
    )
    if config.ch_secure:
        kwargs["interface"] = "https"
        if config.ch_ca_file:
            kwargs["ca_cert"] = config.ch_ca_file
    return kwargs


def health_rows(gauges: Iterable[Gauge], now: datetime, tenant_id: str) -> list[list[Any]]:
    """Stamp each gauge with the batch timestamp + tenant and order fields by column."""
    return [
        [now, tenant_id, g.provider, g.device, g.scope, g.metric_class,
         g.sensor, g.metric_name, g.value, g.unit, g.raw]
        for g in gauges
    ]


class HealthWriter:
    """Insert health gauges into ssdf.health_metrics as the ssdf_health user."""

    def __init__(self, config: Config):
        self._config = config
        self._client = clickhouse_connect.get_client(**client_kwargs(config))

    def insert_gauges(self, gauges: list[Gauge], now: datetime) -> int:
        if not gauges:
            return 0
        rows = health_rows(gauges, now, self._config.tenant_id)
        self._client.insert("ssdf.health_metrics", rows, column_names=HEALTH_COLUMNS)
        return len(gauges)
