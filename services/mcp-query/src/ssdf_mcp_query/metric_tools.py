"""Agent-facing façade for the M7c de-identified metrics tools."""

from __future__ import annotations

from typing import Any


class MetricTools:
    """Thin pass-through over ``MetricsStore`` carrying the tool docstrings."""

    def __init__(self, store: Any):
        self._store = store

    def metric_timeseries(
        self, metric: str, since: str | None = None, until: str | None = None
    ) -> dict:
        return self._store.metric_timeseries(metric, since=since, until=until)

    def top_series(self, metric: str, since: str | None = None, limit: int = 10) -> dict:
        return self._store.top_series(metric, since=since, limit=limit)

    def entity_metric_timeseries(
        self, surrogate: str, metric: str, since: str | None = None, until: str | None = None
    ) -> dict:
        return self._store.entity_metric_timeseries(surrogate, metric, since=since, until=until)

    def reidentify(self, surrogate: str) -> dict:
        return self._store.reidentify(surrogate)
