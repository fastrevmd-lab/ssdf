"""Read seam for the M7c de-identified metrics surface.

Reads the public metric tables (always in the ``ssdf_public`` schema) and, for
re-identification only, the sovereign ``ssdf.pseudonym_map``. Returns plain dicts
shaped like the other store seams (``{columns, rows, row_count}``).
"""

from __future__ import annotations

from typing import Any

from .timeparse import parse_time

_METRIC_TABLE = "ssdf_public.metric_timeseries"
_ENTITY_TABLE = "ssdf_public.entity_series"
_MAP_TABLE = "ssdf.pseudonym_map"


class MetricsStore:
    """Queries the de-identified metric tables (+ sovereign map for reidentify)."""

    def __init__(self, client: Any, tenant: str = "t_main"):
        self._client = client
        self._tenant = tenant

    def metric_timeseries(self, metric: str, since: str | None = None,
                          until: str | None = None) -> dict:
        """Aggregate (dim='') time series for one metric over a window."""
        sql = (
            f"SELECT bucket_start, value FROM {_METRIC_TABLE} FINAL "
            "WHERE tenant_id = {tenant:String} AND metric = {metric:String} "
            "AND dim = '' "
            "AND bucket_start >= parseDateTimeBestEffort({since:String}) "
            "AND ({until:String} = '' OR bucket_start <= parseDateTimeBestEffortOrNull({until:String})) "
            "ORDER BY bucket_start"
        )
        params = {"tenant": self._tenant, "metric": metric,
                  "since": _resolve_since(since), "until": _resolve_until(until)}
        return self._client.run(sql, params)

    def top_series(self, metric: str, since: str | None = None,
                   limit: int = 10) -> dict:
        """Top-N surrogates for a per-entity metric over a window, by total value."""
        sql = (
            "SELECT surrogate, sum(value) AS value "
            f"FROM {_ENTITY_TABLE} FINAL "
            "WHERE tenant_id = {tenant:String} AND metric = {metric:String} "
            "AND bucket_start >= parseDateTimeBestEffort({since:String}) "
            "GROUP BY surrogate ORDER BY value DESC LIMIT {limit:UInt32}"
        )
        params = {"tenant": self._tenant, "metric": metric,
                  "since": _resolve_since(since), "limit": int(limit)}
        return self._client.run(sql, params)

    def entity_metric_timeseries(self, surrogate: str, metric: str,
                                 since: str | None = None,
                                 until: str | None = None) -> dict:
        """Per-bucket series for ONE surrogate + metric over a window."""
        sql = (
            f"SELECT bucket_start, value FROM {_ENTITY_TABLE} FINAL "
            "WHERE tenant_id = {tenant:String} AND surrogate = {surrogate:String} "
            "AND metric = {metric:String} "
            "AND bucket_start >= parseDateTimeBestEffort({since:String}) "
            "AND ({until:String} = '' OR bucket_start <= parseDateTimeBestEffortOrNull({until:String})) "
            "ORDER BY bucket_start"
        )
        params = {"tenant": self._tenant, "surrogate": surrogate, "metric": metric,
                  "since": _resolve_since(since), "until": _resolve_until(until)}
        return self._client.run(sql, params)

    def reidentify(self, surrogate: str) -> dict:
        """Map a surrogate back to its real value (SOVEREIGN — reads ssdf.pseudonym_map)."""
        sql = (
            f"SELECT kind, real_value FROM {_MAP_TABLE} FINAL "
            "WHERE surrogate = {surrogate:String} LIMIT 1"
        )
        result = self._client.run(sql, {"surrogate": surrogate})
        rows = result.get("rows", [])
        return {"surrogate": surrogate, "entity": rows[0] if rows else None}


def _resolve_since(since: str | None) -> str:
    """Resolve the lookback bound (default 24h) to an absolute UTC ISO string.

    ClickHouse ``parseDateTimeBestEffort`` cannot read relative expressions like
    ``now-24h``, so relative/ISO inputs are resolved in Python first — mirroring
    the other store seams (see ``timeparse.parse_time``)."""
    return parse_time(since or "now-24h").isoformat()


def _resolve_until(until: str | None) -> str:
    """Resolve an optional upper bound to absolute UTC ISO, or '' when unset."""
    return parse_time(until).isoformat() if until else ""
