-- infra/clickhouse/014_health_metrics.sql
-- M13a host resource-pressure ingest: a narrow long-format (EAV-style) gauge table.
-- One row per (device, metric, sensor, timestamp) reading; a vendor exposing a new
-- sensor lands as new rows with a new `sensor` value -- zero schema change.
-- TTL is configurable; substitute before applying (default 30 days):
--   HEALTH_TTL_DAYS=30 envsubst < 014_health_metrics.sql \
--     | clickhouse-client --host <ct104> --multiquery
CREATE TABLE IF NOT EXISTS ssdf.health_metrics (
    timestamp     DateTime64(3,'UTC'),
    tenant_id     LowCardinality(String) DEFAULT 't_main',
    provider      LowCardinality(String),
    device        LowCardinality(String),
    scope         LowCardinality(String) DEFAULT 'device',
    metric_class  LowCardinality(String),
    sensor        LowCardinality(String) DEFAULT '',
    metric_name   LowCardinality(String),
    metric_value  Float64,
    unit          LowCardinality(String),
    raw           String DEFAULT ''
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (tenant_id, provider, device, metric_class, sensor, timestamp)
TTL toDateTime(timestamp) + INTERVAL ${HEALTH_TTL_DAYS:-30} DAY;

-- Sovereign read access (run_sql / describe_schema surface this immediately).
GRANT SELECT ON ssdf.health_metrics TO ssdf_ro;
