-- infra/clickhouse/013_public_metrics.sql
-- M7c: public de-identified metrics tables + the ssdf_pubmetrics writer user.
-- ClickHouse does NOT expand {name:Type} params inside CREATE USER ... BY '...',
-- so inject the password before applying (never commit the real value):
--   PUBMETRICS_PW="$CH_PUBMETRICS_PASSWORD" envsubst < 013_public_metrics.sql \
--     | clickhouse-client --host <ct104> --multiquery
--
-- Enforcement model (extends 008's hard-floor): the metric tables live in the
-- ssdf_public database and carry ONLY surrogates + numbers. ssdf.pseudonym_map
-- (real<->surrogate) is sovereign: granted to ssdf_ro (for reidentify) and the
-- ssdf_pubmetrics writer ONLY, NEVER to ssdf_public.

CREATE DATABASE IF NOT EXISTS ssdf_public;

-- Aggregate (system-wide) de-identified series. dim carries only de-identified
-- dimensions ('' = system total). ReplacingMergeTree(inserted_at) so a re-run
-- of the same bucket overwrites rather than double-counts (read with FINAL).
CREATE TABLE IF NOT EXISTS ssdf_public.metric_timeseries
(
    bucket_start DateTime,
    metric       LowCardinality(String),
    dim          LowCardinality(String),
    value        Float64,
    tenant_id    LowCardinality(String) DEFAULT 't_main',
    inserted_at  DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(inserted_at)
ORDER BY (tenant_id, metric, dim, bucket_start)
TTL bucket_start + INTERVAL 30 DAY;

-- Per-entity series keyed by SURROGATE only, written only for top-N entities.
CREATE TABLE IF NOT EXISTS ssdf_public.entity_series
(
    bucket_start DateTime,
    surrogate    String,
    metric       LowCardinality(String),
    value        Float64,
    tenant_id    LowCardinality(String) DEFAULT 't_main',
    inserted_at  DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(inserted_at)
ORDER BY (tenant_id, metric, surrogate, bucket_start)
TTL bucket_start + INTERVAL 30 DAY;

-- SOVEREIGN: the keyed real<->surrogate map. Never granted to ssdf_public.
CREATE TABLE IF NOT EXISTS ssdf.pseudonym_map
(
    kind        LowCardinality(String),
    real_value  String,
    surrogate   String,
    key_version UInt16,
    first_seen  DateTime64(3, 'UTC'),
    last_seen   DateTime64(3, 'UTC')
)
ENGINE = ReplacingMergeTree(last_seen)
ORDER BY (kind, real_value, key_version);

-- Least-privilege writer for the resolver (ct109).
CREATE USER IF NOT EXISTS ssdf_pubmetrics IDENTIFIED WITH sha256_password BY '${PUBMETRICS_PW}';
GRANT SELECT ON ssdf.events TO ssdf_pubmetrics;
GRANT INSERT, SELECT ON ssdf_public.metric_timeseries TO ssdf_pubmetrics;
GRANT INSERT, SELECT ON ssdf_public.entity_series TO ssdf_pubmetrics;
GRANT INSERT, SELECT ON ssdf.pseudonym_map TO ssdf_pubmetrics;

-- Public reader: granted ONLY the two de-identified metric tables. No base
-- ssdf.* grant, and explicitly NOT ssdf.pseudonym_map.
GRANT SELECT ON ssdf_public.metric_timeseries TO ssdf_public;
GRANT SELECT ON ssdf_public.entity_series TO ssdf_public;

-- Sovereign reader (ct106): the metrics tools also run on the sovereign tier, and
-- reidentify reads the pseudonym map. Both grants stay sovereign-side.
GRANT SELECT ON ssdf_public.metric_timeseries TO ssdf_ro;
GRANT SELECT ON ssdf_public.entity_series TO ssdf_ro;
GRANT SELECT ON ssdf.pseudonym_map TO ssdf_ro;
