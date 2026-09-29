-- infra/clickhouse/019_rule_usage_hourly.sql
-- MEC-566 (Firewall Memory v1): hourly rollup of ssdf.events.rule_name, one of the
-- two independent usage signals unused_rules cross-checks (the other is the
-- device's own hit-count counter, collected read-only into ssdf.entities policy
-- attrs -- see services/policy/src/ssdf_policy/collectors/{junos,panos}.py).
--
-- rule_name is already populated by the RT_FLOW parser (Junos) and the
-- TRAFFIC/THREAT parser (PAN-OS) in infra/vector/vector.toml -- confirmed for
-- both vendors before adding this rollup, no new ingest work required.
--
-- ReplacingMergeTree(inserted_at): ssdf_policy.rule_usage_rollup recomputes a
-- trailing window of whole hours on every run (late-arriving events land on
-- the next pass), so a bucket may be written more than once. A rerun with the
-- same key overwrites rather than double-counts -- the same pattern already
-- used for ssdf_public.metric_timeseries (013_public_metrics.sql). Readers
-- must query with FINAL (or argMax over inserted_at).
--
-- Least-privilege writer, separate from ssdf_entity: this rollup reads
-- ssdf.events and writes only this table, and has no reason to touch
-- ssdf.entities/entity_edges. Inject the password before applying (never
-- commit the real value):
--   RULEUSAGE_PW="$CH_RULEUSAGE_PASSWORD" envsubst < 019_rule_usage_hourly.sql \
--     | clickhouse-client --host <ct104> --multiquery
CREATE TABLE IF NOT EXISTS ssdf.rule_usage_hourly
(
    tenant_id         LowCardinality(String) DEFAULT 't_main',
    bucket_start      DateTime,
    provider          LowCardinality(String),
    observer_hostname LowCardinality(String) DEFAULT '',
    rule_name         String,
    sessions          UInt64,
    bytes             UInt64,
    inserted_at       DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(inserted_at)
ORDER BY (tenant_id, provider, observer_hostname, rule_name, bucket_start)
TTL bucket_start + INTERVAL 30 DAY;

CREATE USER IF NOT EXISTS ssdf_ruleusage IDENTIFIED WITH sha256_password BY '${RULEUSAGE_PW}';
GRANT SELECT ON ssdf.events TO ssdf_ruleusage;
GRANT INSERT, SELECT ON ssdf.rule_usage_hourly TO ssdf_ruleusage;

-- Sovereign read access (rule_usage / unused_rules / explain_rule tools).
GRANT SELECT ON ssdf.rule_usage_hourly TO ssdf_ro;
