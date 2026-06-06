CREATE DATABASE IF NOT EXISTS ssdf;

CREATE TABLE IF NOT EXISTS ssdf.events
(
    timestamp             DateTime64(3, 'UTC'),
    event_id              String,
    tenant_id             LowCardinality(String) DEFAULT 't_main',
    event_kind            LowCardinality(String),
    event_category        Array(LowCardinality(String)),
    event_action          LowCardinality(String),
    event_outcome         LowCardinality(String),
    event_provider        LowCardinality(String),
    source_ip             Nullable(IPv4),
    source_port           Nullable(UInt16),
    source_bytes          Nullable(UInt64),
    destination_ip        Nullable(IPv4),
    destination_port      Nullable(UInt16),
    destination_bytes     Nullable(UInt64),
    network_transport     LowCardinality(String),
    network_bytes         Nullable(UInt64),
    rule_name             String,
    observer_ingress_zone LowCardinality(String),
    observer_egress_zone  LowCardinality(String),
    user_name             String,
    ext                   Map(String, String),
    raw                   String
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (tenant_id, timestamp, event_action)
TTL toDateTime(timestamp) + INTERVAL 30 DAY;
