-- infra/clickhouse/002_topology.sql
-- M4 topology graph: append-only observations + materialized node/edge projection.

CREATE TABLE IF NOT EXISTS ssdf.topo_observations
(
    observed_at      DateTime64(3, 'UTC'),
    collector        LowCardinality(String),
    source_device    String,
    tenant_id        LowCardinality(String) DEFAULT 't_main',
    layer            LowCardinality(String),
    observation_type LowCardinality(String),
    subj_kind        LowCardinality(String),
    subj_id          String,
    obj_kind         LowCardinality(String),
    obj_id           String,
    attrs            Map(String, String),
    raw              String
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(observed_at)
ORDER BY (tenant_id, collector, observed_at)
TTL toDateTime(observed_at) + INTERVAL 30 DAY;

CREATE TABLE IF NOT EXISTS ssdf.graph_nodes
(
    node_id     String,
    tenant_id   LowCardinality(String) DEFAULT 't_main',
    kind        LowCardinality(String),
    name        String,
    identifiers Map(String, String),
    first_seen  DateTime64(3, 'UTC'),
    last_seen   DateTime64(3, 'UTC'),
    attrs       Map(String, String)
)
ENGINE = ReplacingMergeTree(last_seen)
ORDER BY (tenant_id, node_id);

CREATE TABLE IF NOT EXISTS ssdf.graph_edges
(
    edge_id    String,
    tenant_id  LowCardinality(String) DEFAULT 't_main',
    src_id     String,
    dst_id     String,
    edge_type  LowCardinality(String),
    layer      LowCardinality(String),
    first_seen DateTime64(3, 'UTC'),
    last_seen  DateTime64(3, 'UTC'),
    confidence Float32,
    attrs      Map(String, String)
)
ENGINE = ReplacingMergeTree(last_seen)
ORDER BY (tenant_id, edge_id);
