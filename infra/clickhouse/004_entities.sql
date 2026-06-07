-- infra/clickhouse/004_entities.sql
-- M6a entity/correlation layer: resolved Asset/Policy entities + their edges.
-- Separate from M4 graph_nodes/graph_edges so the entity store can relocate
-- (Postgres-as-graph in M6c) without touching the topology graph.

CREATE TABLE IF NOT EXISTS ssdf.entities
(
    entity_id      String,
    tenant_id      LowCardinality(String) DEFAULT 't_main',
    kind           LowCardinality(String),              -- asset | policy | identity
    name           String,
    identifiers    Map(String, String),                 -- mac, ip, ip2, rule, provider, ...
    source         LowCardinality(String) DEFAULT 'observed',  -- observed | configured
    identity_basis LowCardinality(String) DEFAULT '',   -- mac | ip_only | ''
    confidence     Float32,
    attrs          Map(String, String),
    first_seen     DateTime64(3, 'UTC'),
    last_seen      DateTime64(3, 'UTC')
)
ENGINE = ReplacingMergeTree(last_seen)
ORDER BY (tenant_id, entity_id)
TTL toDateTime(last_seen) + INTERVAL 30 DAY;

CREATE TABLE IF NOT EXISTS ssdf.entity_edges
(
    edge_id    String,
    tenant_id  LowCardinality(String) DEFAULT 't_main',
    src_id     String,
    dst_id     String,
    edge_type  LowCardinality(String),                  -- communicated_with | governed_by | authenticated_as
    source     LowCardinality(String) DEFAULT 'observed',
    confidence Float32,
    attrs      Map(String, String),
    first_seen DateTime64(3, 'UTC'),
    last_seen  DateTime64(3, 'UTC')
)
ENGINE = ReplacingMergeTree(last_seen)
ORDER BY (tenant_id, edge_id)
TTL toDateTime(last_seen) + INTERVAL 30 DAY;
