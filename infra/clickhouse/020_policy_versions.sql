-- infra/clickhouse/020_policy_versions.sql
-- MEC-566 (Firewall Memory v1): append-only history of configured-policy rule
-- content. ssdf.entities (004_entities.sql) is a ReplacingMergeTree snapshot of
-- CURRENT state only -- services/policy/src/ssdf_policy/resolve_policies.py's
-- own docstring says so explicitly ("no rule-version history -- see spec §6").
-- This table is the history that rule_history reads.
--
-- INSERT-only, mirroring 007_audit.sql: a row is appended only when the
-- collected rule's content hash differs from the last known hash for that
-- (provider, device_name, rule_name) -- see
-- services/policy/src/ssdf_policy/policy_versions.py (pure diff, no I/O). An
-- unchanged rule re-collected on the next pass is a no-op, so this table
-- grows with rule CHANGES, not with every collection run.
--
-- No TTL: this is the rule's change history, not a high-volume log -- one row
-- per (rule, change), not per event. Revisit if that assumption breaks.
CREATE TABLE IF NOT EXISTS ssdf.policy_versions
(
    tenant_id    LowCardinality(String) DEFAULT 't_main',
    provider     LowCardinality(String),
    device_name  LowCardinality(String),
    rule_name    String,
    valid_from   DateTime64(3, 'UTC'),
    content_hash String,
    action       LowCardinality(String),
    from_zone    String,
    to_zone      String,
    enabled      Bool,
    position     String
)
ENGINE = MergeTree
ORDER BY (tenant_id, provider, device_name, rule_name, valid_from);

-- ssdf_entity is the existing configured-policy writer identity
-- (005_entity_user.sql); it needs SELECT here too, to diff a newly-collected
-- rule against its last known hash before deciding whether to append.
-- Deliberately no ALTER DELETE grant to anyone (see 007_audit.sql for the
-- same reasoning): this is a history table, and even the writer that owns it
-- can only ever add rows.
GRANT INSERT, SELECT ON ssdf.policy_versions TO ssdf_entity;

-- Sovereign read access (rule_history / explain_rule tools).
GRANT SELECT ON ssdf.policy_versions TO ssdf_ro;
