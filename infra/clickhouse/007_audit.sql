-- infra/clickhouse/007_audit.sql
-- M7a append-only audit of MCP tool calls + INSERT-only ssdf_audit user.
-- ClickHouse does NOT expand {name:Type} params inside CREATE USER ... BY '...',
-- so inject the password before applying (never commit the real value):
--   AUDIT_PW="$CH_AUDIT_PASSWORD" envsubst < 007_audit.sql \
--     | clickhouse-client --host <ct104> --multiquery
--
-- Schema reserves room for future hash-chained tamper-evidence (prev_hash/row_hash)
-- to be added without migrating existing rows (M7a does NOT build that).
CREATE TABLE IF NOT EXISTS ssdf.audit
(
    ts           DateTime64(3, 'UTC'),
    principal    LowCardinality(String),
    tier         LowCardinality(String),
    tool         LowCardinality(String),
    args         String,
    data_classes Array(LowCardinality(String)),
    decision     LowCardinality(String),
    row_count    UInt32,
    error        String
)
ENGINE = MergeTree
ORDER BY (ts, principal)
TTL toDateTime(ts) + INTERVAL 90 DAY;

-- INSERT-only writer. Deliberately no SELECT grant: the query identity (ssdf_ro)
-- cannot read or edit the trail, and ssdf_audit cannot read what it wrote.
CREATE USER IF NOT EXISTS ssdf_audit IDENTIFIED WITH sha256_password BY '${AUDIT_PW}';
GRANT INSERT ON ssdf.audit TO ssdf_audit;
