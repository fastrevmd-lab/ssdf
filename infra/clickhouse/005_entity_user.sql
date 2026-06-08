-- infra/clickhouse/005_entity_user.sql
-- Least-privilege writer for the M6 entity service. Run as CH admin.
-- ClickHouse does NOT expand {name:Type} params inside CREATE USER ... BY '...',
-- so inject the password before applying (never commit the real value):
--   ENTITY_PW="$CH_ENTITY_PASSWORD" envsubst < 005_entity_user.sql \
--     | clickhouse-client --host <ct104> --multiquery
CREATE USER IF NOT EXISTS ssdf_entity IDENTIFIED WITH sha256_password BY '${ENTITY_PW}';
GRANT INSERT, SELECT ON ssdf.entities TO ssdf_entity;
GRANT INSERT, SELECT ON ssdf.entity_edges TO ssdf_entity;
GRANT SELECT ON ssdf.events TO ssdf_entity;
GRANT SELECT ON ssdf.graph_nodes TO ssdf_entity;
GRANT SELECT ON ssdf.entities TO ssdf_ro;
GRANT SELECT ON ssdf.entity_edges TO ssdf_ro;
