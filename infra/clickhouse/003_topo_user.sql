-- infra/clickhouse/003_topo_user.sql
-- Least-privilege writer for the M4 topo service. Run as CH admin.
-- NOTE: ClickHouse does NOT expand query parameters ({name:Type}) inside a
-- CREATE USER ... BY '...' literal, so the password must be substituted before
-- applying. Inject it with envsubst (never commit the real value):
--   TOPO_PW="$CH_TOPO_PASSWORD" envsubst < 003_topo_user.sql \
--     | clickhouse-client --host <ct104> --multiquery
CREATE USER IF NOT EXISTS ssdf_topo IDENTIFIED WITH sha256_password BY '${TOPO_PW}';
GRANT INSERT, SELECT ON ssdf.topo_observations TO ssdf_topo;
GRANT INSERT, SELECT ON ssdf.graph_nodes TO ssdf_topo;
GRANT INSERT, SELECT ON ssdf.graph_edges TO ssdf_topo;
GRANT SELECT ON ssdf.events TO ssdf_topo;
