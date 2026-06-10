-- infra/clickhouse/008_public_views.sql
-- M7b: public-tier shareable views + least-privilege users.
--
-- ClickHouse does NOT expand {name:Type} params inside CREATE USER ... BY '...',
-- so inject the two passwords before applying (never commit real values):
--   DEFINER_PW="$CH_DEFINER_PASSWORD" PUBLIC_PW="$CH_PUBLIC_PASSWORD" \
--     envsubst < 008_public_views.sql \
--     | clickhouse-client --host <ct104> --multiquery
--
-- Enforcement model: ssdf_public is granted SELECT on the ssdf_public.* views
-- ONLY (no base-table grant). The views run with SQL SECURITY DEFINER as
-- ssdf_view_definer, which can read ONLY the two shareable base tables. So the
-- public process is structurally unable to name a sovereign table.

CREATE DATABASE IF NOT EXISTS ssdf_public;

-- Least-privilege definer: its readable surface == the shareable surface.
CREATE USER IF NOT EXISTS ssdf_view_definer IDENTIFIED WITH sha256_password BY '${DEFINER_PW}';
GRANT SELECT ON ssdf.graph_nodes TO ssdf_view_definer;
GRANT SELECT ON ssdf.graph_edges TO ssdf_view_definer;

-- Coarse v0 shareable views (full node/edge shape; tenant filtering stays in the
-- tool SQL exactly like the sovereign path).
CREATE OR REPLACE VIEW ssdf_public.graph_nodes
    DEFINER = ssdf_view_definer SQL SECURITY DEFINER
    AS SELECT * FROM ssdf.graph_nodes;

CREATE OR REPLACE VIEW ssdf_public.graph_edges
    DEFINER = ssdf_view_definer SQL SECURITY DEFINER
    AS SELECT * FROM ssdf.graph_edges;

-- Public reader: granted on the VIEWS ONLY. No base ssdf.* grant.
CREATE USER IF NOT EXISTS ssdf_public IDENTIFIED WITH sha256_password BY '${PUBLIC_PW}';
GRANT SELECT ON ssdf_public.graph_nodes TO ssdf_public;
GRANT SELECT ON ssdf_public.graph_edges TO ssdf_public;
