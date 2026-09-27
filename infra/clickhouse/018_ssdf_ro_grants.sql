-- infra/clickhouse/018_ssdf_ro_grants.sql
-- M16d: the canonical, versioned definition of the ssdf_ro (query-path) identity.
--
-- ssdf_ro has never been created by a committed migration -- CREATE USER and its
-- base grants (events, graph_nodes, graph_edges, topo_observations) happened by
-- hand against the lab, and the rest accreted one GRANT per feature migration
-- (005_entity_user.sql, 013_public_metrics.sql, 014_health_metrics.sql). No
-- single file has ever stated the full set, which is how a run_sql-only token
-- ended up able to `SELECT real_value FROM ssdf.pseudonym_map` and reverse a
-- surrogate the reidentify tool was supposed to gate. The actual fix for that
-- is the table exclusion in sql_guard.py (run_sql refuses audit, pseudonym_map
-- and topo_observations at the application layer); this file is the DB-level
-- ceiling those app-level rules sit under, made explicit and reviewable.
--
-- Re-running this file is a no-op on an already-provisioned lab: CREATE USER
-- IF NOT EXISTS never touches an existing user's password, and GRANT is
-- idempotent.
--
-- ClickHouse does NOT expand {name:Type} params inside CREATE USER ... BY '...',
-- so inject the password before applying (never commit the real value):
--   RO_PW="$CH_RO_PASSWORD" envsubst < 018_ssdf_ro_grants.sql \
--     | clickhouse-client --host <ct104> --multiquery
CREATE USER IF NOT EXISTS ssdf_ro IDENTIFIED WITH sha256_password BY '${RO_PW}';

-- Base query surface: the tables the sovereign MCP tools (query_flows,
-- top_talkers, describe_schema, run_sql, topology/entity tools) read directly.
GRANT SELECT ON ssdf.events TO ssdf_ro;
GRANT SELECT ON ssdf.graph_nodes TO ssdf_ro;
GRANT SELECT ON ssdf.graph_edges TO ssdf_ro;
GRANT SELECT ON ssdf.entities TO ssdf_ro;
GRANT SELECT ON ssdf.entity_edges TO ssdf_ro;
GRANT SELECT ON ssdf.health_metrics TO ssdf_ro;
GRANT SELECT ON ssdf_public.metric_timeseries TO ssdf_ro;
GRANT SELECT ON ssdf_public.entity_series TO ssdf_ro;

-- fabric_status (ingest liveness) reads topo_observations.observed_at to prove
-- the topo resolver is alive; that is the only sanctioned reader. run_sql
-- refuses this table at the application layer (sql_guard._BLOCKED_TABLES)
-- because raw observations carry per-device/port/VLAN detail no ad hoc query
-- should be able to enumerate.
GRANT SELECT ON ssdf.topo_observations TO ssdf_ro;

-- reidentify is the only sanctioned reader of the real<->surrogate mapping;
-- run_sql refuses this table at the application layer (sql_guard) for the
-- same reason -- the missing piece before this review was exactly that DB
-- grants alone did not stop a run_sql-only token from reading it directly.
GRANT SELECT ON ssdf.pseudonym_map TO ssdf_ro;

-- Never grant ssdf.audit to ssdf_ro: the query identity must not be able to
-- read or edit the trail that records what it did (see 007_audit.sql, which
-- keeps the writer INSERT-only for the same reason).
