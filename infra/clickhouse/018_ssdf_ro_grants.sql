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
-- and topo_observations at the application layer); this file states the DB-level
-- grants those app-level rules sit under, made explicit and reviewable -- it is
-- NOT a ceiling: GRANT only adds, so a hand-made grant on a live cluster (e.g. a
-- database-wide `ssdf.*`) is not revoked by re-running this file. After
-- applying, confirm the live grant set matches this file exactly:
--   SELECT database, table, access_type FROM system.grants
--   WHERE user_name = 'ssdf_ro' ORDER BY 1, 2;
-- Expect no row with a NULL table (a database-wide grant) and no row for
-- ssdf.audit.
--
-- FRESH CLUSTER: 005, 010, 013 and 014 grant to or ALTER USER ssdf_ro before
-- this file creates it, so applying migrations in numeric order on a clean
-- cluster fails at 005 with "ssdf_ro not found". Apply 018 before 005 on a
-- fresh cluster; re-running 018 afterwards (in numeric order, on subsequent
-- deploys) is still the idempotent no-op described below.
--
-- Re-running this file is a no-op on an already-provisioned lab: CREATE USER
-- IF NOT EXISTS never touches an existing user's password, GRANT is
-- idempotent, and the ALTER USER SETTINGS block below is a plain overwrite of
-- the same values.
--
-- ClickHouse does NOT expand {name:Type} params inside CREATE USER ... BY '...',
-- so inject the password before applying (never commit the real value):
--   : "${RO_PW:?RO_PW must be set}"; RO_PW="$RO_PW" envsubst < 018_ssdf_ro_grants.sql \
--     | clickhouse-client --host <ct104> --multiquery
CREATE USER IF NOT EXISTS ssdf_ro IDENTIFIED WITH sha256_password BY '${RO_PW}';

-- Same bounded caps as 010_ro_settings_constraints.sql, copied here so a fresh
-- cluster gets them from the user's first CREATE rather than depending on 010
-- running afterwards: readonly=1 users reject per-query settings unless
-- declared CHANGEABLE_IN_READONLY with MAX bounds (live-found, M1).
ALTER USER ssdf_ro SETTINGS
    readonly = 1,
    max_execution_time = 10 MAX 60 CHANGEABLE_IN_READONLY,
    max_result_rows = 100000 MAX 1000000 CHANGEABLE_IN_READONLY,
    max_memory_usage = 1000000000 MAX 4000000000 CHANGEABLE_IN_READONLY,
    result_overflow_mode = 'throw' CHANGEABLE_IN_READONLY;

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
