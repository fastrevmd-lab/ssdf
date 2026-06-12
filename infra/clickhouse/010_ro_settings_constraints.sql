-- infra/clickhouse/010_ro_settings_constraints.sql
-- M1 live-deploy fix: ssdf_ro is readonly=1, so clickhouse-connect refuses to send
-- the per-query resource caps added in PR #16 (max_execution_time / max_result_rows /
-- max_memory_usage / result_overflow_mode) — "Setting ... is unknown or readonly".
-- Declare the settings CHANGEABLE_IN_READONLY with hard MAX bounds so the client may
-- request values up to the cap but can never exceed it. Also pins ssdf_public to
-- readonly=1 (it previously relied on grants alone) with the same bounded caps.
--
-- Apply: clickhouse-client --host <ct104> --multiquery < 010_ro_settings_constraints.sql
-- Restart ssdf-mcp-query (ct106) + ssdf-mcp-public (ct113) afterwards: the client
-- snapshots settings writability at connect time.

ALTER USER ssdf_ro SETTINGS
    readonly = 1,
    max_execution_time = 10 MAX 60 CHANGEABLE_IN_READONLY,
    max_result_rows = 100000 MAX 1000000 CHANGEABLE_IN_READONLY,
    max_memory_usage = 1000000000 MAX 4000000000 CHANGEABLE_IN_READONLY,
    result_overflow_mode = 'throw' CHANGEABLE_IN_READONLY;

ALTER USER ssdf_public SETTINGS
    readonly = 1,
    max_execution_time = 10 MAX 60 CHANGEABLE_IN_READONLY,
    max_result_rows = 100000 MAX 1000000 CHANGEABLE_IN_READONLY,
    max_memory_usage = 1000000000 MAX 4000000000 CHANGEABLE_IN_READONLY,
    result_overflow_mode = 'throw' CHANGEABLE_IN_READONLY;
