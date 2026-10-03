-- infra/clickhouse/024_audit_ocsf_export.sql
-- MEC-565: an export projection of ssdf.audit_evidence (023) for consumers
-- that want audit-chain integrity events in an OCSF-flavoured shape.
--
-- DEVIATION FROM OCSF 1.9, STATED EXPLICITLY: OCSF 1.9 has no canonical
-- "record_integrity" event class. This view is a best-effort, mapped-for-export
-- projection using OCSF's common base-event field names (time, activity_name,
-- actor.*, status) where they apply cleanly, plus three ssdf-specific integrity
-- fields (prev_hash, row_hash, is_checkpoint_anchored) that have no OCSF
-- equivalent. `class_name` is set to the literal string
-- 'record_integrity (mapped-for-export; not a registered OCSF 1.9 class)' so no
-- downstream consumer mistakes this for a conformant class_uid. Treat this as
-- "OCSF-shaped", not "OCSF-certified".
--
-- Sourced from audit_evidence (410-day retention), not audit (90-day TTL):
-- export is for long-horizon compliance review, which is exactly the case the
-- 90-day table cannot serve alone.
--
-- `has_later_checkpoint_unverified`: true when *some* row exists in
-- audit_checkpoints for this row's chain with checkpoint_ts >= this row's ts.
-- Deliberately named and documented as unverified, not as a signature-backed
-- guarantee (MEC-565 review F4): this view does not check the checkpoint's
-- Ed25519 signature, and GRANT INSERT on audit_checkpoints is the only bar to
-- flipping every row in a chain to "true" by inserting one unsigned row with
-- a far-future checkpoint_ts. `verify_audit.py` (which does check the
-- signature, via checkpoint_verify.py) is the authoritative integrity check;
-- this column is a cheap, advisory hint for export consumers only, and must
-- not be read as proof of anchoring.
--
-- Computed by pre-aggregating each chain's latest checkpoint_ts and LEFT
-- JOINing that onto audit_evidence, not a per-row correlated EXISTS subquery:
-- ClickHouse's planner does not support a subquery referencing columns from
-- its enclosing SELECT ("Resolve identifier ... from parent scope only
-- supported for constants and CTE" -- confirmed by a live run against a
-- throwaway ClickHouse instance; the EXISTS form this migration originally
-- shipped with does not execute at all). A LEFT JOIN against each chain's
-- max(checkpoint_ts) is equivalent to the EXISTS check -- if the latest
-- checkpoint's ts is >= this row's ts, at least one qualifying checkpoint
-- exists -- and keeps row cardinality unchanged because the right side is
-- pre-aggregated to one row per (tier, server_id) before joining.
--
-- parseDateTime64BestEffortOrNull, not parseDateTime64BestEffort: an
-- unparsable checkpoint_ts (malformed or absent) must fall through to NULL
-- (`>=` against NULL is NULL, which this column's `AND` turns into NULL ->
-- treated as not-anchored) rather than throwing and breaking the entire
-- export view for every row.
CREATE VIEW IF NOT EXISTS ssdf.audit_ocsf_export AS
SELECT
    toUnixTimestamp64Milli(e.ts)                                   AS time,
    'record_integrity (mapped-for-export; not a registered OCSF 1.9 class)' AS class_name,
    e.tool                                                         AS activity_name,
    e.principal                                                    AS actor_user_name,
    e.decision                                                     AS status,
    e.tier                                                         AS tier,
    e.row_count                                                    AS row_count,
    e.prev_hash                                                    AS prev_hash,
    e.row_hash                                                     AS row_hash,
    coalesce(
        (latest.max_checkpoint_ts != '')
            AND (parseDateTime64BestEffortOrNull(latest.max_checkpoint_ts) >= e.ts),
        false
    )                                                               AS has_later_checkpoint_unverified
FROM ssdf.audit_evidence AS e
LEFT JOIN
(
    SELECT tier, server_id, max(checkpoint_ts) AS max_checkpoint_ts
    FROM ssdf.audit_checkpoints
    GROUP BY tier, server_id
) AS latest
ON latest.tier = e.tier AND latest.server_id = JSONExtractString(e.args, 'server_id');

-- ssdf_audit_export: the ONLY identity with read access to the export view.
-- Deliberately not granted to ssdf_ro -- audit content (who did what) stays
-- out of the general query surface for the same reason ssdf.audit itself is
-- never granted to ssdf_ro (007_audit.sql, 018_ssdf_ro_grants.sql). Export
-- tooling authenticates as this identity specifically, not through run_sql.
CREATE USER IF NOT EXISTS ssdf_audit_export IDENTIFIED WITH sha256_password BY '${AUDIT_EXPORT_PW}';
GRANT SELECT ON ssdf.audit_ocsf_export TO ssdf_audit_export;
-- The view's own SELECT runs with the *view's definer* privileges by default
-- in ClickHouse only when DEFINER is set; without it, the querying user needs
-- underlying read rights too. Grant those narrowly to the export identity only.
GRANT SELECT ON ssdf.audit_evidence TO ssdf_audit_export;
GRANT SELECT ON ssdf.audit_checkpoints TO ssdf_audit_export;
