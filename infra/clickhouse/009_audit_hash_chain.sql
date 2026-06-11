-- infra/clickhouse/009_audit_hash_chain.sql
-- M3: add per-tier hash-chain columns to ssdf.audit + a READ-ONLY verifier user.
-- The INSERT-only ssdf_audit writer (007) is unchanged. ClickHouse does NOT expand
-- {name:Type} params inside CREATE USER ... BY '...', so inject the password first:
--   AUDIT_VERIFY_PW="$CH_AUDIT_VERIFY_PASSWORD" envsubst < 009_audit_hash_chain.sql \
--     | clickhouse-client --host <ct104> --multiquery
--
-- Rows written before this migration keep prev_hash='' / row_hash='' (column DEFAULT);
-- the verifier treats the first hashed row per tier as that tier's chain start. No
-- backfill — historical rows cannot be authentically re-hashed.
ALTER TABLE ssdf.audit ADD COLUMN IF NOT EXISTS prev_hash String DEFAULT '';
ALTER TABLE ssdf.audit ADD COLUMN IF NOT EXISTS row_hash  String DEFAULT '';

-- Read-only verifier identity: used for startup chain-seeding and verify_audit.
-- Separate from ssdf_audit (which stays INSERT-only) and ssdf_ro (query path).
CREATE USER IF NOT EXISTS ssdf_audit_verify IDENTIFIED WITH sha256_password BY '${AUDIT_VERIFY_PW}';
GRANT SELECT ON ssdf.audit TO ssdf_audit_verify;
