-- infra/clickhouse/008_public_views.sql
-- M7b: public-tier shareable views + least-privilege users.
--
-- ClickHouse does NOT expand {name:Type} params inside CREATE USER ... BY '...',
-- so inject the two passwords and the two pseudonym-key halves before applying
-- (never commit real values). The key halves are two independent UInt64s (e.g.
-- `python3 -c "print(__import__('secrets').randbits(64))"`, run twice):
--   DEFINER_PW="$CH_DEFINER_PASSWORD" PUBLIC_PW="$CH_PUBLIC_PASSWORD" \
--     VIEW_PSEUDONYM_KEY_HI="$CH_VIEW_PSEUDONYM_KEY_HI" \
--     VIEW_PSEUDONYM_KEY_LO="$CH_VIEW_PSEUDONYM_KEY_LO" \
--     envsubst < 008_public_views.sql \
--     | clickhouse-client --host <ct104> --multiquery
--
-- Enforcement model: ssdf_public is granted SELECT on the ssdf_public.* views
-- ONLY (no base-table grant). The views run with SQL SECURITY DEFINER as
-- ssdf_view_definer, which can read ONLY the two shareable base tables plus
-- (below) the pseudonym-key table. So the public process is structurally
-- unable to name a sovereign table.
--
-- Column model: the views select an explicit allowlist, never every column. `name`,
-- `identifiers` (raw MACs/IPs/hostnames) and `attrs` (free-form, collector-set)
-- are sovereign-only and are never projected into ssdf_public. `node_id` /
-- `src_id` / `dst_id` / `edge_id` are re-hashed with a keyed hash before
-- exposure: the sovereign id is `sha1(tenant|kind|canonical_key)[:16]` (see
-- ssdf_topo.models), which is unkeyed and guessable by dictionary attack over
-- plausible names/MACs/IPs, so passing it through unchanged would let a public
-- reader dictionary-attack the sovereign id space. ClickHouse has no built-in
-- HMAC function, so `sipHash128Keyed` (its native keyed, cryptographic-strength
-- hash) is the pseudonymization primitive instead -- same property the
-- HMAC-SHA256 in ssdf_pubmetrics.pseudonym provides (keyed, deterministic,
-- one-way), just a different keyed hash because ClickHouse SQL has no literal
-- HMAC to call. The same key is used for both views so a public `src_id`/
-- `dst_id` still joins against the corresponding public `node_id`.
--
-- F2 (MEC-167): the key itself must NEVER be an inline literal in a view
-- body. A view's `AS SELECT ...` is queryable by anyone holding SELECT on the
-- view -- `SHOW CREATE TABLE` and `system.tables.as_select` both return it
-- verbatim -- so a literal key here handed ssdf_public everything needed to
-- recompute pseudonyms offline from a dictionary of plausible MACs/IPs/names,
-- defeating the pseudonymisation this migration exists to provide. The key
-- instead lives in the sovereign-only `ssdf.view_pseudonym_key` table (SELECT
-- granted to ssdf_view_definer alone, never to ssdf_public) and the views
-- resolve it at query time through a `WITH (SELECT ...) AS k` scalar
-- subquery, which is NOT present in the compiled view text.

CREATE DATABASE IF NOT EXISTS ssdf_public;

-- Least-privilege definer: its readable surface == the shareable surface.
CREATE USER IF NOT EXISTS ssdf_view_definer IDENTIFIED WITH sha256_password BY '${DEFINER_PW}';
GRANT SELECT ON ssdf.graph_nodes TO ssdf_view_definer;
GRANT SELECT ON ssdf.graph_edges TO ssdf_view_definer;

-- Sovereign-only key table (F2). TinyLog: one row, no merge/versioning needed.
-- The `WHERE (SELECT count() ...) = 0` guard makes the seed idempotent -- a
-- re-apply of this migration (e.g. adding a future public view) must never
-- rotate the key out from under already-pseudonymised ids.
CREATE TABLE IF NOT EXISTS ssdf.view_pseudonym_key (hi UInt64, lo UInt64) ENGINE = TinyLog;
INSERT INTO ssdf.view_pseudonym_key (hi, lo)
    SELECT toUInt64(${VIEW_PSEUDONYM_KEY_HI}), toUInt64(${VIEW_PSEUDONYM_KEY_LO})
    WHERE (SELECT count() FROM ssdf.view_pseudonym_key) = 0;
-- ssdf_view_definer ONLY. Never grant this table to ssdf_public or ssdf_ro.
GRANT SELECT ON ssdf.view_pseudonym_key TO ssdf_view_definer;

-- De-identified shareable views: pseudonymised ids only, no name/identifiers/attrs.
CREATE OR REPLACE VIEW ssdf_public.graph_nodes
    DEFINER = ssdf_view_definer SQL SECURITY DEFINER
    AS WITH (SELECT (hi, lo) FROM ssdf.view_pseudonym_key LIMIT 1) AS k
    SELECT
        hex(sipHash128Keyed(k, node_id)) AS node_id,
        tenant_id,
        kind,
        first_seen,
        last_seen
    FROM ssdf.graph_nodes;

CREATE OR REPLACE VIEW ssdf_public.graph_edges
    DEFINER = ssdf_view_definer SQL SECURITY DEFINER
    AS WITH (SELECT (hi, lo) FROM ssdf.view_pseudonym_key LIMIT 1) AS k
    SELECT
        hex(sipHash128Keyed(k, edge_id)) AS edge_id,
        tenant_id,
        hex(sipHash128Keyed(k, src_id)) AS src_id,
        hex(sipHash128Keyed(k, dst_id)) AS dst_id,
        edge_type,
        layer,
        first_seen,
        last_seen,
        confidence
    FROM ssdf.graph_edges;

-- Public reader: granted on the VIEWS ONLY. No base ssdf.* grant, no grant on
-- ssdf.view_pseudonym_key.
CREATE USER IF NOT EXISTS ssdf_public IDENTIFIED WITH sha256_password BY '${PUBLIC_PW}';
GRANT SELECT ON ssdf_public.graph_nodes TO ssdf_public;
GRANT SELECT ON ssdf_public.graph_edges TO ssdf_public;
