-- 017: caller attribution on audit rows (issue #9).
--
-- ssdf.audit is the one place to ask "who did what" across SSDF's own MCP
-- servers and the rust*mcp family. SSDF's own rows recorded only `principal`,
-- while mecmcp-audit's rows in this same table already carried client, model
-- and actor type -- the schema steward's rows were the thinner ones.
--
-- DEFAULT '' matters for the hash chain. audit_chain.canonical() appends these
-- three fields only when at least one is non-empty, so every existing row and
-- every mecmcp evidence row (which never sets them) still serialises to the
-- original nine-element form and verifies against its stored hash. No coordinated
-- release with mecmcp is required, and no backfill is possible or wanted: a row
-- written before this migration genuinely had no attribution, and inventing one
-- would be a fabricated audit record.
--
-- Trust levels differ per column and are NOT interchangeable:
--   client_name  client-asserted   (MCP clientInfo; a client may claim anything)
--   model_id     operator-declared (token entry; needs token-file write access)
--   actor_type   operator-declared (token entry; constrained to human|agent|unknown)
ALTER TABLE ssdf.audit ADD COLUMN IF NOT EXISTS client_name String DEFAULT '';
ALTER TABLE ssdf.audit ADD COLUMN IF NOT EXISTS model_id    String DEFAULT '';
ALTER TABLE ssdf.audit ADD COLUMN IF NOT EXISTS actor_type  String DEFAULT '';
