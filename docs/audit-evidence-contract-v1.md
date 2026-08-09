# ssdf.audit Evidence Contract v1.0

**Version:** 1.0
**Date:** 2026-08-09
**Status:** Active
**SSDF Compatibility:** Requires schema 009 (hash chain support)

## Purpose

This contract defines the ingestion schema for firewall configuration-change evidence records written by mecmcp-audit (the rustsdcmcp audit sink) into ssdf.audit. It extends the existing MCP tool-call audit trail to carry a complete evidence chain for each configuration change: proposal, approval, apply intent, and result receipt.

## Schema Ownership

- **Table:** `ssdf.audit` (existing, created by migration 007, hash-chained by 009)
- **Write Identity:** `ssdf_audit` (INSERT-only, no SELECT)
- **Verify Identity:** `ssdf_audit_verify` (SELECT-only, hash-chain verification)
- **Schema Steward:** ssdf repo (this contract document)
- **Primary Consumer:** mecmcp-audit (rustsdcmcp audit sink, will implement in Task 7+9)

## Record Types

Evidence records use the existing `ssdf.audit` schema with the following `tool` field values:

| tool | Description | Decision Phase |
|------|-------------|----------------|
| `evidence:proposal` | Configuration change proposed by an agent | Pre-approval |
| `evidence:approval` | Human approval of a proposed change | Approval gate |
| `evidence:apply_intent` | System begins executing the approved change | Execution start |
| `evidence:result_receipt` | Execution result returned from the device | Execution complete |

All evidence records share `tier = "evidence"` to enable chain verification independent of the MCP tool audit trail.

## Field Schema

Evidence records populate the existing `ssdf.audit` columns as follows:

| Column | Type | Evidence Semantics | Example |
|--------|------|-------------------|---------|
| `ts` | DateTime64(3,'UTC') | Evidence event timestamp (UTC) | `2026-08-09T14:32:10.500Z` |
| `principal` | LowCardinality(String) | Originating agent/user identity | `"agent:mechub-config-agent"` for proposals, `"user:alice@example.com"` for approvals |
| `tier` | LowCardinality(String) | **Always `"evidence"`** for these records | `"evidence"` |
| `tool` | LowCardinality(String) | Evidence record kind (see Record Types) | `"evidence:proposal"` |
| `args` | String | JSON-encoded evidence payload (see Payload Schema) | `{"request_id":"req_abc123",...}` |
| `data_classes` | Array(LowCardinality(String)) | Affected device/changeset classifications | `["device:vsrx-prod","changeset:cs_xyz"]` |
| `decision` | LowCardinality(String) | Approval outcome (`"approved"`, `"rejected"`, `""`) | `"approved"` (approval records only) |
| `row_count` | UInt32 | Devices/rules affected count | `1` |
| `error` | String | Error detail (execution failures only) | `"commit failed: syntax error at line 42"` |
| `prev_hash` | String | Previous row hash in the evidence tier chain | `"sha256:abc123..."` |
| `row_hash` | String | This row's computed hash | `"sha256:def456..."` |

### Payload Schema (`args` column)

The `args` field carries a JSON object with evidence-specific fields:

```json
{
  "request_id": "req_abc123",
  "changeset_id": "cs_xyz789",
  "device_id": "vsrx-prod",
  "diff_hash": "sha256:fedcba...",
  "run_id": "run_20260809_143210",
  "server_id": "rustsdcmcp-606",
  "segment_seq": 0,
  "prev_hash": "sha256:...",
  "approver": "alice@example.com",
  "metadata": {
    "commit_message": "Fix NAT rule typo",
    "change_summary": "Updated rule policy-1 source address"
  }
}
```

| Payload Field | Type | Required | Description |
|--------------|------|----------|-------------|
| `request_id` | string | Yes | Unique change request identifier |
| `changeset_id` | string | Yes | Configuration changeset identifier |
| `device_id` | string | Yes | Target device identifier |
| `diff_hash` | string | Yes | SHA-256 hash of the configuration diff |
| `run_id` | string | Yes | Audit run identifier (for deduplication) |
| `server_id` | string | Yes | Originating audit server identifier |
| `segment_seq` | integer | Yes | Sequence number within this run (0-based) |
| `prev_hash` | string | Conditional | Previous record hash (empty for first record) |
| `approver` | string | Approval only | Approving user identity |
| `metadata` | object | Optional | Additional context (commit message, etc.) |

## Deduplication Contract

Re-ingestion after a demo reset or test re-run MUST be idempotent. The deduplication key is:

```
(server_id, run_id, segment_seq)
```

**Implementation note:** ClickHouse `ReplacingMergeTree` or application-level `INSERT ... WHERE NOT EXISTS` using this tuple ensures no duplicate evidence rows for the same run segment.

## Query Contract

The evidence chain for a given `run_id` is queried as:

```sql
SELECT ts, tool, principal, args, row_hash, prev_hash
FROM ssdf.audit
WHERE tier = 'evidence'
  AND JSONExtractString(args, 'run_id') = '<run_id>'
ORDER BY ts ASC
```

This query is consumed by:
- The Task 11 mechub-web evidence viewer
- Hash-chain verification tools
- Audit reports

## Retention

Evidence records follow the existing `ssdf.audit` TTL:
- **90 days** (per migration 007)
- Evidence older than 90 days is automatically purged by ClickHouse

For long-term compliance storage, export evidence rows to cold archive before TTL expiration.

## Authentication

Evidence records are written via the existing `ssdf_audit` identity (INSERT-only, no SELECT). The mecmcp-audit sink authenticates with:

```bash
# Environment variable (per .env.example pattern)
CH_AUDIT_PASSWORD=<from-vault>
```

No new authentication identity is required for this contract — the existing `ssdf_audit` user supports the evidence record shape.

## Hash Chain Integrity

Evidence records participate in the tier-specific hash chain (migration 009):

1. **First evidence record** per tier has `prev_hash = ""` (chain start)
2. **Subsequent records** include `prev_hash = <previous row_hash>`
3. **row_hash** computation includes: `(ts, principal, tool, args, prev_hash)`

The hash chain is verified offline via:

```bash
python -m ssdf_mcp_query.verify_audit
```

This verifier reads as `ssdf_audit_verify` and confirms:
- No missing sequence gaps
- Each `prev_hash` matches the prior row's `row_hash`
- No tampered fields (recomputed hash matches stored hash)

## Version History

- **v1.0** (2026-08-09): Initial contract pin for mechub demo milestone
