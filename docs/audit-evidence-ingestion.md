# Audit Evidence Ingestion Endpoint

**Contract:** [audit-evidence-contract-v1.md](./audit-evidence-contract-v1.md)
**Status:** Specification (implementation deferred to Task 9)
**Consumer:** mecmcp-audit (rustsdcmcp audit sink, Task 7+9)

## Endpoint Design

Evidence records flow from mecmcp-audit to ssdf.audit via ClickHouse HTTP INSERT:

```
mecmcp-audit → ClickHouse HTTP API → ssdf.audit table
```

No intermediate Vector transform or custom HTTP endpoint is required — mecmcp-audit writes directly to ClickHouse.

## Authentication

Evidence records authenticate via the existing `ssdf_audit` ClickHouse user:

```bash
# mecmcp-audit environment (vault-backed)
SSDF_CH_HOST=198.51.100.104  # ct104 on pve3
SSDF_CH_PORT=8443
SSDF_CH_SECURE=true
SSDF_CH_AUDIT_USER=ssdf_audit
SSDF_CH_AUDIT_PASSWORD=<from-vault>
```

## HTTP INSERT Protocol

Evidence records are inserted via ClickHouse HTTP interface:

```http
POST https://198.51.100.104:8443/?database=ssdf&query=INSERT%20INTO%20audit%20FORMAT%20JSONEachRow
Authorization: Basic <base64(ssdf_audit:password)>
Content-Type: application/x-ndjson

{"ts":"2026-08-09 14:32:10.500","principal":"agent:mechub-agent","tier":"evidence","tool":"evidence:proposal","args":"{\"request_id\":\"req_123\",\"run_id\":\"run_001\",\"server_id\":\"rustsdcmcp-606\",\"segment_seq\":0,...}","data_classes":["device:vsrx-prod"],"decision":"","row_count":1,"error":"","prev_hash":"","row_hash":"sha256:abc123..."}
```

### Format Notes

- **JSONEachRow:** One JSON object per line (newline-delimited)
- **Timestamp format:** `YYYY-MM-DD HH:MM:SS.sss` (UTC, millisecond precision)
- **Arrays:** Native JSON arrays (`["item1","item2"]`)
- **Nested JSON in args:** Double-escaped string (`"{\"key\":\"value\"}"`)

## Deduplication Guard

To enforce the `(server_id, run_id, segment_seq)` deduplication contract, mecmcp-audit MUST guard each INSERT:

```sql
INSERT INTO ssdf.audit (...)
SELECT ... FROM input('...')
WHERE NOT EXISTS (
  SELECT 1 FROM ssdf.audit
  WHERE tier = 'evidence'
    AND JSONExtractString(args, 'server_id') = <server_id>
    AND JSONExtractString(args, 'run_id') = <run_id>
    AND JSONExtractInt(args, 'segment_seq') = <segment_seq>
)
```

Without this guard, re-ingestion creates duplicate rows.

## Query Endpoint (Task 11 Web App)

The mechub-web evidence viewer queries via the existing ssdf MCP tools or direct ClickHouse SELECT:

```sql
SELECT ts, tool, principal, args, row_hash, prev_hash
FROM ssdf.audit
WHERE tier = 'evidence'
  AND JSONExtractString(args, 'run_id') = ?
ORDER BY ts ASC
```

This query runs as `ssdf_ro` (sovereign MCP tools) or `ssdf_audit_verify` (hash-chain verification).

## Implementation Checklist (Task 9)

- [ ] mecmcp-audit HTTP client (rustsdcmcp `ssdf` crate)
- [ ] ClickHouse auth via Basic auth (ssdf_audit user)
- [ ] JSONEachRow serialization (evidence record → ndjson)
- [ ] Deduplication guard (INSERT ... WHERE NOT EXISTS)
- [ ] TLS trust anchor (ssdf CA cert in rustsdcmcp container)
- [ ] Retry/backoff on transient failures
- [ ] Unit test: mock ClickHouse response
- [ ] Integration test: live insert → query back (ct104 lab instance)

## Security

- **TLS required:** HTTP plaintext rejected (ct104 enforces HTTPS on 8443)
- **Credential source:** Vault-backed secret (never committed to repo)
- **Least privilege:** ssdf_audit can INSERT ssdf.audit ONLY (no SELECT, no other tables)
- **Audit immutability:** INSERT-only user cannot edit or delete past records
- **Hash chain:** Tamper-evidence via cryptographic chain (migration 009)

## References

- Contract: [audit-evidence-contract-v1.md](./audit-evidence-contract-v1.md)
- Schema: [../infra/clickhouse/007_audit.sql](../infra/clickhouse/007_audit.sql)
- Hash chain: [../infra/clickhouse/009_audit_hash_chain.sql](../infra/clickhouse/009_audit_hash_chain.sql)
- Verification: [../scripts/verify_evidence_contract.py](../scripts/verify_evidence_contract.py)
