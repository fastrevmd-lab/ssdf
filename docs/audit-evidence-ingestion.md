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
SSDF_CH_HOST=198.51.100.151  # 701 ssdf-event-store on pve2
SSDF_CH_PORT=8443
SSDF_CH_SECURE=true
SSDF_CH_AUDIT_USER=ssdf_audit
SSDF_CH_AUDIT_PASSWORD=<from-vault>
```

## HTTP INSERT Protocol

Evidence records are inserted via ClickHouse HTTP interface:

```http
POST https://198.51.100.151:8443/?database=ssdf&query=INSERT%20INTO%20audit%20FORMAT%20JSONEachRow
Authorization: Basic <base64(ssdf_audit:password)>
Content-Type: application/x-ndjson

{"ts":"2026-08-09 14:32:10.500","principal":"agent:mechub-agent","tier":"evidence","tool":"evidence:proposal","args":"{\"request_id\":\"req_123\",\"run_id\":\"run_001\",\"server_id\":\"rustsdcmcp-606\",\"segment_seq\":0,...}","data_classes":["device:vsrx-prod"],"decision":"","row_count":1,"error":"","prev_hash":"","row_hash":"sha256:abc123..."}
```

### Format Notes

- **JSONEachRow:** One JSON object per line (newline-delimited)
- **Timestamp format:** `YYYY-MM-DD HH:MM:SS.sss` (UTC, millisecond precision)
- **Arrays:** Native JSON arrays (`["item1","item2"]`)
- **Nested JSON in args:** Double-escaped string (`"{\"key\":\"value\"}"`)

## Deduplication — a high-water mark, not a per-INSERT guard

**Resolved 2026-08-20 (ssdf#47, mecmcp#292).** An earlier version of this
document required every INSERT to be guarded:

```sql
INSERT INTO ssdf.audit (...) SELECT ... WHERE NOT EXISTS (SELECT 1 FROM ssdf.audit ...)
```

That guard cannot be implemented, for a reason worth stating so it is not
reintroduced: **a single SQL statement runs as exactly one identity**, and the
writer `ssdf_audit` has no SELECT. That absence is deliberate, not an oversight
— `007_audit.sql` says so at the grant:

> INSERT-only writer. Deliberately no SELECT grant: the query identity
> (`ssdf_ro`) cannot read or edit the trail, and `ssdf_audit` cannot read what
> it wrote.

It is a containment property: an attacker holding the writer credential can
append, but cannot enumerate or exfiltrate the history. Granting SELECT to
`ssdf_audit` to satisfy the guard would trade that away to solve a problem the
chain already solves.

### What replaces it

Dedup falls out of chain-seeding, which the sink has to do anyway.

`ssdf_audit_verify` exists precisely for this — `009_audit_hash_chain.sql`
describes it as "used for **startup chain-seeding** and verify_audit". Before
replaying anything, the sink reads its own high-water mark as that identity:

```sql
-- as ssdf_audit_verify
SELECT count() AS landed,
       max(JSONExtractUInt(args, 'segment_seq')) AS high_water
FROM ssdf.audit
WHERE tier = 'evidence'
  AND JSONExtractString(args, 'server_id') = {server_id:String}
  AND JSONExtractString(args, 'run_id')    = {run_id:String}
```

then INSERTs, as `ssdf_audit`, only segments above `high_water` — **and every
segment when `landed = 0`.**

`count()` is not decoration. ClickHouse's `max()` over no rows returns `0`, and
`segment_seq` is 0-based, so "nothing has landed" and "segment 0 has landed"
both render as `high_water = 0`. Inserting only `> high_water` on that alone
drops segment 0 of every new run — the first evidence record a writer ever
produces, and the root of its chain. `count()` separates the two cases;
`maxOrNull` returning `NULL` for the empty set would do equally well. Verified
live against 701: an empty run returns `[0, 0]`.

Two identities, two statements, each doing only what it is granted. The security
boundary stays where `007` put it.

### Why this is sufficient

- **Segments are ordered and gapless per `(server_id, run_id)`.** A
  high-water mark is therefore a complete statement of what landed; there is no
  case where segment 5 is present and 3 is missing, because the chain would not
  verify.
- **Writers are serialised per `server_id`, across all of its runs** — not
  merely per `(server_id, run_id)`. The chain is per writer, so every run of one
  `server_id` extends the *same* chain: its second run seeds from the final
  `row_hash` of its first. Two runs of one writer proceeding concurrently would
  therefore fork it just as surely as two writers would, and per-`(server_id,
  run_id)` serialisation permits exactly that. One process per `server_id`, and
  one run at a time within it.

  This is a real constraint on deployment, not a modelling nicety: two
  containers configured with the same `server_id` produce a fork that verifies
  as two valid chains, which is the failure mode this whole document exists to
  prevent. Give each container its own `server_id`.
- **A duplicate is a lost ack, not a divergent row.** The retry carries the
  identical serialised record and the identical `row_hash`, so the failure being
  protected against is re-appending a row already present, never a conflicting
  one.

### Why this is not sufficient on its own

The three points above cover a **replay** — an insert known to have failed,
sent again. They do not cover an insert whose outcome is **unknown**.

A read-then-insert is not atomic against a request already in flight. If an
INSERT times out while ClickHouse is still committing it, the high-water read
before the retry can answer "nothing landed" and the original can commit
afterwards, alongside the retry. Two identical rows, which the hash chain
cannot see: same content, same `row_hash`, so linkage and reachability both
pass.

That gap is closed in the database, not here — `non_replicated_deduplication_window`
plus an `insert_deduplication_token` per segment, see
[audit-evidence-contract-v1.md](audit-evidence-contract-v1.md) and migration
`016_audit_insert_dedup.sql`. **Until that migration is applied the window is
open**, and the mitigation is detection: `verify_audit.py` reports
`duplicate_row`. A sink implemented from the high-water protocol alone is not
finished, and a test suite that only replays known failures will not show it.

### Startup order, when an outcome was left unknown

The token suppresses a *second copy* of a segment. It does not stop a writer
from seeding its chain from a **stale head**, and that produces a fork with no
duplicate anywhere in it:

1. segment B's insert times out; the sink restarts before learning the outcome
2. on startup it reads the tail and gets A, B's predecessor — B has not
   committed yet
3. B commits
4. the replay pass reads the high-water mark, which now includes B, and skips
   it as already landed
5. the next record is written with `prev_hash = A`

Two branches from A, both internally valid, and no duplicated row for
`verify_audit.py` to report. The token cannot help: nothing was inserted twice.

**So the two reads are ordered, and the tail read comes last.** Resolve unknown
outcomes first — read the high-water mark per pending run and finish the replay
— and only then read the tail to seed the chain. The head a writer starts from
must reflect every insert whose fate has been settled, including the ones
settled during startup.

A sink that reads the tail once at boot, before replaying, has this bug. So
does one that caches the tail across a replay pass. If the tail changes between
the read and the first new record, that is not a race to retry through: another
writer holds the same `server_id`, and it should stop.

### What it does not do

It does not protect against two processes writing the same `(server_id,
run_id)`. Nothing here does, and nothing should: that configuration forks the
hash chain, and the verifier is what must catch it. A dedup guard that quietly
absorbed the second writer would hide a broken chain rather than surface it.

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
- [ ] ClickHouse auth via Basic auth (`ssdf_audit` to write, `ssdf_audit_verify` to seed)
- [ ] JSONEachRow serialization (evidence record → ndjson)
- [ ] High-water-mark read as `ssdf_audit_verify` before replay (see above)
- [ ] Tail read for chain seeding, ordered **after** replay resolves unknown
      outcomes (see "Startup order" above) — reading it at boot forks the chain
      after a timeout
- [ ] `insert_deduplication_token` on every insert, byte-length-prefixed as
      `<len(server_id)>:<server_id>:<len(run_id)>:<run_id>:<segment_seq>`
      (e.g. `9:junos-950:5:run-7:42`) — joining on the separator alone is not
      injective, and two segments sharing a token means one is dropped with
      success reported
- [ ] Migration `016_audit_insert_dedup.sql` applied — without it the setting
      is absent and the token is ignored, so the in-flight window stays open
- [ ] Test: retry after an **unknown** outcome, not only after a known failure
      — a replay-only suite passes with none of the above
- [ ] TLS trust anchor (ssdf CA cert in rustsdcmcp container)
- [ ] Retry/backoff on transient failures
- [ ] Unit test: mock ClickHouse response
- [ ] Integration test: live insert → query back (701 lab instance)

## Security

- **TLS required:** HTTP plaintext rejected (701 enforces HTTPS on 8443)
- **Credential source:** Vault-backed secret (never committed to repo)
- **Least privilege:** ssdf_audit can INSERT ssdf.audit ONLY (no SELECT, no other tables)
- **Audit immutability:** INSERT-only user cannot edit or delete past records
- **Hash chain:** Tamper-evidence via cryptographic chain (migration 009)

## References

- Contract: [audit-evidence-contract-v1.md](./audit-evidence-contract-v1.md)
- Schema: [../infra/clickhouse/007_audit.sql](../infra/clickhouse/007_audit.sql)
- Hash chain: [../infra/clickhouse/009_audit_hash_chain.sql](../infra/clickhouse/009_audit_hash_chain.sql)
- Verification: [../scripts/verify_evidence_contract.py](../scripts/verify_evidence_contract.py)
