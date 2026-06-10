# SSDF — P1 in-place hardening (M1, M3, M4, M5, M6)

**Date:** 2026-06-10
**Status:** design approved, pre-implementation
**Scope:** in-place hardening of existing services/config — no new infra components
**Source:** `docs/security/2026-06-10-vulnerability-review.md` P1 findings M1, M3, M4, M5, M6
**Out of scope (separate spec):** M2 (rate-limit / reverse proxy / token rotation) — new
internet-facing component, to be brainstormed separately alongside P2 L1/L3/L6.

## Problem

Five Medium findings, each a self-contained gap in an existing service or deploy artifact.
They do not interact; the only shared concern is the `services/mcp-query` test harness (M1,
M3, M6). Each is implemented and committed independently (TDD per finding).

- **M1** — query-execution timeout is dead config (DoS). `config.py:35,102` load
  `max_execution_time`, but `ClickHouseClient.run()` (`clickhouse.py:45`) calls `query()` with
  no `settings=`, so it is never applied. Heavy SELECTs run unbounded.
- **M3** — `ssdf.audit` has no tamper-evidence. `007_audit.sql` reserves `prev_hash`/`row_hash`
  in a comment but never creates them; any ALTER/DROP identity can silently rewrite history.
- **M4** — `services/topo/collectors/panos.py:7,26` and `services/policy/collectors/panos.py:7,27`
  parse vendor XML with stdlib `xml.etree`, which does not defend against billion-laughs entity
  expansion (a hostile/compromised PAN-OS response can hang/OOM the collector).
- **M5** — none of the five `ssdf-*.service` units set any hardening; with no `User=` each runs
  as **root** while reading a secrets `EnvironmentFile`. Worst case: the internet-facing public
  server compromise yields root on ct113.
- **M6** — `tools.py:88,101` return `{"error":"upstream","detail":str(exc)}`, handing raw
  ClickHouse exception strings (column/type/host detail) back to the LLM client.

## Decisions (locked during brainstorm 2026-06-10)

- **M1:** wire the timeout **and** add `max_result_rows` + `max_memory_usage` caps.
- **M3:** **per-tier, in-process hash chain**, seeded on startup via a new read-only
  `ssdf_audit_verify` identity; writer stays INSERT-only; insert path stays read-free.
- **M5:** `DynamicUser=yes` (transient unprivileged user) + the standard hardening directive set.

---

## M1 — Wire query limits (`services/mcp-query`)

### Changes

- `config.py`: add two fields to `Config` (frozen dataclass) and wire them in `load_config()`:
  - `max_result_rows: int = 100000` ← env `MCP_MAX_RESULT_ROWS` (default `"100000"`).
  - `max_memory_usage: int = 1_000_000_000` ← env `MCP_MAX_MEMORY_BYTES` (default
    `"1000000000"`, i.e. ~1 GB).
- `clickhouse.py` `ClickHouseClient.run()`: pass a settings dict (the client already holds
  `self._config`):
  ```python
  result = self._client.query(
      sql,
      parameters=params or {},
      settings={
          "max_execution_time": self._config.max_execution_time,
          "max_result_rows": self._config.max_result_rows,
          "max_memory_usage": self._config.max_memory_usage,
          "result_overflow_mode": "throw",
      },
  )
  ```
  `result_overflow_mode="throw"` makes a `max_result_rows` breach raise rather than silently
  truncate (a truncated result is a correctness hazard for an agent).

### Tests (`tests/test_clickhouse.py`, unit)
- With a mocked `clickhouse_connect` client, assert `query()` is called once with a `settings`
  kwarg containing all of `max_execution_time`, `max_result_rows`, `max_memory_usage`,
  `result_overflow_mode` and the configured values.
- `tests/test_config.py`: `load_config()` reads the two new env vars; defaults applied when
  unset.

### Deploy
Pure code; reaches ct106/ct113 via the existing editable-install sync + service restart. New
env vars optional (defaults safe). No CH change.

---

## M3 — Audit hash chain (per-tier, in-process)

Make row edits, deletions, and reordering in `ssdf.audit` **detectable** without giving the
writer read access and without a per-insert read on the hot path.

### Schema — new `infra/clickhouse/009_audit_hash_chain.sql` (idempotent, `envsubst`)

```sql
ALTER TABLE ssdf.audit ADD COLUMN IF NOT EXISTS prev_hash String DEFAULT '';
ALTER TABLE ssdf.audit ADD COLUMN IF NOT EXISTS row_hash  String DEFAULT '';

CREATE USER IF NOT EXISTS ssdf_audit_verify IDENTIFIED BY '${AUDIT_VERIFY_PW}';
GRANT SELECT ON ssdf.audit TO ssdf_audit_verify;
```

- Columns appended at the table's end ⇒ safe for the positional insert once `AUDIT_COLUMNS` is
  extended to match. `ssdf_audit` is unchanged (still INSERT-only). `ssdf_audit_verify` is the
  only SELECT path (used for startup seeding + the verify CLI). Mirrors the `005`/`007`
  `envsubst`-of-a-password pattern.

### Hashing — new pure module `services/mcp-query/src/ssdf_mcp_query/audit_chain.py`

```python
def canonical(row: dict) -> str:
    # Deterministic serialization of the 9 NON-hash fields in fixed order.
    return json.dumps(
        [row["ts_iso"], row["principal"], row["tier"], row["tool"], row["args"],
         row["data_classes"], row["decision"], row["row_count"], row["error"]],
        separators=(",", ":"), ensure_ascii=False,
    )

def compute_row_hash(prev_hash: str, row: dict) -> str:
    return hashlib.sha256((prev_hash + "\n" + canonical(row)).encode("utf-8")).hexdigest()
```

`ts` is serialized as a stable ISO-8601 string (`ts_iso`) so the hash is reproducible by the
verifier from the stored `DateTime64`. Pure + deterministic ⇒ unit-testable offline.

### Chain advance — modify `audit.py`

- Extend `AUDIT_COLUMNS` with `"prev_hash", "row_hash"` (end of list).
- `build_audit_row` additionally carries a stable `ts_iso` (derived from `ts`) for hashing; the
  stored `ts` column is unchanged.
- `Auditor` gains `self._last_hash: str` (this process's tier chain head) and a
  `threading.Lock`. `record()`:
  1. acquire lock;
  2. `rh = compute_row_hash(self._last_hash, row)`; set `row["prev_hash"]=self._last_hash`,
     `row["row_hash"]=rh`;
  3. `self._insert(row)`;
  4. **on success only:** `self._last_hash = rh`;
  5. on insert failure: leave `_last_hash` unchanged, log to stderr (the dropped row is simply
     absent; the next successful row links to the last *landed* hash, so the chain stays
     intact);
  6. release lock.
- **Seeding:** `make_ch_auditor(config, tier)` gains a `tier` arg (the server knows its tier).
  When `config.ch_audit_verify_password` is set, open a second read-only connection as
  `ssdf_audit_verify` and seed
  `SELECT row_hash FROM ssdf.audit WHERE tier={tier:String} ORDER BY ts DESC LIMIT 1`
  (genesis `""` when empty). When unset: seed `""` + stderr warn (chain self-consistent going
  forward; degrades, never fails). The no-op auditor path (no `CH_AUDIT_PASSWORD`) is unchanged.
- `config.py`: add `ch_audit_verify_password: str | None = None` ← env
  `CH_AUDIT_VERIFY_PASSWORD`.
- `server.py`: pass the server's `tier` into `make_ch_auditor(config, tier)`.

**Why per-tier / per-process:** ct106 (sovereign) and ct113 (public) write independently; each
keeps its own linear chain keyed by `tier`. A single global chain across two writers would need
a distributed lock — against the minimal principle and out of scope.

### Verification — new CLI `services/mcp-query/src/ssdf_mcp_query/verify_audit.py`

Reads as `ssdf_audit_verify`. Per tier: build `{row_hash: row}`, start at the row with
`prev_hash==""`, walk `prev_hash → row_hash` links, recomputing each `row_hash`. Reports:
- **content edit** — recomputed `row_hash` ≠ stored;
- **deletion** — a row's `prev_hash` names a `row_hash` not present;
- **insertion/reorder** — rows not reachable from genesis (orphans).

Follows the **linkage, not `ts`**, so same-millisecond `ts` ties don't cause false positives.
Exit non-zero if any tier fails. Runnable as `python -m ssdf_mcp_query.verify_audit`.

### Tests
- `tests/test_audit_chain.py` (unit): `canonical` determinism; `compute_row_hash` changes iff a
  field changes; a fixed known-vector digest.
- `tests/test_audit.py` (unit, fake insert): chains correctly across calls; **does not advance
  `_last_hash` on insert failure**; N concurrent threads still yield one valid linear chain.
- `tests/test_verify_audit.py` (unit, synthetic rows): clean chain passes; a flipped field, a
  deleted row, and an orphan/reordered row are each flagged with the right category.
- Live (`-m integration`): write several rows via the real auditor → `verify_audit` clean;
  `ALTER UPDATE` one field on ct104 → `verify_audit` flags it.

### Deploy
- Apply `009` on ct104: `AUDIT_VERIFY_PW="$CH_AUDIT_VERIFY_PASSWORD" envsubst < 009… |
  clickhouse-client --host <ct104> --multiquery`.
- Add `CH_AUDIT_VERIFY_PASSWORD` to **ct106 and ct113** `/etc/ssdf-mcp/secrets.env` (mode 600);
  restart both services. ct113's auditor chains tier=`public`.
- **Documented caveat:** rows written before `009` have empty `prev_hash`/`row_hash` (column
  DEFAULT `''`); the verifier treats the first hashed row per tier as the chain start. No
  backfill — historical rows can't be authentically re-hashed.

---

## M4 — `defusedxml` for vendor XML (`services/topo`, `services/policy`)

`defusedxml` wraps **parsing only**, not serialization. `services/topo/collectors/panos.py` also
calls `ET.tostring` (lines 63, 92), which `defusedxml` does not provide.

### Changes
- Add `defusedxml` to `[project].dependencies` in both `services/topo/pyproject.toml` and
  `services/policy/pyproject.toml`.
- In each `panos.py`: parse via `defusedxml.ElementTree` (re-exports `fromstring` and
  `ParseError`), e.g. `from defusedxml.ElementTree import fromstring as _xml_fromstring` and
  use it where `ET.fromstring` was called. Keep `import xml.etree.ElementTree as ET` **only**
  for `ET.tostring` in the topo collector. The policy collector uses no `tostring`, so its
  stdlib import is removed entirely.
- `ParseError` handling is unchanged in shape (defusedxml raises the same `ParseError` type).

### Tests
- `services/topo/tests/test_collector_panos.py` and `services/policy/tests/test_panos_rules.py`:
  add a billion-laughs / nested-entity-expansion fixture and assert parsing raises a defused
  error (`defusedxml.common.EntitiesForbidden` / `ParseError`) and the collector degrades
  safely (returns `[]` / `None`) rather than hanging or expanding. Existing parse-success tests
  must still pass.

### Deploy
Dependency add + import swap; reaches ct109 via the existing venv reinstall
(`pip install --force-reinstall --no-deps` from `/opt/src/*` per the M6a-fix deploy note) — the
new dependency requires a normal `pip install` (with deps) of the updated package, then the
collectors run on the next timer tick. No CH change.

---

## M5 — systemd hardening (5 unit files)

Add the same hardening block to the `[Service]` section of all five units:
`services/mcp-query/infra/ssdf-mcp-query.service`,
`services/mcp-query/infra/ssdf-mcp-public.service`,
`services/topo/infra/ssdf-topo.service`,
`services/entity/infra/ssdf-entity.service`,
`services/policy/infra/ssdf-policy.service`.

```ini
DynamicUser=yes
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
CapabilityBoundingSet=
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
Environment=PYTHONDONTWRITEBYTECODE=1
```

### Why this is safe (verified facts)
- `EnvironmentFile` (mode-600 root) is parsed by **systemd (PID 1, root)** before dropping to
  the transient user, so DynamicUser does not break secrets loading.
- Services write nothing to disk at runtime (output goes to ClickHouse / vendor MCPs over the
  network); `/opt/*` venvs are world-readable; `PYTHONDONTWRITEBYTECODE=1` avoids `__pycache__`
  writes under read-only `/opt`.
- Listen ports are >1024 (30032/30033) ⇒ empty `CapabilityBoundingSet=` (drop all caps) is fine;
  no `CAP_NET_BIND_SERVICE` needed.
- `RestrictAddressFamilies` keeps INET/INET6 (HTTP to CH + MCP) and UNIX; drops the rest.

### Verification (no unit tests possible)
- `systemd-analyze security <unit>` before/after — expect a large exposure-score drop
  (target: out of the "UNSAFE" band).
- After redeploy: `systemctl is-active` for the MCP services; one live MCP tool call succeeds;
  the ct109 timers fire one clean collect→resolve cycle.

### Deploy
Copy each updated unit to its host, `systemctl daemon-reload`, restart (MCP services) / let the
timer fire (collectors). **Gated on operator go-ahead** (live-affecting, like the H1 apply).

---

## M6 — Scrub upstream error text (`services/mcp-query/tools.py`)

Only the two generic `upstream` handlers leak internals. The two `validation` handlers
(lines 48, 56) return caller-input errors (`BuilderError`/`TimeParseError`/`ValueError`) that are
safe and useful for the agent to self-correct — leave them.

### Changes
- Add a module logger: `logger = logging.getLogger("ssdf_mcp_query.tools")` and a one-time basic
  stderr config at server start (or rely on existing handlers; keep minimal).
- Rewrite the two `except Exception as exc:` blocks (lines 88, 101) to:
  ```python
  cid = uuid.uuid4().hex
  logger.exception("tool upstream error correlation_id=%s", cid)
  return {"error": "upstream", "detail": "query failed", "correlation_id": cid}
  ```
  Full exception (with traceback) is logged server-side; the caller gets a generic detail plus a
  correlation id for support.

### Tests (`tests/test_tools.py`, unit)
- Force the underlying client to raise an exception carrying a recognizable internal string;
  assert the returned dict has `error=="upstream"`, `detail=="query failed"`, a 32-hex
  `correlation_id`, and that the internal string does **not** appear anywhere in the response.
- Assert a validation error still returns its helpful `detail` (regression — not scrubbed).

### Deploy
Pure code; editable-install sync + restart on ct106/ct113. No CH change.

---

## Order, risk, reversibility

1. **M1** (smallest, pure code, immediate DoS reduction).
2. **M6** (pure code, no behavior change beyond error shape).
3. **M4** (dep add + import swap; isolated to collectors).
4. **M3** (schema migration + chain logic + verify CLI; biggest code surface).
5. **M5** (unit-file edits; live redeploy gated on operator).

All reversible: M1/M6 are code reverts; M4 reverts the import; M3's `009` only **adds** columns
+ a read-only user (drop the user / ignore the columns to revert); M5 reverts to the prior unit
files + `daemon-reload`. No stored rows are mutated, no read-path tool contract changes (M1
adds caps that only ever *error* on abuse; M6 changes only the error payload shape; M3 adds two
columns the existing tools never select).

## Out of scope

- **M2** — rate-limiting / reverse proxy / token rotation (separate edge-hardening spec, with
  P2 L1 TLS / L3 bind / L6 origin checks).
- All remaining **P2 L1–L6** defense-in-depth items.
- No change to the event schema, the entity/topology read path, or the M7a/M7b tool surface.
