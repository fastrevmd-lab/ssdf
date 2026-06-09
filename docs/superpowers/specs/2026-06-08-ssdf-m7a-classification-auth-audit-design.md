# SSDF M7a — Data Classification, Multi-Principal Auth & Audit (Design)

**Date:** 2026-06-08
**Status:** Approved (brainstorm) — ready for implementation plan
**Sub-project of:** M7 (sovereignty + MCP split). M7a is the first of two cycles; **M7b**
(public MCP server + shareable views + `ssdf_public` least-privilege user) is brainstormed
and built separately, after M7a.

---

## Goal

Lay the sovereignty foundation on the existing read-only MCP server (`ssdf-mcp-query`, ct106):
a **secure-by-default data-classification taxonomy**, **multi-principal token auth** (distinct
agent identities, optionally tool-scoped), and an **append-only audit log** of every tool call.
This hardens the server that exists today and produces the shared classification + audit modules
that M7b's physical public/sovereign split will reuse.

## Non-goals (explicitly out of scope for M7a)

- The second physical **public** MCP process — that is M7b.
- ClickHouse **shareable views** and the `ssdf_public` least-privilege user — M7b.
- Any **redaction / withholding** of data based on classification — on the sovereign server every
  authorized caller still receives everything; classification here only *labels* and *feeds audit*.
  Enforcement (withholding) is M7b's job, gated at the CH-grant floor.
- Cryptographic **tamper-evidence** (hash-chained audit rows) — schema leaves room; not built now.
- Wiring an actual frontier/cloud LLM — no egress is configured yet.

## Background / why this shape

SSDF is sovereign by construction (read-only, self-hosted, no mandatory cloud). Today the MCP
server (`services/mcp-query/.../server.py`) authenticates with a **single static bearer token**
mapped to one principal (`sub:"agent", client_id:"ssdf"`) and exposes 10 read tools all-or-nothing,
with **no record** of who called what. M7's driver: the operator needs to mark *which data may ever
be shared with a public LLM* and physically prevent leakage. The classification is **by data type**
("a firewall log is sovereign; an interface statistic is shareable"), **not** per-field, and is
**secure-by-default**: every class is sovereign unless config opts it to shareable.

M7 is delivered via Approach 2 (two physical servers; CH grants as the hard floor). M7a builds the
non-split foundation; M7b adds the second process.

## Data-classification taxonomy

A fixed v0 set of **data classes**, each with a sovereignty label. Secure-by-default: the *default*
for every class is `sovereign`; config may flip only the two configurable classes to `shareable`.

| Class | Meaning | Default | Configurable? |
|---|---|---|---|
| `security_log` | Firewall traffic/session/system/config logs (`ssdf.events`) | sovereign | no (v0) |
| `firewall_config` | Configured firewall rules/policies (`entities` source=configured) | sovereign | no (v0) |
| `topology` | Interfaces, LLDP, ports, VLANs, link stats (`graph_nodes/edges`) | sovereign | **yes** |
| `identity` | Assets / MAC↔IP / hostname inventory (`entities` source=observed) | sovereign | **yes** |

Each MCP tool declares the set of classes its output can contain (static map, single source of
truth):

| Tool | Classes returned |
|---|---|
| `query_flows` | `security_log` |
| `describe_schema` | `security_log` |
| `top_talkers` | `security_log` |
| `run_sql` | `security_log` (arbitrary `ssdf.*` read; treated as most-sensitive) |
| `get_entity` | `identity` |
| `locate` | `topology` |
| `neighbors` | `topology` |
| `find_path` | `topology` |
| `enforcement_points` | `topology`, `firewall_config` |
| `topology_snapshot` | `topology` |
| `explain_access` | `security_log`, `topology`, `identity`, `firewall_config` |

> Classes are finer than tables (`ssdf.entities` holds both `identity` and `firewall_config`;
> `ssdf.events` is all `security_log`). M7a only *labels* — it does not gate — so table-vs-class
> granularity is purely an audit-tagging concern here. M7b resolves it with classification-generated
> shareable **views**, granting `ssdf_public` on views only.

## Components

### 1. `classification.py` (new)

- A frozen registry of the four data classes and their default label (`sovereign`).
- The static `TOOL_DATA_CLASSES: dict[str, frozenset[str]]` map above.
- A config loader: reads an optional JSON config (env `MCP_CLASSIFICATION_FILE`, else built-in
  defaults) of the form `{"topology": "shareable", "identity": "sovereign"}`. Only the two
  configurable classes may be overridden; an attempt to set a non-configurable class (or an unknown
  class, or a value other than `sovereign`/`shareable`) raises `ConfigError`. Missing keys default
  to `sovereign`.
- Pure module, no I/O beyond reading the optional file at load. Exposes:
  - `classes_for_tool(tool_name) -> frozenset[str]`
  - `label_for_class(cls) -> "sovereign" | "shareable"`
  - `load_classification(path: str | None) -> Classification` (frozen dataclass)

### 2. Multi-principal auth (extend `config.py`, wire in `server.py`)

- Replace the single-token model. Config gains a **token map** loaded from a JSON file
  (env `MCP_TOKENS_FILE`) of shape:
  ```json
  {
    "<bearer-token-1>": {"principal": "triage-agent", "allowed_tools": ["query_flows", "top_talkers", "explain_access"]},
    "<bearer-token-2>": {"principal": "admin-agent"}
  }
  ```
  - `allowed_tools` omitted ⇒ all tools allowed.
  - Backward compatibility: if `MCP_TOKENS_FILE` is unset, fall back to the existing
    `MCP_AUTH_TOKEN`/`MCP_TOKEN_FILE` single-token path, mapped to principal `"agent"` with all
    tools allowed. (Existing deploy keeps working with no env change.)
- `StaticTokenVerifier` is populated from the token map; each token's verifier payload carries
  `{"sub": <principal>, "client_id": "ssdf", "tier": "sovereign"}`.
- Per-tool authorization: the tool-call wrapper checks the caller's `allowed_tools` against the tool
  being invoked. A disallowed tool returns a structured `{"error": "forbidden", "detail": ...}` and
  is audited as `decision="deny"`. (Tier is always `sovereign` on this server.)

### 3. Audit (`audit.py` + `infra/clickhouse/007_audit.sql`)

- New table `ssdf.audit` (MergeTree, `ORDER BY (ts, principal)`, 90-day TTL):

  | Column | Type | Notes |
  |---|---|---|
  | `ts` | `DateTime64(3)` | call time (UTC) |
  | `principal` | `LowCardinality(String)` | from token map |
  | `tier` | `LowCardinality(String)` | `sovereign` (M7a) / `public` (M7b) |
  | `tool` | `LowCardinality(String)` | tool name |
  | `args` | `String` | JSON of the call arguments (see redaction note) |
  | `data_classes` | `Array(LowCardinality(String))` | classes the tool can return |
  | `decision` | `LowCardinality(String)` | `allow` / `deny` |
  | `row_count` | `UInt32` | rows returned (0 on deny/error) |
  | `error` | `String` | error code/detail, else empty |

  Schema reserves the option to add a future `prev_hash`/`row_hash` pair (B, tamper-evidence)
  without migrating existing rows.
- A dedicated CH user **`ssdf_audit`** with `INSERT`-only on `ssdf.audit` (the MCP writes audit
  rows as this user, on a separate connection from the `ssdf_ro` query path, so the query identity
  cannot edit/read the trail). `ssdf_ro` gets no audit grant in M7a.
- `audit.py` exposes a `record(...)` that builds the row and inserts it; failures to write audit are
  logged but must **not** fail the tool call (audit is best-effort observ­ability, never a query
  blocker) — except they are surfaced in server logs for monitoring.
- **Args redaction:** argument JSON is recorded as-is in v0 (the read tools take only identifiers /
  filters / SQL, not secrets). The single sensitivity is `run_sql.query`; recorded verbatim because
  the whole point of audit is to know what SQL ran. No field-level redaction in M7a.

### 4. Tool-call wrapper (in `server.py`)

A single decorator/wrapper applied to every `@mcp.tool` function that, per call:
1. resolves the caller principal + `allowed_tools` from the auth context,
2. enforces per-tool authorization (deny → structured error, audited),
3. invokes the underlying tool,
4. derives `row_count` from the result (best-effort: `len(result["rows"])` or `result["row_count"]`
   when present, else 0) and `error` from a structured `{"error": ...}` result,
5. records one `ssdf.audit` row,
6. returns the tool's result unchanged.

The wrapper must not alter existing tool return shapes (agents already bind to them).

## Data flow

```
agent ──bearer token──► FastMCP auth (token map → principal, allowed_tools, tier=sovereign)
                           │
                           ▼
                     tool-call wrapper
                       ├─ authz: tool ∈ allowed_tools?  ──no──► {error: forbidden}  ┐
                       ├─ run tool (unchanged) ──────────────► result               │
                       └─ classes_for_tool(tool) ─────────────────────────────┐     │
                                                                              ▼     ▼
                                                              audit.record(ts, principal, tier,
                                                                tool, args, data_classes,
                                                                decision, row_count, error)
                                                                  └─INSERT as ssdf_audit─► ssdf.audit
```

## Error handling

- Missing/empty token map AND missing single-token env ⇒ `ConfigError` at startup (fail closed).
- Invalid classification config (non-configurable class override, unknown class, bad value) ⇒
  `ConfigError` at startup (fail closed — do not silently mislabel).
- Unknown/invalid bearer token ⇒ FastMCP auth rejects (existing behavior).
- Disallowed tool for an authorized principal ⇒ structured `{"error":"forbidden"}`, HTTP 200 with
  error body (consistent with existing tool error contract), audited `decision="deny"`.
- Audit INSERT failure ⇒ logged to server stderr, tool result still returned (audit is best-effort).
- Tool raising/returning an error ⇒ audited with `decision="allow"` (authz passed), `error` set,
  `row_count=0`.

## Testing

Unit (no live CH; mock the audit writer + auth context):
- `classification.py`: defaults all-sovereign; valid override of `topology`/`identity`; rejects
  override of `security_log`/`firewall_config`; rejects unknown class / bad value; `classes_for_tool`
  returns the documented sets for each of the 10 tools.
- token map: parse a multi-principal file; `allowed_tools` omitted ⇒ all allowed; single-token
  fallback maps to principal `agent` all-tools; empty/missing both ⇒ `ConfigError`.
- wrapper: allowed tool runs + audits `allow` with correct `data_classes` and `row_count`;
  disallowed tool returns `forbidden` + audits `deny` and does NOT invoke the underlying tool;
  tool-error result audits `allow` + `error` + `row_count=0`; audit-write exception does not
  propagate (tool result still returned).
- audit row builder: shapes the row dict with all columns; serializes `args` to JSON.

Live integration (real CH, marked `integration`):
- apply `007_audit.sql`; a tool call as a configured principal lands exactly one `ssdf.audit` row
  with the expected `principal/tool/data_classes/decision/row_count`.
- `ssdf_audit` user can `INSERT` but cannot `SELECT` `ssdf.audit` (grant assertion).

## Deployment (ct106, as-built mechanics)

- ct106 `ssdf-mcp-query` is an **editable** install at `/opt/src/mcp-query/src` — sync source +
  `systemctl restart ssdf-mcp-query.service` (no reinstall needed; contrast ct109's regular install).
- Apply `infra/clickhouse/007_audit.sql` on ct104 as CH admin (creates `ssdf.audit` + `ssdf_audit`
  INSERT-only user; inject `ssdf_audit` password via env like `005_entity_user.sql`).
- Add to ct106 env (`/etc/ssdf-mcp/…`, mode 600): `MCP_TOKENS_FILE` (token map), optional
  `MCP_CLASSIFICATION_FILE`, and `CH_AUDIT_USER`/`CH_AUDIT_PASSWORD` for the audit connection.
  Leaving `MCP_TOKENS_FILE` unset preserves today's single-token behavior.
- Live proof: call a tool through the MCP, then `SELECT * FROM ssdf.audit ORDER BY ts DESC LIMIT 1`
  shows the matching row; a disallowed-tool call shows `decision='deny'`.

## What M7a hands to M7b

- `classification.py` (the taxonomy + config loader + tool→class map) — M7b's public server imports
  it to decide which tools are all-shareable and which shareable views to expose.
- `audit.py` + `ssdf.audit` — M7b's public process writes the same audit rows with `tier="public"`.
- The token-map auth pattern — M7b mints `tier="public"` principals.
- Classes flagged `shareable` in config drive M7b's view generation + `ssdf_public` grants.
