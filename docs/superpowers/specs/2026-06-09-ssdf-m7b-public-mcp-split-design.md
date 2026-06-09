# SSDF M7b — Public MCP Split (Design)

**Date:** 2026-06-09
**Status:** Approved (brainstorm) — ready for implementation plan
**Sub-project of:** M7 (sovereignty + MCP split). M7b is the second of two cycles; it builds on
**M7a** (classification + multi-principal auth + audit), which is merged + deployed + live-proven
on the sovereign server (ct106).

---

## Goal

Stand up a second, **physically isolated public MCP server** that exposes only
`shareable`-classed tools, backed by ClickHouse `SQL SECURITY DEFINER` views and enforced at the
**grant floor** so the public process is structurally unable to read sovereign data. A public
frontier LLM consumes it exactly like any other MCP client — a URL + bearer token (remote MCP
connector) — which is the *same* interface a local LLM uses against the sovereign MCP. There is no
separate API or egress to build: **the MCP endpoint is the interface for both tiers.**

## Non-goals (explicitly out of scope for M7b)

- **Frontier-LLM / egress / API configuration.** Handing the public MCP URL+token to a chosen public
  model is operator configuration, not engineering. M7b stops at exposing and live-proving the public
  MCP.
- **Per-class column redaction.** v0 uses one coarse shareable view over the graph tables (Approach A
  from the brainstorm). Finer per-class column projection is deferred.
- **Entity-table views.** No public-candidate tool reads `ssdf.entities` / `ssdf.entity_edges`, so no
  shareable views are created over them.
- **Tamper-evident audit hash chain.** M7a already reserved schema room; not built here.
- **Changes to the sovereign server (ct106).** It is untouched; M7b only adds a second service.

## Background / why this shape

M7 is delivered via two physical servers, with **ClickHouse grants as the hard enforcement floor**.
M7a hardened the existing sovereign server and produced the shared modules M7b reuses verbatim:
`classification.py` (taxonomy + `classes_for_tool` + `load_classification`), `auth.py`
(`current_caller`), `audit.py` + `ssdf.audit` (the INSERT-only `ssdf_audit` user), the token-map
loader in `config.py`, and the `wrapper.audited_tool` decorator — which **already accepts a `tier`
keyword** (default `"sovereign"`), pre-wired for this milestone.

**Key ClickHouse fact that drives the design:** a *plain* view is only a query rewrite, so
`SELECT FROM view` checks privileges on the **underlying base tables** — granting on the view alone
does not create a boundary. ClickHouse 26.5 (ct104 runs 26.5.1) supports `SQL SECURITY DEFINER`
views, which run against base tables with the **definer's** privileges, so the invoker needs SELECT
on the view *only*. That is the mechanism that makes "grant `ssdf_public` on views only" an actual
hard floor.

**Co-mingling fact:** all five public-candidate tools (`get_entity`, `locate`, `neighbors`,
`find_path`, `topology_snapshot`) read the **same two base tables** — `ssdf.graph_nodes` /
`ssdf.graph_edges` — via `graphstore.py`. `graph_nodes` carries both `topology` data (ports, VLANs,
links) and `identity` data (MAC, hostname, IP identifiers) in the same rows. v0 (Approach A) exposes
them through a single coarse view; flipping either `topology` or `identity` to shareable exposes the
same node/edge view. This is documented, not hidden.

## Public tool surface (derivation)

A tool is exposable on the public server **iff every data class it returns is `shareable`**, using
M7a's `TOOL_DATA_CLASSES`. Only `topology` and `identity` are configurable to `shareable`
(`security_log` / `firewall_config` are locked sovereign in v0), so the maximum public surface is:

| Class flipped to `shareable` | Public tools that become exposable |
|---|---|
| `topology` | `locate`, `neighbors`, `find_path`, `topology_snapshot` |
| `identity` | `get_entity` |
| both | all five above |

Additional rules:

- **`run_sql` is hard-excluded** from the public build regardless of classification (defense in depth:
  arbitrary SQL must never live on the public process).
- Tools touching `security_log` / `firewall_config` — `query_flows`, `describe_schema`,
  `top_talkers`, `run_sql`, `enforcement_points`, `explain_access` — are **never** registered on the
  public build.
- **Secure-by-default:** if no class is flipped, the public server boots with **zero tools** and logs
  a clear warning (inert-by-default is correct, not an error).

## Architecture

- New LXC **ct110** (`ssdf-mcp-public`, **198.51.100.154**, verified free: not configured on any LXC,
  no ARP entry, no ping response; natural next address after the SSDF cluster .150–.153) on
  pve3.example.com, no Docker.
- Runs the **same** `services/mcp-query` package as a **public-tier** systemd service on port
  **30033** (sovereign uses 30032).
- Holds **only**: the `ssdf_public` CH credential (SELECT on shareable views only), the `ssdf_audit`
  CH credential (INSERT-only on `ssdf.audit`, cannot SELECT anything), and the public token map. It
  **never** holds `ssdf_ro`, sovereign tokens, or any base-table grant.
- The sovereign server (ct106) is unchanged.

## Components

### 1. ClickHouse enforcement floor — `infra/clickhouse/008_public_views.sql` (new)

Pattern mirrors `005_entity_user.sql` / `007_audit.sql` (password injected via `envsubst`, never
committed). Idempotent (`IF NOT EXISTS` / `CREATE OR REPLACE`).

- `CREATE DATABASE IF NOT EXISTS ssdf_public;`
- Dedicated **definer** user `ssdf_view_definer` (least privilege: its blast radius equals the
  shareable surface):
  - `CREATE USER IF NOT EXISTS ssdf_view_definer IDENTIFIED WITH sha256_password BY '${DEFINER_PW}';`
  - `GRANT SELECT ON ssdf.graph_nodes TO ssdf_view_definer;`
  - `GRANT SELECT ON ssdf.graph_edges TO ssdf_view_definer;`
- Two `SQL SECURITY DEFINER` views (coarse v0 — full node/edge shape, pass-through columns; tenant
  filtering stays in the tool SQL just like the sovereign path):
  - `CREATE OR REPLACE VIEW ssdf_public.graph_nodes DEFINER = ssdf_view_definer SQL SECURITY DEFINER AS SELECT * FROM ssdf.graph_nodes;`
  - `CREATE OR REPLACE VIEW ssdf_public.graph_edges DEFINER = ssdf_view_definer SQL SECURITY DEFINER AS SELECT * FROM ssdf.graph_edges;`
- Public reader user `ssdf_public` — granted on the **views only**, no base-table grant:
  - `CREATE USER IF NOT EXISTS ssdf_public IDENTIFIED WITH sha256_password BY '${PUBLIC_PW}';`
  - `GRANT SELECT ON ssdf_public.graph_nodes TO ssdf_public;`
  - `GRANT SELECT ON ssdf_public.graph_edges TO ssdf_public;`

**Boundary proof (live assertion):** as `ssdf_public`, `SELECT FROM ssdf_public.graph_nodes`
succeeds; `SELECT FROM ssdf.graph_nodes` and `SELECT FROM ssdf.events` both raise `ACCESS_DENIED`.

> Note: `SELECT *` in the view freezes column order. If a future migration adds a column to
> `ssdf.graph_nodes`, re-run `CREATE OR REPLACE VIEW` so the view picks it up. Acceptable for v0;
> explicit column lists are a later hardening if column-level redaction (Approach B) is ever needed.

### 2. `schema` parameter threaded through the graph store (code)

`ClickHouseGraphStore` and the `build_*_sql` helpers in `graphstore.py` currently hardcode the
`ssdf.` qualifier (`FROM ssdf.graph_nodes`, `FROM ssdf.graph_edges`). Add a `schema: str = "ssdf"`
parameter:

- `build_node_match_sql(value, tenant, schema="ssdf")`, `build_subgraph_sql(...)`,
  `build_nodes_by_id_sql(...)` interpolate `{schema}.graph_nodes` / `{schema}.graph_edges`.
- `ClickHouseGraphStore.__init__(self, ch_client, tenant="t_main", schema="ssdf")` stores `schema`
  and passes it to the builders.
- Default `"ssdf"` keeps the sovereign path byte-for-byte unchanged; the public build constructs the
  store with `schema="ssdf_public"`.

The schema name is **not** user input — it is a fixed build-time constant — so interpolation is safe;
tenant and value remain bound parameters exactly as today.

### 3. `build_app(tier)` — public build path (`server.py`)

Refactor `build_app()` to `build_app(tier: str = "sovereign")`:

- **Sovereign tier (default):** behaves exactly as today — all 11 tools, `schema="ssdf"`,
  verifier payload `tier="sovereign"`, `audited_tool(..., tier="sovereign")`.
- **Public tier:**
  1. Load classification (`load_classification()` — fail closed on invalid config).
  2. Compute the public tool set: for each registered tool, include it iff
     `classes_for_tool(name)` is non-empty **and** every class in it has label `shareable`; then
     **remove `run_sql`** unconditionally.
  3. If the set is empty, log a warning (`[public] no shareable classes configured; 0 tools exposed`)
     and continue (server still boots).
  4. Build the graph store with `schema="ssdf_public"`; the entity store / access tools are **not**
     constructed (no public tool needs them).
  5. Verifier payload carries `tier="public"`; register each public tool via
     `audited_tool(name, fn, auditor, tier="public")`.
- `main()` reads the tier from env `MCP_TIER` (`"sovereign"` default; the ct110 unit sets
  `MCP_TIER=public`) and calls `build_app(tier)`.

`classification.py`, `auth.py`, `audit.py`, `wrapper.py`, and the token-map loader are reused
**verbatim** — no changes.

### 4. Auth & audit (public tier)

- `MCP_TOKENS_FILE` on ct110 defines `public`-tier principal(s); per-token `allowed_tools` may scope
  further within the already-shareable set. (Single-token fallback also works, mapped to principal
  `agent`/all-public-tools.)
- Every call writes one `ssdf.audit` row with `tier="public"` via the INSERT-only `ssdf_audit` user
  on a connection separate from the `ssdf_public` query path. Deny → `{"error":"forbidden"}` (HTTP
  200), audited `decision="deny"`, underlying tool not invoked. Audit remains best-effort (an insert
  failure logs to stderr and never blocks the call).

## Data flow

```
public LLM ──bearer token──► public MCP (ct110, MCP_TIER=public)
                               │  FastMCP auth: token map → principal, allowed_tools, tier=public
                               ▼
                         tool-call wrapper (audited_tool, tier="public")
                           ├─ authz: tool ∈ public set ∧ allowed_tools? ──no──► {error: forbidden}
                           ├─ run tool ─► graphstore(schema="ssdf_public")
                           │                 └─SELECT─► ssdf_public.graph_nodes/edges
                           │                              (DEFINER view → reads base ssdf.* as
                           │                               ssdf_view_definer; invoker = ssdf_public)
                           └─ audit.record(tier="public", …) ──INSERT as ssdf_audit──► ssdf.audit
```

## Error handling

- `ssdf_public` having no base-table grant is the **intended** floor, not an error.
- A misconfigured view (e.g. definer missing a base grant) surfaces as a per-tool error result,
  audited, and never crashes the server.
- No shareable class configured ⇒ warn + zero tools (secure default).
- Invalid classification / token-map config ⇒ `ConfigError` at startup (fail closed) — inherited
  from M7a.
- Unknown/invalid bearer token ⇒ FastMCP auth rejects (existing behavior).
- `CH_AUDIT_PASSWORD` unset ⇒ no-op auditor (server still runs) — inherited from M7a.

## Testing

**Unit (no live CH; mock the audit writer + auth context):**

- `build_app(tier="public")` with `topology`+`identity` shareable registers exactly
  `{get_entity, locate, neighbors, find_path, topology_snapshot}` and **not** `run_sql`,
  `query_flows`, `describe_schema`, `top_talkers`, `enforcement_points`, `explain_access`.
- Flipping only `topology` registers exactly the four topology tools (no `get_entity`).
- Zero shareable classes ⇒ empty tool set + a warning is emitted; server object still builds.
- `run_sql` is excluded from the public build even if a (hypothetical) classification made its class
  shareable.
- `build_*_sql(..., schema="ssdf_public")` emits `FROM ssdf_public.graph_nodes` /
  `FROM ssdf_public.graph_edges`; default still emits `ssdf.`.
- `ClickHouseGraphStore(schema="ssdf_public")` threads the schema into every query it issues.
- Public build sets verifier payload `tier="public"` and wraps tools with `audited_tool(tier="public")`
  (assert the audit row's `tier` is `public`).
- Sovereign build (`tier="sovereign"`) is unchanged: all 11 tools, `schema="ssdf"`, tier `sovereign`.

**Live integration (real CH, marked `integration`):**

- Apply `008_public_views.sql`. As `ssdf_public`: `SELECT count() FROM ssdf_public.graph_nodes`
  succeeds; `SELECT count() FROM ssdf.graph_nodes` and `SELECT count() FROM ssdf.events` both raise
  `ACCESS_DENIED` (the hard-floor assertion).
- A public-tier MCP call to `topology_snapshot` (or `locate`) returns rows sourced from the view, and
  exactly one `ssdf.audit` row lands with `tier="public"`, the expected `principal`, `tool`,
  `data_classes`, `decision="allow"`.
- A sovereign-only tool (e.g. `query_flows`) is **not** in the public server's tool list (assert via
  the MCP tool listing) and, if forced, is denied.

## Deployment (ct110, as-built mechanics)

1. Create LXC **ct110** `ssdf-mcp-public` on pve3 (198.51.100.154), provision Python venv + install the
   `ssdf-mcp-query` package (regular or editable — record which in CLAUDE.md, mirroring ct106).
2. Apply `infra/clickhouse/008_public_views.sql` on ct104 as CH admin, injecting `DEFINER_PW` and
   `PUBLIC_PW` via `envsubst` (creates `ssdf_public` db, `ssdf_view_definer`, the two DEFINER views,
   and the `ssdf_public` reader user).
3. Configure ct110 env (`/etc/ssdf-mcp/…`, mode 600):
   - `MCP_TIER=public`, `MCP_PORT=30033`, `MCP_BIND=0.0.0.0`
   - `CH_HOST=198.51.100.151`, `CH_PORT=8123`, `CH_USER=ssdf_public`, `CH_PASSWORD=<PUBLIC_PW>`,
     `CH_DATABASE=ssdf_public`
   - `MCP_CLASSIFICATION_FILE` flipping `topology` and/or `identity` to `shareable` (required for any
     tool to appear)
   - `MCP_TOKENS_FILE` with the public principal(s) (or single-token fallback)
   - `CH_AUDIT_USER=ssdf_audit`, `CH_AUDIT_PASSWORD=<audit_pw>` (same INSERT-only user as ct106)
4. Install + start the `ssdf-mcp-public.service` systemd unit; verify clean boot and the exposed tool
   list.
5. Live-prove: a public-tier MCP call returns graph data and writes a `tier="public"` audit row; the
   `ssdf_public` base-table SELECT denial holds.

## What M7b completes

- The two-physical-server M7 split is realized: sovereign (ct106) + public (ct110), each least-
  privileged at the ClickHouse grant floor.
- The public surface is a single auditable artifact: `ssdf_public.*` views + their grants define
  exactly what a public LLM can ever see, independent of application code.
- A public frontier LLM is integrated by pointing it (as an MCP client) at
  `http://198.51.100.154:30033/mcp` with a `public`-tier token — no further engineering.
