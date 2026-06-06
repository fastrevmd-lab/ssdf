# SSDF M2 — MCP Query Layer Design

**Date:** 2026-06-06
**Status:** Approved design (pre-implementation)
**Milestone:** M2 (follows M1: SRX → Vector → ClickHouse, merged in PR #1)

## Goal

Expose the M1 security-event store (`ssdf.events` in ClickHouse) to LLM agents as a
read-only **MCP tool surface**. This is the first piece of SSDF's "AI-native" product
thesis: agents bind to these tools the same way they bind to `rust-junosmcp`, and can
ask time-ranged/filtered questions about security flows and get real data back.

**Done when:** an LLM agent (e.g. Claude Code with the server added via `.mcp.json`)
can call the tools and retrieve real, correctly-typed `ssdf.events` rows — including the
M1 acceptance question "denied/allowed flows by host in the last hour" — over the network,
authenticated, with no ability to mutate data.

## Principles honored

- **Read-only.** SSDF stores/queries/correlates; it never manages devices. M2 adds query
  tools only. No write/management tools.
- **Sovereign / self-hosted.** Runs on Proxmox LXC, no Docker, no cloud dependency. The
  ClickHouse choice stays behind a wrapper (`clickhouse.py`) so the storage backend remains
  swappable.
- **AI-native.** The MCP tool surface is the product API; tools are designed for safe
  autonomous invocation by multiple LLMs (no single model is load-bearing).
- **Minimal.** Smallest thing that works: four tools, one LXC, one read-only DB user.

## Architecture

```
LLM agents ──(.mcp.json, bearer token)──► ssdf-mcp-query (ct10x, Python/FastMCP)
                                              │  http://<ip>:30032/mcp  (streamable-HTTP)
                                              ▼
                                          ClickHouse ct104:8123
                                          (read-only CH user, database ssdf, table events)
```

- **Language/framework:** Python + FastMCP, **streamable-HTTP** transport (mirrors the
  existing `rust-junosmcp` deployment pattern).
- **ClickHouse access:** `clickhouse-connect` (official Python HTTP client). All access
  goes through a single `clickhouse.py` wrapper — the storage seam.
- **Deployment:** dedicated Proxmox LXC on pve3.example.com, next free 100-range VMID,
  unused IP; systemd service; bearer token in-container at `/etc/ssdf-mcp/token`. No Docker.
- **Repo location:** `services/mcp-query/` — establishes the Python side of the polyglot
  split described in CLAUDE.md.

### Read-only by construction (defense in depth)

The server connects to ClickHouse as a **dedicated read-only user** (`readonly=1`), created
during deployment. Even a bug in the SQL guard cannot mutate or delete data. This is the
final backstop beneath the `run_sql` guard.

## Components

```
services/mcp-query/
  pyproject.toml            # uv-managed; deps: fastmcp (or mcp), clickhouse-connect, sqlglot, pytest
  src/ssdf_mcp_query/
    server.py               # FastMCP app, bearer-token auth, tool registration, config load
    clickhouse.py           # read-only ClickHouse client wrapper (the storage seam)
    tools.py                # query_flows, describe_schema, top_talkers
    sql_guard.py            # run_sql parse / allowlist / limit guard
    timeparse.py            # relative time ("now-1h") + ISO-8601 -> datetime
  tests/
    test_sql_guard.py       # allow/deny table (the highest-value tests)
    test_tools.py           # param -> SQL builder unit tests
    test_integration.py     # four tools against live ct104 (read-only)
  infra/ssdf-mcp-query.service   # systemd unit
```

Each file has one responsibility. `server.py` knows MCP/transport/auth; `tools.py` knows
the four tool contracts; `sql_guard.py` is the isolated, heavily-tested safety unit;
`clickhouse.py` is the only place the storage backend is named.

## Tool surface (the API contract)

All tools are read-only, scoped to `ssdf.events`. Results serialize to JSON-friendly
`list[dict]`: timestamps as ISO-8601 strings, IPv4 as strings, `null` preserved. Every tool
returns `{rows, row_count, truncated, elapsed_ms}` on success or `{error, detail}` on failure
(see Error Handling).

### 1. `query_flows` — filtered flow query (the workhorse)

```
query_flows(src_ip?, dst_ip?, dst_port?, action?, outcome?,
            provider?, zone?, since?, until?, limit=100) -> result
```

- All filters optional, AND-combined; an omitted filter adds no constraint.
- `since`/`until`: ISO-8601 or relative (`"now-1h"`, `"now-24h"`); default window
  `now-24h .. now`.
- `action` validated against known `event_action` values; `outcome` against
  `event_outcome`; `provider` against `event_provider`. `zone` matches either
  `observer_ingress_zone` or `observer_egress_zone`.
- `limit` default 100, hard max 1000. `truncated: true` when the cap is hit.
- Built as a **parameterized** query (clickhouse-connect bound params); user values are
  never string-interpolated into SQL.
- Covers the M1 acceptance question: e.g.
  `query_flows(action="flow_session_deny", since="now-1h")`.

### 2. `describe_schema` — introspection

```
describe_schema() -> { columns: [{name, type}],
                       event_actions: [...], event_outcomes: [...],
                       event_providers: [...], zones: [...],
                       row_count, time_range: {min, max} }
```

- `columns` from `DESCRIBE ssdf.events`.
- Enum-ish distinct values via cheap `SELECT DISTINCT <col> FROM ssdf.events LIMIT <n>`
  (capped) so an LLM can write correct filters and `run_sql` queries without guessing.
- `row_count` and `time_range` from a single aggregate query.

### 3. `top_talkers` — aggregation

```
top_talkers(by="bytes"|"flows", side="src"|"dst",
            since?, until?, limit=10) -> result
```

- Groups by `source_ip` (side="src") or `destination_ip` (side="dst").
- Orders by `sum(network_bytes)` (by="bytes") or `count()` (by="flows"), descending.
- Same time-window semantics and defaults as `query_flows`; `limit` default 10, max 100.

### 4. `run_sql` — guarded read-only SQL escape hatch

```
run_sql(query: str) -> result
```

- For questions the purpose-built tools don't cover. SELECT-only, scoped to `ssdf.*`.
  Guard detailed below.

### Deferred (YAGNI)

`flow_stats` (grouped counts/sums), additional vendors' tables, multi-tenant auth beyond a
single bearer token, write/management tools (out of scope — SSDF is read-only).

## The `run_sql` guard (critical safety surface)

`run_sql` is the only place untrusted LLM-generated text reaches the database, so it gets
layered defenses. The guard lives in `sql_guard.py` and is validated before execution.

1. **Parse, don't regex.** Parse the query with `sqlglot`. Reject unless it is exactly
   **one** statement and that statement is a `SELECT`. This blocks DDL/DML
   (`INSERT`/`ALTER`/`DROP`/`DELETE`), multi-statement payloads (`; DELETE ...`), and
   comment-based injection that regexes miss.
2. **Table allowlist.** Walk the AST; every referenced table must be in the `ssdf` database.
   Block `system.*`, `information_schema`, and ClickHouse table functions
   (`url`, `file`, `remote`, `s3`, `mysql`, etc.), including inside subqueries/CTEs.
3. **Enforced row limit.** If the query has no `LIMIT`, inject one (max 1000); if present,
   clamp to the max.
4. **DB-side ceilings.** Execute with ClickHouse settings `readonly=1`,
   `max_execution_time` (~10s), and `max_result_rows`, so even a parser bypass cannot
   mutate data or run away.
5. **Read-only CH user.** Final backstop (see Architecture).

On rejection, return `{error: "validation", detail: "<reason>"}` so the agent can
self-correct rather than failing opaquely.

## Data flow

Agent calls tool → FastMCP validates the bearer token and typed params → server builds a
parameterized query (or guards `run_sql`) → `clickhouse.py` executes against ct104 as the
read-only user → rows serialized to JSON-friendly `list[dict]` → returned with metadata
(`row_count`, `truncated`, `elapsed_ms`).

## Error handling

Tools never surface raw exceptions/tracebacks to the agent. Three result classes:

- **Validation** — bad enum value, malformed time expression, rejected SQL:
  `{error: "validation", detail}`. The LLM can correct and retry.
- **Upstream** — ClickHouse unreachable, query timeout:
  `{error: "upstream", detail}`.
- **Success** — `{rows, row_count, truncated, elapsed_ms}`.

## Configuration

Nothing hardcoded; loaded from environment + token file (mirrors the M1 `ENV.local`
convention, secrets gitignored):

| Var | Purpose | Example |
|-----|---------|---------|
| `CH_HOST` | ClickHouse host | `198.51.100.151` |
| `CH_PORT` | ClickHouse HTTP port | `8123` |
| `CH_USER` | read-only ClickHouse user | `ssdf_ro` |
| `CH_PASSWORD` | read-only user password | (secret) |
| `MCP_BIND` | bind address | `0.0.0.0` |
| `MCP_PORT` | MCP HTTP port | `30032` |
| (token file) | bearer token | `/etc/ssdf-mcp/token` |

Default `limit=100` (hard max 1000), default time window `now-24h`, `max_execution_time`
~10s — keeps responses within an LLM token budget.

## Testing

TDD throughout. Risk-weighted:

- **`test_sql_guard.py` (highest value):** an allow/deny table. *Allowed:* plain `SELECT`,
  `SELECT` with `WHERE`/`GROUP BY`/`LIMIT`, subqueries over `ssdf.events`. *Rejected:*
  `INSERT`/`UPDATE`/`ALTER`/`DROP`, `SELECT ... ; DELETE ...` (multi-statement),
  `SELECT * FROM system.tables`, `SELECT * FROM url(...)`, commented-out injection,
  non-`ssdf` tables.
- **`test_tools.py`:** param→SQL builder unit tests for `query_flows`/`top_talkers`
  (correct filters, default window applied, limit clamping, parameter binding); time
  parsing (`now-1h`, ISO-8601, invalid).
- **`test_integration.py`:** the four tools run against live ct104 as the read-only user,
  asserting real rows return and the M1 acceptance query works through `query_flows`.

## Commands (to record in CLAUDE.md at implementation time)

- Run tests: `cd services/mcp-query && uv run pytest`
- Run server locally: `uv run python -m ssdf_mcp_query.server`
- Deployment: systemd service on the new LXC; add to agents via `.mcp.json`
  (`{"mcpServers":{"ssdf-query":{"type":"http","url":"http://<ip>:30032/mcp"}}}`).

## Out of scope (parked behind seams)

- Non-ClickHouse storage backends — isolated behind `clickhouse.py`.
- Additional vendor event tables (PAN-OS, Okta, Wazuh) — tools target `ssdf.events` today;
  generic enough to extend later.
- Write/management/correlation-graph tools, multi-tenant auth, agent/LLM orchestration —
  later milestones.
