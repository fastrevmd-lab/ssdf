# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

> **Status: greenfield.** As of this writing the repository is empty — no code, no
> git history, no build files. Everything below describes the *intended* architecture
> and conventions for the project, derived from the project brief. When you scaffold
> real code, update this file to match what actually exists and remove this notice.

## What this project is

**SSDF — Sovereign Security Data Fabric.** A minimal, AI-native security data platform
built from scratch to power **conversational / agent-based management of security
products** (NGFWs, SASE, IDaaS, XDR, etc.) through **MCP tools driven by multiple LLMs**.

Two principles shape every design decision:

- **AI-native, not AI-bolted-on.** The data model, APIs, and tooling exist so that LLM
  agents can query, correlate, and act on security data via MCP. Human UIs are secondary;
  the MCP tool surface is the primary product.
- **Sovereign.** All data and inference stay under the operator's control (self-hosted,
  no mandatory SaaS). Do **not** introduce hard dependencies on external/cloud SIEM/XDR
  platforms (e.g. Wazuh, Splunk, cloud-only LLM APIs). LLM and storage backends must be
  swappable, with self-hosted options as first-class citizens. "Minimal" is a hard
  constraint — prefer the smallest thing that works over feature-complete frameworks.

## Stack & language split

The project is intentionally **polyglot (Rust + Python)**, split by responsibility:

- **Rust** — performance- and correctness-critical core: log/event ingestion, parsing,
  the data-fabric storage/query layer, and any long-running services. Favor single-binary,
  low-overhead services. (Mirrors the existing `rust-junosmcp` MCP work.)
- **Python** — LLM orchestration, MCP tool/server implementations, agent logic, and
  product-integration adapters (NGFW / SASE / IDaaS / XDR connectors). Use async
  (FastAPI-style) services.

The boundary between the two is a network/IPC contract (HTTP/gRPC or a message bus), **not**
shared in-process code. Keep the interface schema-defined and versioned so either side can
be rebuilt independently.

## Architecture (intended, big-picture)

Data flows in one direction with agents acting back through the same fabric:

```
security products ──► ingest/parse (Rust) ──► data fabric (Rust) ──► MCP tools (Python)
   NGFW/SASE/IDaaS/XDR     normalize/enrich        store + query        ▲
                                                                        │
                                          LLM agents (Python, multi-LLM) ┘
```

- **Ingest/parse (Rust):** receive raw telemetry from security products, normalize into a
  common event/entity schema, enrich, and hand off to the fabric. This is the only place
  vendor-specific log formats should live.
- **Data fabric (Rust):** the system of record — stores normalized events/entities and
  serves correlation/query. Storage backend must be swappable (sovereignty requirement).
- **MCP tool layer (Python):** exposes the fabric and product-control actions as MCP tools.
  This is the contract LLM agents bind to. Treat tool definitions as the public API.
- **Agent/LLM layer (Python):** multiple LLMs are supported behind a common abstraction;
  no single model provider may be load-bearing. Agents read via MCP tools and issue
  management actions back to security products via MCP tools.

### Cross-cutting rules

- **Normalize at ingest, never downstream.** A single common schema is the contract every
  other layer depends on. Schema changes ripple everywhere — treat them as breaking and
  version them.
- **The MCP tool surface is an API.** Adding/renaming/removing a tool changes what every
  agent and LLM can do. Design tools to be safe for autonomous invocation (clear scope,
  explicit destructive-action gating) given they manage live security infrastructure.
- **Provider-agnostic by construction.** Anything that assumes one specific LLM, one storage
  engine, or one SIEM violates the sovereignty principle. Put such choices behind interfaces.

## Commands

### M1 (SRX → Vector → ClickHouse)
- Run Vector unit tests: `vector test infra/vector/vector.toml`
- Validate Vector config: `CH_HOST=127.0.0.1 vector validate --no-environment infra/vector/vector.toml`
- Apply ClickHouse schema: `CH_HOST=<ip> ./scripts/apply_clickhouse_schema.sh`
- Query events: `clickhouse-client --host <ch-host> --query "SELECT ... FROM ssdf.events ..."`
- Infra runs on Proxmox LXC (no Docker): ClickHouse=ct104, Vector=ct102 on pve3.example.com.
- SRX onboarding applied via rust-junosmcp using onboarding/srx/stream-config.set.

### M2 (MCP query layer — ssdf-mcp-query)
- Unit tests: `cd services/mcp-query && uv run pytest -m "not integration"`
- Integration tests (live CH): `CH_HOST=<ip> CH_USER=ssdf_ro CH_PASSWORD=<pw> uv run pytest -m integration`
- Run locally: `uv run python -m ssdf_mcp_query.server`
- Deployed: streamable-HTTP MCP on its own Proxmox LXC (ct106, no Docker), bearer-token auth,
  reading ClickHouse ct104 as the read-only `ssdf_ro` user. As-built coords in gitignored
  `services/mcp-query/infra/ENV.local`.
- Add to an agent via `.mcp.json`: `{"type":"http","url":"http://<ip>:30032/mcp",
  "headers":{"Authorization":"Bearer <token>"}}`.

### M3 (PAN-OS ingest — Vector VRL/CSV → ClickHouse)
- Run Vector unit tests (on ct102 where Vector is installed, not dev host): `ssh root@ct102 "cd /etc/vector && vector test /path/to/vector.toml"` or push the toml and run `vector test infra/vector/vector.toml` remotely.
- Validate config locally (syntax only, no live sinks): `CH_HOST=127.0.0.1 vector validate --no-environment infra/vector/vector.toml`
- PAN-OS source: Vector ct102 listens UDP **port 515** (SRX uses 514; PAN-OS is separate source to avoid collision).
- Onboarding artifact: `onboarding/panos/log-forwarding.set` — apply to host `panosvm` (VMID 900) via panos-mcp. Preview first with `pan_config_diff`, then commit with `load_and_commit_pan_config`. SSDF never applies device config in its own data path.
- Sample query: `clickhouse-client --host <ch-host> --query "SELECT event_action, count() FROM ssdf.events WHERE event_provider='paloalto' GROUP BY event_action"`
- PAN-OS version pinned: **12.1.5**. Field positions in the `panos_ecs` VRL transform are tied to the PAN-OS 12.1 default CSV syslog format — re-validate the transform on any major PAN-OS upgrade before relying on parsed fields.

### M4 (topology graph — services/topo + topology MCP tools)
- Unit tests: `cd services/topo && uv run pytest -m "not integration"`
- Live integration: `cd services/topo && CH_HOST=<ip> CH_PASSWORD=<pw> JUNOS_MCP_URL=… JUNOS_MCP_TOKEN=… uv run pytest -m integration`
- One collection cycle: `cd services/topo && uv run python -m ssdf_topo.collect_all`
- One resolver pass: `cd services/topo && uv run python -m ssdf_topo.resolve_main`
- Deployed: collectors+resolver on Proxmox LXC **ct109** (`ssdf-topo`, 198.51.100.153, no
  Docker) on a 5-min systemd timer (`ssdf-topo.timer` → oneshot collect→resolve); writes CH
  ct104 as `ssdf_topo`. Topology MCP tools (`get_entity`, `locate`, `neighbors`, `find_path`,
  `enforcement_points`, `topology_snapshot`) live on the existing `ssdf-mcp-query` (ct106).
  As-built coords in gitignored `services/topo/infra/ENV.local`.

Future Rust/Python components will record their own commands here as they are scaffolded.

## Related external systems

- This operator already runs a live Junos MCP server (`rust-junosmcp`, see the global
  `~/.claude/CLAUDE.md`). It is a reference implementation for the Rust + MCP pattern this
  project follows, and a likely first product-control integration target.
