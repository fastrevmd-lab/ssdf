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

No build, lint, test, or run commands exist yet — there is no code. **When you scaffold a
component, add its real commands here**, per language:

- Rust services: standard `cargo build` / `cargo test` / `cargo run -p <crate>` (record the
  actual crate/workspace layout once it exists, including how to run a single test:
  `cargo test <name>`).
- Python services: record the chosen tooling (e.g. `uv` / `poetry`), how to run the MCP
  server(s), and how to run a single test (e.g. `pytest path::test_name`).

Until then, do not invent commands.

## Related external systems

- This operator already runs a live Junos MCP server (`rust-junosmcp`, see the global
  `~/.claude/CLAUDE.md`). It is a reference implementation for the Rust + MCP pattern this
  project follows, and a likely first product-control integration target.
