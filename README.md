<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/mechub-mark.svg">
    <img src="docs/assets/mechub-mark-light.svg" width="72" alt="mechub mark">
  </picture>
</p>

<h1 align="center">ssdf</h1>

<p align="center"><strong>Sovereign Security Data Fabric — minimal, AI-native, MCP-driven</strong><br>
<em>a mechub project — sovereign network-security automation</em></p>

A minimal, AI-native security data platform built from scratch to power conversational / agent-based management of security products (NGFWs, SASE, IDaaS, XDR, etc.) through MCP tools driven by multiple LLMs.

Two principles shape every design decision:

- **AI-native, not AI-bolted-on.** The data model, APIs, and tooling exist so that LLM agents can query, correlate, and act on security data via MCP. Human UIs are secondary; the MCP tool surface is the primary product.
- **Sovereign.** All data and inference stay under the operator's control (self-hosted, no mandatory SaaS). Do not introduce hard dependencies on external/cloud SIEM/XDR platforms (e.g. Wazuh, Splunk, cloud-only LLM APIs). LLM and storage backends must be swappable, with self-hosted options as first-class citizens. "Minimal" is a hard constraint — prefer the smallest thing that works over feature-complete frameworks.

## Stack

- **Ingest = Vector (VRL transforms)** on LXC 700 `ssdf-log-ingest` — vendor syslog normalized to ECS-ish events at ingest. Vendor log formats live ONLY in `infra/vector/vector.toml`. See [Ingest sources](#ingest-sources) for the port map.
- **Storage = ClickHouse** on LXC ct104 — `ssdf.events` (events), `ssdf.entities`/`ssdf.entity_edges` (entity graph), topology observations, `ssdf.audit`. The swappable-backend seam is the Python store classes (graphstore/entitystore), not a Rust fabric.
- **Services + MCP layer = Python** (`services/*`, uv + FastMCP) — resolvers (topo/entity/policy on ct109 systemd timers) and the MCP tool surface (sovereign ct106 :30032, public ct113 :30033) behind an nginx TLS edge.
- **Rust is permitted, not doctrine** — use it where a future component is genuinely performance-critical; nothing in SSDF is Rust today. `rust-junosmcp` remains the external reference implementation, not part of this repo.
- Everything runs on Proxmox LXCs (no Docker) on pve3.example.com.

## Architecture

Data flows one direction; LLM agents are read-only consumers via MCP:

```
security products ──► Vector VRL (ct102) ──► ClickHouse (ct104) ──► MCP tools (ct106/ct113)
  SRX / PAN-OS syslog    normalize at ingest     events + entity        ▲
                                                 graph + audit          │
                          resolvers (ct109): topo/entity/policy   LLM agents (multi-LLM)
```

## Ingest sources

| Port | Proto | Source | Notes |
|---|---|---|---|
| 514 | UDP | SRX flow (`security log`) | high volume, individually disposable |
| 515 | UDP | PAN-OS | |
| 516 | UDP | UniFi | CEF |
| 517 | UDP | Proxmox host syslog | pve auth + admin actions via rsyslog |
| 518 | UDP | Junos system syslog | commits, rollbacks, logins — `system syslog host` |

All five are device telemetry over UDP: high volume, and losing an individual
record is tolerable.

### The MCP control-plane audit trail does not arrive here

Audit records from the `rust*mcp` servers — who asked an MCP server to change
what, which second principal approved it — do **not** come through Vector. They
are written directly into `ssdf.audit` as hash-chained rows, per
[`docs/audit-evidence-contract-v1.md`](docs/audit-evidence-contract-v1.md) and
[`docs/audit-evidence-ingestion.md`](docs/audit-evidence-ingestion.md).

That is deliberate. A syslog path was proposed and rejected: it is cheaper, but
syslog records are unchained, and the value of this trail is that tampering is
detectable. The producing side is tracked in
[mecmcp#292](https://github.com/fastrevmd-lab/mecmcp/issues/292).

`ssdf.audit` is therefore the single place to ask "who did what" — SSDF's own
MCP servers (`tier="sovereign"`) and the `rust*mcp` family alike. `ssdf.events`
is device telemetry only.

> **Note:** container references elsewhere in this README (`ct102`, `ct104`,
> `ct106`, `ct109`, `ct113`) predate the 2026-08-12 VMID renumber. The stack now
> lives at 700–711. Ingest is 700 `ssdf-log-ingest`; ClickHouse is reached at
> `198.51.100.151:8443`.

---

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/mechub-mark.svg">
    <img src="docs/assets/mechub-mark-light.svg" width="28" alt="">
  </picture><br>
  <sub><code>a mechub project</code> · deterministic decides · the model explains · a human approves<br>
  <a href="https://github.com/fastrevmd-lab">github.com/fastrevmd-lab</a></sub>
</p>
