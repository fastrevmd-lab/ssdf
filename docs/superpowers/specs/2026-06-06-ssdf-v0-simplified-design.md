# SSDF — Simplified v0 Design (ECS / push-syslog / phased)

- **Date:** 2026-06-06
- **Status:** Approved design (pre-implementation)
- **Authors:** mharman + Claude
- **Supersedes (for v0):** `2026-06-05-ssdf-data-fabric-design.md`. That document's long-term
  vision (sovereignty model, read-only boundary, eventual entity graph, service/MCP surface)
  still stands. This document **replaces its v0/v0.1 build** with a smaller, phased footprint
  and a different normalization + source strategy. The 7 plans under
  `docs/superpowers/plans/2026-06-05-ssdf-*.md` are **superseded** and will be regenerated.

---

## 1. Why this revision

The original v0/v0.1 stood up too much at once for a greenfield "minimal" project: a custom
ontology, dual store (ClickHouse + Neo4j), Redpanda, MinIO, Vector, gRPC service mesh + API
gateway, multiple MCP servers, multiple connectors, entity resolution, sovereignty, and audit
— before anything worked end-to-end. Two operator decisions reshape it:

1. **Adopt an existing normalization standard — Elastic Common Schema (ECS)** — instead of
   inventing a custom ontology. Every chosen source already has a published ECS field mapping
   we can reuse as reference (Elastic `juniper_srx`, `panw`, `suricata`, `system` modules).
2. **Build in thin phases behind seams.** Each component returns only when a concrete need
   pulls it in, behind an interface — never speculatively.

## 2. Principles (unchanged)

- **Sovereign** — all data + inference stay on-prem; storage/LLM backends swappable; no
  public-cloud-only critical path.
- **Read-only product boundary** — SSDF stores/queries/correlates security data. It **never**
  manages, configures, or writes back to any security product. Acting on insights is a
  separate project (vendor MCP servers).
- **AI-native** — the eventual MCP tool surface is the product; schemas/outputs shaped for LLMs.
- **Minimal** — smallest thing that works; defer everything not needed for the current milestone.

## 3. Decisions changed from the prior spec

| Topic | Prior spec | This spec |
|---|---|---|
| **Normalization** | Custom 8-entity / 5-event ontology | **ECS subset** + vendor extras under namespaces (`juniper.srx.*`, `panw.panos.*`, …). Reuse Elastic mappings. |
| **Sources** | SRX, Okta, Wazuh, PAN-OS | **Junos/SRX, PAN-OS, UniFi, Proxmox** — products with real devices + working MCP servers. (Okta/Wazuh deferred; same connector pattern later.) |
| **Vendor MCP role** | Onboarding hand-off | Unchanged in principle: **MCP = onboarding/config of the device to push telemetry**, never the ingest path. SSDF emits device config; the vendor MCP (`rust-junosmcp`, `panos-mcp`, `unifi-mcp`) applies it. |
| **Ingest** | syslog→Vector→Redpanda→Rust normalizer | **syslog → Vector (parse + ECS-normalize via VRL) → store.** Redpanda + custom Rust normalizer deferred. |
| **Store** | ClickHouse + Neo4j dual, day one | **ClickHouse only** for v0 events. Postgres-as-graph and Neo4j deferred behind a `GraphStore` seam. |
| **Services** | 5 gRPC services + API gateway | Deferred. Add a query/service seam at M3; gRPC only when a second consumer exists. |
| **MCP servers** | 2–3 servers in v0.1 | One read MCP server first (M4), split local/frontier when frontier access is wired. |
| **Deployment** | Docker Compose | **Proxmox LXC/VMs.** No Docker. |
| **Language** | Rust + Python day one | **Rust-only until needed.** Python enters with the MCP layer / API-poller connectors. |
| **MinIO cold tier** | listed in v0 | Deferred (v0.2+). |

## 4. Milestone 1 (the only committed build right now)

**Approach A — "Vector does the heavy lifting." Source: Junos/SRX.**

**Scope / done:** a single pipe — SRX security logs → Vector (parse + ECS normalize) →
ClickHouse → answerable via SQL. **Done =** time-ranged/filtered flow queries (e.g. "denied
flows from host X in the last hour") return real vSRX data.

### Pipeline
1. **SRX** emits security logs in **stream mode**, format **`sd-syslog`** (RFC5424 structured,
   key=value) to the Vector collector. RT_FLOW `SESSION_CREATE` / `SESSION_CLOSE` / `SESSION_DENY`.
2. **Vector** (LXC): `syslog` source → **VRL** transform parsing RT_FLOW into an **ECS subset**,
   with Juniper-specific fields under `juniper.srx.*`. Field map cribbed from Elastic's
   `juniper_srx` integration. (Elastic SRX integration expects `structured-data brief`.)
3. **ClickHouse** sink (LXC): one `events` table — ECS core fields as **typed columns** (fast
   queries) + a `raw` column (full-fidelity message) + an `ext` map (vendor extras). Partitioned
   by day. Exact DDL is a plan detail.

### ECS event shape (the contract)
Core columns (ECS names): `@timestamp`, `event.kind/category/action/outcome`,
`source.ip/port/bytes`, `destination.ip/port/bytes`, `network.transport/bytes`, `rule.name`,
`observer.ingress.zone` / `observer.egress.zone`, `user.name`, `event.provider=juniper`, plus
`tenant_id`, `event.id`. Design commitment: *ECS-subset typed columns + raw + ext*. Versioned
from day one.

### SRX onboarding (via `rust-junosmcp`)
Device config SSDF requires (small, well-defined; may be applied manually first to de-risk,
then driven through the MCP):
```
set security log mode stream
set security log source-address <srx-src-ip>
set security log stream SSDF format sd-syslog
set security log stream SSDF category all
set security log stream SSDF host <vector-lxc-ip> port 514
```

### Deployment
Proxmox **LXC**, no Docker. One LXC for Vector, one for ClickHouse (co-located acceptable for
M1). Source = existing **vSRX lab devices**. Repo stays a git project, but M1 is mostly **Vector
config + VRL + ClickHouse DDL + the SRX onboarding snippet** — little/no Rust yet.

### Gotchas (from research)
- SRX stream-mode source IP is a data-plane interface (set `source-address`); collector ACLs +
  asset correlation must expect that, not fxp0.
- Format gotcha to verify during impl: we use stream-mode `sd-syslog`; Elastic's SRX pipeline
  examples often assume event-mode system syslog with `structured-data brief`. Confirm the VRL
  parser matches the actual stream-mode `sd-syslog` wire format before relying on the Elastic map.
- BSD syslog timestamps lack TZ/year — inject `event.timezone` in VRL.

## 5. Roadmap after M1 (each phase adds one seam)

> Roadmap note (2026-06-07): M2 was implemented as the MCP query layer first, because exposing
> the existing ClickHouse event store to agents was the smallest AI-native step after M1. The
> entity/graph ambitions remain, but return only where a concrete operator question pulls them in.

- **M2 — MCP read query layer.** One read-only FastMCP server over ClickHouse with guarded SQL,
  `query_flows`, `top_talkers`, and schema introspection. This is the first agent-facing SSDF API.
- **M3 — completed current milestone.** Do not reuse this number for new design work; M4+ is
  the forward roadmap.
- **M4 — dynamic connectivity graph.** Build an **observed connectivity graph** from existing
  flow events as ClickHouse rollup edges first, then expose MCP tools for connectivity, rule
  usage, trends, new paths, and evidence-backed explanations. Spec:
  `docs/superpowers/specs/2026-06-07-ssdf-m4-dynamic-connectivity-graph-design.md`.
- **M5 — second NGFW source.** Add **PAN-OS** (Elastic `panw` map; Log Forwarding Profile via
  `panos-mcp`) and prove the M4 edge model works across Junos/SRX + PAN-OS.
- **M6 — entity layer / GraphStore seam.** Add deterministic Asset/Identity/Application/Policy
  resolution and a swappable `GraphStore` projection. Start with Postgres-as-graph adjacency
  tables; defer Neo4j until path traversal becomes load-bearing.
- **M7 — sovereignty split + audit hardening.** Split local/frontier MCP exposure when frontier
  egress is wired; add policy-gated redaction and stronger audit.
- **Later sources:** UniFi (CEF ≥ fw 9.3.43 + Suricata EVE for IPS; SIEM-server setting via
  `unifi-mcp`; plus an API-poller for DPI/client stats) and Proxmox (rsyslog host logs + PVE
  API poller for tasks/inventory — pull, not push).

## 6. Parked components (return only on concrete need, behind a seam)

Redpanda (bus) · custom Rust Normalizer service · Neo4j · gRPC service mesh + API gateway ·
second/third MCP servers · MinIO cold tier · Okta/Wazuh connectors · high-throughput syslog
tuning · hash-chained audit · full configured-reachability simulation · firewall change workflow.

## 7. Open questions / future

- When does ClickHouse rollup-as-graph stop sufficing and a dedicated GraphStore become
  load-bearing?
- How should configured connectivity from firewall config snapshots be represented separately
  from observed telemetry so SSDF does not overclaim reachability?
- ECS version pin + how vendor extras (`*.ext`) evolve without breaking the typed columns.
- API-poller connector shape for pull-only data (Proxmox tasks/inventory, UniFi DPI) — Rust or
  Python.
