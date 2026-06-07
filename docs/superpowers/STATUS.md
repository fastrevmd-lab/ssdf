# SSDF — Build Status & Milestone Ledger

**Last updated:** 2026-06-07
**Purpose:** Single source of truth for *what is actually built* vs. what the design docs
planned. Read this first; the dated specs/plans are historical and have drifted from reality.

---

## Authoritative design

`docs/superpowers/specs/2026-06-06-ssdf-v0-simplified-design.md` is the current design of
record. It **supersedes** the original `2026-06-05-ssdf-data-fabric-design.md` and the seven
`2026-06-05-ssdf-*.md` plans (custom ontology, Redpanda, Neo4j, gRPC mesh, docker-compose) —
those are **historical only, do not execute them.**

The long-term *principles* from the 2026-06-05 design still hold: sovereign, read-only product
boundary, AI-native, minimal.

## As-built milestones (canonical numbering)

| Milestone | What | Status | Where | Proof |
|---|---|---|---|---|
| **M1** | SRX security logs → Vector (VRL/ECS-subset) → ClickHouse `ssdf.events`, SQL-queryable | ✅ Done | `infra/vector/`, `infra/clickhouse/`, `onboarding/srx/`; LXC ct102 (Vector, .150) + ct104 (ClickHouse, .151) | PR #1; real vSRX-test10 data |
| **M2** | Read-only **MCP query layer** over `ssdf.events` (Python/FastMCP): `query_flows`, `describe_schema`, `top_talkers`, guarded `run_sql` | ✅ Done | `services/mcp-query/`; LXC ct106 (.152:30032), reads CH as read-only `ssdf_ro` | PR #2; 47 unit + 5 live integration tests; bearer-auth enforced |
| **M3** | PAN-OS firewall logs → Vector (VRL/CSV) → ClickHouse `ssdf.events` (2nd vendor; `event_provider=paloalto`, vendor extras under `panw.panos.*`) | ✅ Done (Stage A+B live; real-wire validated) | `infra/vector/vector.toml` (`panos_ecs` transform), `onboarding/panos/`; live device panosvm (VMID 900, PAN-OS 12.1.5, 198.51.100.225); Vector ct102 UDP:515 (live); reads via M2 MCP ct106 | 10 vector unit tests; real-wire validated: SYSTEM (9 subtypes) + CONFIG logs → `ssdf.events`; TRAFFIC via synthetic line → `query_flows(provider="paloalto")`; both vendors coexist |

## Numbering reconciliation (the drift)

The simplified-design doc used a *different* milestone numbering than what got built. Canonical
= the as-built column.

| Simplified-design doc | As-built reality |
|---|---|
| M1 = SRX→Vector→ClickHouse | **M1** (same) ✅ |
| M2 = entity/resolver → Postgres-graph | *not built* — deferred (see forward roadmap) |
| M3 = PAN-OS + query seam | *not built* — PAN-OS deferred |
| M4 = MCP read server + sovereignty | **M2** (MCP read server, pulled forward; sovereignty/scope-gating not yet built) ✅(partial) |

**Why the reorder:** the AI-native query surface (the product thesis) was prioritized over the
entity graph, consistent with the design's own open question — "when does ClickHouse-only stop
sufficing and the graph become load-bearing?" Answer so far: it still suffices.

## Forward roadmap (proposed, renumbered from as-built — adjust as we go)

- **M3 — completed current milestone.** Do not assign new design work to M3.
- **M4 — dynamic connectivity / topology graph.** ✅ Built 2026-06-07. Collectors (junos,
  unifi, panos, proxmox) reuse the deployed read-only MCPs to gather LLDP/MAC/ARP/interface +
  VM-NIC facts into `ssdf.topo_observations`; a resolver fuses them with L3 flow rollups into
  `ssdf.graph_nodes`/`graph_edges` (MAC-anchored identity, IP-never-identity-alone). Six
  read-only topology tools added to `ssdf-mcp-query`. Deployed on LXC **ct109** (`ssdf-topo`,
  .153, 5-min timer); graph tools on ct106. First live cycle: 197 observations → 209 nodes /
  205 edges. Spec: `specs/2026-06-07-ssdf-m4-topology-graph-design.md`; plan:
  `plans/2026-06-07-ssdf-m4-topology-graph*.md`. (Supersedes the earlier proposed M4 —
  `connectivity_edges_hourly` rollups; the shipped M4 is the richer topology-graph design.
  Note: plan reserved ct107, but VMID 107 was occupied by an unrelated VM, so ct109 was used.)
- **M5 — second source: PAN-OS.** ✅ Done. VRL/CSV parser (`panos_ecs`) + 10 unit tests; live
  Vector config on ct102 listening UDP:515. **Stage A onboarding live on panosvm** (VMID 900,
  PAN-OS 12.1.5, 198.51.100.225): syslog server profile `SSDF` → 198.51.100.150:515 BSD, log-
  forwarding profile `SSDF-LF` (applied via XML), attached `log-setting SSDF-LF` to all 5 security
  rules (via XML — the panos-mcp set-CLI mangles quoted `filter "All Logs"`). Pipeline validated
  end-to-end: a PAN-OS 12.1 TRAFFIC CSV line → ct102:515 → `ssdf.events` with `event_provider=
  paloalto`, IPv4 src/dst, ports, bytes, `rule_name`, `panw.panos.*` extras; returned by the M2
  MCP `query_flows(provider="paloalto")`; both vendors coexist (`juniper:13, paloalto:1`). Proves
  the ECS-subset schema generalizes to a 2nd vendor.
  - **Stage B device-plane log-settings (system + config) — applied & validated 2026-06-07.**
    `shared log-settings system|config` match-lists → SSDF syslog profile, committed live. Gave
    **real-wire validation** without transit traffic: the firewall's own SYSTEM logs (9 subtypes:
    general/vpn/routing/ras/sslmgr/satd/auth/url-filtering/device-telemetry) and CONFIG set/commit
    logs land in `ssdf.events` with correct typed columns — CONFIG `user_name`/`command`/`client`/
    `result` map exactly as the unit tests asserted (admin idx 10, command idx 9). correlation/
    globalprotect/hipmatch intentionally not applied (those features aren't configured → no logs).
  - **The earlier "Unauthorized request" was NOT an auth defect.** Root cause: pan-os-python's
    `xapi.set` does not prepend `/config/`, so a relative xpath (`shared/log-settings`) is rejected
    by PAN-OS as "Unauthorized request". Fix = pass **absolute `/config/...` xpaths** to
    `load_and_commit_pan_config` (fmt=xml). The `mcp-api` admin is superuser; no credential change
    was needed.
  - **Remaining carve-out:** panosvm still has **no transit traffic** (empty session table), so
    real-wire **TRAFFIC** validation used a synthetic-but-positionally-exact line; it self-confirms
    the first time traffic hits a logged rule (PAN-OS transit-only-logging trap, same as SRX).
  - **Observation (pre-existing M1 concern, not M5):** PAN-OS stamps receive-time in local EDT
    (`-04:00`); ingest stores it without TZ conversion, so event `timestamp` sits ~4h behind
    ClickHouse `now()` (UTC). Affects relative-time `WHERE` filters across all sources.
- **M6 — entity/correlation layer.** Deterministic Asset/Identity resolution from ECS events
  behind a `GraphStore` seam (Postgres-as-graph first, Neo4j deferred). Build when
  ClickHouse-only correlation stops sufficing.
- **M7 — sovereignty + MCP split.** Scope-gating, sovereignty policy + audit on the read MCP;
  split local/frontier MCP when frontier egress is wired.
- **Later sources:** UniFi (CEF + Suricata EVE via `unifi-mcp`), Proxmox (rsyslog + PVE API
  poller), Okta/Wazuh (same connector pattern).

## Cross-cutting seams (kept clean, watch when extending)

- **Storage seam:** all ClickHouse access stays in `services/mcp-query/.../clickhouse.py` and
  the M1 Vector sink. Swapping storage shouldn't touch tools/builders.
- **Normalization:** ECS-subset typed columns + `raw` + `ext` map; versioned. New vendors add
  fields under namespaces (`juniper.srx.*`, `panw.panos.*`), not new core columns, where possible.
- **Read-only boundary:** no write/management tools in SSDF. Acting on insights = separate
  vendor-MCP project.

## Protected lab infra (do not reclaim)

SSDF LXCs on Proxmox pve3.example.com: **ct102** (Vector), **ct104** (ClickHouse), **ct106**
(MCP query server), **ct109** (topo collectors+resolver). Plus the cluster-wide protected
VMIDs in `~/.claude/CLAUDE.md`.
