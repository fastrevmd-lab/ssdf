# SSDF M4 — Topology / Connectivity Graph (design)

**Date:** 2026-06-07
**Status:** Approved design, pre-implementation.
**Supersedes for M4:** the "M4 = entity layer / Postgres-as-graph" line item in
`STATUS.md` and the 2026-06-06 simplified-design roadmap. The *principles* there still
hold (sovereign, read-only product boundary, AI-native, minimal); the as-built shape is
this document.

## 1. Purpose

M1–M3 made SSDF a queryable security **event** store (SRX + PAN-OS flows → `ssdf.events`
in ClickHouse, exposed by the read-only `ssdf-mcp-query` MCP service). M4 adds the
missing dimension: a **dynamic connectivity / topology graph** so an LLM agent or a human
can see *how the network is wired and how traffic actually flows*, and pinpoint **where a
problem lives or where a correction belongs**.

The graph fuses three things events alone can't express:
- **L2 topology** — LLDP device-to-device links, MAC-table host-to-port learning.
- **L3 binding** — ARP/ND IP↔MAC, the glue that joins L3 flows to L2 topology.
- **Flow connectivity** — who talked to whom, governed by which firewall rule/zone
  (already in `ssdf.events`).

M4 must *design* a provider-agnostic model that will generalize to endpoints, switches,
routers, firewalls, hypervisors, access points, remote-access VPNs (WireGuard), and cloud
IaaS (AWS). M4 *builds* collectors for every source with a live read-only MCP today —
UniFi, SRX (Junos), PAN-OS, Proxmox — to prove the model, exactly as M3 proved the event
schema generalized to a second vendor.

### Non-goals / boundary
- **Read-only product boundary holds.** Every collector uses `show`/GET operations only.
  M4 *identifies* the enforcement point for a fix; it never applies one. Acting on insight
  remains the job of the separate vendor MCPs (junos-mcp / panos-mcp / unifi-mcp), which
  may consume SSDF as read-only context.
- **No second always-on store.** ClickHouse stays the single system of record (the
  sovereignty/minimal choice). The graph is derived from CH and periodically remapped.
- WireGuard and AWS collectors are **out of scope for M4** — the taxonomy is designed to
  absorb them as later collectors with no new node/edge kinds.

## 2. Architecture & data flow

```
                deployed read-only MCPs (device-access layer)
   junos-mcp(.194)  unifi-mcp(ct603)  panos-mcp(.199)  proxmox-mcp(ct604)
        │                │                │                │
        └──────── Python collectors (MCP clients, pull/poll) ───────┘
                              │  normalize → observations
                              ▼
                   ClickHouse ssdf.topo_observations   (append-only, time-versioned)
                              +
                   ssdf.events (flows, already there)  ──┐
                              │                          │
                   periodic Python resolver/remap  ◄─────┘
                   (entity resolution + graph build)
                              │  upsert
                              ▼
                   ssdf.graph_nodes / ssdf.graph_edges  (ReplacingMergeTree)
                              │
                   topology MCP tools  (added to ssdf-mcp-query, ct106)
                   load subgraph → in-memory traverse (networkx)
                              ▲
                       LLM agents / humans
```

Three new moving parts, all Python, all on the existing fabric:

1. **Collectors** — one adapter per source. Each is an MCP *client* that calls read-only
   tools, normalizes the result, and `INSERT`s rows into `topo_observations`.
2. **Resolver / remap** — a scheduled, stateless job that reads recent observations + flow
   aggregates, resolves entities to canonical nodes, builds typed edges, and upserts the
   graph tables. Recomputes from a CH window each run → idempotent, crash-safe.
3. **Topology tools** — a new read-only tool group inside the existing `ssdf-mcp-query`
   service.

**Chosen representation (Approach A):** observations *and* the materialized graph live in
ClickHouse; multi-hop traversal loads the (small, lab-scale) subgraph into memory at query
time. Rationale: honors "derive from CH" + "minimal / single store"; inspectable via SQL;
the `GraphStore` seam keeps Postgres-as-graph / Neo4j as a future upgrade without touching
tool signatures. (Postgres-as-graph and an embedded store were considered and rejected for
adding a second store against the single-store choice.)

## 3. ClickHouse schema (3 new tables)

### `ssdf.topo_observations` — append-only raw facts
```sql
observed_at      DateTime64(3,'UTC')    -- when the collector saw it
collector        LowCardinality(String) -- 'junos'|'unifi'|'panos'|'proxmox'
source_device    String                 -- which device reported it (the observer)
tenant_id        LowCardinality(String) DEFAULT 't_main'
layer            LowCardinality(String) -- 'l2'|'l3'|'virt'|'flow'
observation_type LowCardinality(String) -- 'lldp_neighbor'|'mac_entry'|'arp_entry'|'iface_state'|'vm_nic'|'wlan_assoc'|...
subj_kind        LowCardinality(String)
subj_id          String                 -- natural identifier (mac/ip/chassis-id/vmid/...)
obj_kind         LowCardinality(String)
obj_id           String
attrs            Map(String,String)     -- vendor extras (port, vlan, speed, ttl, ...)
raw              String                 -- original tool output fragment, full fidelity
-- ENGINE MergeTree, PARTITION BY toYYYYMMDD(observed_at),
-- ORDER BY (tenant_id, collector, observed_at), TTL toDateTime(observed_at) + INTERVAL 30 DAY
```

### `ssdf.graph_nodes` — current resolved entities (upsert)
```sql
node_id      String                 -- deterministic canonical id (hash of strongest key)
tenant_id    LowCardinality(String)
kind         LowCardinality(String) -- device|host|interface|identity|segment|zone|rule
name         String                 -- best human label
identifiers  Map(String,String)     -- {mac:..., ip:..., chassis_id:..., vmid:..., hostname:...}
first_seen   DateTime64(3,'UTC')
last_seen    DateTime64(3,'UTC')
attrs        Map(String,String)
-- ENGINE ReplacingMergeTree(last_seen), ORDER BY (tenant_id, node_id)
```

### `ssdf.graph_edges` — current resolved relationships (upsert)
```sql
edge_id    String                 -- hash(src_id,dst_id,edge_type,layer)
tenant_id  LowCardinality(String)
src_id     String
dst_id     String
edge_type  LowCardinality(String) -- physical_link|attaches_to|has_address|member_of|routes_to|tunnel|hosts|talked_to|governed_by|in_zone|authenticated_as
layer      LowCardinality(String)
first_seen DateTime64(3,'UTC')
last_seen  DateTime64(3,'UTC')
confidence Float32                 -- 0..1, from corroborating observations
attrs      Map(String,String)     -- port, vlan, bytes, rule_name, allowed_ips, ...
-- ENGINE ReplacingMergeTree(last_seen), ORDER BY (tenant_id, edge_id)
```

`topo_observations` retains full history/provenance and TTLs like events. The two graph
tables hold only the *current best* projection; the resolver re-writes rows by stable id
and ReplacingMergeTree collapses duplicates on merge.

## 4. Node & edge taxonomy

Small fixed set of kinds; everything vendor-/domain-specific goes in `attrs`/`identifiers`
— the same discipline as the ECS-subset typed columns + `ext` map used for events.

### Node kinds (7)
| kind | what it is | canonical key precedence | example sources |
|---|---|---|---|
| `device` | managed net/compute element: switch, router, firewall, AP, hypervisor host, cloud gateway (`role` attr distinguishes) | chassis-id/serial → system-name → mgmt-ip | LLDP, inventory |
| `interface` | attachment point: phys port, SVI, vNIC, ENI, tunnel/WG iface | (device_id, ifname) → port-mac | LLDP port, iface_state, vm_nic |
| `host` | endpoint: workstation, server, VM, container, wireless/VPN client | MAC → (IP-at-time via ARP if no MAC) | mac_entry, arp_entry, wlan_assoc, vm_nic |
| `identity` | user/principal | provider + user.name | flow events, VPN auth |
| `segment` | L2/L3 domain: VLAN, subnet, VPC, WG overlay | (tenant, vlan-id/cidr/vpc-id) | mac vlan, arp subnet, cloud |
| `zone` | firewall security zone | (device_id, zone-name) | event observer zones |
| `rule` | firewall/security-group rule record (read-only) | (device_id, rule-name) | event `rule_name`, policy ingest |

### Edge types (11), each tagged with a layer
| edge_type | layer | src → dst | built from |
|---|---|---|---|
| `physical_link` | l2 | interface ↔ interface | lldp_neighbor |
| `attaches_to` | l2 | host/interface → device(:port,+vlan) | mac_entry, wlan_assoc, vm_nic |
| `has_address` | l3 | host/interface ↔ ip (+segment) | arp_entry |
| `member_of` | l3 | host/segment → segment | subnet/vlan/vpc membership |
| `routes_to` | l3 | segment/device → device (next-hop) | routing/default-gw |
| `tunnel` | l3 | interface ↔ interface (peers, allowed-ips) | WireGuard/IPsec (later) |
| `hosts` | virt | device(hypervisor) → host(VM) | Proxmox inventory |
| `talked_to` | flow | host → host | `ssdf.events` flow aggregates |
| `governed_by` | flow | talked_to-edge → rule | event `rule_name` |
| `in_zone` | flow | host → zone | event observer zones |
| `authenticated_as` | flow | identity → host/session | event `user.name`, VPN auth |

### Layer fusion (the chain the "where's the fix" goal needs)
```
host(MAC) --attaches_to--> device(switch):port,vlan --physical_link--> device(firewall)
   │                                                                      ▲
   has_address                                                            │
   ▼                                                                governed_by
  ip ──(same host, via ARP join)── talked_to ──► host(ip2) ── in_zone ──► zone ── on ── rule
```
"Host A reached host B" resolves to: A attaches to switch S port 3 (VLAN 10); S links to
firewall F; the flow is governed by rule R in zone Z on F → the enforcement point is
**F / rule R**.

### Extensibility (not built in M4)
WireGuard = `tunnel` edges + a WG-overlay `segment`. AWS = `device(role=cloud-gw)`,
`segment(vpc/subnet)`, `interface(eni)`, reusing the same edges. No new kinds — future
collectors only emit observations that map into this taxonomy.

## 5. Collectors (4 sources)

Each collector implements a common `Collector` protocol (`collect() -> list[Observation]`),
is an MCP client to one deployed read-only server, and emits only `topo_observations` rows.
All operations are `show`/GET — read-only.

**`junos`** (rust-junosmcp `.194:30031`, `execute_junos_command` with `| display json`):
- `show lldp neighbors` → `lldp_neighbor` (physical_link)
- `show ethernet-switching table` → `mac_entry` (attaches_to: mac→port,vlan)
- `show arp` → `arp_entry` (has_address: ip↔mac)
- `show interfaces terse` / `show lldp local-information` → `iface_state`, device self-identity

**`unifi`** (unifi-mcp ct603, structured JSON tools):
- `list_devices_by_type` / `get_device_details` → `device` inventory (role: switch/AP/gateway)
- `get_network_topology` / `get_device_connections` → `lldp_neighbor`/uplink (physical_link)
- `list_active_clients` → `mac_entry` + `arp_entry` + `wlan_assoc` (client MAC ↔ port/AP, VLAN, IP)
- `list_vlans` → `segment`

**`panos`** (panos-mcp `.199`, `execute_pan_op` returning XML):
- `<show><lldp><neighbors>` → `lldp_neighbor`
- `show arp all` → `arp_entry`
- `show mac all` (L2/vwire) → `mac_entry`
- `show interface all` → `iface_state` + device self-identity
  (zones/rules already arrive via `ssdf.events`)

**`proxmox`** (proxmox-mcp ct604, structured API):
- `get_nodes` → `device(role=hypervisor)`
- `get_vms` + `get_vm_config` → `host(VM)` + `hosts` edge to node; per `netN` the vNIC MAC +
  bridge + VLAN tag → `vm_nic` (attaches_to `vmbrX`)
- `get_containers` + `get_container_config`/`get_container_ip` → `host` + `has_address`

**Scheduling & idempotency:** a single `collect-all` entrypoint runs each enabled collector
once and bulk-inserts observations; a systemd **timer** fires it on an interval (default
5 min, per-collector configurable), then triggers the resolver. Re-runs are safe —
observations are append-only with `observed_at`.

**Known risk:** MCP tool outputs are LLM-oriented. Where a server returns raw CLI text, the
collector must parse defensively — mitigated by requesting JSON/XML (`| display json`,
PAN-OS XML) and pinning to asserted fields. Each collector ships a recorded-fixture test of
real tool output.

## 6. Resolver / identity resolution

Stateless Python job; recomputes the current projection from a CH window each run
(idempotent, crash-safe).

**Run lifecycle:**
1. Read `topo_observations` over a window (default 24h, configurable) + flow aggregates from
   `ssdf.events` (grouped `talked_to`: summed bytes, ports, `rule_name`, zones, user).
2. Resolve entities → canonical `node_id`s.
3. Build typed edges between resolved nodes.
4. Compute `first_seen`/`last_seen`/`confidence`.
5. Bulk-upsert `graph_nodes` + `graph_edges`.

**Identity resolution — union-find over observed identifiers.** Each observation contributes
equivalence facts; identifiers that co-occur in a single deterministic observation are
unioned, and each connected component yields one canonical node.
- `arp_entry` → `ip@segment ≡ mac` (time-bounded)
- `mac_entry` / `wlan_assoc` / `vm_nic` → confirm the MAC is a host and pin its attach point
  (do **not** union the switch with the host)
- `lldp_neighbor` → `chassis_id ≡ device`; links two devices (no host union)

**Canonical-key precedence** within a component: `device`: chassis-id/serial → system-name
→ mgmt-ip; `host`: MAC → (IP only if no MAC); `identity`: provider+user.name; `segment`:
vlan-id/cidr/vpc-id.

**IP is never an identity by itself** — it is a time-bounded `has_address` of a MAC/host
(NAT, DHCP reuse). An IP with no ARP-resolvable MAC becomes a `host` keyed on `ip@segment`
with `attrs.unresolved=l3_only`, so flow-only assets still appear, honestly labeled.

**Conflicts across time** (same IP → different MAC at different times) are **not merged** —
they produce separate time-bounded `has_address` edges, preserving history.

**Confidence & staleness:** `confidence` rises with corroboration (e.g. a `physical_link`
seen from both LLDP ends = 1.0; one end only = 0.7). `last_seen` drives staleness; tools can
filter `last_seen >= now()-Xh`. Resolver compares in UTC and stamps `observed_at` at
collection time, sidestepping source-clock drift (the known M1/M3 TZ skew).

**Auditability / reversibility:** every node/edge carries `attrs.evidence` = the
`observation_type`s + `source_device`s that justified it. Because `topo_observations` is
retained, any merge is explainable and the entire graph is reproducible by re-running the
resolver. No destructive state.

## 7. MCP query surface

New read-only topology tool group added to the existing `ssdf-mcp-query` service (same
ct106 endpoint, bearer auth, `ssdf_ro` reader). Each tool loads the relevant subgraph from
`graph_nodes`/`graph_edges` and traverses in-memory (networkx); returns structured dicts in
the established result shape.

| tool | args | returns | purpose |
|---|---|---|---|
| `get_entity` | `identifier` (ip/mac/hostname/name), `tenant?` | canonical node + `identifiers` + `attrs` + first/last seen | "what is X" from any alias |
| `locate` | `ip` \| `mac` \| `host` | attach point: switch/AP + port + VLAN, hypervisor (if VM), segment, zone, last_seen | "where does this attach" |
| `neighbors` | `entity`, `layer?`, `depth=1`, `since?` | adjacent nodes + edges (layer/staleness filtered) | few-hop exploration |
| `find_path` | `src`, `dst`, `layer?` (physical\|flow\|any) | ordered path(s) of nodes+edges | "how does A reach B" |
| `enforcement_points` | `src`, `dst` | firewall device(s) + zone(s) + `rule`(s) on the path, with governing evidence | read-only "where would a fix go" |
| `topology_snapshot` | `scope?` (device/segment/zone), `layer?`, `since?` | bounded nodes+edges subgraph | LLM/visualization context |

Notes:
- **Staleness-aware by default** — traversal tools default to `last_seen >= now()-24h`;
  callers widen explicitly.
- **`enforcement_points` is observational** — identifies the device/zone/rule governing a
  path; applying any change is out of scope.
- **Bounded outputs** — `topology_snapshot`/`neighbors` cap node/edge counts (like the
  existing `MAX_LIMIT`) and report `truncated`.
- **Seam preserved** — tools call a `GraphStore` interface (CH-backed impl now); a future
  Postgres/Neo4j impl won't change tool signatures.

## 8. Deployment, security, testing

**Deployment (Proxmox LXC, no Docker — consistent with M1–M3):**
- New service `services/topo` (Python, `uv`): collectors + resolver + a `collect-all`
  entrypoint.
- Runs on a new LXC **ct107 `ssdf-topo`** (keeps ct106's read MCP cleanly read-only and
  separates the write-path workload). Reaches the 4 MCP servers over the lab network and CH
  on ct104.
- **systemd timer** fires `collect-all` then `resolve` on an interval (default 5 min). One-
  shot, idempotent — no always-on daemon.
- Topology MCP tools are added to the existing `ssdf-mcp-query` on ct106 (no new endpoint).
- As-built coordinates in a gitignored `services/topo/infra/ENV.local` (mirrors M2).

**Security / least privilege:**
- New CH user **`ssdf_topo`** with INSERT + SELECT on the topo + events tables, used only by
  ct107. `ssdf_ro` (the MCP reader) is unchanged and read-only.
- Collectors hold read-only MCP bearer tokens and call only `show`/GET tools. No write/
  management capability anywhere in M4 — the read-only boundary holds by construction.
- Per-source enable flags + creds in `ENV.local`; a failing collector (device down, auth) is
  logged and skipped, never aborting the run.

**Testing:**
- **Unit (`-m "not integration"`):** resolver rules (union-find, IP-not-identity, conflict
  preservation, key precedence), edge/confidence construction, each collector's parser
  against a recorded real-output fixture.
- **Integration (`-m integration`, live):** `collect-all` against the real MCPs writes
  observations; resolver builds a graph; topology tools return the expected fused chain
  (host → switch-port → firewall → rule).
- **Acceptance / exit criteria:** a real endpoint resolves to one canonical node carrying
  MAC+IP+hostname; `locate` returns its switch/port/VLAN; `find_path` returns the physical
  path to the firewall; `enforcement_points` names the governing zone+rule; devices from
  both vendors appear in one graph.

**Commands (to be added to CLAUDE.md):**
```
cd services/topo && uv run pytest -m "not integration"   # unit
CH_HOST=… uv run pytest -m integration                   # live
uv run python -m ssdf_topo.collect_all                   # one collection cycle
uv run python -m ssdf_topo.resolve                       # one resolver pass
```

## 9. Cross-cutting seams (kept clean)

- **Storage seam:** all CH access stays behind the `GraphStore` interface + the resolver's
  CH client. Swapping the graph backend must not touch tools or collectors.
- **Collector seam:** the `Collector` protocol isolates per-source quirks; adding WireGuard /
  AWS / Okta later means a new collector, not schema or taxonomy changes.
- **Normalization at ingest:** collectors normalize to the fixed node/edge taxonomy; vendor
  extras go in `attrs`, never new core columns.
- **Read-only boundary:** no write/management tools or device ops anywhere in M4.
