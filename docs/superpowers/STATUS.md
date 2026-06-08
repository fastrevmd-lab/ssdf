# SSDF — Build Status & Milestone Ledger

**Last updated:** 2026-06-08
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
| **M4** | Dynamic topology/connectivity graph: collectors (junos/unifi/panos/proxmox) → `ssdf.topo_observations`; resolver fuses with L3 flow rollups into `ssdf.graph_nodes`/`graph_edges` (MAC-anchored identity); 6 read-only topology MCP tools | ✅ Done | `services/topo/`, `infra/clickhouse/002_topology.sql`; topo tools in `services/mcp-query/`; LXC ct109 (.153, 5-min timer) + tools on ct106 | PR #4; first cycle 197 obs → 209 nodes / 205 edges |
| **M5** | PAN-OS firewall logs → Vector (VRL/CSV) → ClickHouse `ssdf.events` (2nd vendor; `event_provider=paloalto`, vendor extras under `panw.panos.*`) | ✅ Done (Stage A+B live; real-wire validated) | `infra/vector/vector.toml` (`panos_ecs` transform), `onboarding/panos/`; live device panosvm (VMID 900, PAN-OS 12.1.5, 198.51.100.225); Vector ct102 UDP:515 (live); reads via M2 MCP ct106 | PR #3; 10 vector unit tests; real-wire validated: SYSTEM (9 subtypes) + CONFIG logs → `ssdf.events`; TRAFFIC via synthetic line → `query_flows(provider="paloalto")`; both vendors coexist |
| **M6a** | Semantic **entity/correlation layer**: deterministic Asset (MAC-anchored, IP-never-merges-alone) + observed Policy resolution from `ssdf.events` + M4 hosts → `ssdf.entities`/`ssdf.entity_edges` behind a swappable `EntityStore` seam; `explain_access(client, server)` MCP tool fuses observed flows + observed controls + M4 topology firewall attribution | ✅ Done (live-validated) | `services/entity/` (resolver), `infra/clickhouse/004_entities.sql`+`005_entity_user.sql`, `entitystore.py`/`access_tools.py` in `services/mcp-query/`; resolver on LXC ct109 (5-min timer, writes CH as `ssdf_entity`), `explain_access` tool on ct106 | 9+4+5+4 unit tests + live integration; first live cycle 6 entities / 4 edges; `explain_access` returns sessions>0, controls `source:observed`, `coverage.configured:pending_m6b` |
| **M6b** | **Configured-policy layer**: read each firewall's *configured* security ruleset (PAN-OS `get_pan_config` + vSRX `display set`) → `source='configured'` Policy entities keyed `provider:device:rule_name` (per-firewall identity, fixes M6a same-name collapse) + Firewall entities + `Firewall──GOVERNED_BY(configured)──►Policy` edges into shared `ssdf.entities`/`ssdf.entity_edges` (no schema change); `explain_access` gains `configured_controls` + integer `coverage.configured` | ✅ Done (deployed; configured-side live-proven) | `services/policy/` (collectors+resolver+writer), `entitystore.py`/`access_tools.py` in `services/mcp-query/`; collector+resolver on LXC ct109 (hourly `ssdf-policy.timer`, writes CH as `ssdf_entity`), updated `explain_access` on ct106 | 22 policy unit + 2 live integration; first live pass 8 entities / 6 edges (2 firewalls: panosvm=5 rules paloalto, vSRX-test10=1 rule juniper; 6 configured policies; 6 governed_by edges); `configured_policies_for_firewalls` returns all 6 live. **Live `explain_access` coverage.configured=0** — M4↔M6b bridge gap (issue #6; see below). PR #5 (merged) |

## Numbering reconciliation (the drift)

The simplified-design doc used a *different* milestone numbering than what got built. Canonical
= the as-built column.

| Simplified-design doc | As-built reality |
|---|---|
| M1 = SRX→Vector→ClickHouse | **M1** (same) ✅ |
| M2 = entity/resolver → Postgres-graph | *not built* — deferred (see forward roadmap) |
| M3 = PAN-OS + query seam | PAN-OS **built as M5** ✅; query seam = M2 |
| M4 = MCP read server + sovereignty | **M2** (MCP read server, pulled forward; sovereignty/scope-gating not yet built) ✅(partial) |

**Why the reorder:** the AI-native query surface (the product thesis) was prioritized over the
entity graph, consistent with the design's own open question — "when does ClickHouse-only stop
sufficing and the graph become load-bearing?" Answer so far: it still suffices.

## Forward roadmap (proposed, renumbered from as-built — adjust as we go)

- **M3 — retired placeholder slot.** Used transitionally during the M4 build; no standalone
  artifact. Canonical built milestones are M1, M2, M4, M5. Do not reuse the M3 number.
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
- **M6a — entity/correlation layer (Asset + observed Policy).** ✅ Built 2026-06-07. Deterministic
  resolution from `ssdf.events` flow-aggregates + M4 `graph_nodes` hosts into `ssdf.entities`/
  `ssdf.entity_edges` (`ReplacingMergeTree(last_seen)`, 30-day TTL), separate from M4's
  graph_nodes so M6c can relocate just the entity store to Postgres. Asset identity is
  MAC-anchored (IP-only assets are low-confidence 0.5 singletons, never merged on IP alone);
  Policy is keyed `(provider, rule_name)` and stamped `source:observed`. New `EntityStore`
  Protocol + `ClickHouseEntityStore` seam; one MCP tool `explain_access(client, server)` answers
  "show me end-to-end flow + security controls for this client→server" — fusing observed flows,
  observed controls, and M4 topology firewall attribution (firewall named only when topology
  yields exactly one; `firewall_basis:topology`). Honesty contract: `coverage.configured ==
  "pending_m6b"`. Resolver on LXC ct109 (5-min `ssdf-entity.timer`, writes CH as `ssdf_entity`).
  Spec: `specs/2026-06-07-ssdf-m6-entity-correlation-design.md`; plan:
  `plans/2026-06-07-ssdf-m6a-entity-correlation.md`.
  - **Known limitation — `first_seen` collapses to the current window.** Each resolver pass
    recomputes `first_seen` from the active window only, and `ReplacingMergeTree(last_seen)`
    keeps the latest row, so `first_seen` does not track the true earliest sighting across passes.
    This is the **same trade-off M4's topology resolver already makes**; accepted for M6a rather
    than deviating mid-build. Revisit if/when historical first-seen becomes load-bearing.
  - **Live-validation bug fixed:** the comm-edge window filter compared the `toString(last_seen)`
    SELECT alias (a String) instead of the real DateTime64 column, silently dropping every edge
    (lexical compare: space < 'T'). Fixed by qualifying `entity_edges.last_seen` in the WHERE.
- **M6b — configured policy.** ✅ Built 2026-06-08, merged to `main` via PR #5. Pull device-configured rules (not just observed)
  so `explain_access` exposes configured controls alongside observed traffic. New `services/policy/`
  service: per-vendor collectors (PAN-OS via `get_pan_config`, vSRX via `show configuration security
  policies | display set`) → normalized rule dicts → resolver emits `source='configured'` Policy
  entities keyed `provider:device:rule_name` (per-firewall identity — **fixes M6a's same-name
  collapse** where two firewalls' identically-named rules merged into one entity), Firewall entities
  keyed `device:<name>`, and `Firewall──GOVERNED_BY(configured)──►Policy` edges, written to the shared
  `ssdf.entities`/`ssdf.entity_edges` (no schema change, reuses the `ssdf_entity` CH user). `explain_
  access` (ct106) gains `configured_controls` + an integer `coverage.configured`. Deployed as ct109's
  **third** role (venv `/opt/ssdf-policy`, env `/etc/ssdf-policy/ENV.local` mode 600) on an HOURLY
  `ssdf-policy.timer` → oneshot `ssdf-policy.service`, installed without disturbing the two existing
  5-min M4/M6a timers. First live pass: 8 entities / 6 edges upserted (2 firewalls: panosvm=5 rules
  paloalto, vSRX-test10=1 rule juniper; 6 configured policies; 6 governed_by edges). Spec:
  `specs/2026-06-08-ssdf-m6b-configured-policy-design.md`; plan:
  `plans/2026-06-08-ssdf-m6b-configured-policy.md`.
  - **M4↔M6b name-bridge gap (live finding, blocks `coverage.configured>0`).** `explain_access`
    discovers a path's firewalls via M4 `enforcement_points`, which only returns graph nodes with
    `kind=="device"` AND `attrs.role=="firewall"`. M4 currently models **0** such nodes (confirmed by
    CH query), so live `explain_access` on real transit pairs returns `configured_basis:no_path_
    firewall` and `coverage.configured:0`. **The configured side is proven correct independently:** a
    direct `configured_policies_for_firewalls(["panosvm","vSRX-test10"])` returns all 6 policies. The
    gap is purely topology→firewall attribution; closing it requires M4 to emit firewall-role device
    nodes (tracked as the M6b→M4 dependency in **issue #6**). This was recorded honestly rather than fabricating M4
    nodes to make the number non-zero.
    - **Scope A closed by M6c (2026-06-08).** M4's junos/panos collectors now self-emit a
      `device_inventory(role=firewall)` observation per device, so `panosvm` and `vSRX-test10`
      resolve as `kind=device, attrs.role=firewall` in `ssdf.graph_nodes` (verified live on ct104).
      `enforcement_points` now returns them when they sit in a path's L1/L2 component. **Scope B**
      (host↔firewall L2/L3 connectivity so a real transit pair yields `coverage.configured>0`
      end-to-end) remains open under issue #6 / M6c.
- **M6c — firewall-node tagging (issue #6, scope A).** ✅ Built 2026-06-08. Closes the M6b→M4
  bridge gap's *node-tagging* half. New `firewall_inventory()` helper in `collectors/base.py`;
  junos + panos collectors each append one `device_inventory(role=firewall, name=<device>)`
  observation, merged by the resolver onto the same name-keyed device node. Also fixed a latent
  M4 collector bug surfaced when the collectors first ran live on ct109: `execute_junos_command`
  needs `router_name` (not `router`) and `execute_pan_op` needs `host` — both raised
  `missing_argument` and were silently skipped before. Added `JUNOS_DEVICES=vSRX-test10` to
  ct109's `/etc/ssdf-topo/ENV.local` (junos collector had never run live — list was empty).
  Live proof: collect cycle 197→223 obs, 204→218 nodes; CH query returns `panosvm` and
  `vSRX-test10` both `kind=device, role=firewall`. Spec:
  `specs/2026-06-08-m4-firewall-node-tagging-design.md`; plan:
  `plans/2026-06-08-m4-firewall-node-tagging.md`. **Scope B still open** under issue #6.
- **M6d — multi-hop L3 stitching + Postgres-as-graph.** Relocate the entity store off ClickHouse
  to Postgres-as-graph (Neo4j still deferred); stitch multi-hop paths. Deferred. (Renumbered from
  M6c, which is now the firewall-node tagging milestone above.)
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
(MCP query server + topology/`explain_access` tools), **ct109** (topo collectors+resolver **and**
the M6a entity resolver — two independent 5-min timers on the same host). Plus the cluster-wide
protected VMIDs in `~/.claude/CLAUDE.md`.
