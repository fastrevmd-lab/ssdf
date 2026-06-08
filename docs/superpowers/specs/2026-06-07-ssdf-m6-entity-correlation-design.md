# SSDF — M6 Entity / Correlation Layer (design)

- **Date:** 2026-06-07
- **Status:** Approved design (pre-implementation)
- **Authors:** mharman + Claude
- **Milestone:** M6 (entity layer / GraphStore seam) per
  `docs/superpowers/specs/2026-06-06-ssdf-v0-simplified-design.md` §5 and `docs/superpowers/STATUS.md`.
- **Build scope of this spec:** the **full M6 architecture** is described here; **only M6a is
  implemented first** (see §8 Phasing). M6b/M6c are documented so the model is built right from
  day one, but their code lands in later plans.

---

## 1. Why this milestone, and what it answers

The operator question driving M6:

> **"Show me the end-to-end flow and security controls for this client → server."**

Today this can't be answered cleanly. M1/M2 give SQL over raw flow events; M4 gives an
infrastructure topology graph (`find_path`, `enforcement_points`) but requires you to know the
raw IP/MAC and does not resolve a human-named client/server or dedupe controls across vendors.
Neither resolves the *semantic security entities* an analyst reasons about (the Asset behind many
IPs/MACs, the Policy behind a rule name seen on two firewalls).

M6 adds a **semantic entity layer** on top of M4 + `ssdf.events`: deterministic resolution of the
things events are *about*, deduped across vendors, behind a **swappable store seam**. It directly
addresses the design's open questions — "when does ClickHouse-as-graph stop sufficing?" (answered
empirically, only introducing Postgres in M6c if traversal needs it) and "how to represent
configured vs observed connectivity without overclaiming reachability?" (a first-class `source`
discriminator, §3).

## 2. Principles (unchanged, applied here)

- **Read-only.** M6 reads `ssdf.events` and M4's graph; it never writes to or manages any device.
  Configured-policy ingestion (M6b) reuses the **read-only** vendor MCP collector pattern M4
  already established — pulling config snapshots is telemetry, not management.
- **Sovereign / swappable.** The entity store sits behind an `EntityStore` seam; ClickHouse first,
  Postgres-as-graph deferred to M6c behind the same interface.
- **AI-native.** The deliverable is an MCP tool (`explain_access`) shaped for an agent, with an
  explicit honesty contract about what is observed vs configured.
- **Minimal / YAGNI.** Build one entity-driven use case, phased. Identity is a seam only until an
  IDaaS source exists; configured policy and L3 stitching are later phases.

## 3. Entity model

An **entity** is a stable, deduped thing that events/observations are *about*. M6 defines three
kinds; M6a builds Asset and observed Policy, and defines Identity as an empty seam.

### Asset
A client or server. Resolution determinism is carried forward verbatim from M4:

- **MAC anchors identity** — two observations sharing a MAC are one Asset (union-find fusion).
- **IP never merges two Assets on its own.** An IP seen for two different MACs over time stays two
  Assets.
- **IP-only Assets are legitimate.** A server seen only in flows (no MAC — M4's
  `unresolved=l3_only`) is a real Asset, represented as a low-confidence singleton with
  `identity_basis: ip_only`. IP→MAC is enriched from M4 host nodes when M4 already knows the
  binding (then `identity_basis: mac`).

Identifiers map carries `mac`, `ip`(s), `name` where known. `confidence` < 1.0 for ip_only.

### Policy
A firewall rule that governs traffic. Every Policy carries a **`source` discriminator**:

- **`observed`** (M6a) — resolved from `rule.name` present in actual flow events. **Keyed by
  `(provider, rule_name)`**, because `ssdf.events` carries no reliable per-firewall observer
  identity (only `event_provider`; SRX dumps SD fields into `ext` with no stable firewall key,
  PAN-OS does not extract device name/serial). *Firewall* attribution is therefore **not** part of
  the Policy entity — it is derived at tool time from the topology (M4 `enforcement_points`, which
  infers the firewall device(s) from the L2 connected component). Rules with the same name on
  different *vendors* are distinct Policy entities; same name across two firewalls of the *same*
  vendor collapse to one entity in M6a — a known limitation lifted in M6b/M6c when per-device
  identity (config snapshots / stitched path) is available.
- **`configured`** (M6b) — resolved from firewall policy snapshots. Reserved in the model from day
  one; populated later. A configured Policy represents a rule that *would* apply, independent of
  whether traffic ever hit it.

The discriminator exists from the start so configured rules can **never** masquerade as observed
reachability.

### Identity (seam only in M6a)
A user/principal. M6a defines the `identity` entity kind and an `authenticated_as`
Identity→Asset edge type, but populates nothing — current SRX/PAN-OS flows are too thin on
`user.name` and no IDaaS source is wired in. Populated when Okta/UniFi land (a later source).

### Edges (M6a)
- `Asset —communicated_with→ Asset` — observed traffic between two Assets, carrying flow stats in
  `attrs` (sessions, bytes, ports, transports, providers) for the resolution window.
- `(communicated_with edge) —governed_by→ Policy` — which observed rule on which firewall handled
  that traffic. Mirrors M4's `talked_to`/`governed_by` pattern at the resolved-entity level.

### Provenance
Every entity and edge records `source` (`observed` now; `configured` in M6b) and evidence (which
collectors/events backed it), so answers can state coverage honestly (§5).

## 4. Components, data flow, storage

### New service: `services/entity/`
Python, structured like `services/topo/` (the same in-memory-resolve → project-to-store pattern
proven in M4). M6a may run on the existing topo LXC **ct109** to avoid new infra; a dedicated LXC
is only considered if M6c needs it.

- **Event reader** — reads `ssdf.events` over a window via the M2 ClickHouse client seam
  (`services/mcp-query/src/ssdf_mcp_query/clickhouse.py`), read-only `ssdf_ro`-style user. Pulls
  flow rows: `source.ip/port`, `destination.ip/port`, bytes, `network.transport`, `rule.name`,
  `event.provider`, `observer.name` (firewall).
- **Topology reader** — reads M4 `graph_nodes` (host nodes) through the existing `GraphStore` to
  enrich IP→MAC bindings so flow endpoints inherit MAC identity when M4 already knows it.
- **Entity resolver** (`resolve_entities.py`) — deterministic pure function
  `resolve_entities(flow_aggregates, topo_hosts, tenant) -> (entities, edges)`. Asset identity is
  **keyed**: a flow endpoint's Asset key is its MAC when the topology (`graph_nodes` host) already
  binds that IP→MAC, else the IP itself. So two IPs sharing a MAC collapse to one Asset (MAC
  anchors identity) while distinct IPs never merge (no merge on IP alone) — keying alone achieves
  this; no union-find is needed in M6a (multi-token fusion, e.g. by hostname, is deferred). All
  observed IPs of a MAC-keyed Asset are kept in `identifiers` (`ip`, `ip2`, …) so lookup by any of
  them works via `has(mapValues(identifiers), …)`. One observed Policy per `(provider, rule_name)`;
  `communicated_with` + `governed_by` edges with flow stats.
- **Projector** — writes resolved entities/edges to the entity store via the `EntityStore` seam.
- **Tool surface** — `explain_access` added to the existing `ssdf-mcp-query` server (ct106), bound
  to the entity store (§5).

### Storage — the swappable seam (key decision)
The entity layer gets its **own tables**, distinct from M4's `graph_nodes`/`graph_edges`:

```sql
CREATE TABLE ssdf.entities (
    entity_id      String,
    tenant_id      String,
    kind           String,              -- asset | policy | identity
    name           String,
    identifiers    Map(String, String), -- mac, ip, name, ...
    source         String,              -- observed | configured
    identity_basis String,              -- mac | ip_only | '' (policy/identity)
    confidence     Float64,
    attrs          Map(String, String),
    first_seen     DateTime64(3, 'UTC'),
    last_seen      DateTime64(3, 'UTC')
) ENGINE = ReplacingMergeTree(last_seen)
ORDER BY (tenant_id, entity_id)
TTL toDateTime(last_seen) + INTERVAL 30 DAY;

CREATE TABLE ssdf.entity_edges (
    edge_id    String,
    tenant_id  String,
    src_id     String,
    dst_id     String,
    edge_type  String,                  -- communicated_with | governed_by | authenticated_as
    source     String,                  -- observed | configured
    confidence Float64,
    attrs      Map(String, String),     -- sessions, bytes, ports, providers, firewall, rule, ...
    first_seen DateTime64(3, 'UTC'),
    last_seen  DateTime64(3, 'UTC')
) ENGINE = ReplacingMergeTree(last_seen)
ORDER BY (tenant_id, edge_id)
TTL toDateTime(last_seen) + INTERVAL 30 DAY;
```

DDL lives in `infra/clickhouse/004_entities.sql` (a least-privilege `ssdf_entity` user in
`infra/clickhouse/005_entity_user.sql`). Engine/TTL choices match M4's graph tables
(`ReplacingMergeTree(last_seen)`, 30-day TTL, `FINAL` on read for dedup).

**Why separate tables** (not new kinds on M4's graph): it keeps the semantic entity layer cleanly
relocatable. In **M6c** we can move *just* the entity store to Postgres-as-graph behind the seam
without touching M4's topology graph. The `GraphStore` Protocol is generalized into an
`EntityStore` interface (`upsert_entities`, `upsert_edges`, `find_entity`, `load_entity_subgraph`);
`ClickHouseEntityStore` is the M6a implementation. M4's `ClickHouseGraphStore` is unchanged.

### Data flow (M6a)
```
ssdf.events ───┐
               ├─► entity resolver ─► (assets, policies, edges) ─► EntityStore (ClickHouse) ─► explain_access (ct106)
M4 graph_nodes ┘   (deterministic, in-memory)
```

## 5. Tool contract: `explain_access`

Added to `ssdf-mcp-query` (ct106), read-only:

```
explain_access(client: str, server: str, since_hours: int = 24) -> dict
```

`client`/`server` accept IP, MAC, or name. MAC-shaped inputs are lowercased via the existing
`_normalize_identifier` (M6/M4) since MACs are stored lowercase.

**Behavior:**
1. Resolve `client` and `server` → Asset entities (`EntityStore.find_entity`). If either is
   unresolved → `{"error": "not_found", "detail": "..."}`.
2. Find observed `communicated_with` edges between the two Assets in-window.
3. For each, gather `governed_by` → observed Policy entities (provider, rule).
4. Attach the M4 topology path (`find_path`) and `enforcement_points` so the answer shows *where*
   in the fabric traffic flows. `enforcement_points` also supplies the **firewall** attribution for
   each control (inferred from topology, not the event stream). This is M6a's stand-in for M6c's
   full stitched L3 path.

**Return shape (M6a):**
```json
{
  "client": {"entity_id": "...", "name": "...", "identity_basis": "mac|ip_only"},
  "server": {"entity_id": "...", "name": "...", "identity_basis": "mac|ip_only"},
  "observed_flows": {"sessions": 42, "bytes": 1234567, "ports": [443],
                     "providers": ["juniper", "paloalto"], "window_hours": 24},
  "controls": [
    {"firewall": "vSRX-test10", "vendor": "juniper", "rule": "trust-to-untrust",
     "source": "observed", "sessions": 42, "firewall_basis": "topology"}
  ],
  "topology_path": {"found": true, "path_nodes": ["..."], "hops": 3},
  "coverage": {"observed": true, "configured": "pending_m6b"}
}
```

**Honesty contract (load-bearing).** In M6a only `observed` data exists, so every control is
stamped `source: "observed"` and `coverage.configured: "pending_m6b"`. The tool never implies a
rule exists or permits traffic unless a flow actually hit it. When M6b adds configured policy,
`controls[]` gains `source: "configured"` entries (rules that would apply but were not observed)
and `coverage.configured` flips to `true`. An empty `controls` with `observed_flows.sessions > 0`
is surfaced as a finding (observed traffic with no resolved governing rule), never hidden.

> **As-built reconciliation (2026-06-07).** The shipped `controls[]` entry omits the per-control
> `sessions` field shown in the example above; session/byte/port counts are reported once in
> `observed_flows` (the aggregate over all comm edges for the pair), not duplicated per control.
> Each control carries `firewall`, `vendor`, `rule`, `source`, `firewall_basis`. See
> `docs/superpowers/STATUS.md` (M6a row) for the canonical as-built shape.

## 6. Edge cases

- **IP-only endpoint** → Asset with `identity_basis: ip_only`, confidence < 1.0; never merged on
  IP alone; tool flags the weaker basis.
- **Conflicting IP→MAC over time** → stays two Assets (carried from M4's
  `test_conflicting_ip_mac_over_time_not_merged`).
- **Flow with empty `rule.name`** → `communicated_with` edge with no `governed_by`; surfaced as a
  finding, not dropped.
- **Same rule name across vendors** → distinct Policy entities keyed by `(provider, rule_name)`.
  Same rule name across two firewalls of the *same vendor* collapses to one Policy entity in M6a
  (no per-firewall identity in the event stream); a known limitation lifted in M6b/M6c.
- **Endpoint not found** → structured `{"error":"not_found"}`, consistent with M4 tool conventions.
- **TZ skew** (known M5 concern: PAN-OS stamps local EDT; ingest stores without conversion).
  `since_hours` windows inherit this caveat; documented, not fixed in M6a.

## 7. Testing

TDD, mirroring `services/topo`.

- **Unit (no infra, `-m "not integration"`)** — `resolve_entities` is a pure function, so most
  tests are deterministic fixtures: MAC fusion; IP-only singleton; no-merge-on-IP;
  conflicting-MAC; observed-Policy dedup per `(provider, firewall, rule_name)`; distinct policies
  for same name across vendors; empty-rule edge with no `governed_by`. SQL builders tested by
  asserting SQL text + params (no live CH), like M2/M4.
- **Integration (live, `-m integration`)** — against ClickHouse ct104: project a small synthetic
  event set, run the resolver, assert entities/edges land; call `explain_access` end-to-end and
  assert the observed/`coverage` contract.
- **Security** — all ClickHouse access parameterized (`{name:Type}`), no string interpolation,
  consistent with M2's `sql_guard` discipline. Run the vulnerability scan + full suite after
  changes, per the operator workflow rule.

## 8. Phasing (Approach A)

- **M6a (this plan)** — Asset resolution + observed Policy resolution; `EntityStore` seam +
  `ClickHouseEntityStore`; `infra/clickhouse/004_entities.sql` + `005_entity_user.sql`;
  `explain_access` tool on ct106; `services/entity/` resolver+projector (run on ct109). Fully
  answerable from today's data.
- **M6b (later plan)** — configured-policy collector pulling firewall security-policy snapshots
  via the read-only vendor MCPs (rust-junosmcp `get_junos_config`, panos-mcp `get_pan_config`);
  versioned `configured` Policy entities, distinct from observed; tool reports configured vs
  observed; `coverage.configured` → `true`.
- **M6c (later plan)** — full multi-hop L3 stitching across vendors (ordered hop sequence
  client→fw1→…→server) replacing the union-of-firewalls answer. Introduce Postgres-as-graph behind
  the `EntityStore` seam **only if** traversal needs it.

## 9. Open questions / future

- Exact Asset confidence scoring for mixed-evidence cases (MAC from one source, IP-only from
  another within the same window).
- How configured-policy snapshot versioning (M6b) keys to firewall config-change events.
- Whether the entity resolver should run on the same timer as the M4 topo resolver (shared cycle)
  or independently.
- The TZ-skew issue (M5) affects `since_hours` windows across all sources; a fabric-wide fix is
  out of scope for M6.
