# SSDF M6b — Configured Policy: Design

**Date:** 2026-06-08
**Status:** Design of record for M6b. Builds on M6a (`2026-06-07-ssdf-m6-entity-correlation-design.md`)
and M4 (`2026-06-07-ssdf-m4-topology-graph-design.md`). Read those first.

## 1. Goal

Ingest each firewall's **configured** security ruleset (read-only) as `source='configured'`
Policy entities with real **per-firewall identity**, and enrich `explain_access` to list the
rules that govern a `client→server` path **even when no traffic has been observed** — flipping
`coverage.configured` from the M6a `pending_m6b` literal to a real count.

This lifts M6a's documented limitation: *"the same rule name across two firewalls of the same
vendor collapses to one Policy"* — configured Policies are keyed per device, so they no longer
collide.

### Scope (decided during brainstorming)

- **Vendors:** PAN-OS **and** vSRX in the first cut (matches M5's two-vendor precedent).
- **Rule detail:** rich match criteria — action, zones, addresses, application/service, position.
- **explain_access:** list configured rules on path firewalls + flip `coverage.configured`.
  **No** match-scoring, **no** drift verdicts in M6b (deferred).
- **Cadence:** own slower timer (~hourly) on ct109, independent of the two existing 5-min timers.
- **Link model:** firewall-anchored edges — firewall is a first-class entity; resolver writes
  `Firewall ──GOVERNED_BY(source=configured)──► Policy` edges; `explain_access` finds path
  firewalls via M4 topology, then lists their configured Policies.

### Non-goals (M6b)

- Match-scoring a configured rule against an actual flow's zones/addresses/service.
- Drift verdicts (observed-flow-with-no-allow-rule; configured-allow-never-observed).
- Config-change-event versioning / rule history (snapshot-only, see §6).
- Acting on or changing any device config — SSDF stays read-only.

## 2. Architecture

Reuses the M4 collector pattern and the M6a resolver/writer/seam patterns. No new ClickHouse
tables and no new ClickHouse user.

```
firewalls ──(read-only MCP)──► policy collector ──► resolver ──► ssdf.entities / ssdf.entity_edges
  panosvm    panos-mcp           services/policy/      (Firewall +      (Firewall + Policy entities,
  vSRX×N     rust-junosmcp        get_pan_config /       configured        Firewall─GOVERNED_BY→Policy)
                                  get_junos_config       Policy                       │
                                  per device)            resolve)                     ▼
                                                                         explain_access (ct106) reads,
                                                                         joins M4 path-firewalls → rules
```

- **New service `services/policy/`** (Python; mirrors `services/topo/`): a registry of vendor
  collectors. Each `collect(client, device, now)` calls the vendor MCP and parses the security
  ruleset into a normalized list of rule dicts.
- **Resolver** (pure function; mirrors M6a `resolve_entities`): normalized rules → `configured`
  Policy entities + one Firewall entity per device + `Firewall ──GOVERNED_BY(configured)──►
  Policy` edges.
- **Writer:** reuses M6a `ClickHouseEntityWriter` against the existing `ssdf.entities` /
  `ssdf.entity_edges` tables. `source='configured'` and `kind='firewall'` distinguish the rows.
- **Tool change:** `explain_access` in `services/mcp-query/` gains a `configured_controls` block
  and a real `coverage.configured` count, sourced through the existing `EntityStore` seam
  (extended with a configured-policy lookup).

## 3. Data sources & vendor parsing

The only vendor-specific logic in M6b lives in the per-vendor collectors. Both tools are
already deployed read-only MCPs (see global CLAUDE.md).

### 3.1 PAN-OS (panosvm, VMID 900) via `panos-mcp` `get_pan_config`

- Pull the security rulebase (vsys rules + shared pre/post rules where present).
- Each rule → normalized dict:
  - `rule_name`, `action` (allow/deny/drop/reset), `from_zone[]`, `to_zone[]`,
    `source_addresses[]`, `dest_addresses[]`, `application[]`, `service[]`,
    `position` (0-based order), `enabled` (negation of `disabled`).
  - Vendor extras under `panw.panos.*` (e.g. rule UUID, rulebase = pre/post/security).
- PAN-OS version pinned **12.1.5**; re-validate the config shape on any major PAN-OS upgrade.

### 3.2 vSRX (rust-junosmcp inventory) via `rust-junosmcp` `get_junos_config`

- Pull `security policies` (per from-zone/to-zone policy blocks).
- Each policy term → normalized dict with the same normalized fields:
  - `rule_name` (the policy name), `action` (permit→allow / deny / reject),
    `from_zone`, `to_zone`, `source_addresses[]`, `dest_addresses[]`,
    `application[]` (Junos applications), `service[]` (alias of application for Junos),
    `position` (order within the zone-pair), `enabled` (Junos policies are enabled unless
    `inactive`).
  - Vendor extras under `juniper.srx.*`.
- Devices come from the collector config (the rust-junosmcp inventory has 6 vSRX devices).

Both collectors return a flat `list[NormalizedRule]` tagged with `provider`, `device_name`, and
`collected_at`. A collector that fails for one device is skipped with a warning (M4 behavior),
so one unreachable firewall never blocks the others.

## 4. Entity model

No schema change — M6a's `ssdf.entities` / `ssdf.entity_edges` already carry `kind`, `source`,
`identifiers`, `confidence`, `attrs`. M6b adds a new `kind` value and a new `source` value on
Policy rows.

### 4.1 Firewall entity

- `kind = 'firewall'`, `source = 'configured'`.
- Canonical key: `device:{device_name}` where `device_name` is the MCP inventory name
  (e.g. `vSRX-test10`, `panosvm`). Stable across passes.
- `identifiers`: `{device_name: <name>}`, plus MAC/IP if the resolver can bridge to an M4
  `graph_nodes` firewall node by name (best-effort enrichment, not required for identity).
- `confidence = 1.0` (we pulled this device's own config; identity is authoritative).
- `attrs`: `provider`, `device_name`, `rule_count`, optional topology-bridge note.

### 4.2 Configured Policy entity

- `kind = 'policy'`, `source = 'configured'`.
- Canonical key: **`(provider, device_name, rule_name)`** — the fix for M6a's same-name
  collapse. The same `rule_name` on two firewalls yields two distinct entity_ids.
- M6a observed Policies keep their `(provider, rule_name)` canonical key (M6a `policy_for`
  builds `f"{provider}:{rule_name}"`) with `source='observed'`. M6b configured Policies use
  `f"{provider}:{device_name}:{rule_name}"`. Because `entity_id(tenant, kind, canonical_key)`
  hashes the canonical key, the two keys differ and the rows get **distinct entity_ids** — no
  collision. (`source` is a stored column for display/filtering, not part of `entity_id`.)
- `confidence = 1.0`.
- Rich `attrs`: `action`, `from_zone`, `to_zone`, `source_addresses`, `dest_addresses`,
  `application`, `service`, `position`, `enabled`, plus namespaced vendor extras.

### 4.3 Edges

- `Firewall ──GOVERNED_BY(source='configured')──► Policy`, one per configured rule.
- Reuses M6a `GOVERNED_BY` edge type and `edge_id(tenant, src_id, dst_id, edge_type, source)`
  so observed and configured governed-by edges are distinct.
- No Asset↔Policy edges for configured rules in M6b (that would be match-scoring — deferred).

## 5. explain_access enrichment

`explain_access(client, server)` keeps its M6a behavior and adds:

1. Resolve `client` and `server` Assets (unchanged).
2. **Find path firewalls via M4 topology** (reuse `enforcement_points` / `find_path` logic):
   the firewall device(s) between client and server.
3. For each path firewall, look up its Firewall entity by `device:{name}`, follow its
   `GOVERNED_BY(configured)` edges, and collect the configured Policy entities.
4. Return a new top-level `configured_controls` block: a list of
   `{firewall, rule_name, action, from_zone, to_zone, position, enabled, ...}`, grouped by
   firewall. Distinct from M6a's `observed` controls block.
5. Set `coverage.configured` = total count of configured rules found on the path firewalls
   (replaces the `pending_m6b` literal).

### Honesty contract (extends M6a's, load-bearing)

- Every configured control is stamped `source:'configured'`; observed controls are unchanged.
- `configured_controls` lists rules **present on the path firewalls**. M6b does **not** claim
  which rule matches the flow (no match-scoring) and emits **no** drift verdicts.
- **Topology↔firewall bridge is best-effort by name.** M4 path-firewalls are matched to
  Firewall entities by `device_name`. If a path firewall has no matching Firewall entity, its
  rules are omitted and a `configured_basis` note flags the gap (same spirit as M6a's
  `firewall_basis`). We never silently drop without signaling.
- If topology yields no firewall on the path, `configured_controls` is empty and
  `coverage.configured = 0` with `configured_basis:"no_path_firewall"`.

## 6. Known limitations (accepted for M6b)

- **Snapshot, not history.** `ReplacingMergeTree(last_seen)` keeps only the latest config pull;
  no rule-version history. Same trade-off accepted in M4 and M6a. Config-change-event
  versioning is a future item.
- **No match-scoring** between a configured rule and the actual flow's zones/addresses/service.
  `explain_access` lists rules on the path firewalls, not "the rule that matched."
- **Name-based topology bridge.** If the MCP inventory device name differs from the M4
  topology firewall node's name, the rules for that firewall are reported as omitted rather
  than attributed. Reconciling device naming across sources is deferred.
- **`first_seen` collapses to the current window** (inherited M6a/M4 trade-off).
- **vsys1 security rulebase only (no shared pre/post).** §3.1 aspires to "vsys rules + shared
  pre/post rules where present," but the implemented PAN-OS collector scopes to the vsys1
  `rulebase/security/rules`. The lab target is single-vsys, no Panorama, so there are no
  shared pre/post-rulebases to read; Panorama pre/post-rule collection is a future item.

## 7. Deployment

- New `services/policy/` deployed to **ct109** (third role alongside topo + entity).
  - Own venv `/opt/ssdf-policy`; env `/etc/ssdf-policy/ENV.local` (mode 600).
  - Writes ClickHouse ct104 as the existing `ssdf_entity` user (same tables; no new CH user).
  - Config via env: per-vendor `{PREFIX}_MCP_URL` / `{PREFIX}_MCP_TOKEN` (JUNOS, PANOS) and a
    device list, mirroring `services/topo` config.
- **Own `ssdf-policy.timer`** (hourly) → oneshot `ssdf-policy.service` (collect → resolve →
  write). Independent of `ssdf-topo.timer` and `ssdf-entity.timer` (both 5-min) so the heavy
  full-config pulls don't run every 5 minutes.
- `explain_access` change ships on the existing `ssdf-mcp-query` (ct106), reading as `ssdf_ro`.

## 8. Testing

- **Unit (per-vendor parsers):** feed a captured `get_pan_config` payload and a captured
  `get_junos_config` payload → assert normalized rule dicts (fields, action mapping, position,
  enabled, vendor extras).
- **Unit (resolver):** per-firewall identity (same rule name on two firewalls → two distinct
  entity_ids); Firewall entity per device; `GOVERNED_BY(configured)` edge per rule; observed and
  configured Policies coexist without collision; idempotency (re-run → same ids).
- **Unit (`explain_access`):** `configured_controls` block shape; `coverage.configured` count;
  `configured_basis` notes for no-path-firewall and unmatched-firewall cases.
- **Live integration:** one collector pass against panosvm + one vSRX → assert configured Policy
  + Firewall entities land in `ssdf.entities` and edges in `ssdf.entity_edges`; `explain_access`
  on a client/server whose path crosses a firewall returns `configured_controls` with
  `coverage.configured > 0`.

## 9. Cross-cutting seams (kept clean)

- **Storage seam:** all ClickHouse access stays in the writer / `clickhouse.py`; M6b adds no new
  table and reuses the M6a writer.
- **EntityStore seam:** `explain_access`'s configured-policy lookup goes through the existing
  `EntityStore` Protocol (extended with a `configured_policies_for_firewalls` method), so M6c can
  relocate the entity store to Postgres without touching the tool.
- **Read-only boundary:** configured policy is read **as telemetry** via read-only MCP tools;
  SSDF never writes device config. The honesty contract keeps `configured` strictly separate from
  `observed`.
- **ClickHouse `toString(col) AS col` alias trap:** any new WHERE/ORDER BY against the entity
  SELECTs must qualify the column (e.g. `entities.last_seen`) — see M6a.
