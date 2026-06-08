# M6a Asset Identity — Segment Scoping & Duplicate Reconciliation (design)

**Date:** 2026-06-08
**Status:** approved (design); implementation pending
**Milestone:** M6a-fix (folds into the M6a entity layer; precondition for clean `explain_access` provenance)

---

## Problem

The M6a resolver keys an Asset by `mac:<mac>` when M4 topology binds the IP→MAC, else by
the bare IP `ip:<ip>`. Two failures follow:

1. **Duplicate twins.** When M4 *transiently* loses a binding for one resolver pass, the
   pass emits a second, MAC-less `ip:<ip>` entity. Because the entity_id differs from the
   `mac:<mac>` entity, ReplacingMergeTree keeps both forever. `find_entity`
   (`ORDER BY last_seen DESC LIMIT 1`) then returns whichever twin is newer — often the
   stale `ip_only` one, whose edge lacks the provenance that M6c-B attached to the real
   asset. This is the live caveat behind by-IP `explain_access` returning
   `firewall_basis:topology`/no provenance.

2. **Global IP-uniqueness assumption.** The bare `ip:<ip>` key assumes an IP identifies one
   device network-wide. With NAT and standardized branch addressing, the *same* IP
   (`198.51.100.150`) legitimately exists at many branches as *different* devices. A global
   `ip:<ip>` key wrongly collapses them, and a flat `ip → mac` binding map cannot represent
   one IP bound to different MACs in different segments.

## Identity model (revised)

- **MAC is the identity.** A device is its MAC. An Asset may carry many IPs
  (`identifiers.ip`, `ip2`, `ip3`, …), already supported.
- **IP is a scope-local observation.** It identifies a device only *within a segment*.
- **Segment = firewall vantage.** On the flow side this is the ECS `observer.hostname`
  (the firewall that logged the flow, present on every event since M6c-B). On the binding
  side it is `topo_observations.source_device` (the device whose ARP/neighbor table bound
  IP→MAC). In a branch these are the same physical firewall.
- **Identity rules:**
  - Same IP + **same MAC** → same device → may merge/reconcile.
  - Same IP + **different MAC, same segment** → genuine IP conflict → flag, never merge.
  - Same IP + **different MAC, different segments** → legitimate reuse (NAT/branch) →
    distinct devices, silent, no merge.
  - **Same MAC across two entities** → data error → flag, never silently merge.

### Segment normalization

`observer.hostname` is an ECS hostname that may be an FQDN (`panosvm.example.com`) while
`source_device` is the collector's device name (`panosvm`, `vSRX-test10`). To make the two
sides agree, both are normalized identically:

```
normalize_segment(name) = first dotted label, lowercased
  "panosvm.example.com" -> "panosvm"
  "vSRX-test10"         -> "vsrx-test10"
```

This is the same domain-suffix mismatch M6c-B already flagged for PAN-OS; normalizing here
fixes it for both layers. Empty/unknown observer normalizes to the literal segment
`unknown` (so MAC-less observations with no vantage still get a stable, non-colliding key
rather than silently sharing the global IP space).

## Binding map (segment-aware, sticky)

The resolver builds the IP→MAC binding map from **`topo_observations` `arp_entry` rows over
a lookback window** (default 7 days) rather than from the flattened `graph_nodes` snapshot:

- Each `arp_entry` observation has `source_device` (segment), `subj_id = ip:<ip>`,
  `obj_id = mac:<mac>`, and `observed_at`.
- Build `binding[(segment, ip)] = mac`, keeping the **most recent `observed_at`** per
  `(segment, ip)` key (last-seen-wins). The current snapshot still wins because it is the
  newest; a *transient single-pass drop* no longer matters because the wider window still
  carries the binding — this is the **prevention (P1)** mechanism, and it is segment-aware
  by construction (no need to read prior Asset entities).
- **Conflict detection:** if a `(segment, ip)` key is claimed by ≥2 distinct MACs within
  the window, record it as an IP conflict for that segment+IP.

The lookback window is configurable (`TOPO_BINDING_LOOKBACK_HOURS`, default 168). It is
bounded by the `topo_observations` 30-day TTL.

## Resolver changes (`services/entity`)

### Flow aggregate gains the observer grouping

`build_flow_agg_sql` currently groups by `(src_ip, dst_ip)` and collects
`groupUniqArray(observer_hostname) AS observer_hosts`. Add `observer_hostname` as a
**grouping key** so each row carries a single raw observer (its segment). The edge's
`observer_hosts` comma-set is still reassembled in `resolve_entities` via the existing
`_merge_set_attr`, so the COMMUNICATED_WITH edge attribute is unchanged.

```
GROUP BY src_ip, dst_ip, observer_hostname
```

### `asset_for(ip, segment, …)`

```
mac = binding[(segment, ip)]              # segment-scoped lookup
if mac:
    canonical      = f"mac:{mac}"
    identity_basis = "mac"
    confidence     = 1.0
else:
    canonical      = f"ip:{segment}:{ip}"  # scope-local, never global
    identity_basis = "ip_only"
    confidence     = 0.5
eid = entity_id(tenant, ASSET, canonical)
```

`segment` for a flow row is `normalize_segment(row.observer_hostname)`. Both endpoints of a
flow are scoped to the logging firewall's vantage (consistent: a firewall's own view of the
IPs it sees). Public/globally-unique IPs are unaffected (still one device per real owner).

### Conflict flag

When `asset_for` produces a `mac:<mac>` Asset whose `(segment, ip)` was marked a conflict in
the binding map, set `attrs["ip_conflict"] = ip` on that Asset. `explain_access` may surface
it later; no behavioral change is required by this spec beyond setting the attribute.

## Reconciliation (P2) — one-shot/periodic cleanup

Prevention stops *new* twins; existing twins (old global `ip:<ip>` keys, and any
ReplacingMergeTree duplicates) must be cleaned explicitly because the new resolver writes
*different* keys and never overwrites the legacy rows.

A standalone entry point `python -m ssdf_entity.reconcile_assets`, run as the
`ssdf_entity` writer on ct109:

1. Read all Assets with `identity_basis = 'ip_only'` (covers both legacy global `ip:<ip>`
   keys and any new `ip:<segment>:<ip>` rows).
2. For each, take its IP(s) and its segment (legacy global `ip:<ip>` keys have no segment —
   match across **any** segment; new `ip:<segment>:<ip>` keys match within their segment).
   If the binding map resolves that IP to a MAC **and** a MAC-anchored Asset exists carrying
   that IP (i.e. IP *and* MAC agree), it is a confirmed twin of that MAC Asset.
3. **Merge then delete (lossless):** merge the twin's COMMUNICATED_WITH edge attributes
   (`observer_hosts`, `sessions`, `bytes`, `ports`, `providers`, `transports`) into the MAC
   Asset's corresponding edge (same peer + edge_type + source), widening windows and
   set-unioning attrs; then `ALTER TABLE ssdf.entities DELETE` the twin and
   `ALTER TABLE ssdf.entity_edges DELETE` its now-redundant edges, `SETTINGS
   mutations_sync = 1`.
4. Twins with **no** matching MAC binding are left untouched (legitimate cross-segment
   reuse or genuinely unknown devices).

Reconciliation reuses the same binding map and `(segment, ip, mac)`-agreement predicate as
the resolver, so prevention and cleanup share one identity rule.

## Query-time disambiguation (`services/mcp-query`)

`build_entity_match_sql` orders `ORDER BY entities.last_seen DESC LIMIT 1`. Change to:

```
ORDER BY confidence DESC, entities.last_seen DESC LIMIT 1
```

so a MAC-anchored Asset (confidence 1.0) wins over an `ip_only` one (0.5) on a by-IP lookup,
independent of which was written more recently. This makes by-IP `explain_access` return the
provenance-bearing asset even before P2 has deleted a twin. Residual ambiguity (one IP held
by two MAC assets across segments under NAT) is a known limitation; an optional segment hint
to `explain_access` is out of scope for this fix.

## Files touched

- **Modify** `services/entity/src/ssdf_entity/chwriter.py`
  - `build_flow_agg_sql`: add `observer_hostname` to `SELECT` and `GROUP BY`.
  - Replace `build_topo_hosts_sql` with `build_binding_sql(lookback_hours, tenant)` reading
    `topo_observations` `arp_entry` rows (`source_device`, `subj_id`, `obj_id`,
    `observed_at`).
- **Modify** `services/entity/src/ssdf_entity/resolve_entities.py`
  - Add `normalize_segment`.
  - Build the segment-scoped binding map (`(segment, ip) → mac`) + conflict set from the new
    binding rows.
  - `asset_for(ip, segment, …)`: segment-scoped key, conflict flag.
  - Per-flow `segment = normalize_segment(row["observer_hostname"])`.
- **Modify** `services/entity/src/ssdf_entity/resolve_main.py`
  - Pass the binding lookback window; wire the new binding query in place of topo hosts.
- **Modify** `services/entity/src/ssdf_entity/config.py`
  - Add `TOPO_BINDING_LOOKBACK_HOURS` (default 168).
- **Create** `services/entity/src/ssdf_entity/reconcile_assets.py`
  - P2 reconciliation entry point (read ip_only assets, merge edges, ALTER DELETE twins).
- **Modify** `services/mcp-query/src/ssdf_mcp_query/entitystore.py`
  - `build_entity_match_sql`: `ORDER BY confidence DESC, entities.last_seen DESC`.
- **Tests** (unit, `-m "not integration"`):
  - `services/entity/tests/` — `normalize_segment`; segment-scoped keying (two branches,
    same IP, different MAC → two assets); sticky binding survives a one-pass drop; conflict
    flag (same segment, same IP, two MACs); reconciliation merge-then-delete on a synthetic
    twin.
  - `services/mcp-query/tests/` — `build_entity_match_sql` orders by confidence first;
    MAC asset wins over ip_only twin.

## Deployment

- Resolver change deploys to ct109 (existing `ssdf-entity.timer`); no schema migration
  (identity is in `entity_id` values, not columns).
- `reconcile_assets` run once manually on ct109 as `ssdf_entity` to clean current twins;
  optionally add a low-frequency `ssdf-entity-reconcile.timer` (daily) — deferred unless the
  one-shot proves twins recur (P1 should prevent recurrence).
- mcp-query ordering change deploys to ct106 editable install (`/opt/src/mcp-query/src`),
  restart the service.

## Out of scope

- Segment hint parameter on `explain_access`.
- Surfacing `ip_conflict` in `explain_access` output (attribute is set; reporting deferred).
- VLAN/subnet capture in M4 (segment proxy is the firewall vantage, sufficient here).
- The M6a IP-vs-MAC split for assets that genuinely never get a MAC binding (still
  `ip_only`, now correctly segment-scoped rather than merged).
