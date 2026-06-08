# M6c scope B — provenance-based firewall attribution (issue #6)

**Date:** 2026-06-08
**Tracking:** issue #6 (milestone M6c), scope B — the second half of the M6b→M4 bridge.
**Depends on:** M6b configured-policy layer (Firewall entities + `configured_policies_for_firewalls`).
Independent of M6c scope A (firewall-role topology nodes, PR #7): scope B does not use those
nodes — it attributes via M6b **Firewall entities**, not M4 topology device nodes.

## 1. Problem

`explain_access(client, server)` reports `coverage.configured` by attributing the firewalls on a
path (`access_tools.py:49`, via `topo.enforcement_points`) and listing their configured rules
(`configured_policies_for_firewalls`). Live, `coverage.configured == 0` for real transit pairs.

Scope A fixed firewall **tagging**. Scope B addresses the **attribution model itself**:
`enforcement_points` (`topo_tools.py:121-128`) attributes a firewall only if a host endpoint is in
the firewall's **L1/L2 connected component**. This is topologically wrong for a *transit* firewall:
it routes between two L3 segments, so the endpoints are never L2-adjacent to it. Verified live —
vSRX-test10's ARP table contains neither `10.65.1.10` nor `10.66.2.20` (the transit pair); a transit
firewall only ARP-learns directly-connected neighbors, never the far-end hosts it routes between.
No synthesized ARP/MAC edge can create adjacency that physically does not exist.

## 2. Approach (confirmed: provenance-primary)

The firewall that **logged** a flow is, by definition, on that flow's path — an observed fact, not
a graph inference. SRX RT_FLOW and PAN-OS traffic logs carry the logging device's hostname. We
expose that hostname as a normalized field and attribute the firewall from it, falling back to the
existing topology heuristic only when provenance is absent.

Verified live: the 12 real juniper flow rows in `ssdf.events` were logged by host **`vSRX-test10`**
(rule `baseline-permit(global)`), which **already equals** the M4/M6b device name — so no
name-mapping layer is needed. (One stale synthetic row uses `srx-test10`; ignored.)

Rejected alternatives:
- **L2-topology completion** (synthesize host↔firewall L2 edges): structurally impossible for
  transit firewalls, as shown in §1.
- **L3/routing attribution** (model firewall routing between subnets): needs
  routing/interface-subnet data we do not collect.
- **Zone-based** (`observer_ingress_zone`/`egress_zone` → firewall): zones don't uniquely identify a
  device when firewalls share zone names.

## 3. Normalize at ingest

Per the project's "normalize at ingest, never downstream" rule, the logging device becomes a typed
column, not a downstream regex over `raw`.

New column **`observer_hostname LowCardinality(String) DEFAULT ''`** on `ssdf.events` (ECS
`observer.hostname` — the device observing/reporting the event; consistent with the existing
`observer_ingress_zone`/`observer_egress_zone`).

## 4. Components / changes

### 4.1 Schema — `infra/clickhouse/006_observer_hostname.sql` (new)
```sql
ALTER TABLE ssdf.events
  ADD COLUMN IF NOT EXISTS observer_hostname LowCardinality(String) DEFAULT '';
```
Idempotent. The `ssdf_ro` and `ssdf_entity` users already hold table-level SELECT, so no grant
change. **Must be applied before** the updated Vector config (the ClickHouse sink inserts the
column by name; an unknown column would fail the insert).

### 4.2 Ingest — `infra/vector/vector.toml`
- `transforms.srx_ecs` (`.= {...}` map, ~line 95): add
  `"observer_hostname": string(parsed.hostname) ?? "",`. RFC5424 HOSTNAME field → `vSRX-test10`.
- `transforms.panos_ecs`: set `ev.observer_hostname = string(parsed.hostname) ?? ""` alongside the
  existing `ev.observer_*` assignments. PAN-OS parsing already slices the CSV manually; the syslog
  HOSTNAME token is unaffected by that workaround. Validated by a unit test (PAN-OS has no live
  transit, so this side is mechanism + test only). If `parsed.hostname` proves empty for the PAN-OS
  header shape, fall back to the CSV device-name field — decided by the unit test, not assumed.

### 4.3 Entity resolver — `services/entity`
- `chwriter.py` `build_flow_agg_sql` (lines 21-36): add
  `groupUniqArray(observer_hostname) AS observer_hosts,` to the SELECT. Returns a list of distinct
  hostnames per `(src_ip, dst_ip)` group.
- `resolve_entities.py` (comm-edge build, lines 100-114):
  - default attrs (line 104-105): add `"observer_hosts": ""`.
  - after the `providers` merge (line 112): `_merge_set_attr(comm["attrs"], "observer_hosts",
    row.get("observer_hosts") or [])`.

  `observer_hosts` is stored as a comma-joined set string on the COMMUNICATED_WITH edge attrs, the
  same shape as `providers`/`ports`. No schema change to `ssdf.entity_edges` (attrs is a Map).

### 4.4 `explain_access` — `services/mcp-query/.../access_tools.py`
Replace the topology-only firewall attribution (lines 48-51) with provenance-primary:
```
observer_hosts = union of _csv_list(edge.attrs["observer_hosts"]) over comm_edges
if observer_hosts:
    firewalls = sorted(observer_hosts)
    firewall_basis = "provenance"
else:
    firewalls = self._topo.enforcement_points(client, server).get("firewalls", [])
    firewall_basis = "topology" if firewalls else "no_path_firewall"
```
- `configured_controls` / `coverage.configured`: unchanged downstream — call
  `configured_policies_for_firewalls(firewalls)` exactly as today. A provenance hostname with no
  matching M6b Firewall entity simply yields no configured rules (→ `configured_basis =
  "firewall_name_unmatched"`), which is correct.
- Add `firewall_basis` to the response (top level) so callers see how the firewall was attributed.
- The observed-`controls` items (lines 76-86) currently hardcode `"firewall_basis": "topology"` and
  `"firewall": attributed_fw` (topology-derived). Update both to use the resolved `firewall_basis`
  and the provenance-attributed firewall, so the observed-controls story matches the top-level
  attribution rather than asserting "topology" unconditionally.
- `enforcement_points` (`topo_tools.py`) is **not modified** — it remains the fallback and an
  independent topology tool.

## 5. Data flow

```
RT_FLOW syslog  (HOSTNAME = vSRX-test10)
   └─► Vector srx_ecs ─► ssdf.events.observer_hostname = "vSRX-test10"
         └─► entity resolver: groupUniqArray ─► comm_edge.attrs.observer_hosts = "vSRX-test10"
               └─► explain_access: firewalls=["vSRX-test10"], firewall_basis="provenance"
                     └─► configured_policies_for_firewalls(["vSRX-test10"])
                           └─► coverage.configured = 1   (baseline-permit(global))
```

## 6. Testing

- **Vector unit (SRX):** an RT_FLOW input line with HOSTNAME `vSRX-test10` yields
  `observer_hostname == "vSRX-test10"`.
- **Vector unit (PAN-OS):** a PAN-OS TRAFFIC CSV line yields a non-empty `observer_hostname`
  matching the device hostname (asserts the chosen source field is correct).
- **Entity resolver unit:** a flow-agg row with `observer_hosts=["vSRX-test10"]` produces a
  COMMUNICATED_WITH edge whose `attrs["observer_hosts"] == "vSRX-test10"`; two rows with different
  hosts union into a comma-set.
- **`explain_access` unit (provenance):** comm edge with `observer_hosts="vSRX-test10"` and a
  Firewall entity + configured policy for it ⇒ `firewall_basis=="provenance"`,
  `firewalls==["vSRX-test10"]`, `coverage["configured"]==1`. Topology stub is NOT consulted.
- **`explain_access` unit (fallback):** comm edge with empty `observer_hosts` ⇒ falls back to the
  topology stub's firewalls, `firewall_basis=="topology"`.
- **`explain_access` unit (none):** empty `observer_hosts` and empty topology ⇒
  `firewall_basis=="no_path_firewall"`, `coverage["configured"]==0`.
- **Live integration (end-to-end):** after deploy, `explain_access("198.51.100.150",
  "203.0.113.1")` returns `firewall_basis=="provenance"`, `firewalls==["vSRX-test10"]`,
  `coverage.configured >= 1`. See §8 for the data-freshness step this depends on.

## 7. Deployment

Ordered (the column must exist before Vector emits it):
1. Apply `006_observer_hostname.sql` to ClickHouse ct104.
2. Push updated `infra/vector/vector.toml` to ct102; `vector validate` then reload.
3. Push updated `services/entity` package to ct109 (`/opt/ssdf-entity`); the 5-min
   `ssdf-entity.timer` picks it up.
4. Push updated `services/mcp-query` (`access_tools.py`) to ct106 and restart the MCP service.

No new infra, no new LXC, no MCP-tool added/renamed (the `explain_access` response gains one field).

## 8. Risks & limitations

- **Data freshness for the live proof.** The 12 existing real rows predate the column and read
  `observer_hostname=''`, so they will not attribute. Live end-to-end proof requires either (a)
  fresh transit traffic through vSRX-test10 after the Vector reload, or (b) a one-time
  `ALTER TABLE ssdf.events UPDATE observer_hostname = <parsed-from-raw> WHERE event_provider='juniper'
  AND raw ILIKE '%vSRX-test10%'` backfill. Decide at plan time; (a) is preferred (proves the live
  path), (b) is the fallback if generating cross-zone transit traffic in the lab is impractical.
- **Provenance ≠ full enforcement coverage.** Provenance attributes only firewalls that *logged*
  the flow. An on-path firewall with logging disabled for the matching rule contributes nothing —
  reported honestly as absence, never as a fabricated topology claim. `firewall_basis` exposes this.
- **PAN-OS unproven live.** panosvm has no transit traffic (empty session table; same transit-only
  trap as SRX), so the PAN-OS side is validated by unit test only until real PAN-OS transit exists.
- **Window alignment.** `explain_access` default window is 24h and the entity resolver uses its own
  window/TTL; the live proof may need an explicit `since_hours` and a fresh resolver pass so the
  comm edge carries the new `observer_hosts`.
