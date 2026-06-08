# M4 firewall-node tagging — design (issue #6, scope A)

**Date:** 2026-06-08
**Tracking:** issue #6 (milestone M6c), the M6b→M4 bridge dependency.
**Scope:** A (narrow node-tagging) — see "Scope & non-goals". Confirmed with operator.

## 1. Problem

M6b shipped configured-policy attribution to `explain_access`, but live calls return
`configured_basis: "no_path_firewall"` / `coverage.configured: 0`. Root cause is in **M4**:
`enforcement_points` (services/mcp-query `topo_tools.py:121-128`) attributes a firewall to a
path only when a graph node has `kind == "device"` **and** `attrs.role == "firewall"` and sits
in the path's L1/L2 connected component. M4 currently models **0** firewall-role device nodes,
so no firewall is ever attributed and the M6b configured side never surfaces.

The M4 resolver already *honours* `role`: the `device_inventory` branch
(`resolver/resolve.py:196-203`) sets `dev["attrs"]["role"] = o.attrs.get("role", "device")`.
The gap is purely upstream — neither the junos nor the panos topology collector emits a
`device_inventory` observation, so the `panosvm` / `vSRX-test10` device nodes (created by
lldp/mac/arp observations, keyed by name) are never tagged.

## 2. Scope & non-goals

**In scope (A):** make `panosvm` and `vSRX-test10` resolve as `device` nodes with
`attrs.role == "firewall"` in `ssdf.graph_nodes`. Acceptance: `enforcement_points` returns
them when they are already in the path's L1/L2 component.

**Out of scope (deferred to scope B):** guaranteeing that a real client→server transit pair
yields `coverage.configured > 0` live end-to-end. That additionally requires L2/L3
host↔firewall connectivity observations linking endpoints to the firewall's component, and may
surface further topology-completeness gaps. Tracked separately under the same issue/milestone.

## 3. Approach (confirmed: collector self-emits)

Both M4 firewall collectors inherently target firewalls — the junos collector talks to vSRX
(SRX = firewall), the panos collector to a PAN-OS NGFW. Each collector emits one additional
`device_inventory` observation for its own device, tagged `role=firewall`. This is data-driven,
reuses the existing resolver path, and adds no new config (rejected alternative: a config-driven
firewall-name allowlist, which would duplicate the M6b device-name list and require sync).

### 3.1 Observation shape

Mirror the existing emitter (`collectors/unifi.py:95-110`). The resolver's `device_inventory`
branch reads `attrs.name` and `attrs.role` (and optionally `attrs.mac`/`attrs.ip`, omitted here):

```
Observation(
    observed_at=now,
    collector=<"junos" | "panos">,
    source_device=<device name>,
    layer="l2",
    observation_type="device_inventory",
    subj_kind="device",
    subj_id=f"device:{device_name}",
    obj_kind="",
    obj_id="",
    attrs={"role": "firewall", "name": device_name},
)
```

`name` MUST equal the collector's `source_device` so the resolver's name-keyed `device_node`
merges this observation onto the same node built from that device's lldp/mac/arp facts (and the
`_merge_devices` name-token union preserves the merge across collectors).

## 4. Components / changes

1. **New helper** `firewall_inventory(collector: str, source_device: str, now: str) -> Observation`
   in `services/topo/src/ssdf_topo/collectors/base.py` — builds the observation in §3.1. Shared
   by both collectors (DRY); the only varying input is `collector` and `source_device`.
2. **`collectors/junos.py`** `JunosCollector.collect()` — inside the existing `for dev in
   self.devices` loop, append `firewall_inventory("junos", dev, now)`.
3. **`collectors/panos.py`** `PanosCollector.collect()` — append
   `firewall_inventory("panos", self.device, now)` to the returned observations.

No change to `resolver/resolve.py`, the ClickHouse schema, or `topo_tools.enforcement_points`.

## 5. Data flow

```
junos/panos collector
   ├─ lldp/mac/arp observations ─┐
   └─ device_inventory(role=firewall, name=dev) ─┤
                                                  ▼
                          resolver: device_node(name) touched by both,
                          attrs.role = "firewall"  →  ssdf.graph_nodes
                                                  ▼
        enforcement_points: returns firewall when it is in the
        path's L1/L2 connected component  (scope-A boundary)
```

## 6. Testing

- **Unit — junos collector:** with a stub MCP client, `JunosCollector(["vSRX-test10"]).collect()`
  includes exactly one `device_inventory` observation per device with
  `attrs["role"] == "firewall"` and `attrs["name"] == "vSRX-test10"`.
- **Unit — panos collector:** `PanosCollector("panosvm").collect()` includes one
  `device_inventory` observation with `role=firewall`, `name="panosvm"`.
- **Unit — resolver merge:** feeding `resolve_graph` a `device_inventory(role=firewall,
  name="vSRX-test10")` plus an lldp or mac observation naming the same device yields exactly
  **one** `device` node whose `attrs["role"] == "firewall"` (proves merge-by-name, no duplicate).
- **Live integration (ct109):** after one collect→resolve pass, the `panosvm` and `vSRX-test10`
  nodes in `ssdf.graph_nodes` carry `attrs.role == "firewall"`.

## 7. Deployment

Push the updated `services/topo` package to ct109 (the existing M4 venv/src). The existing 5-min
`ssdf-topo.timer` (oneshot collect→resolve) picks up the change on its next cycle — no new infra,
no schema migration, no MCP-tool redeploy (ct106 is unaffected; `enforcement_points` logic is
unchanged and simply starts seeing tagged nodes).

## 8. Risks & limitations

- **Assumes every device a firewall collector targets is a firewall.** True today (junos→SRX,
  panos→PAN-OS). If a future non-firewall Junos/PAN-OS device is added to these collectors, it
  would be mis-tagged; revisit by moving to per-device role inference at that point.
- **Scope A does not by itself flip live `coverage.configured` to > 0** — it removes the
  `no_path_firewall` cause only for pairs whose endpoints already share the firewall's L1/L2
  component. The broader end-to-end guarantee is scope B.
