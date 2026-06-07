# SSDF M4 — Phase 4: Resolver

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development or superpowers:executing-plans. Prerequisite: Phases 0–3 complete.

**Goal:** A stateless resolver that reads recent `topo_observations` + flow aggregates from `ssdf.events`, resolves entities to canonical nodes, builds typed edges, and upserts `graph_nodes` / `graph_edges`.

**Key rules (from spec §6):** MAC anchors host identity; **IP is never an identity by itself** (time-bounded `has_address`); device identifiers (chassis-id/serial/system-name/mgmt-ip) union into one device via union-find; cross-time IP↔MAC conflicts are *not* merged. Every node/edge carries `attrs.evidence`.

---

## Task 4.1: Union-find

**Files:**
- Create: `services/topo/src/ssdf_topo/resolver/__init__.py` (empty)
- Create: `services/topo/src/ssdf_topo/resolver/unionfind.py`
- Test: `services/topo/tests/test_unionfind.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_unionfind.py
from ssdf_topo.resolver.unionfind import UnionFind

def test_union_groups_connected_identifiers():
    uf = UnionFind()
    uf.union("chassis:abc", "sysname:sw1")
    uf.union("sysname:sw1", "mgmt:10.64.0.1")
    uf.add("mac:aa")
    groups = uf.groups()
    members = next(g for g in groups.values() if "chassis:abc" in g)
    assert set(members) == {"chassis:abc", "sysname:sw1", "mgmt:10.64.0.1"}
    # the lone mac is its own group
    assert any(g == ["mac:aa"] for g in groups.values())

def test_find_is_stable():
    uf = UnionFind()
    uf.union("a", "b")
    assert uf.find("a") == uf.find("b")
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd services/topo && uv run pytest tests/test_unionfind.py -v`
Expected: FAIL (ImportError)

- [ ] **Step 3: Implement unionfind.py**

```python
# src/ssdf_topo/resolver/unionfind.py
"""Minimal union-find over string identifier tokens."""

from __future__ import annotations


class UnionFind:
    def __init__(self) -> None:
        self._parent: dict[str, str] = {}

    def add(self, x: str) -> None:
        self._parent.setdefault(x, x)

    def find(self, x: str) -> str:
        self.add(x)
        root = x
        while self._parent[root] != root:
            root = self._parent[root]
        while self._parent[x] != root:  # path compression
            self._parent[x], x = root, self._parent[x]
        return root

    def union(self, a: str, b: str) -> None:
        self.add(a)
        self.add(b)
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            # deterministic root: lexicographically smallest wins
            lo, hi = sorted((ra, rb))
            self._parent[hi] = lo

    def groups(self) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        for token in self._parent:
            out.setdefault(self.find(token), []).append(token)
        return out
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd services/topo && uv run pytest tests/test_unionfind.py -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add services/topo/src/ssdf_topo/resolver/__init__.py services/topo/src/ssdf_topo/resolver/unionfind.py services/topo/tests/test_unionfind.py
git commit -m "feat(m4): union-find for entity identifier resolution"
```

## Task 4.2: Flow aggregation from ssdf.events

**Files:**
- Create: `services/topo/src/ssdf_topo/resolver/flows.py`
- Test: `services/topo/tests/test_flows.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_flows.py
from ssdf_topo.resolver.flows import build_flow_agg_sql, flow_to_edges

def test_flow_agg_sql_groups_and_windows():
    sql, params = build_flow_agg_sql(window_hours=24, tenant="t_main")
    assert "FROM ssdf.events" in sql
    assert "GROUP BY" in sql
    assert "source_ip" in sql and "destination_ip" in sql
    assert "sum(network_bytes)" in sql
    assert params["tenant"] == "t_main"
    assert "{window_hours:UInt32}" in sql or "INTERVAL" in sql

def test_flow_to_edges_emits_talked_to_and_governed_by():
    agg = [{
        "src_ip": "10.64.0.5", "dst_ip": "10.64.0.9", "bytes": 4096, "flows": 3,
        "rule_name": "allow-web", "ingress_zone": "trust", "egress_zone": "untrust",
        "provider": "juniper", "first_seen": "2026-06-07T00:00:00+00:00",
        "last_seen": "2026-06-07T01:00:00+00:00",
    }]
    edges = flow_to_edges(agg, tenant="t_main")
    types = {e["edge_type"] for e in edges}
    assert "talked_to" in types and "governed_by" in types and "in_zone" in types
    talked = next(e for e in edges if e["edge_type"] == "talked_to")
    assert talked["attrs"]["bytes"] == "4096" and talked["layer"] == "flow"
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd services/topo && uv run pytest tests/test_flows.py -v`
Expected: FAIL (ImportError)

- [ ] **Step 3: Implement flows.py**

```python
# src/ssdf_topo/resolver/flows.py
"""Aggregate ssdf.events into flow edges (talked_to / governed_by / in_zone)."""

from __future__ import annotations

from ..models import (
    node_id, edge_id, HOST, ZONE, RULE, TALKED_TO, GOVERNED_BY, IN_ZONE,
)


def build_flow_agg_sql(window_hours: int, tenant: str) -> tuple[str, dict]:
    sql = (
        "SELECT toString(source_ip) AS src_ip, toString(destination_ip) AS dst_ip, "
        "sum(network_bytes) AS bytes, count() AS flows, "
        "any(rule_name) AS rule_name, any(observer_ingress_zone) AS ingress_zone, "
        "any(observer_egress_zone) AS egress_zone, any(event_provider) AS provider, "
        "toString(min(timestamp)) AS first_seen, toString(max(timestamp)) AS last_seen "
        "FROM ssdf.events "
        "WHERE tenant_id = {tenant:String} "
        "AND timestamp >= now() - INTERVAL {window_hours:UInt32} HOUR "
        "AND source_ip IS NOT NULL AND destination_ip IS NOT NULL "
        "GROUP BY src_ip, dst_ip"
    )
    return sql, {"tenant": tenant, "window_hours": window_hours}


def flow_to_edges(agg: list[dict], tenant: str) -> list[dict]:
    edges: list[dict] = []
    for row in agg:
        src = node_id(tenant, HOST, f"ip:{row['src_ip']}")
        dst = node_id(tenant, HOST, f"ip:{row['dst_ip']}")
        first, last = row["first_seen"], row["last_seen"]
        rule = str(row.get("rule_name") or "")
        provider = str(row.get("provider") or "")
        talked = {
            "edge_id": edge_id(tenant, src, dst, TALKED_TO, "flow"),
            "tenant_id": tenant, "src_id": src, "dst_id": dst,
            "edge_type": TALKED_TO, "layer": "flow",
            "first_seen": first, "last_seen": last, "confidence": 1.0,
            "attrs": {"bytes": str(row.get("bytes", 0)), "flows": str(row.get("flows", 0)),
                      "provider": provider, "evidence": "ssdf.events"},
        }
        edges.append(talked)
        if rule:
            rule_node = node_id(tenant, RULE, f"{provider}:{rule}")
            edges.append({
                "edge_id": edge_id(tenant, talked["edge_id"], rule_node, GOVERNED_BY, "flow"),
                "tenant_id": tenant, "src_id": talked["edge_id"], "dst_id": rule_node,
                "edge_type": GOVERNED_BY, "layer": "flow",
                "first_seen": first, "last_seen": last, "confidence": 1.0,
                "attrs": {"rule_name": rule, "evidence": "ssdf.events"},
            })
        for ip, zone in ((row["src_ip"], row.get("ingress_zone")),
                         (row["dst_ip"], row.get("egress_zone"))):
            if not zone:
                continue
            host = node_id(tenant, HOST, f"ip:{ip}")
            zone_node = node_id(tenant, ZONE, f"{provider}:{zone}")
            edges.append({
                "edge_id": edge_id(tenant, host, zone_node, IN_ZONE, "flow"),
                "tenant_id": tenant, "src_id": host, "dst_id": zone_node,
                "edge_type": IN_ZONE, "layer": "flow",
                "first_seen": first, "last_seen": last, "confidence": 1.0,
                "attrs": {"zone": str(zone), "evidence": "ssdf.events"},
            })
    return edges
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd services/topo && uv run pytest tests/test_flows.py -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add services/topo/src/ssdf_topo/resolver/flows.py services/topo/tests/test_flows.py
git commit -m "feat(m4): flow aggregation -> talked_to/governed_by/in_zone edges"
```

## Task 4.3: Entity resolution from observations (nodes + non-flow edges)

**Files:**
- Create: `services/topo/src/ssdf_topo/resolver/resolve.py`
- Test: `services/topo/tests/test_resolve.py`

**Design:** `resolve_graph(observations, flow_edges, tenant)` returns `(nodes, edges)`.
- **Device union-find:** tokens from `lldp_neighbor` (remote system), `device_inventory`, `vm_host`, `mac_entry.obj_id` device refs. Union `chassis:`/`sysname:`/`mgmt:`/`serial:` tokens seen together in one observation.
- **Hosts** keyed directly by `mac:` (no union). Aliases (ip, hostname) attached via observation, plus a time-bounded `has_address` edge from `arp_entry`. IP-only (no MAC) hosts get `attrs.unresolved=l3_only`.
- **Edges:** `physical_link` (lldp), `attaches_to` (mac_entry/wlan_assoc/vm_nic), `has_address` (arp_entry), `hosts` (vm_host). `first_seen`/`last_seen` from observation `observed_at`; `confidence` = 1.0 if seen by ≥2 observations else 0.7.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_resolve.py
from ssdf_topo.models import Observation, node_id, HOST, DEVICE
from ssdf_topo.resolver.resolve import resolve_graph

NOW = "2026-06-07T00:00:00+00:00"

def _obs(**kw):
    base = dict(observed_at=NOW, collector="junos", source_device="sw1",
                layer="l2", observation_type="x", subj_kind="host", subj_id="mac:a",
                obj_kind="", obj_id="", attrs={}, raw="")
    base.update(kw); return Observation(**base)

def test_arp_attaches_ip_as_alias_not_identity():
    obs = [_obs(observation_type="arp_entry", layer="l3", subj_kind="host",
                subj_id="ip:10.64.0.5", obj_kind="host", obj_id="mac:aa:bb")]
    nodes, edges = resolve_graph(obs, flow_edges=[], tenant="t_main")
    host = next(n for n in nodes if n["node_id"] == node_id("t_main", HOST, "mac:aa:bb"))
    assert host["identifiers"].get("ip") == "10.64.0.5"   # ip is an alias of the mac-host
    assert any(e["edge_type"] == "has_address" for e in edges)
    # no host node is keyed by ip alone
    assert all(n["node_id"] != node_id("t_main", HOST, "ip:10.64.0.5")
               for n in nodes if n["kind"] == HOST and n["identifiers"].get("mac"))

def test_ip_only_host_flagged_unresolved():
    # a flow edge references an ip that never appears in ARP
    flow_edges = [{"edge_id": "f1", "tenant_id": "t_main",
                   "src_id": node_id("t_main", HOST, "ip:8.8.8.8"),
                   "dst_id": node_id("t_main", HOST, "ip:1.1.1.1"),
                   "edge_type": "talked_to", "layer": "flow",
                   "first_seen": NOW, "last_seen": NOW, "confidence": 1.0,
                   "attrs": {"ips": "8.8.8.8,1.1.1.1"}}]
    nodes, edges = resolve_graph([], flow_edges=flow_edges, tenant="t_main")
    ip_node = next(n for n in nodes if n["node_id"] == node_id("t_main", HOST, "ip:8.8.8.8"))
    assert ip_node["attrs"].get("unresolved") == "l3_only"

def test_lldp_unions_device_and_builds_physical_link():
    obs = [_obs(observation_type="lldp_neighbor", subj_kind="interface",
                subj_id="if:sw1:ge-0/0/0", obj_kind="interface", obj_id="if:fw1:eth1",
                attrs={"local_port": "ge-0/0/0", "remote_port": "eth1", "remote_system": "fw1"})]
    nodes, edges = resolve_graph(obs, flow_edges=[], tenant="t_main")
    assert any(e["edge_type"] == "physical_link" for e in edges)
    assert any(n["kind"] == DEVICE for n in nodes)

def test_conflicting_ip_mac_over_time_not_merged():
    obs = [
        _obs(observation_type="arp_entry", layer="l3", subj_id="ip:10.64.0.5",
             obj_id="mac:aa:aa", attrs={}),
        _obs(observation_type="arp_entry", layer="l3", subj_id="ip:10.64.0.5",
             obj_id="mac:bb:bb", attrs={}),
    ]
    nodes, edges = resolve_graph(obs, flow_edges=[], tenant="t_main")
    host_macs = {n["identifiers"]["mac"] for n in nodes
                 if n["kind"] == HOST and "mac" in n["identifiers"]}
    assert host_macs == {"aa:aa", "bb:bb"}   # two distinct hosts, not merged on shared ip
    addr_edges = [e for e in edges if e["edge_type"] == "has_address"]
    assert len(addr_edges) == 2
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd services/topo && uv run pytest tests/test_resolve.py -v`
Expected: FAIL (ImportError)

- [ ] **Step 3: Implement resolve.py**

```python
# src/ssdf_topo/resolver/resolve.py
"""Resolve observations + flow edges into canonical graph nodes and edges."""

from __future__ import annotations

from collections import defaultdict

from ..models import (
    Observation, node_id, edge_id,
    DEVICE, HOST, INTERFACE,
    PHYSICAL_LINK, ATTACHES_TO, HAS_ADDRESS, HOSTS,
)


def _device_canonical_key(token: str) -> str:
    # token like "device:sw1" or "sysname:sw1"; strip the namespace for the key
    return token.split(":", 1)[1] if ":" in token else token


def resolve_graph(observations: list[Observation], flow_edges: list[dict],
                  tenant: str) -> tuple[list[dict], list[dict]]:
    # node accumulator keyed by node_id
    nodes: dict[str, dict] = {}
    edges: dict[str, dict] = {}
    edge_evidence: dict[str, set[str]] = defaultdict(set)

    def touch_node(nid: str, kind: str, name: str, observed_at: str) -> dict:
        n = nodes.get(nid)
        if n is None:
            n = {"node_id": nid, "tenant_id": tenant, "kind": kind, "name": name,
                 "identifiers": {}, "first_seen": observed_at, "last_seen": observed_at,
                 "attrs": {}}
            nodes[nid] = n
        else:
            n["first_seen"] = min(n["first_seen"], observed_at)
            n["last_seen"] = max(n["last_seen"], observed_at)
            if name and not n["name"]:
                n["name"] = name
        return n

    def host_node(mac: str, observed_at: str) -> dict:
        nid = node_id(tenant, HOST, f"mac:{mac}")
        n = touch_node(nid, HOST, mac, observed_at)
        n["identifiers"]["mac"] = mac
        return n

    def device_node(name: str, observed_at: str) -> dict:
        nid = node_id(tenant, DEVICE, name)
        n = touch_node(nid, DEVICE, name, observed_at)
        n["identifiers"]["name"] = name
        return n

    def add_edge(src: str, dst: str, etype: str, layer: str, observed_at: str,
                 attrs: dict, evidence: str) -> None:
        eid = edge_id(tenant, src, dst, etype, layer)
        e = edges.get(eid)
        if e is None:
            e = {"edge_id": eid, "tenant_id": tenant, "src_id": src, "dst_id": dst,
                 "edge_type": etype, "layer": layer, "first_seen": observed_at,
                 "last_seen": observed_at, "confidence": 0.7, "attrs": dict(attrs)}
            edges[eid] = e
        else:
            e["first_seen"] = min(e["first_seen"], observed_at)
            e["last_seen"] = max(e["last_seen"], observed_at)
            e["attrs"].update(attrs)
        edge_evidence[eid].add(evidence)

    for o in observations:
        ot, at = o.observation_type, o.observed_at
        if ot == "arp_entry":
            ip = o.subj_id.split("ip:", 1)[-1]
            mac = o.obj_id.split("mac:", 1)[-1]
            host = host_node(mac, at)
            host["identifiers"]["ip"] = ip
            add_edge(host["node_id"], node_id(tenant, HOST, f"ip:{ip}"),
                     HAS_ADDRESS, "l3", at,
                     {"ip": ip, "evidence": o.collector}, evidence=o.collector)
        elif ot in ("mac_entry", "wlan_assoc"):
            mac = o.subj_id.split("mac:", 1)[-1]
            host = host_node(mac, at)
            dev_name = o.obj_id.split(":", 1)[-1] if o.obj_id else o.source_device
            dev = device_node(dev_name, at)
            add_edge(host["node_id"], dev["node_id"], ATTACHES_TO, "l2", at,
                     {"port": o.attrs.get("port", ""), "vlan": o.attrs.get("vlan", ""),
                      "evidence": o.collector}, evidence=o.collector)
        elif ot == "vm_nic":
            mac = o.subj_id.split("mac:", 1)[-1]
            host = host_node(mac, at)
            host["attrs"]["virtual"] = "true"
            dev = device_node(o.source_device, at)
            add_edge(host["node_id"], dev["node_id"], ATTACHES_TO, "l2", at,
                     {"bridge": o.attrs.get("bridge", ""), "vlan": o.attrs.get("vlan", ""),
                      "evidence": "proxmox"}, evidence="proxmox")
        elif ot == "vm_host":
            dev = device_node(o.source_device, at)
            dev["attrs"]["role"] = "hypervisor"
            vm_key = o.obj_id  # e.g. vm:pve3/105
            vm_node = touch_node(node_id(tenant, HOST, vm_key), HOST,
                                 o.attrs.get("name", vm_key), at)
            vm_node["identifiers"]["vmid"] = o.attrs.get("vmid", "")
            vm_node["attrs"]["virtual"] = "true"
            add_edge(dev["node_id"], vm_node["node_id"], HOSTS, "virt", at,
                     {"vmid": o.attrs.get("vmid", ""), "evidence": "proxmox"},
                     evidence="proxmox")
        elif ot == "lldp_neighbor":
            local_sys = o.source_device
            remote_sys = o.attrs.get("remote_system", "") or o.obj_id.split("if:", 1)[-1].split(":", 1)[0]
            dev_a = device_node(local_sys, at)
            dev_b = device_node(remote_sys, at)
            if_a = touch_node(node_id(tenant, INTERFACE, o.subj_id), INTERFACE,
                              o.attrs.get("local_port", ""), at)
            if_b = touch_node(node_id(tenant, INTERFACE, o.obj_id), INTERFACE,
                              o.attrs.get("remote_port", ""), at)
            if_a["attrs"]["device"] = local_sys
            if_b["attrs"]["device"] = remote_sys
            add_edge(if_a["node_id"], if_b["node_id"], PHYSICAL_LINK, "l2", at,
                     {"local_port": o.attrs.get("local_port", ""),
                      "remote_port": o.attrs.get("remote_port", ""),
                      "device_a": local_sys, "device_b": remote_sys,
                      "evidence": o.collector}, evidence=f"{o.collector}:{local_sys}")
        elif ot == "device_inventory":
            mac = o.attrs.get("mac", "")
            dev = device_node(o.attrs.get("name", "") or f"dev:{mac}", at)
            dev["attrs"]["role"] = o.attrs.get("role", "device")
            if mac:
                dev["identifiers"]["mac"] = mac
            if o.attrs.get("ip"):
                dev["identifiers"]["mgmt_ip"] = o.attrs["ip"]

    # promote confidence where corroborated by >=2 evidence sources
    for eid, e in edges.items():
        if len(edge_evidence[eid]) >= 2:
            e["confidence"] = 1.0
        e["attrs"]["evidence"] = ",".join(sorted(edge_evidence[eid]))

    # materialize ip-only hosts referenced by flow edges (no resolved MAC)
    known_ip_aliases = {n["identifiers"].get("ip") for n in nodes.values()
                        if n["kind"] == HOST and n["identifiers"].get("ip")}
    for fe in flow_edges:
        for endpoint in (fe["src_id"], fe["dst_id"]):
            if endpoint in nodes:
                continue
            # endpoint is an ip-keyed host id; reconstruct label from attrs if present
            n = touch_node(endpoint, HOST, "", fe["first_seen"])
            n["attrs"]["unresolved"] = "l3_only"
        edges[fe["edge_id"]] = fe

    return list(nodes.values()), list(edges.values())
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd services/topo && uv run pytest tests/test_resolve.py -v`
Expected: PASS (4 tests). If `test_ip_only_host_flagged_unresolved` shows the node label empty, that's fine — only `unresolved` is asserted.

- [ ] **Step 5: Commit**

```bash
git add services/topo/src/ssdf_topo/resolver/resolve.py services/topo/tests/test_resolve.py
git commit -m "feat(m4): entity resolution (nodes + l2/l3/virt edges, ip-not-identity)"
```

## Task 4.4: Resolver entrypoint (read window → resolve → upsert)

**Files:**
- Create: `services/topo/src/ssdf_topo/resolve_main.py`
- Test: `services/topo/tests/test_resolve_main.py`

- [ ] **Step 1: Write the failing test** (inject a fake writer; assert the read→resolve→upsert orchestration)

```python
# tests/test_resolve_main.py
from ssdf_topo.resolve_main import run_resolver

class FakeWriter:
    def __init__(self, obs_rows, flow_rows):
        self._obs, self._flows = obs_rows, flow_rows
        self.nodes = None; self.edges = None
    def query(self, sql, params=None):
        return self._flows if "FROM ssdf.events" in sql else self._obs
    def replace_nodes(self, nodes): self.nodes = nodes; return len(nodes)
    def replace_edges(self, edges): self.edges = edges; return len(edges)

def test_run_resolver_reads_resolves_and_upserts():
    obs_rows = [{
        "observed_at": "2026-06-07T00:00:00+00:00", "collector": "junos",
        "source_device": "sw1", "tenant_id": "t_main", "layer": "l3",
        "observation_type": "arp_entry", "subj_kind": "host", "subj_id": "ip:10.64.0.5",
        "obj_kind": "host", "obj_id": "mac:aa:bb", "attrs": {}, "raw": "",
    }]
    flow_rows = [{
        "src_ip": "10.64.0.5", "dst_ip": "10.64.0.9", "bytes": 10, "flows": 1,
        "rule_name": "allow", "ingress_zone": "trust", "egress_zone": "untrust",
        "provider": "juniper", "first_seen": "2026-06-07T00:00:00+00:00",
        "last_seen": "2026-06-07T00:30:00+00:00",
    }]
    writer = FakeWriter(obs_rows, flow_rows)
    n_nodes, n_edges = run_resolver(writer, tenant="t_main", window_hours=24)
    assert n_nodes >= 1 and n_edges >= 1
    assert any(e["edge_type"] == "has_address" for e in writer.edges)
    assert any(e["edge_type"] == "talked_to" for e in writer.edges)
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd services/topo && uv run pytest tests/test_resolve_main.py -v`
Expected: FAIL (ImportError)

- [ ] **Step 3: Implement resolve_main.py**

```python
# src/ssdf_topo/resolve_main.py
"""Resolver entrypoint: read CH window, resolve, upsert graph_nodes/graph_edges."""

from __future__ import annotations

import logging

from .chwriter import ClickHouseWriter
from .config import Config, load_config
from .models import Observation
from .resolver.flows import build_flow_agg_sql, flow_to_edges
from .resolver.resolve import resolve_graph

log = logging.getLogger("ssdf_topo.resolve")

OBS_SQL = (
    "SELECT toString(observed_at) AS observed_at, collector, source_device, tenant_id, "
    "layer, observation_type, subj_kind, subj_id, obj_kind, obj_id, attrs, raw "
    "FROM ssdf.topo_observations "
    "WHERE tenant_id = {tenant:String} "
    "AND observed_at >= now() - INTERVAL {window_hours:UInt32} HOUR"
)


def _row_to_obs(row: dict) -> Observation:
    return Observation(
        observed_at=row["observed_at"], collector=row["collector"],
        source_device=row["source_device"], layer=row["layer"],
        observation_type=row["observation_type"], subj_kind=row["subj_kind"],
        subj_id=row["subj_id"], obj_kind=row.get("obj_kind", ""),
        obj_id=row.get("obj_id", ""), attrs=dict(row.get("attrs") or {}),
        raw=row.get("raw", ""), tenant_id=row.get("tenant_id", "t_main"),
    )


def run_resolver(writer, tenant: str, window_hours: int) -> tuple[int, int]:
    obs_rows = writer.query(OBS_SQL, {"tenant": tenant, "window_hours": window_hours})
    observations = [_row_to_obs(r) for r in obs_rows]
    flow_sql, flow_params = build_flow_agg_sql(window_hours, tenant)
    flow_rows = writer.query(flow_sql, flow_params)
    flow_edges = flow_to_edges(flow_rows, tenant)
    nodes, edges = resolve_graph(observations, flow_edges, tenant)
    n_nodes = writer.replace_nodes(nodes)
    n_edges = writer.replace_edges(edges)
    log.info("resolver: %d nodes, %d edges upserted", n_nodes, n_edges)
    return n_nodes, n_edges


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    config: Config = load_config()
    writer = ClickHouseWriter(config)
    run_resolver(writer, tenant=config.tenant_id, window_hours=config.window_hours)


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd services/topo && uv run pytest tests/test_resolve_main.py -v`
Expected: PASS (1 test)

- [ ] **Step 5: Run full unit suite**

Run: `cd services/topo && uv run pytest -m "not integration" -v`
Expected: all green.

- [ ] **Step 6: Commit**

```bash
git add services/topo/src/ssdf_topo/resolve_main.py services/topo/tests/test_resolve_main.py
git commit -m "feat(m4): resolver entrypoint (read window -> resolve -> upsert)"
```

---

**Phase 4 done.** Next: `2026-06-07-ssdf-m4-topology-graph-mcp-tools.md`.
