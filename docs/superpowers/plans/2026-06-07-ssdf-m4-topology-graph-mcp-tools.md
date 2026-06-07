# SSDF M4 — Phase 5: Topology MCP tools

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development or superpowers:executing-plans. Prerequisite: Phases 0–4 complete; `graph_nodes`/`graph_edges` exist in CH.

**Goal:** Add a read-only topology tool group to the existing `ssdf-mcp-query` service (ct106): `get_entity`, `locate`, `neighbors`, `find_path`, `enforcement_points`, `topology_snapshot`. Tools load the (small, lab-scale) subgraph from CH and traverse in memory (networkx) behind a `GraphStore` seam. All read-only.

**Files live in `services/mcp-query/`** (the consumer service), not `services/topo/`.

---

## Task 5.1: Add networkx dependency

**Files:**
- Modify: `services/mcp-query/pyproject.toml`

- [ ] **Step 1: Add `networkx` to dependencies**

In `[project].dependencies`, add `"networkx>=3.0"` so the block reads:
```toml
dependencies = [
    "fastmcp>=2.0",
    "clickhouse-connect>=0.8",
    "sqlglot>=25.0",
    "networkx>=3.0",
]
```

- [ ] **Step 2: Sync**

Run: `cd services/mcp-query && uv sync --extra dev`
Expected: installs networkx without error.

- [ ] **Step 3: Commit**

```bash
git add services/mcp-query/pyproject.toml services/mcp-query/uv.lock
git commit -m "chore(m4): add networkx to mcp-query for graph traversal"
```

## Task 5.2: GraphStore (CH-backed read seam)

**Files:**
- Create: `services/mcp-query/src/ssdf_mcp_query/graphstore.py`
- Test: `services/mcp-query/tests/test_graphstore.py`

**Design:** `GraphStore` is the interface tools call. `ClickHouseGraphStore` reads `graph_nodes`/`graph_edges` (deduped via `FINAL`) and exposes:
- `find_node(identifier) -> dict | None` — match a node whose `identifiers` map contains the value (ip/mac/hostname/name) or whose `node_id` equals it.
- `load_subgraph(since_iso, node_ids=None) -> (nodes, edges)` — staleness-filtered edges (`last_seen >= since`) plus their incident nodes.

- [ ] **Step 1: Write the failing test** (a fake CH client returns canned rows; tests the SQL shape + matching logic)

```python
# tests/test_graphstore.py
from ssdf_mcp_query.graphstore import ClickHouseGraphStore, build_node_match_sql, build_subgraph_sql

class FakeCH:
    def __init__(self): self.calls = []
    def run(self, sql, params=None):
        self.calls.append((sql, params or {}))
        if "graph_nodes" in sql and "WHERE" in sql:
            return {"columns": [], "rows": [{
                "node_id": "n1", "kind": "host", "name": "h1",
                "identifiers": {"mac": "aa:bb", "ip": "10.64.0.5"},
                "first_seen": "x", "last_seen": "y", "attrs": {}}], "row_count": 1}
        if "graph_edges" in sql:
            return {"columns": [], "rows": [{
                "edge_id": "e1", "src_id": "n1", "dst_id": "n2",
                "edge_type": "attaches_to", "layer": "l2", "first_seen": "x",
                "last_seen": "y", "confidence": 1.0, "attrs": {"port": "3"}}], "row_count": 1}
        return {"columns": [], "rows": [], "row_count": 0}

def test_node_match_sql_uses_final_and_binds_value():
    sql, params = build_node_match_sql("10.64.0.5", tenant="t_main")
    assert "graph_nodes FINAL" in sql
    assert "{val:String}" in sql
    assert params["val"] == "10.64.0.5"

def test_subgraph_sql_filters_staleness():
    sql, params = build_subgraph_sql(since_iso="2026-06-06T00:00:00+00:00", tenant="t_main")
    assert "graph_edges FINAL" in sql
    assert "last_seen >=" in sql
    assert params["since"] == "2026-06-06T00:00:00+00:00"

def test_find_node_returns_match():
    store = ClickHouseGraphStore(FakeCH(), tenant="t_main")
    node = store.find_node("10.64.0.5")
    assert node["node_id"] == "n1" and node["identifiers"]["ip"] == "10.64.0.5"
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd services/mcp-query && uv run pytest tests/test_graphstore.py -v`
Expected: FAIL (ImportError)

- [ ] **Step 3: Implement graphstore.py**

```python
# src/ssdf_mcp_query/graphstore.py
"""Read-only graph access seam over ClickHouse graph_nodes/graph_edges."""

from __future__ import annotations

from typing import Protocol


def build_node_match_sql(value: str, tenant: str) -> tuple[str, dict]:
    sql = (
        "SELECT node_id, kind, name, identifiers, toString(first_seen) AS first_seen, "
        "toString(last_seen) AS last_seen, attrs FROM ssdf.graph_nodes FINAL "
        "WHERE tenant_id = {tenant:String} AND ("
        "node_id = {val:String} OR has(mapValues(identifiers), {val:String})) "
        "ORDER BY last_seen DESC LIMIT 1"
    )
    return sql, {"tenant": tenant, "val": value}


def build_subgraph_sql(since_iso: str, tenant: str, limit: int = 5000) -> tuple[str, dict]:
    sql = (
        "SELECT edge_id, src_id, dst_id, edge_type, layer, "
        "toString(first_seen) AS first_seen, toString(last_seen) AS last_seen, "
        "confidence, attrs FROM ssdf.graph_edges FINAL "
        "WHERE tenant_id = {tenant:String} AND last_seen >= {since:String} "
        f"ORDER BY last_seen DESC LIMIT {int(limit)}"
    )
    return sql, {"tenant": tenant, "since": since_iso}


def build_nodes_by_id_sql(node_ids: list[str], tenant: str) -> tuple[str, dict]:
    sql = (
        "SELECT node_id, kind, name, identifiers, toString(first_seen) AS first_seen, "
        "toString(last_seen) AS last_seen, attrs FROM ssdf.graph_nodes FINAL "
        "WHERE tenant_id = {tenant:String} AND node_id IN {ids:Array(String)}"
    )
    return sql, {"tenant": tenant, "ids": node_ids}


class GraphStore(Protocol):
    def find_node(self, identifier: str) -> dict | None: ...
    def load_subgraph(self, since_iso: str, limit: int = 5000) -> tuple[list[dict], list[dict]]: ...


class ClickHouseGraphStore:
    """GraphStore backed by ClickHouse (the swappable storage seam)."""

    def __init__(self, ch_client, tenant: str = "t_main"):
        self._ch = ch_client
        self._tenant = tenant

    def find_node(self, identifier: str) -> dict | None:
        sql, params = build_node_match_sql(identifier, self._tenant)
        rows = self._ch.run(sql, params)["rows"]
        return rows[0] if rows else None

    def load_subgraph(self, since_iso: str, limit: int = 5000) -> tuple[list[dict], list[dict]]:
        edge_sql, edge_params = build_subgraph_sql(since_iso, self._tenant, limit)
        edges = self._ch.run(edge_sql, edge_params)["rows"]
        node_ids = sorted({e["src_id"] for e in edges} | {e["dst_id"] for e in edges})
        nodes: list[dict] = []
        if node_ids:
            node_sql, node_params = build_nodes_by_id_sql(node_ids, self._tenant)
            nodes = self._ch.run(node_sql, node_params)["rows"]
        return nodes, edges
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd services/mcp-query && uv run pytest tests/test_graphstore.py -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add services/mcp-query/src/ssdf_mcp_query/graphstore.py services/mcp-query/tests/test_graphstore.py
git commit -m "feat(m4): GraphStore seam (ClickHouse read of graph_nodes/edges)"
```

## Task 5.3: Topology tools (traversal logic)

**Files:**
- Create: `services/mcp-query/src/ssdf_mcp_query/topo_tools.py`
- Test: `services/mcp-query/tests/test_topo_tools.py`

**Design:** `TopoTools(store)` builds a networkx graph from `load_subgraph` and answers queries. `enforcement_points` finds, on the path between two endpoints, the `device(role=firewall)` nodes and the `rule`/`zone` governing the `talked_to` edge between them.

- [ ] **Step 1: Write the failing test** (a fake GraphStore returns a fixed fused subgraph)

```python
# tests/test_topo_tools.py
from ssdf_mcp_query.topo_tools import TopoTools

# fused chain: host(h_mac) --attaches_to--> sw1 --physical_link--> fw1 ;
# host(h_ip)=h_mac --talked_to--> host(dst) --governed_by--> rule ; in_zone
NODES = [
    {"node_id": "h", "kind": "host", "name": "h1",
     "identifiers": {"mac": "aa:bb", "ip": "10.64.0.5"}, "first_seen": "x", "last_seen": "y", "attrs": {}},
    {"node_id": "d", "kind": "host", "name": "d1",
     "identifiers": {"ip": "10.64.0.9"}, "first_seen": "x", "last_seen": "y", "attrs": {}},
    {"node_id": "sw1", "kind": "device", "name": "sw1",
     "identifiers": {"name": "sw1"}, "first_seen": "x", "last_seen": "y", "attrs": {"role": "switch"}},
    {"node_id": "fw1", "kind": "device", "name": "fw1",
     "identifiers": {"name": "fw1"}, "first_seen": "x", "last_seen": "y", "attrs": {"role": "firewall"}},
    {"node_id": "r1", "kind": "rule", "name": "allow-web",
     "identifiers": {}, "first_seen": "x", "last_seen": "y", "attrs": {}},
    {"node_id": "z1", "kind": "zone", "name": "untrust",
     "identifiers": {}, "first_seen": "x", "last_seen": "y", "attrs": {}},
]
EDGES = [
    {"edge_id": "e1", "src_id": "h", "dst_id": "sw1", "edge_type": "attaches_to",
     "layer": "l2", "first_seen": "x", "last_seen": "y", "confidence": 1.0,
     "attrs": {"port": "3", "vlan": "10"}},
    {"edge_id": "e2", "src_id": "sw1if", "dst_id": "fw1if", "edge_type": "physical_link",
     "layer": "l2", "first_seen": "x", "last_seen": "y", "confidence": 1.0,
     "attrs": {"device_a": "sw1", "device_b": "fw1"}},
    {"edge_id": "t1", "src_id": "h", "dst_id": "d", "edge_type": "talked_to",
     "layer": "flow", "first_seen": "x", "last_seen": "y", "confidence": 1.0,
     "attrs": {"bytes": "4096"}},
    {"edge_id": "g1", "src_id": "t1", "dst_id": "r1", "edge_type": "governed_by",
     "layer": "flow", "first_seen": "x", "last_seen": "y", "confidence": 1.0,
     "attrs": {"rule_name": "allow-web"}},
    {"edge_id": "iz", "src_id": "d", "dst_id": "z1", "edge_type": "in_zone",
     "layer": "flow", "first_seen": "x", "last_seen": "y", "confidence": 1.0,
     "attrs": {"zone": "untrust"}},
]

class FakeStore:
    def find_node(self, identifier):
        for n in NODES:
            if n["node_id"] == identifier or identifier in n["identifiers"].values():
                return n
        return None
    def load_subgraph(self, since_iso, limit=5000):
        return NODES, EDGES

def tools(): return TopoTools(FakeStore())

def test_get_entity_resolves_alias():
    out = tools().get_entity("10.64.0.5")
    assert out["node"]["identifiers"]["mac"] == "aa:bb"

def test_get_entity_not_found():
    out = tools().get_entity("9.9.9.9")
    assert out.get("error") == "not_found"

def test_locate_returns_attach_point():
    out = tools().locate("aa:bb")
    assert out["attached_to"] == "sw1"
    assert out["port"] == "3" and out["vlan"] == "10"

def test_neighbors_depth1():
    out = tools().neighbors("h", depth=1)
    nbr_ids = {n["node_id"] for n in out["nodes"]}
    assert "sw1" in nbr_ids and "d" in nbr_ids

def test_find_path_physical():
    out = tools().find_path("h", "fw1", layer="physical")
    assert out["found"] is True
    assert "fw1" in [n for n in out["path_nodes"]]

def test_enforcement_points_names_firewall_and_rule():
    out = tools().enforcement_points("10.64.0.5", "10.64.0.9")
    assert "allow-web" in out["rules"]
    assert "fw1" in out["firewalls"]

def test_topology_snapshot_bounded():
    out = tools().topology_snapshot()
    assert out["node_count"] == len(NODES)
    assert out["truncated"] is False
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd services/mcp-query && uv run pytest tests/test_topo_tools.py -v`
Expected: FAIL (ImportError)

- [ ] **Step 3: Implement topo_tools.py**

```python
# src/ssdf_mcp_query/topo_tools.py
"""Read-only topology query tools: load subgraph from GraphStore, traverse in memory."""

from __future__ import annotations

import datetime as _dt

import networkx as nx

DEFAULT_WINDOW_HOURS = 24
MAX_NODES = 5000


def _since(hours: int) -> str:
    return (_dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(hours=hours)).isoformat(
        timespec="milliseconds")


class TopoTools:
    """Stateless topology tool surface bound to a GraphStore."""

    def __init__(self, store, default_window_hours: int = DEFAULT_WINDOW_HOURS):
        self._store = store
        self._window = default_window_hours

    # --- graph building ---
    def _build(self, since_hours: int) -> tuple[nx.MultiDiGraph, dict, list[dict]]:
        nodes, edges = self._store.load_subgraph(_since(since_hours), limit=MAX_NODES)
        node_by_id = {n["node_id"]: n for n in nodes}
        graph = nx.MultiDiGraph()
        for n in nodes:
            graph.add_node(n["node_id"], **n)
        for e in edges:
            graph.add_edge(e["src_id"], e["dst_id"], key=e["edge_id"], **e)
        return graph, node_by_id, edges

    def _undirected_layer(self, graph: nx.MultiDiGraph, layers: set[str]) -> nx.Graph:
        ug = nx.Graph()
        ug.add_nodes_from(graph.nodes(data=True))
        for u, v, data in graph.edges(data=True):
            if data.get("layer") in layers:
                ug.add_edge(u, v, **data)
        return ug

    # --- tools ---
    def get_entity(self, identifier: str) -> dict:
        node = self._store.find_node(identifier)
        if not node:
            return {"error": "not_found", "detail": f"no entity matches '{identifier}'"}
        return {"node": node}

    def locate(self, identifier: str) -> dict:
        node = self._store.find_node(identifier)
        if not node:
            return {"error": "not_found", "detail": f"no entity matches '{identifier}'"}
        graph, _, _ = self._build(self._window)
        nid = node["node_id"]
        result = {"entity": nid, "name": node.get("name", ""), "attached_to": None,
                  "port": None, "vlan": None, "via": None}
        if nid in graph:
            for _, dst, data in graph.out_edges(nid, data=True):
                if data.get("edge_type") == "attaches_to":
                    result["attached_to"] = dst
                    result["port"] = data["attrs"].get("port") or data["attrs"].get("bridge")
                    result["vlan"] = data["attrs"].get("vlan")
                    result["via"] = "bridge" if data["attrs"].get("bridge") else "switchport"
                    break
        return result

    def neighbors(self, identifier: str, layer: str | None = None, depth: int = 1,
                  since_hours: int | None = None) -> dict:
        node = self._store.find_node(identifier)
        if not node:
            return {"error": "not_found", "detail": f"no entity matches '{identifier}'"}
        graph, node_by_id, _ = self._build(since_hours or self._window)
        nid = node["node_id"]
        if nid not in graph:
            return {"nodes": [node], "edges": []}
        ug = graph.to_undirected(as_view=False)
        reach = nx.ego_graph(ug, nid, radius=depth)
        out_nodes, out_edges = [], []
        for n_id in reach.nodes:
            if n_id in node_by_id:
                out_nodes.append(node_by_id[n_id])
        for u, v, data in graph.edges(data=True):
            if u in reach.nodes and v in reach.nodes:
                if layer is None or data.get("layer") == layer:
                    out_edges.append(data)
        return {"nodes": out_nodes, "edges": out_edges, "root": nid}

    def find_path(self, src: str, dst: str, layer: str = "any") -> dict:
        src_node = self._store.find_node(src)
        dst_node = self._store.find_node(dst)
        if not src_node or not dst_node:
            return {"found": False, "error": "not_found"}
        graph, _, _ = self._build(self._window)
        layer_sets = {"physical": {"l1", "l2"}, "flow": {"flow", "l3"},
                      "any": {"l1", "l2", "l3", "virt", "flow"}}
        ug = self._undirected_layer(graph, layer_sets.get(layer, layer_sets["any"]))
        s, d = src_node["node_id"], dst_node["node_id"]
        if s not in ug or d not in ug or not nx.has_path(ug, s, d):
            return {"found": False, "src": s, "dst": d}
        path = nx.shortest_path(ug, s, d)
        return {"found": True, "src": s, "dst": d, "path_nodes": path, "hops": len(path) - 1}

    def enforcement_points(self, src: str, dst: str) -> dict:
        src_node = self._store.find_node(src)
        dst_node = self._store.find_node(dst)
        if not src_node or not dst_node:
            return {"error": "not_found"}
        graph, node_by_id, edges = self._build(self._window)
        s, d = src_node["node_id"], dst_node["node_id"]
        firewalls, rules, zones = set(), set(), set()
        # rules/zones governing the direct flow between the two endpoints
        for e in edges:
            if e["edge_type"] == "talked_to" and {e["src_id"], e["dst_id"]} == {s, d}:
                tid = e["edge_id"]
                for g in edges:
                    if g["edge_type"] == "governed_by" and g["src_id"] == tid:
                        rule = node_by_id.get(g["dst_id"], {})
                        rules.add(rule.get("name") or g["attrs"].get("rule_name", ""))
            if e["edge_type"] == "in_zone" and e["src_id"] in (s, d):
                zones.add(e["attrs"].get("zone", ""))
        # firewalls on the physical path between the two endpoints
        ug = self._undirected_layer(graph, {"l1", "l2"})
        if s in ug and d in ug and nx.has_path(ug, s, d):
            for n_id in nx.shortest_path(ug, s, d):
                node = node_by_id.get(n_id, {})
                if node.get("kind") == "device" and node.get("attrs", {}).get("role") == "firewall":
                    firewalls.add(node.get("name") or n_id)
        return {"src": s, "dst": d, "firewalls": sorted(f for f in firewalls if f),
                "rules": sorted(r for r in rules if r),
                "zones": sorted(z for z in zones if z)}

    def topology_snapshot(self, layer: str | None = None,
                          since_hours: int | None = None) -> dict:
        nodes, edges = self._store.load_subgraph(_since(since_hours or self._window),
                                                 limit=MAX_NODES)
        if layer:
            edges = [e for e in edges if e.get("layer") == layer]
        truncated = len(nodes) >= MAX_NODES
        return {"nodes": nodes, "edges": edges, "node_count": len(nodes),
                "edge_count": len(edges), "truncated": truncated}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd services/mcp-query && uv run pytest tests/test_topo_tools.py -v`
Expected: PASS (7 tests). (`find_path` physical: `h`→`sw1` is `attaches_to` (l2) and `sw1`→`fw1` physical_link (l2); both in the physical layer set, so the path exists.)

- [ ] **Step 5: Commit**

```bash
git add services/mcp-query/src/ssdf_mcp_query/topo_tools.py services/mcp-query/tests/test_topo_tools.py
git commit -m "feat(m4): topology query tools (locate/neighbors/find_path/enforcement_points)"
```

## Task 5.4: Register topology tools in the MCP server

**Files:**
- Modify: `services/mcp-query/src/ssdf_mcp_query/server.py`
- Test: `services/mcp-query/tests/test_server_topo.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_server_topo.py
from ssdf_mcp_query.topo_tools import TopoTools

def test_topo_tools_constructs_with_store():
    # smoke: TopoTools binds to a store and exposes the six tool methods
    class S:
        def find_node(self, i): return None
        def load_subgraph(self, since, limit=5000): return [], []
    t = TopoTools(S())
    for name in ("get_entity", "locate", "neighbors", "find_path",
                 "enforcement_points", "topology_snapshot"):
        assert callable(getattr(t, name))
```

- [ ] **Step 2: Run to verify it fails or passes** (this asserts the API surface; it should pass once topo_tools exists)

Run: `cd services/mcp-query && uv run pytest tests/test_server_topo.py -v`
Expected: PASS (1 test). If it fails, a method name drifted from Task 5.3 — fix the method name in `topo_tools.py`.

- [ ] **Step 3: Wire tools into server.py**

Add imports near the top of `build_app` body (after existing imports in the file):
```python
from .graphstore import ClickHouseGraphStore
from .topo_tools import TopoTools
```

Inside `build_app()`, after `tools = Tools(client)`, add:
```python
    graph_store = ClickHouseGraphStore(client, tenant="t_main")
    topo = TopoTools(graph_store)
```

Before `return mcp`, register the six tools:
```python
    @mcp.tool
    def get_entity(identifier: str) -> dict:
        """Resolve a canonical entity (host/device/identity) from any alias: ip, mac, hostname, or name."""
        return topo.get_entity(identifier)

    @mcp.tool
    def locate(identifier: str) -> dict:
        """Where does an entity attach? Returns switch/AP (or hypervisor bridge), port, and VLAN."""
        return topo.locate(identifier)

    @mcp.tool
    def neighbors(identifier: str, layer: str | None = None, depth: int = 1,
                  since_hours: int | None = None) -> dict:
        """Adjacent nodes/edges around an entity, optionally filtered by layer (l2|l3|flow|virt)."""
        return topo.neighbors(identifier, layer=layer, depth=depth, since_hours=since_hours)

    @mcp.tool
    def find_path(src: str, dst: str, layer: str = "any") -> dict:
        """Shortest path between two entities. layer: 'physical' (l1/l2), 'flow' (l3/flow), or 'any'."""
        return topo.find_path(src, dst, layer=layer)

    @mcp.tool
    def enforcement_points(src: str, dst: str) -> dict:
        """Read-only: firewall device(s), zone(s), and rule(s) governing traffic between two entities."""
        return topo.enforcement_points(src, dst)

    @mcp.tool
    def topology_snapshot(layer: str | None = None, since_hours: int | None = None) -> dict:
        """Bounded nodes+edges subgraph for visualization/LLM context; reports truncation."""
        return topo.topology_snapshot(layer=layer, since_hours=since_hours)
```

- [ ] **Step 4: Run the full mcp-query unit suite**

Run: `cd services/mcp-query && uv run pytest -m "not integration" -v`
Expected: all green (existing M2 tests + new graphstore/topo/server tests).

- [ ] **Step 5: Commit**

```bash
git add services/mcp-query/src/ssdf_mcp_query/server.py services/mcp-query/tests/test_server_topo.py
git commit -m "feat(m4): register topology tools in ssdf-mcp-query server"
```

---

**Phase 5 done.** Next: `2026-06-07-ssdf-m4-topology-graph-deploy.md`.
