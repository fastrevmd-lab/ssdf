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
        for e in edges:
            if e["edge_type"] == "talked_to" and {e["src_id"], e["dst_id"]} == {s, d}:
                tid = e["edge_id"]
                for g in edges:
                    if g["edge_type"] == "governed_by" and g["src_id"] == tid:
                        rule = node_by_id.get(g["dst_id"], {})
                        rules.add(rule.get("name") or g["attrs"].get("rule_name", ""))
            if e["edge_type"] == "in_zone" and e["src_id"] in (s, d):
                zones.add(e["attrs"].get("zone", ""))
        ug = self._undirected_layer(graph, {"l1", "l2"})
        for endpoint in (s, d):
            if endpoint not in ug:
                continue
            for n_id in nx.node_connected_component(ug, endpoint):
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
