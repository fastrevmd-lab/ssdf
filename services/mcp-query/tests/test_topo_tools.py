from ssdf_mcp_query.topo_tools import TopoTools

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
    {"edge_id": "e2", "src_id": "sw1", "dst_id": "fw1", "edge_type": "physical_link",
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
    def nodes_by_attr(self, role=None, kind=None, limit=5000):
        # Mirrors ClickHouseGraphStore: select nodes directly (NOT edge-derived),
        # so isolated role/kind nodes are reachable.
        out = NODES
        if role is not None:
            out = [n for n in out if n.get("attrs", {}).get("role") == role]
        if kind is not None:
            out = [n for n in out if n.get("kind") == kind]
        return out

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


def test_topology_snapshot_role_filters_to_firewalls():
    out = tools().topology_snapshot(role="firewall")
    names = {n["name"] for n in out["nodes"]}
    assert names == {"fw1"}              # only the role=firewall node survives
    assert out["node_count"] == 1
    # edges are pruned to those between surviving nodes
    for e in out["edges"]:
        assert e["src_id"] in {n["node_id"] for n in out["nodes"]}
        assert e["dst_id"] in {n["node_id"] for n in out["nodes"]}


def test_topology_snapshot_kind_filters_to_devices():
    out = tools().topology_snapshot(kind="device")
    kinds = {n["kind"] for n in out["nodes"]}
    assert kinds == {"device"}           # sw1 + fw1
    assert out["node_count"] == 2


def test_topology_snapshot_no_filter_unchanged():
    out = tools().topology_snapshot()
    assert out["node_count"] == len(NODES)


def test_topology_snapshot_role_surfaces_isolated_nodes():
    # Regression (live-found 2026-06-19): firewall device_inventory nodes are
    # isolated (no edges). The edge-derived subgraph excludes them, so the
    # role-filter path MUST query nodes directly. Here load_subgraph yields an
    # empty subgraph yet the firewall must still appear.
    iso_fw = {"node_id": "fwX", "kind": "device", "name": "panosvm",
              "identifiers": {"name": "panosvm"}, "first_seen": "x",
              "last_seen": "y", "attrs": {"role": "firewall"}}

    class IsolatedStore:
        def find_node(self, identifier): return None
        def load_subgraph(self, since_iso, limit=5000): return [], []
        def nodes_by_attr(self, role=None, kind=None, limit=5000):
            return [iso_fw] if role == "firewall" else []

    out = TopoTools(IsolatedStore()).topology_snapshot(role="firewall")
    assert {n["name"] for n in out["nodes"]} == {"panosvm"}
    assert out["edges"] == []
