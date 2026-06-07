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
