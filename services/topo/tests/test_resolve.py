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
    assert host["identifiers"].get("ip") == "10.64.0.5"
    assert any(e["edge_type"] == "has_address" for e in edges)
    assert all(n["node_id"] != node_id("t_main", HOST, "ip:10.64.0.5")
               for n in nodes if n["kind"] == HOST and n["identifiers"].get("mac"))

def test_ip_only_host_flagged_unresolved():
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
    assert host_macs == {"aa:aa", "bb:bb"}
    addr_edges = [e for e in edges if e["edge_type"] == "has_address"]
    assert len(addr_edges) == 2
