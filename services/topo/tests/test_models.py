# tests/test_models.py
from ssdf_topo.models import (
    Observation, node_id, edge_id, NODE_KINDS, EDGE_TYPES, LAYERS,
    HOST, DEVICE, PHYSICAL_LINK,
)

def test_node_id_is_deterministic_and_keyed():
    a = node_id("t_main", HOST, "mac:aa:bb:cc:dd:ee:ff")
    b = node_id("t_main", HOST, "mac:aa:bb:cc:dd:ee:ff")
    c = node_id("t_main", HOST, "mac:11:22:33:44:55:66")
    assert a == b and a != c
    assert len(a) == 16

def test_node_id_kind_separates_namespace():
    assert node_id("t_main", HOST, "x") != node_id("t_main", DEVICE, "x")

def test_edge_id_is_directional_and_typed():
    e1 = edge_id("t_main", "n1", "n2", PHYSICAL_LINK, "l2")
    e2 = edge_id("t_main", "n2", "n1", PHYSICAL_LINK, "l2")
    assert e1 != e2 and len(e1) == 16

def test_observation_defaults():
    obs = Observation(
        observed_at="2026-06-07T00:00:00+00:00", collector="junos",
        source_device="vSRX-test10", layer="l2", observation_type="lldp_neighbor",
        subj_kind="interface", subj_id="if:vSRX-test10:ge-0/0/0",
        obj_kind="interface", obj_id="if:sw1:ge-1",
    )
    assert obs.tenant_id == "t_main" and obs.attrs == {} and obs.raw == ""

def test_taxonomy_constants():
    assert HOST in NODE_KINDS and DEVICE in NODE_KINDS
    assert PHYSICAL_LINK in EDGE_TYPES
    assert "l2" in LAYERS and "flow" in LAYERS
