# tests/test_chwriter.py
from ssdf_topo.models import Observation
from ssdf_topo.chwriter import obs_rows, OBS_COLUMNS, node_rows, edge_rows, NODE_COLUMNS, EDGE_COLUMNS

def test_obs_rows_match_column_order():
    obs = Observation(
        observed_at="2026-06-07T00:00:00+00:00", collector="junos",
        source_device="vSRX-test10", layer="l3", observation_type="arp_entry",
        subj_kind="host", subj_id="ip:10.64.0.5", obj_kind="host", obj_id="mac:aa:bb:cc:dd:ee:ff",
        attrs={"interface": "ge-0/0/0"}, raw="10.64.0.5 aa:bb:cc:dd:ee:ff",
    )
    rows = obs_rows([obs])
    assert len(rows) == 1
    assert len(rows[0]) == len(OBS_COLUMNS)
    # column order: observed_at first, attrs/raw/tenant near end
    idx = {c: i for i, c in enumerate(OBS_COLUMNS)}
    assert rows[0][idx["collector"]] == "junos"
    assert rows[0][idx["attrs"]] == {"interface": "ge-0/0/0"}
    assert rows[0][idx["tenant_id"]] == "t_main"

def test_node_rows_shape():
    node = {
        "node_id": "abc", "tenant_id": "t_main", "kind": "host", "name": "h1",
        "identifiers": {"mac": "aa:bb"}, "first_seen": "2026-06-07T00:00:00+00:00",
        "last_seen": "2026-06-07T01:00:00+00:00", "attrs": {"unresolved": "l3_only"},
    }
    rows = node_rows([node])
    assert len(rows[0]) == len(NODE_COLUMNS)
    assert rows[0][NODE_COLUMNS.index("kind")] == "host"

def test_edge_rows_shape():
    edge = {
        "edge_id": "e1", "tenant_id": "t_main", "src_id": "n1", "dst_id": "n2",
        "edge_type": "physical_link", "layer": "l2",
        "first_seen": "2026-06-07T00:00:00+00:00", "last_seen": "2026-06-07T01:00:00+00:00",
        "confidence": 1.0, "attrs": {},
    }
    rows = edge_rows([edge])
    assert len(rows[0]) == len(EDGE_COLUMNS)
    assert rows[0][EDGE_COLUMNS.index("confidence")] == 1.0
