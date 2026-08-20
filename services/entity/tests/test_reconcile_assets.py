from ssdf_entity.models import ASSET, COMMUNICATED_WITH, GOVERNED_BY, entity_id, edge_id
from ssdf_entity.reconcile_assets import plan_reconciliation

TENANT = "t_main"
MAC = "aa:aa:aa:aa:aa:aa"
PEER = "8.8.8.8"
NOW1 = "2026-06-07 00:00:00.000"
NOW2 = "2026-06-08 00:00:00.000"

MAC_ID = entity_id(TENANT, ASSET, f"mac:{MAC}")
TWIN_ID = entity_id(TENANT, ASSET, "ip:198.51.100.150")  # legacy global key
PEER_ID = entity_id(TENANT, ASSET, "ip:fw1:8.8.8.8")


def _asset(eid, basis, ident, attrs=None):
    return {
        "entity_id": eid,
        "tenant_id": TENANT,
        "kind": ASSET,
        "name": "x",
        "identifiers": ident,
        "source": "observed",
        "identity_basis": basis,
        "confidence": 1.0 if basis == "mac" else 0.5,
        "attrs": attrs or {},
        "first_seen": NOW1,
        "last_seen": NOW2,
    }


def _comm_edge(src, dst, **attrs):
    base = {
        "sessions": "0",
        "bytes": "0",
        "ports": "",
        "providers": "",
        "transports": "",
        "observer_hosts": "",
    }
    base.update({k: str(v) for k, v in attrs.items()})
    return {
        "edge_id": edge_id(TENANT, src, dst, COMMUNICATED_WITH, "observed"),
        "tenant_id": TENANT,
        "src_id": src,
        "dst_id": dst,
        "edge_type": COMMUNICATED_WITH,
        "source": "observed",
        "confidence": 1.0,
        "attrs": base,
        "first_seen": NOW1,
        "last_seen": NOW2,
    }


def test_twin_with_matching_mac_is_merged_and_deleted():
    binding_map = {("fw1", "198.51.100.150"): MAC}
    mac_asset = _asset(MAC_ID, "mac", {"mac": MAC, "ip": "198.51.100.150"})
    twin = _asset(TWIN_ID, "ip_only", {"ip": "198.51.100.150"})
    mac_edge = _comm_edge(MAC_ID, PEER_ID, sessions=5, bytes=500, observer_hosts="vSRX-test10")
    twin_edge = _comm_edge(TWIN_ID, PEER_ID, sessions=3, bytes=300, observer_hosts="")
    plan = plan_reconciliation(
        ip_only_assets=[twin],
        mac_assets=[mac_asset],
        comm_edges=[mac_edge, twin_edge],
        gov_edges=[],
        binding_map=binding_map,
        tenant=TENANT,
    )
    assert TWIN_ID in plan["delete_entity_ids"]
    assert twin_edge["edge_id"] in plan["delete_edge_ids"]
    merged = next(e for e in plan["merged_edges"] if e["edge_id"] == mac_edge["edge_id"])
    assert merged["attrs"]["sessions"] == "8"  # 5 + 3
    assert merged["attrs"]["bytes"] == "800"  # 500 + 300


def test_twin_with_no_matching_mac_is_left_alone():
    binding_map = {}  # IP not bound to any MAC
    twin = _asset(TWIN_ID, "ip_only", {"ip": "198.51.100.150"})
    plan = plan_reconciliation(
        ip_only_assets=[twin],
        mac_assets=[],
        comm_edges=[],
        gov_edges=[],
        binding_map=binding_map,
        tenant=TENANT,
    )
    assert plan["delete_entity_ids"] == []
    assert plan["merged_edges"] == []


def test_ambiguous_ip_two_macs_is_left_alone():
    # IP appears bound to two different MACs across segments => not safe to merge
    binding_map = {("fwa", "198.51.100.150"): MAC, ("fwb", "198.51.100.150"): "bb:bb:bb:bb:bb:bb"}
    mac_asset = _asset(MAC_ID, "mac", {"mac": MAC, "ip": "198.51.100.150"})
    twin = _asset(TWIN_ID, "ip_only", {"ip": "198.51.100.150"})
    plan = plan_reconciliation(
        ip_only_assets=[twin],
        mac_assets=[mac_asset],
        comm_edges=[],
        gov_edges=[],
        binding_map=binding_map,
        tenant=TENANT,
    )
    assert plan["delete_entity_ids"] == []


def test_twin_governed_by_edges_are_deleted():
    binding_map = {("fw1", "198.51.100.150"): MAC}
    mac_asset = _asset(MAC_ID, "mac", {"mac": MAC, "ip": "198.51.100.150"})
    twin = _asset(TWIN_ID, "ip_only", {"ip": "198.51.100.150"})
    twin_edge = _comm_edge(TWIN_ID, PEER_ID, sessions=3, bytes=300)
    gov = {
        "edge_id": edge_id(TENANT, twin_edge["edge_id"], "pol1", GOVERNED_BY, "observed"),
        "tenant_id": TENANT,
        "src_id": twin_edge["edge_id"],
        "dst_id": "pol1",
        "edge_type": GOVERNED_BY,
        "source": "observed",
        "confidence": 1.0,
        "attrs": {},
        "first_seen": NOW1,
        "last_seen": NOW2,
    }
    plan = plan_reconciliation(
        ip_only_assets=[twin],
        mac_assets=[mac_asset],
        comm_edges=[twin_edge],
        gov_edges=[gov],
        binding_map=binding_map,
        tenant=TENANT,
    )
    assert gov["edge_id"] in plan["delete_edge_ids"]


def test_twin_to_twin_edge_remaps_both_endpoints():
    # both endpoints of a flow are ip_only twins that collapse to MAC assets;
    # the merged edge must connect the two MAC assets, not dangle on a deleted id
    MAC_B = "bb:bb:bb:bb:bb:bb"
    MACB_ID = entity_id(TENANT, ASSET, f"mac:{MAC_B}")
    TWINB_ID = entity_id(TENANT, ASSET, "ip:10.64.0.9")
    binding_map = {("fw1", "198.51.100.150"): MAC, ("fw1", "10.64.0.9"): MAC_B}
    mac_a = _asset(MAC_ID, "mac", {"mac": MAC, "ip": "198.51.100.150"})
    mac_b = _asset(MACB_ID, "mac", {"mac": MAC_B, "ip": "10.64.0.9"})
    twin_a = _asset(TWIN_ID, "ip_only", {"ip": "198.51.100.150"})
    twin_b = _asset(TWINB_ID, "ip_only", {"ip": "10.64.0.9"})
    twin_edge = _comm_edge(TWIN_ID, TWINB_ID, sessions=4, bytes=400)
    plan = plan_reconciliation(
        ip_only_assets=[twin_a, twin_b],
        mac_assets=[mac_a, mac_b],
        comm_edges=[twin_edge],
        gov_edges=[],
        binding_map=binding_map,
        tenant=TENANT,
    )
    assert TWIN_ID in plan["delete_entity_ids"]
    assert TWINB_ID in plan["delete_entity_ids"]
    assert twin_edge["edge_id"] in plan["delete_edge_ids"]
    expected_id = edge_id(TENANT, MAC_ID, MACB_ID, COMMUNICATED_WITH, "observed")
    merged = next(e for e in plan["merged_edges"] if e["edge_id"] == expected_id)
    assert merged["src_id"] == MAC_ID and merged["dst_id"] == MACB_ID
    assert merged["attrs"]["sessions"] == "4"
    # the merged edge must not reference any deleted twin id
    assert merged["src_id"] not in plan["delete_entity_ids"]
    assert merged["dst_id"] not in plan["delete_entity_ids"]
