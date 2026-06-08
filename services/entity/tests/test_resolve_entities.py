from ssdf_entity.models import ASSET, POLICY, COMMUNICATED_WITH, GOVERNED_BY, entity_id
from ssdf_entity.resolve_entities import resolve_entities


def test_normalize_segment_strips_domain_and_lowercases():
    from ssdf_entity.resolve_entities import normalize_segment
    assert normalize_segment("panosvm.example.com") == "panosvm"
    assert normalize_segment("vSRX-test10") == "vsrx-test10"
    assert normalize_segment("FW1.local") == "fw1"


def test_normalize_segment_empty_becomes_unknown():
    from ssdf_entity.resolve_entities import normalize_segment
    assert normalize_segment("") == "unknown"
    assert normalize_segment(None) == "unknown"
    assert normalize_segment("   ") == "unknown"

NOW1 = "2026-06-07 00:00:00.000"
NOW2 = "2026-06-07 01:00:00.000"


def _flow(**kw):
    base = dict(src_ip="10.64.0.5", dst_ip="8.8.8.8", bytes=1000, flows=3, ports=[443],
                rule_name="trust-to-untrust", provider="juniper", transport="tcp",
                first_seen=NOW1, last_seen=NOW2)
    base.update(kw)
    return base


def test_ip_only_endpoints_become_singleton_assets():
    entities, edges = resolve_entities([_flow()], topo_hosts=[], tenant="t_main")
    assets = [e for e in entities if e["kind"] == ASSET]
    assert len(assets) == 2
    for a in assets:
        assert a["identity_basis"] == "ip_only"
        assert a["confidence"] == 0.5
        assert a["source"] == "observed"


def test_mac_known_endpoint_is_mac_anchored():
    topo = [{"identifiers": {"mac": "aa:bb:cc:dd:ee:ff", "ip": "10.64.0.5"}}]
    entities, _ = resolve_entities([_flow()], topo_hosts=topo, tenant="t_main")
    src = next(e for e in entities if e["kind"] == ASSET
               and e["identifiers"].get("mac") == "aa:bb:cc:dd:ee:ff")
    assert src["identity_basis"] == "mac"
    assert src["confidence"] == 1.0
    assert src["identifiers"]["ip"] == "10.64.0.5"


def test_two_ips_sharing_a_mac_collapse_to_one_asset():
    topo = [{"identifiers": {"mac": "aa:aa:aa:aa:aa:aa", "ip": "10.64.0.5"}},
            {"identifiers": {"mac": "aa:aa:aa:aa:aa:aa", "ip": "10.64.0.6"}}]
    flows = [_flow(src_ip="10.64.0.5"), _flow(src_ip="10.64.0.6")]
    entities, _ = resolve_entities(flows, topo_hosts=topo, tenant="t_main")
    macs = [e for e in entities if e["kind"] == ASSET
            and e["identifiers"].get("mac") == "aa:aa:aa:aa:aa:aa"]
    assert len(macs) == 1
    ips = {v for k, v in macs[0]["identifiers"].items() if k.startswith("ip")}
    assert ips == {"10.64.0.5", "10.64.0.6"}


def test_distinct_ips_never_merge():
    flows = [_flow(src_ip="10.64.0.5"), _flow(src_ip="10.64.0.6")]
    entities, _ = resolve_entities(flows, topo_hosts=[], tenant="t_main")
    src_ips = {v for e in entities if e["kind"] == ASSET
               for k, v in e["identifiers"].items() if k.startswith("ip")}
    assert "10.64.0.5" in src_ips and "10.64.0.6" in src_ips
    assert len([e for e in entities if e["kind"] == ASSET]) == 3  # two srcs + shared dst


def test_observed_policy_keyed_by_provider_and_rule():
    entities, edges = resolve_entities([_flow()], topo_hosts=[], tenant="t_main")
    policies = [e for e in entities if e["kind"] == POLICY]
    assert len(policies) == 1
    assert policies[0]["name"] == "trust-to-untrust"
    assert policies[0]["identifiers"]["provider"] == "juniper"
    assert policies[0]["source"] == "observed"


def test_same_rule_name_different_vendor_is_distinct_policy():
    flows = [_flow(rule_name="allow-web", provider="juniper"),
             _flow(rule_name="allow-web", provider="paloalto", dst_ip="9.9.9.9")]
    entities, _ = resolve_entities(flows, topo_hosts=[], tenant="t_main")
    assert len([e for e in entities if e["kind"] == POLICY]) == 2


def test_communicated_with_and_governed_by_edges():
    entities, edges = resolve_entities([_flow()], topo_hosts=[], tenant="t_main")
    comm = [e for e in edges if e["edge_type"] == COMMUNICATED_WITH]
    gov = [e for e in edges if e["edge_type"] == GOVERNED_BY]
    assert len(comm) == 1 and len(gov) == 1
    assert comm[0]["attrs"]["sessions"] == "3"
    assert comm[0]["attrs"]["bytes"] == "1000"
    assert "443" in comm[0]["attrs"]["ports"]
    assert gov[0]["src_id"] == comm[0]["edge_id"]


def test_empty_rule_produces_no_governed_by():
    entities, edges = resolve_entities([_flow(rule_name="")], topo_hosts=[], tenant="t_main")
    assert [e for e in entities if e["kind"] == POLICY] == []
    assert [e for e in edges if e["edge_type"] == GOVERNED_BY] == []
    assert [e for e in edges if e["edge_type"] == COMMUNICATED_WITH]  # flow still recorded


def test_flow_stats_accumulate_across_rows_for_same_pair():
    flows = [_flow(flows=3, bytes=1000, ports=[443], first_seen=NOW1, last_seen=NOW1),
             _flow(flows=2, bytes=500, ports=[80], first_seen=NOW2, last_seen=NOW2)]
    _, edges = resolve_entities(flows, topo_hosts=[], tenant="t_main")
    comm = next(e for e in edges if e["edge_type"] == COMMUNICATED_WITH)
    assert comm["attrs"]["sessions"] == "5"
    assert comm["attrs"]["bytes"] == "1500"
    assert set(comm["attrs"]["ports"].split(",")) == {"80", "443"}
    assert comm["first_seen"] == NOW1 and comm["last_seen"] == NOW2


def test_observer_hosts_recorded_on_comm_edge():
    entities, edges = resolve_entities([_flow(observer_hosts=["vSRX-test10"])],
                                       topo_hosts=[], tenant="t_main")
    comm = next(e for e in edges if e["edge_type"] == COMMUNICATED_WITH)
    assert comm["attrs"]["observer_hosts"] == "vSRX-test10"


def test_observer_hosts_union_across_rows():
    flows = [_flow(observer_hosts=["vSRX-test10"], first_seen=NOW1, last_seen=NOW1),
             _flow(observer_hosts=["panosvm"], first_seen=NOW2, last_seen=NOW2)]
    _, edges = resolve_entities(flows, topo_hosts=[], tenant="t_main")
    comm = next(e for e in edges if e["edge_type"] == COMMUNICATED_WITH)
    assert set(comm["attrs"]["observer_hosts"].split(",")) == {"panosvm", "vSRX-test10"}


def test_observer_hosts_absent_defaults_empty():
    _, edges = resolve_entities([_flow()], topo_hosts=[], tenant="t_main")
    comm = next(e for e in edges if e["edge_type"] == COMMUNICATED_WITH)
    assert comm["attrs"]["observer_hosts"] == ""
