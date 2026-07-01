from ssdf_entity.models import ASSET, POLICY, COMMUNICATED_WITH, GOVERNED_BY, entity_id
from ssdf_entity.resolve_entities import (
    resolve_entities, normalize_segment, build_binding_map,
)

NOW1 = "2026-06-07 00:00:00.000"
NOW2 = "2026-06-07 01:00:00.000"


def _flow(**kw):
    base = dict(src_ip="10.64.0.5", dst_ip="8.8.8.8", observer_hostname="fw1",
                bytes=1000, flows=3, ports=[443], rule_name="trust-to-untrust",
                provider="juniper", transport="tcp", first_seen=NOW1, last_seen=NOW2)
    base.update(kw)
    return base


def _binding(ip, mac, source_device="fw1", observed_at=NOW2):
    return {"source_device": source_device, "ip": ip, "mac": mac, "observed_at": observed_at}


# --- normalize_segment (Task 1) ---

def test_normalize_segment_strips_domain_and_lowercases():
    assert normalize_segment("panosvm.example.com") == "panosvm"
    assert normalize_segment("vSRX-test10") == "vsrx-test10"
    assert normalize_segment("FW1.local") == "fw1"


def test_normalize_segment_empty_becomes_unknown():
    assert normalize_segment("") == "unknown"
    assert normalize_segment(None) == "unknown"
    assert normalize_segment("   ") == "unknown"


# --- build_binding_map (Task 2) ---

def test_build_binding_map_keys_by_segment_and_ip():
    rows = [_binding("198.51.100.150", "aa:aa:aa:aa:aa:aa", "fwA", "2026-06-08 10:00:00.000"),
            _binding("198.51.100.150", "bb:bb:bb:bb:bb:bb", "fwB", "2026-06-08 10:00:00.000")]
    binding_map, conflict = build_binding_map(rows)
    assert binding_map[("fwa", "198.51.100.150")] == "aa:aa:aa:aa:aa:aa"
    assert binding_map[("fwb", "198.51.100.150")] == "bb:bb:bb:bb:bb:bb"
    assert conflict == set()


def test_build_binding_map_latest_observation_wins():
    rows = [_binding("10.64.0.5", "aa:aa:aa:aa:aa:aa", "fwA", "2026-06-08 09:00:00.000"),
            _binding("10.64.0.5", "cc:cc:cc:cc:cc:cc", "fwA", "2026-06-08 11:00:00.000")]
    binding_map, conflict = build_binding_map(rows)
    assert binding_map[("fwa", "10.64.0.5")] == "cc:cc:cc:cc:cc:cc"
    assert conflict == {("fwa", "10.64.0.5")}


def test_build_binding_map_skips_missing_ip_or_mac():
    rows = [_binding("", "aa:aa:aa:aa:aa:aa", "fwA"),
            _binding("10.64.0.5", "", "fwA")]
    binding_map, conflict = build_binding_map(rows)
    assert binding_map == {}
    assert conflict == set()


def test_build_binding_map_flags_conflict_from_mac_count():
    """With the server-side aggregation (issue #28 leak fix), an intra-device
    IP that saw multiple MACs over the window arrives as ONE argMax row with
    mac_count>1 — the conflict must still be flagged even though only the
    latest MAC survives in the row."""
    rows = [dict(_binding("10.64.0.5", "cc:cc:cc:cc:cc:cc", "fwA"), mac_count=2)]
    binding_map, conflict = build_binding_map(rows)
    assert binding_map[("fwa", "10.64.0.5")] == "cc:cc:cc:cc:cc:cc"
    assert conflict == {("fwa", "10.64.0.5")}


# --- resolve_entities (segment-scoped) ---

def test_ip_only_endpoints_become_segment_scoped_assets():
    entities, edges = resolve_entities([_flow()], bindings=[], tenant="t_main")
    assets = [e for e in entities if e["kind"] == ASSET]
    assert len(assets) == 2
    for a in assets:
        assert a["identity_basis"] == "ip_only"
        assert a["confidence"] == 0.5
        assert a["source"] == "observed"


def test_same_ip_different_segment_never_merges():
    flows = [_flow(src_ip="198.51.100.150", observer_hostname="fwA"),
             _flow(src_ip="198.51.100.150", observer_hostname="fwB", dst_ip="9.9.9.9")]
    entities, _ = resolve_entities(flows, bindings=[], tenant="t_main")
    srcs = [e for e in entities if e["kind"] == ASSET
            and e["identifiers"].get("ip") == "198.51.100.150"]
    assert len(srcs) == 2  # branch-reused IP across two vantages => two distinct assets


def test_mac_known_endpoint_is_mac_anchored():
    bindings = [_binding("10.64.0.5", "aa:bb:cc:dd:ee:ff")]
    entities, _ = resolve_entities([_flow()], bindings=bindings, tenant="t_main")
    src = next(e for e in entities if e["kind"] == ASSET
               and e["identifiers"].get("mac") == "aa:bb:cc:dd:ee:ff")
    assert src["identity_basis"] == "mac"
    assert src["confidence"] == 1.0
    assert src["identifiers"]["ip"] == "10.64.0.5"


def test_binding_only_matches_within_segment():
    # binding learned on fwA must not anchor a flow seen on fwB
    bindings = [_binding("10.64.0.5", "aa:bb:cc:dd:ee:ff", source_device="fwA")]
    entities, _ = resolve_entities([_flow(observer_hostname="fwB")],
                                   bindings=bindings, tenant="t_main")
    src = next(e for e in entities if e["kind"] == ASSET
               and "10.64.0.5" in e["identifiers"].values())
    assert src["identity_basis"] == "ip_only"


def test_two_ips_sharing_a_mac_collapse_to_one_asset():
    bindings = [_binding("10.64.0.5", "aa:aa:aa:aa:aa:aa"),
                _binding("10.64.0.6", "aa:aa:aa:aa:aa:aa")]
    flows = [_flow(src_ip="10.64.0.5"), _flow(src_ip="10.64.0.6")]
    entities, _ = resolve_entities(flows, bindings=bindings, tenant="t_main")
    macs = [e for e in entities if e["kind"] == ASSET
            and e["identifiers"].get("mac") == "aa:aa:aa:aa:aa:aa"]
    assert len(macs) == 1
    ips = {v for k, v in macs[0]["identifiers"].items() if k.startswith("ip")}
    assert ips == {"10.64.0.5", "10.64.0.6"}


def test_collapsed_mac_endpoints_share_one_comm_edge():
    # two IPs collapse to one MAC asset; both talk to the same peer => the
    # COMMUNICATED_WITH edge is keyed on entity ids, so it merges (not fragments
    # on raw IPs) and accumulates stats. Locks in the entity-id edge keying.
    bindings = [_binding("10.64.0.5", "aa:aa:aa:aa:aa:aa"),
                _binding("10.64.0.6", "aa:aa:aa:aa:aa:aa")]
    flows = [_flow(src_ip="10.64.0.5", flows=3, bytes=1000),
             _flow(src_ip="10.64.0.6", flows=2, bytes=500)]
    _, edges = resolve_entities(flows, bindings=bindings, tenant="t_main")
    comm = [e for e in edges if e["edge_type"] == COMMUNICATED_WITH]
    assert len(comm) == 1
    assert comm[0]["attrs"]["sessions"] == "5"
    assert comm[0]["attrs"]["bytes"] == "1500"


def test_distinct_ips_never_merge():
    flows = [_flow(src_ip="10.64.0.5"), _flow(src_ip="10.64.0.6")]
    entities, _ = resolve_entities(flows, bindings=[], tenant="t_main")
    src_ips = {v for e in entities if e["kind"] == ASSET
               for k, v in e["identifiers"].items() if k.startswith("ip")}
    assert "10.64.0.5" in src_ips and "10.64.0.6" in src_ips
    assert len([e for e in entities if e["kind"] == ASSET]) == 3  # two srcs + shared dst


def test_ip_conflict_sets_flag_on_mac_asset():
    bindings = [_binding("10.64.0.5", "aa:aa:aa:aa:aa:aa", "fw1", "2026-06-08 09:00:00.000"),
                _binding("10.64.0.5", "dd:dd:dd:dd:dd:dd", "fw1", "2026-06-08 11:00:00.000")]
    entities, _ = resolve_entities([_flow(src_ip="10.64.0.5")],
                                   bindings=bindings, tenant="t_main")
    # latest binding wins => dd:.. asset, flagged with the conflicting ip
    asset = next(e for e in entities if e["kind"] == ASSET
                 and e["identifiers"].get("mac") == "dd:dd:dd:dd:dd:dd")
    assert asset["attrs"].get("ip_conflict") == "10.64.0.5"


def test_observed_policy_keyed_by_provider_and_rule():
    entities, edges = resolve_entities([_flow()], bindings=[], tenant="t_main")
    policies = [e for e in entities if e["kind"] == POLICY]
    assert len(policies) == 1
    assert policies[0]["name"] == "trust-to-untrust"
    assert policies[0]["identifiers"]["provider"] == "juniper"
    assert policies[0]["source"] == "observed"


def test_same_rule_name_different_vendor_is_distinct_policy():
    flows = [_flow(rule_name="allow-web", provider="juniper"),
             _flow(rule_name="allow-web", provider="paloalto", dst_ip="9.9.9.9")]
    entities, _ = resolve_entities(flows, bindings=[], tenant="t_main")
    assert len([e for e in entities if e["kind"] == POLICY]) == 2


def test_communicated_with_and_governed_by_edges():
    entities, edges = resolve_entities([_flow()], bindings=[], tenant="t_main")
    comm = [e for e in edges if e["edge_type"] == COMMUNICATED_WITH]
    gov = [e for e in edges if e["edge_type"] == GOVERNED_BY]
    assert len(comm) == 1 and len(gov) == 1
    assert comm[0]["attrs"]["sessions"] == "3"
    assert comm[0]["attrs"]["bytes"] == "1000"
    assert "443" in comm[0]["attrs"]["ports"]
    assert gov[0]["src_id"] == comm[0]["edge_id"]


def test_empty_rule_produces_no_governed_by():
    entities, edges = resolve_entities([_flow(rule_name="")], bindings=[], tenant="t_main")
    assert [e for e in entities if e["kind"] == POLICY] == []
    assert [e for e in edges if e["edge_type"] == GOVERNED_BY] == []
    assert [e for e in edges if e["edge_type"] == COMMUNICATED_WITH]


def test_flow_stats_accumulate_across_rows_for_same_pair():
    flows = [_flow(flows=3, bytes=1000, ports=[443], first_seen=NOW1, last_seen=NOW1),
             _flow(flows=2, bytes=500, ports=[80], first_seen=NOW2, last_seen=NOW2)]
    _, edges = resolve_entities(flows, bindings=[], tenant="t_main")
    comm = next(e for e in edges if e["edge_type"] == COMMUNICATED_WITH)
    assert comm["attrs"]["sessions"] == "5"
    assert comm["attrs"]["bytes"] == "1500"
    assert set(comm["attrs"]["ports"].split(",")) == {"80", "443"}
    assert comm["first_seen"] == NOW1 and comm["last_seen"] == NOW2


def test_observer_hosts_recorded_on_comm_edge():
    entities, edges = resolve_entities([_flow(observer_hostname="vSRX-test10")],
                                       bindings=[], tenant="t_main")
    comm = next(e for e in edges if e["edge_type"] == COMMUNICATED_WITH)
    assert comm["attrs"]["observer_hosts"] == "vSRX-test10"


def test_observer_hosts_union_across_rows():
    # two raw observer names that normalize to the SAME segment => same assets,
    # one comm edge, observer_hosts unions the raw vantage names
    flows = [_flow(observer_hostname="vSRX-test10", first_seen=NOW1, last_seen=NOW1),
             _flow(observer_hostname="vSRX-test10.lab", first_seen=NOW2, last_seen=NOW2)]
    _, edges = resolve_entities(flows, bindings=[], tenant="t_main")
    comm = [e for e in edges if e["edge_type"] == COMMUNICATED_WITH]
    assert len(comm) == 1
    assert set(comm[0]["attrs"]["observer_hosts"].split(",")) == {"vSRX-test10", "vSRX-test10.lab"}


def test_observer_hosts_absent_defaults_empty():
    _, edges = resolve_entities([_flow(observer_hostname="")], bindings=[], tenant="t_main")
    comm = next(e for e in edges if e["edge_type"] == COMMUNICATED_WITH)
    assert comm["attrs"]["observer_hosts"] == ""
