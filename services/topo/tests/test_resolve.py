from ssdf_topo.models import Observation, node_id, HOST, DEVICE
from ssdf_topo.resolver.resolve import resolve_graph

NOW = "2026-06-07T00:00:00+00:00"


def _obs(**kw):
    base = dict(
        observed_at=NOW,
        collector="junos",
        source_device="sw1",
        layer="l2",
        observation_type="x",
        subj_kind="host",
        subj_id="mac:a",
        obj_kind="",
        obj_id="",
        attrs={},
        raw="",
    )
    base.update(kw)
    return Observation(**base)


def test_arp_attaches_ip_as_alias_not_identity():
    obs = [
        _obs(
            observation_type="arp_entry",
            layer="l3",
            subj_kind="host",
            subj_id="ip:10.64.0.5",
            obj_kind="host",
            obj_id="mac:aa:bb",
        )
    ]
    nodes, edges = resolve_graph(obs, flow_edges=[], tenant="t_main")
    host = next(n for n in nodes if n["node_id"] == node_id("t_main", HOST, "mac:aa:bb"))
    assert host["identifiers"].get("ip") == "10.64.0.5"
    assert any(e["edge_type"] == "has_address" for e in edges)
    assert all(
        n["node_id"] != node_id("t_main", HOST, "ip:10.64.0.5")
        for n in nodes
        if n["kind"] == HOST and n["identifiers"].get("mac")
    )


def test_ip_only_host_flagged_unresolved():
    flow_edges = [
        {
            "edge_id": "f1",
            "tenant_id": "t_main",
            "src_id": node_id("t_main", HOST, "ip:8.8.8.8"),
            "dst_id": node_id("t_main", HOST, "ip:1.1.1.1"),
            "edge_type": "talked_to",
            "layer": "flow",
            "first_seen": NOW,
            "last_seen": NOW,
            "confidence": 1.0,
            "attrs": {"ips": "8.8.8.8,1.1.1.1"},
        }
    ]
    nodes, edges = resolve_graph([], flow_edges=flow_edges, tenant="t_main")
    ip_node = next(n for n in nodes if n["node_id"] == node_id("t_main", HOST, "ip:8.8.8.8"))
    assert ip_node["attrs"].get("unresolved") == "l3_only"


def test_lldp_unions_device_and_builds_physical_link():
    obs = [
        _obs(
            observation_type="lldp_neighbor",
            subj_kind="interface",
            subj_id="if:sw1:ge-0/0/0",
            obj_kind="interface",
            obj_id="if:fw1:eth1",
            attrs={"local_port": "ge-0/0/0", "remote_port": "eth1", "remote_system": "fw1"},
        )
    ]
    nodes, edges = resolve_graph(obs, flow_edges=[], tenant="t_main")
    assert any(e["edge_type"] == "physical_link" for e in edges)
    assert any(n["kind"] == DEVICE for n in nodes)


def test_cross_collector_device_merge_by_shared_mac():
    """A switch seen by junos LLDP (name + chassis MAC) and by UniFi inventory
    (different name + same MAC) must collapse to ONE device node."""
    obs = [
        _obs(
            observation_type="lldp_neighbor",
            subj_kind="interface",
            subj_id="if:sw1:ge-0/0/0",
            obj_kind="interface",
            obj_id="if:fw1:eth1",
            attrs={
                "local_port": "ge-0/0/0",
                "remote_port": "eth1",
                "remote_system": "fw1",
                "remote_chassis": "aa:bb:cc:dd:ee:ff",
            },
        ),
        _obs(
            collector="unifi",
            observation_type="device_inventory",
            subj_kind="device",
            subj_id="dev:firewall-1",
            obj_kind="",
            obj_id="",
            attrs={"name": "firewall-1", "mac": "AA:BB:CC:DD:EE:FF", "role": "firewall"},
        ),
    ]
    nodes, edges = resolve_graph(obs, flow_edges=[], tenant="t_main")
    devices = [n for n in nodes if n["kind"] == DEVICE]
    # sw1 + the merged fw1/firewall-1 == 2 devices, not 3
    assert len(devices) == 2
    merged = next(n for n in devices if n["identifiers"].get("mac") == "aa:bb:cc:dd:ee:ff")
    assert merged["attrs"].get("role") == "firewall"


def test_distinct_devices_not_merged():
    """Devices with no shared identity token stay separate."""
    obs = [
        _obs(
            collector="unifi",
            observation_type="device_inventory",
            subj_kind="device",
            subj_id="dev:a",
            attrs={"name": "switch-a", "mac": "aa:aa:aa:aa:aa:aa"},
        ),
        _obs(
            collector="unifi",
            observation_type="device_inventory",
            subj_kind="device",
            subj_id="dev:b",
            attrs={"name": "switch-b", "mac": "bb:bb:bb:bb:bb:bb"},
        ),
    ]
    nodes, _ = resolve_graph(obs, flow_edges=[], tenant="t_main")
    assert len([n for n in nodes if n["kind"] == DEVICE]) == 2


def test_conflicting_ip_mac_over_time_not_merged():
    obs = [
        _obs(
            observation_type="arp_entry",
            layer="l3",
            subj_id="ip:10.64.0.5",
            obj_id="mac:aa:aa",
            attrs={},
        ),
        _obs(
            observation_type="arp_entry",
            layer="l3",
            subj_id="ip:10.64.0.5",
            obj_id="mac:bb:bb",
            attrs={},
        ),
    ]
    nodes, edges = resolve_graph(obs, flow_edges=[], tenant="t_main")
    host_macs = {
        n["identifiers"]["mac"] for n in nodes if n["kind"] == HOST and "mac" in n["identifiers"]
    }
    assert host_macs == {"aa:aa", "bb:bb"}
    addr_edges = [e for e in edges if e["edge_type"] == "has_address"]
    assert len(addr_edges) == 2


def test_device_inventory_role_merges_onto_named_device_node():
    from ssdf_topo.models import Observation
    from ssdf_topo.resolver.resolve import resolve_graph

    now = "2026-06-08T00:00:00+00:00"
    mac_obs = Observation(
        observed_at=now,
        collector="junos",
        source_device="vSRX-test10",
        layer="l2",
        observation_type="mac_entry",
        subj_kind="host",
        subj_id="mac:aa:bb:cc:dd:ee:01",
        obj_kind="device",
        obj_id="device:vSRX-test10",
        attrs={"vlan": "10", "port": "ge-0/0/0"},
    )
    inv_obs = Observation(
        observed_at=now,
        collector="junos",
        source_device="vSRX-test10",
        layer="l2",
        observation_type="device_inventory",
        subj_kind="device",
        subj_id="device:vSRX-test10",
        attrs={"role": "firewall", "name": "vSRX-test10"},
    )

    nodes, _edges = resolve_graph([mac_obs, inv_obs], [], "t_main")

    fw = [n for n in nodes if n["kind"] == "device" and n["name"] == "vSRX-test10"]
    assert len(fw) == 1, "device_inventory must merge onto the named device node, not duplicate it"
    assert fw[0]["attrs"]["role"] == "firewall"


def test_device_seen_by_mac_and_by_name_resolves_to_one_node():
    """A switch/AP referenced by MAC in client observations and by name in
    device_inventory must fuse into one device, not two.

    _merge_devices already fuses on a shared `mac:` identity token; the MAC-named
    node just never had identifiers["mac"] set, so there was nothing to fuse on.
    Live effect: 8 role-less MAC-named phantoms sat alongside the real named
    devices, inflating every device count in the graph.
    """
    from ssdf_topo.models import Observation
    from ssdf_topo.resolver.resolve import resolve_graph

    now = "2026-08-20T00:00:00Z"
    obs = [
        # A client attached to a switch, which the client view knows only by MAC.
        Observation(
            observed_at=now,
            collector="unifi",
            source_device="unifi-site",
            layer="l2",
            observation_type="mac_entry",
            subj_kind="host",
            subj_id="mac:aa:bb:cc:dd:ee:ff",
            obj_kind="device",
            obj_id="device:02:02:01:4c:24:cf",
            attrs={"port": "6", "vlan": "1", "wired": "True"},
            raw="",
        ),
        # The same switch, from device inventory, which knows its name.
        Observation(
            observed_at=now,
            collector="unifi",
            source_device="unifi-site",
            layer="l2",
            observation_type="device_inventory",
            subj_kind="device",
            subj_id="device:02:02:01:4c:24:cf",
            obj_kind="",
            obj_id="",
            attrs={
                "role": "switch",
                "name": "USW Pro HD 24 PoE",
                "mac": "02:02:01:4c:24:cf",
                "ip": "198.51.100.193",
            },
            raw="",
        ),
    ]
    nodes, _edges = resolve_graph(obs, [], "t_main")

    devices = [n for n in nodes if n["kind"] == "device"]
    assert len(devices) == 1, f"expected one fused device, got {[d['name'] for d in devices]}"
    assert devices[0]["name"] == "USW Pro HD 24 PoE"
    assert devices[0]["attrs"]["role"] == "switch"


def test_client_with_no_uplink_mac_creates_no_placeholder_device():
    """A client reporting neither sw_mac nor ap_mac must not manufacture an
    attachment to the collector's own source_device placeholder — that leaked a
    junk `unifi-site` device node into the graph."""
    from ssdf_topo.collectors.unifi import parse_clients

    payload = '{"result": [{"mac": "aa:bb:cc:dd:ee:ff", "is_wired": true, "ip": "10.64.0.5"}]}'
    obs = parse_clients(payload, "unifi-site", "2026-08-20T00:00:00Z")

    attach = [o for o in obs if o.observation_type in ("mac_entry", "wlan_assoc")]
    assert attach == [], "no uplink MAC means no attachment observation"
    # the ARP/IP observation is still useful and should survive
    assert any(o.observation_type == "arp_entry" for o in obs)
