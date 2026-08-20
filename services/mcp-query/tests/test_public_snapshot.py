"""The whole point of this projection is that it cannot leak, so the tests are
mostly adversarial: they assert what must NOT appear."""

import datetime as _dt
import json

from ssdf_mcp_query.public_snapshot import (
    ALLOWLIST,
    MAX_NODES,
    SCHEMA_VERSION,
    build_snapshot,
)

NOW = _dt.datetime(2026, 8, 20, 12, 0, 0, tzinfo=_dt.timezone.utc)
SALT = "test-salt"


def _node(node_id, name, last_seen, kind="device"):
    return {
        "node_id": node_id,
        "kind": kind,
        "name": name,
        "identifiers": {"mac": "02:02:01:4c:24:cf", "mgmt_ip": "198.51.100.193", "name": name},
        "attrs": {"role": "switch"},
        "first_seen": "2026-08-01T00:00:00Z",
        "last_seen": last_seen,
    }


def _edge(src, dst, last_seen):
    return {
        "edge_id": "e1",
        "src_id": src,
        "dst_id": dst,
        "edge_type": "ATTACHES_TO",
        "layer": "l2",
        "first_seen": "2026-08-01T00:00:00Z",
        "last_seen": last_seen,
        "confidence": 1.0,
        "attrs": {"port": "6", "vlan": "1", "evidence": "unifi"},
    }


FRESH = "2026-08-20T11:59:00Z"
OLD = "2026-08-01T00:00:00Z"


def test_output_contains_none_of_the_forbidden_material():
    """The privacy denylist from the issue: no names, IPs, MACs, identifiers,
    ports, VLANs, tenant ids, collector names, raw attrs or raw observations."""
    nodes = [_node("nid-a", "vsrx-prod", FRESH), _node("nid-b", "pve2", FRESH)]
    snap = build_snapshot(nodes, [_edge("nid-a", "nid-b", FRESH)], now=NOW, salt=SALT)
    blob = json.dumps(snap)

    for forbidden in (
        "vsrx-prod",
        "pve2",  # device names
        "198.51.100.193",
        "02:02:01:4c:24:cf",  # mgmt IP, MAC
        "nid-a",
        "nid-b",  # internal node ids
        "ATTACHES_TO",
        "unifi",  # edge type, collector
        "switch",  # raw attrs
        "port",
        "vlan",
        "l2",  # ports, vlans, layer
        "tenant",
        "t_main",  # tenant
        FRESH,
        OLD,
        "2026-08-01",  # observation timestamps
    ):
        assert forbidden not in blob, f"{forbidden!r} leaked into the snapshot"


def test_only_the_declared_fields_are_emitted():
    """A field that does not exist cannot leak. Pin the shape so a future change
    has to consciously widen it."""
    nodes = [_node("nid-a", "vsrx-prod", FRESH), _node("nid-b", "pve2", FRESH)]
    snap = build_snapshot(nodes, [_edge("nid-a", "nid-b", FRESH)], now=NOW, salt=SALT)

    assert set(snap) == {
        "schema_version",
        "generated_at",
        "nodes",
        "edges",
        "node_count",
        "edge_count",
        "truncated",
    }
    assert all(set(n) == {"id", "reachable", "ollama", "site"} for n in snap["nodes"])
    assert all(set(e) == {"source", "target", "remote", "recent_activity"} for e in snap["edges"])
    assert snap["schema_version"] == SCHEMA_VERSION


def test_non_allowlisted_devices_and_non_devices_are_excluded():
    nodes = [
        _node("nid-a", "vsrx-prod", FRESH),
        _node("nid-x", "some-unapproved-box", FRESH),  # not allowlisted
        _node("nid-h", "vsrx-prod", FRESH, kind="host"),  # not a device
    ]
    snap = build_snapshot(nodes, [], now=NOW, salt=SALT)
    assert snap["node_count"] == 1


def test_every_edge_endpoint_references_a_returned_node():
    """An edge must never point at something the consumer cannot see."""
    nodes = [_node("nid-a", "vsrx-prod", FRESH), _node("nid-b", "pve2", FRESH)]
    edges = [
        _edge("nid-a", "nid-b", FRESH),
        _edge("nid-a", "nid-ghost", FRESH),  # endpoint not in the allowlist
        _edge("nid-a", "nid-a", FRESH),  # self-loop
    ]
    snap = build_snapshot(nodes, edges, now=NOW, salt=SALT)

    ids = {n["id"] for n in snap["nodes"]}
    assert snap["edge_count"] == 1
    for e in snap["edges"]:
        assert e["source"] in ids and e["target"] in ids


def test_reachable_and_recent_activity_are_windowed_booleans():
    nodes = [_node("nid-a", "vsrx-prod", FRESH), _node("nid-b", "pve2", OLD)]
    snap = build_snapshot(nodes, [_edge("nid-a", "nid-b", OLD)], now=NOW, salt=SALT)

    by_reach = {n["reachable"] for n in snap["nodes"]}
    assert by_reach == {True, False}, "a stale node must read unreachable"
    assert snap["edges"][0]["recent_activity"] is False


def test_opaque_ids_are_stable_within_a_snapshot():
    """Inside one snapshot the edge endpoints must join to the node ids emitted."""
    nodes = [_node("nid-a", "vsrx-prod", FRESH), _node("nid-b", "pve2", FRESH)]
    snap = build_snapshot(nodes, [_edge("nid-a", "nid-b", FRESH)], now=NOW, salt=SALT)

    ids = {n["id"] for n in snap["nodes"]}
    assert snap["edges"][0]["source"] in ids
    assert snap["edges"][0]["target"] in ids
    assert ids == {"n1", "n2"}


def test_salt_changes_which_device_gets_which_opaque_id():
    """Ordering must not be derivable from the devices themselves, or the ids
    would be correlatable across snapshots before the publisher ever remaps them.

    `pve2` is the only allowlisted device with ollama=True, so it is identifiable
    in the output without exposing its name — which makes it a usable probe for
    where a given device landed.
    """
    nodes = [_node("nid-a", "vsrx-prod", FRESH), _node("nid-b", "pve2", FRESH)]

    placements = set()
    for salt in (f"salt-{i}" for i in range(24)):
        snap = build_snapshot(nodes, [], now=NOW, salt=salt)
        ollama_id = next(n["id"] for n in snap["nodes"] if n["ollama"])
        placements.add(ollama_id)

    assert len(placements) > 1, (
        "the same device landed on the same opaque id under every salt — "
        "ordering is not actually salted"
    )


def test_truncation_is_reported_not_silent():
    nodes = [_node(f"nid-{i}", d.name, FRESH) for i, d in enumerate(ALLOWLIST)]
    snap = build_snapshot(nodes, [], now=NOW, salt=SALT)
    assert snap["truncated"] is False
    assert snap["node_count"] == min(len(ALLOWLIST), MAX_NODES)


def test_remote_membership_is_exposed_only_as_an_enum():
    """Site names must never appear; only primary|remote."""
    nodes = [_node("nid-a", "vsrx-prod", FRESH)]
    snap = build_snapshot(nodes, [], now=NOW, salt=SALT)
    assert snap["nodes"][0]["site"] in {"primary", "remote"}


def test_duplicate_graph_rows_for_one_device_collapse_to_one_node():
    """graph_nodes keys on node_id, so a device that changed identity leaves its
    previous row behind until TTL. Both rows carry the same name, so a name-based
    allowlist would emit the device twice and over-report the lab — observed live
    as 17 nodes for 14 allowlisted devices."""
    nodes = [
        _node("nid-old", "vsrx-prod", OLD),  # stale residue
        _node("nid-new", "vsrx-prod", FRESH),  # current
    ]
    snap = build_snapshot(nodes, [], now=NOW, salt=SALT)

    assert snap["node_count"] == 1
    # the surviving entry must reflect the CURRENT row, not the stale one
    assert snap["nodes"][0]["reachable"] is True
