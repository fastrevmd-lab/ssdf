# src/ssdf_topo/resolver/resolve.py
"""Resolve observations + flow edges into canonical graph nodes and edges."""

from __future__ import annotations

import re
from collections import defaultdict

from ..models import (
    Observation, node_id, edge_id,
    DEVICE, HOST, INTERFACE,
    PHYSICAL_LINK, ATTACHES_TO, HAS_ADDRESS, HOSTS,
)
from .unionfind import UnionFind

_MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$", re.IGNORECASE)


def _device_identity_tokens(node: dict) -> list[str]:
    """Identity tokens that should fuse two device nodes into one entity:
    a shared management MAC, name, or management IP."""
    ids = node["identifiers"]
    tokens = []
    if ids.get("mac"):
        tokens.append(f"mac:{ids['mac'].lower()}")
    if ids.get("name"):
        tokens.append(f"name:{ids['name']}")
    if ids.get("mgmt_ip"):
        tokens.append(f"mgmt_ip:{ids['mgmt_ip']}")
    return tokens


def _merge_devices(nodes: dict, edges: dict, edge_evidence: dict, tenant: str) -> None:
    """Fuse device nodes that share an identity token (cross-collector dedup),
    then remap and re-dedupe every edge onto the canonical device ids.

    MAC anchors identity; name/mgmt_ip union too. Hosts and interfaces are never
    merged here. Mutates nodes/edges/edge_evidence in place.
    """
    device_ids = [nid for nid, n in nodes.items() if n["kind"] == DEVICE]
    union = UnionFind()
    token_owner: dict[str, str] = {}
    for nid in device_ids:
        union.add(nid)
        for token in _device_identity_tokens(nodes[nid]):
            owner = token_owner.setdefault(token, nid)
            if owner != nid:
                union.union(owner, nid)

    canonical = {nid: union.find(nid) for nid in device_ids}
    if all(root == nid for nid, root in canonical.items()):
        return  # nothing fused

    for nid in device_ids:
        root = canonical[nid]
        if root == nid:
            continue
        src, dst = nodes[nid], nodes[root]
        dst["first_seen"] = min(dst["first_seen"], src["first_seen"])
        dst["last_seen"] = max(dst["last_seen"], src["last_seen"])
        if src["name"] and not dst["name"]:
            dst["name"] = src["name"]
        for key, value in src["identifiers"].items():
            dst["identifiers"].setdefault(key, value)
        for key, value in src["attrs"].items():
            dst["attrs"].setdefault(key, value)
        del nodes[nid]

    new_edges: dict[str, dict] = {}
    new_evidence: dict[str, set[str]] = defaultdict(set)
    for old_eid, edge in edges.items():
        edge["src_id"] = canonical.get(edge["src_id"], edge["src_id"])
        edge["dst_id"] = canonical.get(edge["dst_id"], edge["dst_id"])
        if edge["src_id"] == edge["dst_id"]:
            continue  # drop self-loops created by the merge
        new_eid = edge_id(tenant, edge["src_id"], edge["dst_id"],
                          edge["edge_type"], edge["layer"])
        edge["edge_id"] = new_eid
        existing = new_edges.get(new_eid)
        if existing is None:
            new_edges[new_eid] = edge
        else:
            existing["first_seen"] = min(existing["first_seen"], edge["first_seen"])
            existing["last_seen"] = max(existing["last_seen"], edge["last_seen"])
            existing["attrs"].update(edge["attrs"])
        new_evidence[new_eid] |= edge_evidence.get(old_eid, set())
    edges.clear()
    edges.update(new_edges)
    edge_evidence.clear()
    edge_evidence.update(new_evidence)


def resolve_graph(observations: list[Observation], flow_edges: list[dict],
                  tenant: str) -> tuple[list[dict], list[dict]]:
    nodes: dict[str, dict] = {}
    edges: dict[str, dict] = {}
    edge_evidence: dict[str, set[str]] = defaultdict(set)

    def touch_node(nid: str, kind: str, name: str, observed_at: str) -> dict:
        n = nodes.get(nid)
        if n is None:
            n = {"node_id": nid, "tenant_id": tenant, "kind": kind, "name": name,
                 "identifiers": {}, "first_seen": observed_at, "last_seen": observed_at,
                 "attrs": {}}
            nodes[nid] = n
        else:
            n["first_seen"] = min(n["first_seen"], observed_at)
            n["last_seen"] = max(n["last_seen"], observed_at)
            if name and not n["name"]:
                n["name"] = name
        return n

    def host_node(mac: str, observed_at: str) -> dict:
        nid = node_id(tenant, HOST, f"mac:{mac}")
        n = touch_node(nid, HOST, mac, observed_at)
        n["identifiers"]["mac"] = mac
        return n

    def device_node(name: str, observed_at: str) -> dict:
        nid = node_id(tenant, DEVICE, name)
        n = touch_node(nid, DEVICE, name, observed_at)
        n["identifiers"]["name"] = name
        return n

    def add_edge(src: str, dst: str, etype: str, layer: str, observed_at: str,
                 attrs: dict, evidence: str) -> None:
        eid = edge_id(tenant, src, dst, etype, layer)
        e = edges.get(eid)
        if e is None:
            e = {"edge_id": eid, "tenant_id": tenant, "src_id": src, "dst_id": dst,
                 "edge_type": etype, "layer": layer, "first_seen": observed_at,
                 "last_seen": observed_at, "confidence": 0.7, "attrs": dict(attrs)}
            edges[eid] = e
        else:
            e["first_seen"] = min(e["first_seen"], observed_at)
            e["last_seen"] = max(e["last_seen"], observed_at)
            e["attrs"].update(attrs)
        edge_evidence[eid].add(evidence)

    for o in observations:
        ot, at = o.observation_type, o.observed_at
        if ot == "arp_entry":
            ip = o.subj_id.split("ip:", 1)[-1]
            mac = o.obj_id.split("mac:", 1)[-1]
            host = host_node(mac, at)
            host["identifiers"]["ip"] = ip
            add_edge(host["node_id"], node_id(tenant, HOST, f"ip:{ip}"),
                     HAS_ADDRESS, "l3", at,
                     {"ip": ip, "evidence": o.collector}, evidence=o.collector)
        elif ot in ("mac_entry", "wlan_assoc"):
            mac = o.subj_id.split("mac:", 1)[-1]
            host = host_node(mac, at)
            dev_name = o.obj_id.split(":", 1)[-1] if o.obj_id else o.source_device
            dev = device_node(dev_name, at)
            add_edge(host["node_id"], dev["node_id"], ATTACHES_TO, "l2", at,
                     {"port": o.attrs.get("port", ""), "vlan": o.attrs.get("vlan", ""),
                      "evidence": o.collector}, evidence=o.collector)
        elif ot == "vm_nic":
            mac = o.subj_id.split("mac:", 1)[-1]
            host = host_node(mac, at)
            host["attrs"]["virtual"] = "true"
            dev = device_node(o.source_device, at)
            add_edge(host["node_id"], dev["node_id"], ATTACHES_TO, "l2", at,
                     {"bridge": o.attrs.get("bridge", ""), "vlan": o.attrs.get("vlan", ""),
                      "evidence": "proxmox"}, evidence="proxmox")
        elif ot == "vm_host":
            dev = device_node(o.source_device, at)
            dev["attrs"]["role"] = "hypervisor"
            vm_key = o.obj_id
            vm_node = touch_node(node_id(tenant, HOST, vm_key), HOST,
                                 o.attrs.get("name", vm_key), at)
            vm_node["identifiers"]["vmid"] = o.attrs.get("vmid", "")
            vm_node["attrs"]["virtual"] = "true"
            add_edge(dev["node_id"], vm_node["node_id"], HOSTS, "virt", at,
                     {"vmid": o.attrs.get("vmid", ""), "evidence": "proxmox"},
                     evidence="proxmox")
        elif ot == "lldp_neighbor":
            local_sys = o.source_device
            remote_sys = o.attrs.get("remote_system", "") or o.obj_id.split("if:", 1)[-1].split(":", 1)[0]
            dev_a = device_node(local_sys, at)
            dev_b = device_node(remote_sys, at)
            remote_chassis = o.attrs.get("remote_chassis", "")
            if _MAC_RE.match(remote_chassis):
                dev_b["identifiers"]["mac"] = remote_chassis.lower()
            if_a = touch_node(node_id(tenant, INTERFACE, o.subj_id), INTERFACE,
                              o.attrs.get("local_port", ""), at)
            if_b = touch_node(node_id(tenant, INTERFACE, o.obj_id), INTERFACE,
                              o.attrs.get("remote_port", ""), at)
            if_a["attrs"]["device"] = local_sys
            if_b["attrs"]["device"] = remote_sys
            add_edge(if_a["node_id"], if_b["node_id"], PHYSICAL_LINK, "l2", at,
                     {"local_port": o.attrs.get("local_port", ""),
                      "remote_port": o.attrs.get("remote_port", ""),
                      "device_a": local_sys, "device_b": remote_sys,
                      "evidence": o.collector}, evidence=f"{o.collector}:{local_sys}")
        elif ot == "device_inventory":
            mac = o.attrs.get("mac", "").lower()
            dev = device_node(o.attrs.get("name", "") or f"dev:{mac}", at)
            dev["attrs"]["role"] = o.attrs.get("role", "device")
            if mac:
                dev["identifiers"]["mac"] = mac
            if o.attrs.get("ip"):
                dev["identifiers"]["mgmt_ip"] = o.attrs["ip"]

    _merge_devices(nodes, edges, edge_evidence, tenant)

    for eid, e in edges.items():
        if len(edge_evidence[eid]) >= 2:
            e["confidence"] = 1.0
        e["attrs"]["evidence"] = ",".join(sorted(edge_evidence[eid]))

    known_ip_aliases = {n["identifiers"].get("ip") for n in nodes.values()
                        if n["kind"] == HOST and n["identifiers"].get("ip")}
    for fe in flow_edges:
        for endpoint in (fe["src_id"], fe["dst_id"]):
            if endpoint in nodes:
                continue
            n = touch_node(endpoint, HOST, "", fe["first_seen"])
            n["attrs"]["unresolved"] = "l3_only"
        edges[fe["edge_id"]] = fe

    return list(nodes.values()), list(edges.values())
