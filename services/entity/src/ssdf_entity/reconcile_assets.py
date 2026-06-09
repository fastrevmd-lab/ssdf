"""Reconcile duplicate ip_only Asset twins into their MAC-anchored Asset.

A twin is an ip_only Asset whose IP resolves, via the segment-scoped binding map,
to exactly one MAC for which a MAC-anchored Asset already exists (IP and MAC agree).
Twins whose IP is unbound, or bound to multiple MACs (cross-segment reuse / conflict),
are left untouched. Confirmed twins have their COMMUNICATED_WITH edges merged into the
MAC asset's corresponding edge, then the twin and its edges are deleted. GOVERNED_BY
edges off the twin's comm edge are deleted (not re-pointed): the next resolver pass
re-derives GOVERNED_BY on the MAC-anchored comm edge within one cycle.
"""

from __future__ import annotations

import logging

from .chwriter import (
    ClickHouseEntityWriter, build_assets_by_basis_sql,
    build_all_edges_by_type_sql, build_binding_sql,
)
from .config import Config, load_config
from .models import COMMUNICATED_WITH, OBSERVED, edge_id
from .resolve_entities import build_binding_map
from .resolve_entities import _merge_set_attr  # reuse comma-set union

log = logging.getLogger("ssdf_entity.reconcile")


def _ips_of(asset: dict) -> list[str]:
    return [v for k, v in asset.get("identifiers", {}).items() if k.startswith("ip")]


def _ip_to_unique_mac(binding_map: dict[tuple[str, str], str]) -> dict[str, str]:
    """Collapse {(segment, ip) -> mac} to {ip -> mac} only where the IP maps to
    exactly one MAC across all segments (otherwise it is ambiguous)."""
    macs_by_ip: dict[str, set[str]] = {}
    for (_segment, ip), mac in binding_map.items():
        macs_by_ip.setdefault(ip, set()).add(mac)
    return {ip: next(iter(macs)) for ip, macs in macs_by_ip.items() if len(macs) == 1}


def plan_reconciliation(ip_only_assets: list[dict], mac_assets: list[dict],
                        comm_edges: list[dict], gov_edges: list[dict],
                        binding_map: dict[tuple[str, str], str],
                        tenant: str) -> dict:
    ip_to_mac = _ip_to_unique_mac(binding_map)
    mac_asset_by_mac = {a["identifiers"].get("mac"): a for a in mac_assets
                        if a["identifiers"].get("mac")}
    comm_by_id = {e["edge_id"]: e for e in comm_edges}

    # Resolve every confirmed twin to its MAC asset's entity id up front, so an
    # edge whose *peer* is itself a twin has BOTH endpoints rewritten — no dangling
    # reference to a deleted entity, and twin-to-twin stats are not lost.
    twin_to_mac_id: dict[str, str] = {}
    for twin in ip_only_assets:
        for ip in _ips_of(twin):
            mac = ip_to_mac.get(ip)
            if mac and mac in mac_asset_by_mac:
                twin_to_mac_id[twin["entity_id"]] = mac_asset_by_mac[mac]["entity_id"]
                break

    delete_entity_ids: list[str] = list(twin_to_mac_id)
    merged_edges: dict[str, dict] = {}
    delete_edge_ids: list[str] = []

    for edge in comm_edges:
        if edge["src_id"] not in twin_to_mac_id and edge["dst_id"] not in twin_to_mac_id:
            continue
        delete_edge_ids.append(edge["edge_id"])
        new_src = twin_to_mac_id.get(edge["src_id"], edge["src_id"])
        new_dst = twin_to_mac_id.get(edge["dst_id"], edge["dst_id"])
        new_id = edge_id(tenant, new_src, new_dst, COMMUNICATED_WITH, OBSERVED)
        target = merged_edges.get(new_id)
        if target is None:
            seed = comm_by_id.get(new_id)
            if seed is not None:
                target = dict(seed)
                target["attrs"] = dict(seed["attrs"])
            else:
                target = {
                    "edge_id": new_id, "tenant_id": tenant, "src_id": new_src,
                    "dst_id": new_dst, "edge_type": COMMUNICATED_WITH,
                    "source": OBSERVED, "confidence": 1.0,
                    "attrs": {"sessions": "0", "bytes": "0", "ports": "",
                              "providers": "", "transports": "", "observer_hosts": ""},
                    "first_seen": edge["first_seen"], "last_seen": edge["last_seen"],
                }
            merged_edges[new_id] = target
        attrs, src_attrs = target["attrs"], edge["attrs"]
        attrs["sessions"] = str(int(attrs.get("sessions", "0") or "0")
                                + int(src_attrs.get("sessions", "0") or "0"))
        attrs["bytes"] = str(int(attrs.get("bytes", "0") or "0")
                             + int(src_attrs.get("bytes", "0") or "0"))
        for key in ("ports", "providers", "transports", "observer_hosts"):
            _merge_set_attr(attrs, key,
                            filter(None, (src_attrs.get(key, "") or "").split(",")))
        target["first_seen"] = min(target["first_seen"], edge["first_seen"])
        target["last_seen"] = max(target["last_seen"], edge["last_seen"])

        # GOVERNED_BY edges hang off the twin's comm edge id; delete them. The next
        # resolver pass re-derives GOVERNED_BY on the MAC-anchored comm edge (it keys
        # comm edges on entity ids), so policy linkage is restored within one cycle.
        for gov in gov_edges:
            if gov["src_id"] == edge["edge_id"]:
                delete_edge_ids.append(gov["edge_id"])

    return {
        "merged_edges": list(merged_edges.values()),
        "delete_entity_ids": delete_entity_ids,
        "delete_edge_ids": delete_edge_ids,
    }


def reconcile(writer: ClickHouseEntityWriter, tenant: str,
              binding_lookback_hours: int) -> dict:
    ip_only = writer.query(*build_assets_by_basis_sql("ip_only", tenant))
    mac_assets = writer.query(*build_assets_by_basis_sql("mac", tenant))
    comm_edges = writer.query(*build_all_edges_by_type_sql(COMMUNICATED_WITH, tenant))
    gov_edges = writer.query(*build_all_edges_by_type_sql("governed_by", tenant))
    bindings = writer.query(*build_binding_sql(binding_lookback_hours, tenant))
    binding_map, _conflict = build_binding_map(bindings)
    plan = plan_reconciliation(ip_only, mac_assets, comm_edges, gov_edges,
                               binding_map, tenant)
    writer.replace_edges(plan["merged_edges"])
    writer.delete_edges(plan["delete_edge_ids"])
    writer.delete_entities(plan["delete_entity_ids"])
    log.info("reconcile: %d twins deleted, %d edges merged, %d edges deleted",
             len(plan["delete_entity_ids"]), len(plan["merged_edges"]),
             len(plan["delete_edge_ids"]))
    return plan


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    config: Config = load_config()
    writer = ClickHouseEntityWriter(config)
    reconcile(writer, tenant=config.tenant_id,
              binding_lookback_hours=config.binding_lookback_hours)


if __name__ == "__main__":
    main()
