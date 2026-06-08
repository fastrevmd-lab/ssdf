"""Reconcile duplicate ip_only Asset twins into their MAC-anchored Asset.

A twin is an ip_only Asset whose IP resolves, via the segment-scoped binding map,
to exactly one MAC for which a MAC-anchored Asset already exists (IP and MAC agree).
Twins whose IP is unbound, or bound to multiple MACs (cross-segment reuse / conflict),
are left untouched. Confirmed twins have their COMMUNICATED_WITH edges merged into the
MAC asset's corresponding edge, then the twin and its edges are deleted.
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

    merged_edges: dict[str, dict] = {}
    delete_entity_ids: list[str] = []
    delete_edge_ids: list[str] = []

    for twin in ip_only_assets:
        target_mac = None
        for ip in _ips_of(twin):
            mac = ip_to_mac.get(ip)
            if mac and mac in mac_asset_by_mac:
                target_mac = mac
                break
        if target_mac is None:
            continue
        mac_id = mac_asset_by_mac[target_mac]["entity_id"]
        twin_id = twin["entity_id"]
        delete_entity_ids.append(twin_id)

        twin_comm = [e for e in comm_edges if twin_id in (e["src_id"], e["dst_id"])]
        for edge in twin_comm:
            delete_edge_ids.append(edge["edge_id"])
            new_src = mac_id if edge["src_id"] == twin_id else edge["src_id"]
            new_dst = mac_id if edge["dst_id"] == twin_id else edge["dst_id"]
            new_id = edge_id(tenant, new_src, new_dst, COMMUNICATED_WITH, OBSERVED)
            target = merged_edges.get(new_id) or dict(comm_by_id.get(new_id) or {})
            if not target:
                target = {
                    "edge_id": new_id, "tenant_id": tenant, "src_id": new_src,
                    "dst_id": new_dst, "edge_type": COMMUNICATED_WITH,
                    "source": OBSERVED, "confidence": 1.0,
                    "attrs": {"sessions": "0", "bytes": "0", "ports": "",
                              "providers": "", "transports": "", "observer_hosts": ""},
                    "first_seen": edge["first_seen"], "last_seen": edge["last_seen"],
                }
            else:
                target = dict(target)
                target["attrs"] = dict(target["attrs"])
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
            merged_edges[new_id] = target

            # delete governed_by edges hanging off the twin's comm edge
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
