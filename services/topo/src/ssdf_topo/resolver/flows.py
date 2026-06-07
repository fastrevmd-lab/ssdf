# src/ssdf_topo/resolver/flows.py
"""Aggregate ssdf.events into flow edges (talked_to / governed_by / in_zone)."""

from __future__ import annotations

from ..models import (
    node_id, edge_id, HOST, ZONE, RULE, TALKED_TO, GOVERNED_BY, IN_ZONE,
)


def build_flow_agg_sql(window_hours: int, tenant: str) -> tuple[str, dict]:
    sql = (
        "SELECT toString(source_ip) AS src_ip, toString(destination_ip) AS dst_ip, "
        "sum(network_bytes) AS bytes, count() AS flows, "
        "any(rule_name) AS rule_name, any(observer_ingress_zone) AS ingress_zone, "
        "any(observer_egress_zone) AS egress_zone, any(event_provider) AS provider, "
        "toString(min(timestamp)) AS first_seen, toString(max(timestamp)) AS last_seen "
        "FROM ssdf.events "
        "WHERE tenant_id = {tenant:String} "
        "AND timestamp >= now() - INTERVAL {window_hours:UInt32} HOUR "
        "AND source_ip IS NOT NULL AND destination_ip IS NOT NULL "
        "GROUP BY src_ip, dst_ip"
    )
    return sql, {"tenant": tenant, "window_hours": window_hours}


def flow_to_edges(agg: list[dict], tenant: str) -> list[dict]:
    edges: list[dict] = []
    for row in agg:
        src = node_id(tenant, HOST, f"ip:{row['src_ip']}")
        dst = node_id(tenant, HOST, f"ip:{row['dst_ip']}")
        first, last = row["first_seen"], row["last_seen"]
        rule = str(row.get("rule_name") or "")
        provider = str(row.get("provider") or "")
        talked = {
            "edge_id": edge_id(tenant, src, dst, TALKED_TO, "flow"),
            "tenant_id": tenant, "src_id": src, "dst_id": dst,
            "edge_type": TALKED_TO, "layer": "flow",
            "first_seen": first, "last_seen": last, "confidence": 1.0,
            "attrs": {"bytes": str(row.get("bytes", 0)), "flows": str(row.get("flows", 0)),
                      "provider": provider, "evidence": "ssdf.events"},
        }
        edges.append(talked)
        if rule:
            rule_node = node_id(tenant, RULE, f"{provider}:{rule}")
            edges.append({
                "edge_id": edge_id(tenant, talked["edge_id"], rule_node, GOVERNED_BY, "flow"),
                "tenant_id": tenant, "src_id": talked["edge_id"], "dst_id": rule_node,
                "edge_type": GOVERNED_BY, "layer": "flow",
                "first_seen": first, "last_seen": last, "confidence": 1.0,
                "attrs": {"rule_name": rule, "evidence": "ssdf.events"},
            })
        for ip, zone in ((row["src_ip"], row.get("ingress_zone")),
                         (row["dst_ip"], row.get("egress_zone"))):
            if not zone:
                continue
            host = node_id(tenant, HOST, f"ip:{ip}")
            zone_node = node_id(tenant, ZONE, f"{provider}:{zone}")
            edges.append({
                "edge_id": edge_id(tenant, host, zone_node, IN_ZONE, "flow"),
                "tenant_id": tenant, "src_id": host, "dst_id": zone_node,
                "edge_type": IN_ZONE, "layer": "flow",
                "first_seen": first, "last_seen": last, "confidence": 1.0,
                "attrs": {"zone": str(zone), "evidence": "ssdf.events"},
            })
    return edges
