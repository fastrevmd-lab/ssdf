# src/ssdf_mcp_query/graphstore.py
"""Read-only graph access seam over ClickHouse graph_nodes/graph_edges."""

from __future__ import annotations

import re
from typing import Protocol

_MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$", re.IGNORECASE)


def _normalize_identifier(value: str) -> str:
    """Lowercase MAC-shaped lookups since MACs are stored lowercase; pass
    everything else (names, IPs, node_ids) through unchanged."""
    return value.lower() if _MAC_RE.match(value) else value


def build_node_match_sql(value: str, tenant: str) -> tuple[str, dict]:
    sql = (
        "SELECT node_id, kind, name, identifiers, toString(first_seen) AS first_seen, "
        "toString(last_seen) AS last_seen, attrs FROM ssdf.graph_nodes FINAL "
        "WHERE tenant_id = {tenant:String} AND ("
        "node_id = {val:String} OR has(mapValues(identifiers), {val:String})) "
        "ORDER BY last_seen DESC LIMIT 1"
    )
    return sql, {"tenant": tenant, "val": _normalize_identifier(value)}


def build_subgraph_sql(since_iso: str, tenant: str, limit: int = 5000) -> tuple[str, dict]:
    sql = (
        "SELECT edge_id, src_id, dst_id, edge_type, layer, "
        "toString(first_seen) AS first_seen, toString(last_seen) AS last_seen, "
        "confidence, attrs FROM ssdf.graph_edges FINAL "
        "WHERE tenant_id = {tenant:String} AND last_seen >= {since:String} "
        f"ORDER BY last_seen DESC LIMIT {int(limit)}"
    )
    return sql, {"tenant": tenant, "since": since_iso}


def build_nodes_by_id_sql(node_ids: list[str], tenant: str) -> tuple[str, dict]:
    sql = (
        "SELECT node_id, kind, name, identifiers, toString(first_seen) AS first_seen, "
        "toString(last_seen) AS last_seen, attrs FROM ssdf.graph_nodes FINAL "
        "WHERE tenant_id = {tenant:String} AND node_id IN {ids:Array(String)}"
    )
    return sql, {"tenant": tenant, "ids": node_ids}


class GraphStore(Protocol):
    def find_node(self, identifier: str) -> dict | None: ...
    def load_subgraph(self, since_iso: str, limit: int = 5000) -> tuple[list[dict], list[dict]]: ...


class ClickHouseGraphStore:
    """GraphStore backed by ClickHouse (the swappable storage seam)."""

    def __init__(self, ch_client, tenant: str = "t_main"):
        self._ch = ch_client
        self._tenant = tenant

    def find_node(self, identifier: str) -> dict | None:
        sql, params = build_node_match_sql(identifier, self._tenant)
        rows = self._ch.run(sql, params)["rows"]
        return rows[0] if rows else None

    def load_subgraph(self, since_iso: str, limit: int = 5000) -> tuple[list[dict], list[dict]]:
        edge_sql, edge_params = build_subgraph_sql(since_iso, self._tenant, limit)
        edges = self._ch.run(edge_sql, edge_params)["rows"]
        node_ids = sorted({e["src_id"] for e in edges} | {e["dst_id"] for e in edges})
        nodes: list[dict] = []
        if node_ids:
            node_sql, node_params = build_nodes_by_id_sql(node_ids, self._tenant)
            nodes = self._ch.run(node_sql, node_params)["rows"]
        return nodes, edges
