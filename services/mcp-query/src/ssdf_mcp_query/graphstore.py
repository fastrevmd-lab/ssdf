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


# `schema` is a fixed build-time constant ("ssdf" or "ssdf_public"), never user input.
def build_node_match_sql(value: str, tenant: str, schema: str = "ssdf") -> tuple[str, dict]:
    sql = (
        "SELECT node_id, kind, name, identifiers, toString(first_seen) AS first_seen, "
        f"toString(last_seen) AS last_seen, attrs FROM {schema}.graph_nodes FINAL "
        "WHERE tenant_id = {tenant:String} AND ("
        "node_id = {val:String} OR has(mapValues(identifiers), {val:String})) "
        "ORDER BY last_seen DESC LIMIT 1"
    )
    return sql, {"tenant": tenant, "val": _normalize_identifier(value)}


def build_subgraph_sql(
    since_iso: str, tenant: str, limit: int = 5000, schema: str = "ssdf"
) -> tuple[str, dict]:
    sql = (
        "SELECT edge_id, src_id, dst_id, edge_type, layer, "
        "toString(first_seen) AS first_seen, toString(last_seen) AS last_seen, "
        f"confidence, attrs FROM {schema}.graph_edges FINAL "
        "WHERE tenant_id = {tenant:String} AND last_seen >= {since:String} "
        f"ORDER BY last_seen DESC LIMIT {int(limit)}"
    )
    return sql, {"tenant": tenant, "since": since_iso}


def build_nodes_by_id_sql(
    node_ids: list[str], tenant: str, schema: str = "ssdf"
) -> tuple[str, dict]:
    sql = (
        "SELECT node_id, kind, name, identifiers, toString(first_seen) AS first_seen, "
        f"toString(last_seen) AS last_seen, attrs FROM {schema}.graph_nodes FINAL "
        "WHERE tenant_id = {tenant:String} AND node_id IN {ids:Array(String)}"
    )
    return sql, {"tenant": tenant, "ids": node_ids}


def build_nodes_by_attr_sql(
    role: str | None,
    kind: str | None,
    tenant: str,
    limit: int = 5000,
    schema: str = "ssdf",
) -> tuple[str, dict]:
    # Inventory selection by current node state (FINAL = latest version per
    # node_id), NOT edge-derived: firewall device_inventory nodes are isolated
    # (no edges), so an edge-first subgraph can never surface them. No time
    # window — "which devices are firewalls" is a current-state question, and a
    # node lingering stale (collector lull) is still part of the inventory.
    clauses = ["tenant_id = {tenant:String}"]
    params: dict = {"tenant": tenant}
    if role is not None:
        clauses.append("attrs['role'] = {role:String}")
        params["role"] = role
    if kind is not None:
        clauses.append("kind = {kind:String}")
        params["kind"] = kind
    sql = (
        "SELECT node_id, kind, name, identifiers, toString(first_seen) AS first_seen, "
        f"toString(last_seen) AS last_seen, attrs FROM {schema}.graph_nodes FINAL "
        "WHERE " + " AND ".join(clauses) + f" ORDER BY last_seen DESC LIMIT {int(limit)}"
    )
    return sql, params


class GraphStore(Protocol):
    def find_node(self, identifier: str) -> dict | None: ...
    def load_subgraph(self, since_iso: str, limit: int = 5000) -> tuple[list[dict], list[dict]]: ...
    def nodes_by_attr(
        self, role: str | None = None, kind: str | None = None, limit: int = 5000
    ) -> list[dict]: ...


class ClickHouseGraphStore:
    """GraphStore backed by ClickHouse (the swappable storage seam)."""

    def __init__(self, ch_client, tenant: str = "t_main", schema: str = "ssdf"):
        self._ch = ch_client
        self._tenant = tenant
        self._schema = schema

    def find_node(self, identifier: str) -> dict | None:
        sql, params = build_node_match_sql(identifier, self._tenant, schema=self._schema)
        rows = self._ch.run(sql, params)["rows"]
        return rows[0] if rows else None

    def load_subgraph(self, since_iso: str, limit: int = 5000) -> tuple[list[dict], list[dict]]:
        edge_sql, edge_params = build_subgraph_sql(
            since_iso, self._tenant, limit, schema=self._schema
        )
        edges = self._ch.run(edge_sql, edge_params)["rows"]
        node_ids = sorted({e["src_id"] for e in edges} | {e["dst_id"] for e in edges})
        nodes: list[dict] = []
        if node_ids:
            node_sql, node_params = build_nodes_by_id_sql(
                node_ids, self._tenant, schema=self._schema
            )
            nodes = self._ch.run(node_sql, node_params)["rows"]
        return nodes, edges

    def nodes_by_attr(
        self, role: str | None = None, kind: str | None = None, limit: int = 5000
    ) -> list[dict]:
        sql, params = build_nodes_by_attr_sql(role, kind, self._tenant, limit, schema=self._schema)
        return self._ch.run(sql, params)["rows"]
