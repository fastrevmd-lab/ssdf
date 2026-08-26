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
    # The SELECT aliases `toString(last_seen) AS last_seen`. An UNQUALIFIED
    # `last_seen` in WHERE/ORDER BY binds to that String alias, not the real
    # DateTime column, turning the window filter into a lexical string compare
    # against `since_iso` ("...T...+00:00"). Those formats differ at offset 10
    # (' ' vs 'T'), so every row sharing a UTC date with the window start was
    # silently dropped — a same-day window returned 0 edges instead of all of
    # them, with no error. Qualify the column and parse the bound explicitly.
    sql = (
        "SELECT edge_id, src_id, dst_id, edge_type, layer, "
        "toString(first_seen) AS first_seen, toString(last_seen) AS last_seen, "
        f"confidence, attrs FROM {schema}.graph_edges FINAL "
        "WHERE tenant_id = {tenant:String} "
        "AND graph_edges.last_seen >= parseDateTimeBestEffort({since:String}) "
        f"ORDER BY graph_edges.last_seen DESC LIMIT {int(limit)}"
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


def _collapse_superseded(rows: list[dict]) -> list[dict]:
    """Keep one row per named device: the freshest.

    graph_nodes is a ReplacingMergeTree keyed on node_id, so a device whose
    identity changes — a MAC-named node fusing with its inventory name, a rename —
    leaves its previous row behind until TTL expires it. Both rows carry the same
    name, so every consumer counted the device twice; live, 23 rows described 20
    devices.

    Deduping on identity rather than age is deliberate. A staleness filter would
    also hide a device that genuinely stopped reporting, and surfacing exactly that
    is what ingest_status exists for. An unnamed row cannot be matched to another,
    so it is passed through untouched rather than silently dropped.
    """
    freshest: dict[str, dict] = {}
    passthrough: list[dict] = []
    for row in rows:
        name = row.get("name") or ""
        if not name:
            passthrough.append(row)
            continue
        current = freshest.get(name)
        if current is None or row.get("last_seen", "") > current.get("last_seen", ""):
            freshest[name] = row
    return [*freshest.values(), *passthrough]


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
        return _collapse_superseded(self._ch.run(sql, params)["rows"])
