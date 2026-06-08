"""Read-only entity access seam over ClickHouse ssdf.entities / ssdf.entity_edges."""

from __future__ import annotations

from typing import Protocol

from .graphstore import _normalize_identifier  # reuse MAC-aware lowercasing

_ENTITY_COLS = (
    "entity_id, kind, name, identifiers, source, identity_basis, confidence, "
    "toString(first_seen) AS first_seen, toString(last_seen) AS last_seen, attrs"
)
_EDGE_COLS = (
    "edge_id, src_id, dst_id, edge_type, source, confidence, "
    "toString(first_seen) AS first_seen, toString(last_seen) AS last_seen, attrs"
)


def build_entity_match_sql(value: str, tenant: str) -> tuple[str, dict]:
    sql = (
        f"SELECT {_ENTITY_COLS} FROM ssdf.entities FINAL "
        "WHERE tenant_id = {tenant:String} AND ("
        "entity_id = {val:String} OR has(mapValues(identifiers), {val:String})) "
        "ORDER BY last_seen DESC LIMIT 1"
    )
    return sql, {"tenant": tenant, "val": _normalize_identifier(value)}


def build_comm_edges_sql(a_id: str, b_id: str, since_iso: str,
                         tenant: str) -> tuple[str, dict]:
    # `entity_edges.last_seen` is qualified on purpose: `_EDGE_COLS` aliases
    # `toString(last_seen) AS last_seen`, and an unqualified `last_seen` in WHERE
    # binds to that String alias — making this a lexical compare against the
    # ISO `since` value (space < 'T') that silently drops every row. Qualifying
    # forces the real DateTime64 column so ClickHouse parses `since` as a datetime.
    sql = (
        f"SELECT {_EDGE_COLS} FROM ssdf.entity_edges FINAL "
        "WHERE tenant_id = {tenant:String} AND edge_type = 'communicated_with' "
        "AND entity_edges.last_seen >= {since:String} AND ("
        "(src_id = {a:String} AND dst_id = {b:String}) OR "
        "(src_id = {b:String} AND dst_id = {a:String}))"
    )
    return sql, {"tenant": tenant, "a": a_id, "b": b_id, "since": since_iso}


def build_governed_by_sql(comm_edge_ids: list[str], tenant: str) -> tuple[str, dict]:
    sql = (
        f"SELECT {_EDGE_COLS} FROM ssdf.entity_edges FINAL "
        "WHERE tenant_id = {tenant:String} AND edge_type = 'governed_by' "
        "AND src_id IN {ids:Array(String)}"
    )
    return sql, {"tenant": tenant, "ids": comm_edge_ids}


def build_entities_by_id_sql(entity_ids: list[str], tenant: str) -> tuple[str, dict]:
    sql = (
        f"SELECT {_ENTITY_COLS} FROM ssdf.entities FINAL "
        "WHERE tenant_id = {tenant:String} AND entity_id IN {ids:Array(String)}"
    )
    return sql, {"tenant": tenant, "ids": entity_ids}


class EntityStore(Protocol):
    def find_entity(self, identifier: str) -> dict | None: ...
    def communicated_edges(self, a_id: str, b_id: str, since_iso: str) -> list[dict]: ...
    def governed_policies(self, comm_edge_ids: list[str]) -> list[dict]: ...


class ClickHouseEntityStore:
    """EntityStore backed by ClickHouse (the swappable storage seam)."""

    def __init__(self, ch_client, tenant: str = "t_main"):
        self._ch = ch_client
        self._tenant = tenant

    def find_entity(self, identifier: str) -> dict | None:
        sql, params = build_entity_match_sql(identifier, self._tenant)
        rows = self._ch.run(sql, params)["rows"]
        return rows[0] if rows else None

    def communicated_edges(self, a_id: str, b_id: str, since_iso: str) -> list[dict]:
        sql, params = build_comm_edges_sql(a_id, b_id, since_iso, self._tenant)
        return self._ch.run(sql, params)["rows"]

    def governed_policies(self, comm_edge_ids: list[str]) -> list[dict]:
        """Return [{policy: <entity>, edge_attrs: <governed_by attrs>}] for the given comm edges."""
        if not comm_edge_ids:
            return []
        gov_sql, gov_params = build_governed_by_sql(comm_edge_ids, self._tenant)
        gov_edges = self._ch.run(gov_sql, gov_params)["rows"]
        policy_ids = sorted({e["dst_id"] for e in gov_edges})
        if not policy_ids:
            return []
        ent_sql, ent_params = build_entities_by_id_sql(policy_ids, self._tenant)
        policies = {p["entity_id"]: p for p in self._ch.run(ent_sql, ent_params)["rows"]}
        result = []
        for edge in gov_edges:
            policy = policies.get(edge["dst_id"])
            if policy:
                result.append({"policy": policy, "edge_attrs": edge["attrs"]})
        return result
