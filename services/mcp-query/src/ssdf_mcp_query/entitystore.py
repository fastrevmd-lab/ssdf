"""Read-only entity access seam over ClickHouse ssdf.entities / ssdf.entity_edges."""

from __future__ import annotations

from typing import Protocol

from .graphstore import _normalize_identifier  # reuse MAC-aware lowercasing

# NOTE: these column lists alias `toString(...) AS first_seen/last_seen`. An
# unqualified `first_seen`/`last_seen` in a WHERE or ORDER BY binds to that String
# alias, not the real DateTime64 column, turning datetime comparisons/sorts into
# lexical string compares. ALWAYS qualify the column (e.g. `entities.last_seen`)
# in any filter or ordering built against these SELECTs.
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
        "ORDER BY confidence DESC, entities.last_seen DESC LIMIT 1"
    )
    return sql, {"tenant": tenant, "val": _normalize_identifier(value)}


def build_entities_match_sql(value: str, tenant: str) -> tuple[str, dict]:
    # Identical match to build_entity_match_sql WITHOUT LIMIT 1: returns every
    # candidate twin for the identifier. Order is preserved (confidence DESC,
    # last_seen DESC) so row 0 is the same entity find_entity returns today.
    sql = (
        f"SELECT {_ENTITY_COLS} FROM ssdf.entities FINAL "
        "WHERE tenant_id = {tenant:String} AND ("
        "entity_id = {val:String} OR has(mapValues(identifiers), {val:String})) "
        "ORDER BY confidence DESC, entities.last_seen DESC"
    )
    return sql, {"tenant": tenant, "val": _normalize_identifier(value)}


def build_comm_edges_sql(a_id: str, b_id: str, since_iso: str,
                         tenant: str) -> tuple[str, dict]:
    # `entity_edges.last_seen` is qualified per the alias-shadowing note above:
    # an unqualified `last_seen` here binds to the String alias and lexically
    # drops every row (space < 'T' vs the ISO `since` value).
    sql = (
        f"SELECT {_EDGE_COLS} FROM ssdf.entity_edges FINAL "
        "WHERE tenant_id = {tenant:String} AND edge_type = 'communicated_with' "
        "AND entity_edges.last_seen >= {since:String} AND ("
        "(src_id = {a:String} AND dst_id = {b:String}) OR "
        "(src_id = {b:String} AND dst_id = {a:String}))"
    )
    return sql, {"tenant": tenant, "a": a_id, "b": b_id, "since": since_iso}


def build_comm_edges_multi_sql(a_ids: list[str], b_ids: list[str], since_iso: str,
                               tenant: str) -> tuple[str, dict]:
    # Same shape as build_comm_edges_sql but with IN-lists on both directions, so
    # candidate twin sets on each side are matched in one query. `entity_edges.last_seen`
    # is qualified per the alias-shadowing note above (unqualified binds the String alias).
    sql = (
        f"SELECT {_EDGE_COLS} FROM ssdf.entity_edges FINAL "
        "WHERE tenant_id = {tenant:String} AND edge_type = 'communicated_with' "
        "AND entity_edges.last_seen >= {since:String} AND ("
        "(src_id IN {a:Array(String)} AND dst_id IN {b:Array(String)}) OR "
        "(src_id IN {b:Array(String)} AND dst_id IN {a:Array(String)}))"
    )
    return sql, {"tenant": tenant, "a": a_ids, "b": b_ids, "since": since_iso}


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


def build_firewall_match_sql(device_names: list[str], tenant: str) -> tuple[str, dict]:
    sql = (
        f"SELECT {_ENTITY_COLS} FROM ssdf.entities FINAL "
        "WHERE tenant_id = {tenant:String} AND kind = 'firewall' "
        "AND identifiers['device_name'] IN {names:Array(String)}"
    )
    return sql, {"tenant": tenant, "names": device_names}


def build_configured_governed_sql(firewall_ids: list[str], tenant: str) -> tuple[str, dict]:
    sql = (
        f"SELECT {_EDGE_COLS} FROM ssdf.entity_edges FINAL "
        "WHERE tenant_id = {tenant:String} AND edge_type = 'governed_by' "
        "AND source = 'configured' AND src_id IN {ids:Array(String)}"
    )
    return sql, {"tenant": tenant, "ids": firewall_ids}


def build_alerts_for_pair_sql(ips: list[str], since_iso: str,
                              tenant: str) -> tuple[str, dict]:
    # UniFi IPS alerts (M9) touching either endpoint IP in-window. source_ip/
    # destination_ip are Nullable(IPv4); compare via toString to match the
    # dotted-quad params without IPv4-cast fragility. IPv6 alerts (kept only in
    # ext/raw) do not match here by design (events schema is IPv4-only).
    # LIMIT 200: most-recent-200 detections; bounded to avoid result-overflow
    # throw on busy endpoints (CH client runs result_overflow_mode="throw").
    sql = (
        "SELECT toString(timestamp) AS timestamp, toString(source_ip) AS source_ip, "
        "toString(destination_ip) AS destination_ip, "
        "ext['unifi.ips.signature'] AS signature, "
        "ext['unifi.ips.signature_id'] AS signature_id, "
        "ext['unifi.ips.category'] AS category, "
        "ext['unifi.ips.severity'] AS severity "
        "FROM ssdf.events "
        "WHERE tenant_id = {tenant:String} AND event_provider = 'unifi' "
        "AND event_kind = 'alert' AND timestamp >= {since:String} AND ("
        "toString(source_ip) IN {ips:Array(String)} OR "
        "toString(destination_ip) IN {ips:Array(String)}) "
        "ORDER BY timestamp DESC LIMIT 200"
    )
    return sql, {"tenant": tenant, "ips": ips, "since": since_iso}


class EntityStore(Protocol):
    def find_entity(self, identifier: str) -> dict | None: ...
    def communicated_edges(self, a_id: str, b_id: str, since_iso: str) -> list[dict]: ...
    def find_entities(self, identifier: str) -> list[dict]: ...
    def communicated_edges_multi(self, a_ids: list[str], b_ids: list[str],
                                 since_iso: str) -> list[dict]: ...
    def governed_policies(self, comm_edge_ids: list[str]) -> list[dict]: ...
    def configured_policies_for_firewalls(self, firewall_names: list[str]) -> list[dict]: ...
    def alerts_for_pair(self, ips: list[str], since_iso: str) -> list[dict]: ...


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

    def find_entities(self, identifier: str) -> list[dict]:
        sql, params = build_entities_match_sql(identifier, self._tenant)
        return self._ch.run(sql, params)["rows"]

    def communicated_edges_multi(self, a_ids: list[str], b_ids: list[str],
                                 since_iso: str) -> list[dict]:
        if not a_ids or not b_ids:
            return []
        sql, params = build_comm_edges_multi_sql(a_ids, b_ids, since_iso, self._tenant)
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

    def configured_policies_for_firewalls(self, firewall_names: list[str]) -> list[dict]:
        """Return [{firewall: <device_name>, policy: <entity>}] for configured rules on the
        named firewalls (matched to Firewall entities by identifiers['device_name'])."""
        if not firewall_names:
            return []
        fw_sql, fw_params = build_firewall_match_sql(firewall_names, self._tenant)
        firewalls = self._ch.run(fw_sql, fw_params)["rows"]
        fw_by_id = {f["entity_id"]: f for f in firewalls}
        if not fw_by_id:
            return []
        gov_sql, gov_params = build_configured_governed_sql(list(fw_by_id), self._tenant)
        gov_edges = self._ch.run(gov_sql, gov_params)["rows"]
        policy_ids = sorted({e["dst_id"] for e in gov_edges})
        if not policy_ids:
            return []
        pol_sql, pol_params = build_entities_by_id_sql(policy_ids, self._tenant)
        policies = {p["entity_id"]: p for p in self._ch.run(pol_sql, pol_params)["rows"]}
        result = []
        for edge in gov_edges:
            fw = fw_by_id.get(edge["src_id"])
            policy = policies.get(edge["dst_id"])
            if fw and policy:
                name = fw["identifiers"].get("device_name") or fw.get("name", "")
                result.append({"firewall": name, "policy": policy})
        return result

    def alerts_for_pair(self, ips: list[str], since_iso: str) -> list[dict]:
        if not ips:
            return []
        sql, params = build_alerts_for_pair_sql(ips, since_iso, self._tenant)
        return self._ch.run(sql, params)["rows"]
