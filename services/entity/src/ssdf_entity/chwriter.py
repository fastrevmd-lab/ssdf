"""ClickHouse I/O for the entity layer: read flow-agg + topo hosts, write entities/edges."""

from __future__ import annotations

from typing import Any, Iterable

import clickhouse_connect

from .config import Config

ENTITY_COLUMNS = [
    "entity_id", "tenant_id", "kind", "name", "identifiers", "source",
    "identity_basis", "confidence", "attrs", "first_seen", "last_seen",
]
ENTITY_EDGE_COLUMNS = [
    "edge_id", "tenant_id", "src_id", "dst_id", "edge_type", "source",
    "confidence", "attrs", "first_seen", "last_seen",
]


def build_flow_agg_sql(window_hours: int, tenant: str) -> tuple[str, dict]:
    """Aggregate ssdf.events into per-(src_ip,dst_ip,observer) flow rows.

    Grouping by observer_hostname gives each row a single firewall vantage
    (its segment), so the resolver can scope IP identity. The COMMUNICATED_WITH
    edge's observer_hosts set is reassembled across rows in resolve_entities.
    """
    sql = (
        "SELECT toString(source_ip) AS src_ip, toString(destination_ip) AS dst_ip, "
        "toString(observer_hostname) AS observer_hostname, "
        "sum(network_bytes) AS bytes, count() AS flows, "
        "groupUniqArray(destination_port) AS ports, "
        "any(rule_name) AS rule_name, any(event_provider) AS provider, "
        "any(network_transport) AS transport, "
        "toString(min(timestamp)) AS first_seen, toString(max(timestamp)) AS last_seen "
        "FROM ssdf.events "
        "WHERE tenant_id = {tenant:String} "
        "AND timestamp >= now() - INTERVAL {window_hours:UInt32} HOUR "
        "AND source_ip IS NOT NULL AND destination_ip IS NOT NULL "
        "GROUP BY src_ip, dst_ip, observer_hostname"
    )
    return sql, {"tenant": tenant, "window_hours": window_hours}


def build_topo_hosts_sql(tenant: str) -> tuple[str, dict]:
    """Read M4 host nodes to enrich IP->MAC bindings."""
    sql = (
        "SELECT identifiers FROM ssdf.graph_nodes FINAL "
        "WHERE tenant_id = {tenant:String} AND kind = 'host'"
    )
    return sql, {"tenant": tenant}


def build_binding_sql(lookback_hours: int, tenant: str) -> tuple[str, dict]:
    """Read M4 arp_entry observations as (source_device, ip, mac, observed_at).

    Reads topo_observations (which retains source_device, unlike the flattened
    graph_nodes) over a lookback window so a transient single-pass binding drop
    does not orphan a host. subj_id is 'ip:<ip>', obj_id is 'mac:<mac>'.
    """
    sql = (
        "SELECT source_device, "
        "replaceOne(subj_id, 'ip:', '') AS ip, "
        "replaceOne(obj_id, 'mac:', '') AS mac, "
        "toString(observed_at) AS observed_at "
        "FROM ssdf.topo_observations "
        "WHERE tenant_id = {tenant:String} "
        "AND observation_type = 'arp_entry' "
        "AND observed_at >= now() - INTERVAL {lookback_hours:UInt32} HOUR"
    )
    return sql, {"tenant": tenant, "lookback_hours": lookback_hours}


def entity_rows(entities: Iterable[dict]) -> list[list[Any]]:
    return [[e[c] for c in ENTITY_COLUMNS] for e in entities]


def edge_rows(edges: Iterable[dict]) -> list[list[Any]]:
    return [[e[c] for c in ENTITY_EDGE_COLUMNS] for e in edges]


class ClickHouseEntityWriter:
    """Read the resolver input window and upsert entities/edges."""

    def __init__(self, config: Config):
        self._config = config
        self._client = clickhouse_connect.get_client(
            host=config.ch_host, port=config.ch_port, username=config.ch_user,
            password=config.ch_password, database=config.ch_database,
        )

    def query(self, sql: str, params: dict | None = None) -> list[dict]:
        result = self._client.query(sql, parameters=params or {})
        cols = list(result.column_names)
        return [dict(zip(cols, row)) for row in result.result_rows]

    def replace_entities(self, entities: list[dict]) -> int:
        if not entities:
            return 0
        self._client.insert("entities", entity_rows(entities), column_names=ENTITY_COLUMNS)
        return len(entities)

    def replace_edges(self, edges: list[dict]) -> int:
        if not edges:
            return 0
        self._client.insert("entity_edges", edge_rows(edges), column_names=ENTITY_EDGE_COLUMNS)
        return len(edges)
