# src/ssdf_topo/chwriter.py
"""ClickHouse writer for topology data (the storage seam, write side)."""

from __future__ import annotations

from typing import Any, Iterable

import clickhouse_connect

from ssdf_common.clickhouse import client_kwargs as _client_kwargs
from .config import Config
from .models import Observation

OBS_COLUMNS = [
    "observed_at", "collector", "source_device", "tenant_id", "layer",
    "observation_type", "subj_kind", "subj_id", "obj_kind", "obj_id", "attrs", "raw",
]
NODE_COLUMNS = [
    "node_id", "tenant_id", "kind", "name", "identifiers",
    "first_seen", "last_seen", "attrs",
]
EDGE_COLUMNS = [
    "edge_id", "tenant_id", "src_id", "dst_id", "edge_type", "layer",
    "first_seen", "last_seen", "confidence", "attrs",
]


def client_kwargs(config: Config) -> dict[str, Any]:
    """get_client kwargs from config; adds TLS (interface/ca_cert) when ch_secure."""
    return _client_kwargs(
        host=config.ch_host,
        port=config.ch_port,
        user=config.ch_user,
        password=config.ch_password,
        database=config.ch_database,
        secure=config.ch_secure,
        ca_file=config.ch_ca_file,
    )


def obs_rows(observations: Iterable[Observation]) -> list[list[Any]]:
    return [
        [
            o.observed_at, o.collector, o.source_device, o.tenant_id, o.layer,
            o.observation_type, o.subj_kind, o.subj_id, o.obj_kind, o.obj_id,
            o.attrs, o.raw,
        ]
        for o in observations
    ]


def node_rows(nodes: Iterable[dict]) -> list[list[Any]]:
    return [[n[c] for c in NODE_COLUMNS] for n in nodes]


def edge_rows(edges: Iterable[dict]) -> list[list[Any]]:
    return [[e[c] for c in EDGE_COLUMNS] for e in edges]


class ClickHouseWriter:
    """Insert observations and upsert nodes/edges; read the resolver input window."""

    def __init__(self, config: Config):
        self._config = config
        self._client = clickhouse_connect.get_client(**client_kwargs(config))

    def insert_observations(self, observations: list[Observation]) -> int:
        if not observations:
            return 0
        self._client.insert("topo_observations", obs_rows(observations), column_names=OBS_COLUMNS)
        return len(observations)

    def replace_nodes(self, nodes: list[dict]) -> int:
        if not nodes:
            return 0
        self._client.insert("graph_nodes", node_rows(nodes), column_names=NODE_COLUMNS)
        return len(nodes)

    def replace_edges(self, edges: list[dict]) -> int:
        if not edges:
            return 0
        self._client.insert("graph_edges", edge_rows(edges), column_names=EDGE_COLUMNS)
        return len(edges)

    def query(self, sql: str, params: dict | None = None) -> list[dict]:
        result = self._client.query(sql, parameters=params or {})
        cols = list(result.column_names)
        return [dict(zip(cols, row)) for row in result.result_rows]
