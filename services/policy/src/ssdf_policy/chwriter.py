"""ClickHouse writer for configured entities/edges into the shared M6a tables."""

from __future__ import annotations

from typing import Any, Iterable

import clickhouse_connect

from ssdf_common.clickhouse import client_kwargs as _client_kwargs
from .config import Config

# Byte-identical to services/entity/src/ssdf_entity/chwriter.py column orders.
ENTITY_COLUMNS = [
    "entity_id",
    "tenant_id",
    "kind",
    "name",
    "identifiers",
    "source",
    "identity_basis",
    "confidence",
    "attrs",
    "first_seen",
    "last_seen",
]
ENTITY_EDGE_COLUMNS = [
    "edge_id",
    "tenant_id",
    "src_id",
    "dst_id",
    "edge_type",
    "source",
    "confidence",
    "attrs",
    "first_seen",
    "last_seen",
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


def entity_rows(entities: Iterable[dict]) -> list[list[Any]]:
    return [[e[c] for c in ENTITY_COLUMNS] for e in entities]


def edge_rows(edges: Iterable[dict]) -> list[list[Any]]:
    return [[e[c] for c in ENTITY_EDGE_COLUMNS] for e in edges]


class ClickHouseEntityWriter:
    """Upserts configured entities/edges (ReplacingMergeTree dedups by id on merge)."""

    def __init__(self, config: Config):
        self._config = config
        self._client = clickhouse_connect.get_client(**client_kwargs(config))

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
