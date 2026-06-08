"""Entrypoint: read CH window (flow-agg + topo hosts), resolve, upsert entities/edges."""

from __future__ import annotations

import logging

from .chwriter import ClickHouseEntityWriter, build_flow_agg_sql, build_topo_hosts_sql
from .config import Config, load_config
from .resolve_entities import resolve_entities

log = logging.getLogger("ssdf_entity.resolve")


def run_resolver(writer, tenant: str, window_hours: int) -> tuple[int, int]:
    flow_sql, flow_params = build_flow_agg_sql(window_hours, tenant)
    flow_aggregates = writer.query(flow_sql, flow_params)
    host_sql, host_params = build_topo_hosts_sql(tenant)
    topo_hosts = writer.query(host_sql, host_params)
    entities, edges = resolve_entities(flow_aggregates, topo_hosts, tenant)
    n_entities = writer.replace_entities(entities)
    n_edges = writer.replace_edges(edges)
    log.info("entity resolver: %d entities, %d edges upserted", n_entities, n_edges)
    return n_entities, n_edges


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    config: Config = load_config()
    writer = ClickHouseEntityWriter(config)
    run_resolver(writer, tenant=config.tenant_id, window_hours=config.window_hours)


if __name__ == "__main__":
    main()
