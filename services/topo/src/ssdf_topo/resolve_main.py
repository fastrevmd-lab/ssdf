# src/ssdf_topo/resolve_main.py
"""Resolver entrypoint: read CH window, resolve, upsert graph_nodes/graph_edges."""

from __future__ import annotations

import logging

from .chwriter import ClickHouseWriter
from .config import Config, load_config
from .models import Observation
from .resolver.flows import build_flow_agg_sql, flow_to_edges
from .resolver.resolve import resolve_graph

log = logging.getLogger("ssdf_topo.resolve")

OBS_SQL = (
    "SELECT toString(observed_at) AS observed_at, collector, source_device, tenant_id, "
    "layer, observation_type, subj_kind, subj_id, obj_kind, obj_id, attrs, raw "
    "FROM ssdf.topo_observations "
    "WHERE tenant_id = {tenant:String} "
    "AND observed_at >= now() - INTERVAL {window_hours:UInt32} HOUR"
)


def _row_to_obs(row: dict) -> Observation:
    return Observation(
        observed_at=row["observed_at"], collector=row["collector"],
        source_device=row["source_device"], layer=row["layer"],
        observation_type=row["observation_type"], subj_kind=row["subj_kind"],
        subj_id=row["subj_id"], obj_kind=row.get("obj_kind", ""),
        obj_id=row.get("obj_id", ""), attrs=dict(row.get("attrs") or {}),
        raw=row.get("raw", ""), tenant_id=row.get("tenant_id", "t_main"),
    )


def run_resolver(writer, tenant: str, window_hours: int) -> tuple[int, int]:
    obs_rows = writer.query(OBS_SQL, {"tenant": tenant, "window_hours": window_hours})
    observations = [_row_to_obs(r) for r in obs_rows]
    flow_sql, flow_params = build_flow_agg_sql(window_hours, tenant)
    flow_rows = writer.query(flow_sql, flow_params)
    flow_edges = flow_to_edges(flow_rows, tenant)
    nodes, edges = resolve_graph(observations, flow_edges, tenant)
    n_nodes = writer.replace_nodes(nodes)
    n_edges = writer.replace_edges(edges)
    log.info("resolver: %d nodes, %d edges upserted", n_nodes, n_edges)
    return n_nodes, n_edges


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    config: Config = load_config()
    writer = ClickHouseWriter(config)
    run_resolver(writer, tenant=config.tenant_id, window_hours=config.window_hours)


if __name__ == "__main__":
    main()
