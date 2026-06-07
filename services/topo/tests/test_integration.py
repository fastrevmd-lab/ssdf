# tests/test_integration.py
"""Live end-to-end: collect against real MCPs, resolve, assert graph populated.

Run: cd services/topo && CH_HOST=<ct104> CH_PASSWORD=<pw> \
     JUNOS_MCP_URL=... JUNOS_MCP_TOKEN=... [other *_MCP_URL/_TOKEN] \
     uv run pytest -m integration -v
"""
import os
import pytest

from ssdf_topo.chwriter import ClickHouseWriter
from ssdf_topo.config import load_config
from ssdf_topo.collect_all import run_collectors, _build_collector, _now
from ssdf_topo.mcp_client import McpToolClient
from ssdf_topo.resolve_main import run_resolver

pytestmark = pytest.mark.integration

requires_ch = pytest.mark.skipif(
    not os.environ.get("CH_PASSWORD"), reason="CH_PASSWORD not set"
)


@requires_ch
def test_collect_then_resolve_populates_graph():
    config = load_config()
    writer = ClickHouseWriter(config)

    inserted = run_collectors(
        enabled=config.enabled_collectors,
        client_factory=lambda name: McpToolClient(config.mcp_endpoint(name)),
        collector_factory=_build_collector,
        writer=writer,
        now=_now(),
    )
    assert inserted > 0, "no observations collected from any live MCP"

    n_nodes, n_edges = run_resolver(
        writer, tenant=config.tenant_id, window_hours=config.window_hours
    )
    assert n_nodes > 0 and n_edges > 0

    # Graph tables actually hold rows for this tenant (FINAL to dedup the upserts).
    rows = writer.query(
        "SELECT count() AS c FROM ssdf.graph_nodes FINAL "
        "WHERE tenant_id = {t:String}",
        {"t": config.tenant_id},
    )
    assert int(rows[0]["c"]) >= n_nodes
