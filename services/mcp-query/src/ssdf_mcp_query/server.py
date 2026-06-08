# src/ssdf_mcp_query/server.py
"""FastMCP streamable-HTTP server exposing the read-only query tools."""

from __future__ import annotations

from fastmcp import FastMCP
from fastmcp.server.auth import StaticTokenVerifier

from .config import load_config
from .clickhouse import ClickHouseClient
from .tools import Tools
from .graphstore import ClickHouseGraphStore
from .topo_tools import TopoTools
from .entitystore import ClickHouseEntityStore
from .access_tools import AccessTools


def build_app() -> FastMCP:
    config = load_config()
    client = ClickHouseClient(config)
    tools = Tools(client)
    graph_store = ClickHouseGraphStore(client, tenant="t_main")
    topo = TopoTools(graph_store)
    entity_store = ClickHouseEntityStore(client, tenant="t_main")
    access = AccessTools(entity_store, topo)
    auth = StaticTokenVerifier(
        tokens={config.auth_token: {"sub": "agent", "client_id": "ssdf"}}
    )
    mcp = FastMCP("ssdf-mcp-query", auth=auth)

    @mcp.tool
    def query_flows(src_ip: str | None = None, dst_ip: str | None = None,
                    dst_port: int | None = None, action: str | None = None,
                    outcome: str | None = None, provider: str | None = None,
                    zone: str | None = None, since: str | None = None,
                    until: str | None = None, limit: int = 100) -> dict:
        """Query normalized security flow events with optional filters and a time window.

        Times accept ISO-8601 or relative ("now-1h"). Default window is the last 24h.
        Returns rows plus {row_count, truncated, elapsed_ms} or {error, detail}.
        """
        return tools.query_flows(src_ip=src_ip, dst_ip=dst_ip, dst_port=dst_port,
                                 action=action, outcome=outcome, provider=provider,
                                 zone=zone, since=since, until=until, limit=limit)

    @mcp.tool
    def describe_schema() -> dict:
        """Return ssdf.events columns/types, distinct enum values, row count and time range."""
        return tools.describe_schema()

    @mcp.tool
    def top_talkers(by: str = "bytes", side: str = "src", since: str | None = None,
                    until: str | None = None, limit: int = 10) -> dict:
        """Top source/destination IPs by bytes or flow count over a time window."""
        return tools.top_talkers(by=by, side=side, since=since, until=until, limit=limit)

    @mcp.tool
    def run_sql(query: str) -> dict:
        """Run a guarded read-only SELECT against ssdf.* (single statement, enforced LIMIT)."""
        return tools.run_sql(query)

    @mcp.tool
    def get_entity(identifier: str) -> dict:
        """Resolve a canonical entity (host/device/identity) from any alias: ip, mac, hostname, or name."""
        return topo.get_entity(identifier)

    @mcp.tool
    def locate(identifier: str) -> dict:
        """Where does an entity attach? Returns switch/AP (or hypervisor bridge), port, and VLAN."""
        return topo.locate(identifier)

    @mcp.tool
    def neighbors(identifier: str, layer: str | None = None, depth: int = 1,
                  since_hours: int | None = None) -> dict:
        """Adjacent nodes/edges around an entity, optionally filtered by layer (l2|l3|flow|virt)."""
        return topo.neighbors(identifier, layer=layer, depth=depth, since_hours=since_hours)

    @mcp.tool
    def find_path(src: str, dst: str, layer: str = "any") -> dict:
        """Shortest path between two entities. layer: 'physical' (l1/l2), 'flow' (l3/flow), or 'any'."""
        return topo.find_path(src, dst, layer=layer)

    @mcp.tool
    def enforcement_points(src: str, dst: str) -> dict:
        """Read-only: firewall device(s), zone(s), and rule(s) governing traffic between two entities."""
        return topo.enforcement_points(src, dst)

    @mcp.tool
    def topology_snapshot(layer: str | None = None, since_hours: int | None = None) -> dict:
        """Bounded nodes+edges subgraph for visualization/LLM context; reports truncation."""
        return topo.topology_snapshot(layer=layer, since_hours=since_hours)

    @mcp.tool
    def explain_access(client: str, server: str, since_hours: int | None = None) -> dict:
        """End-to-end view: observed flows + observed controls + CONFIGURED rules (from each
        firewall's ruleset) + topology path between a client and a server. Accepts ip/mac/name.
        `configured_controls` lists rules on the path firewalls (no match-scoring); `coverage`
        reports observed (bool) and configured (rule count). Firewall attribution is from
        topology; `configured_basis` flags no_path_firewall / firewall_name_unmatched."""
        return access.explain_access(client, server, since_hours=since_hours)

    return mcp


def main() -> None:
    config = load_config()
    app = build_app()
    app.run(transport="http", host=config.mcp_bind, port=config.mcp_port)


if __name__ == "__main__":
    main()
