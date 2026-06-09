# src/ssdf_mcp_query/server.py
"""FastMCP streamable-HTTP server exposing the read-only query tools.

M7a: every tool is registered through ``audited_tool`` so each call is
authorized (per-principal ``allowed_tools``) and recorded to ``ssdf.audit``.
"""

from __future__ import annotations

import os
import sys

from fastmcp import FastMCP
from fastmcp.server.auth import StaticTokenVerifier

from .config import load_config
from .classification import load_classification, public_tool_names
from .audit import Auditor, make_ch_auditor
from .wrapper import audited_tool
from .clickhouse import ClickHouseClient
from .tools import Tools
from .graphstore import ClickHouseGraphStore
from .topo_tools import TopoTools
from .entitystore import ClickHouseEntityStore
from .access_tools import AccessTools


def build_app(tier: str = "sovereign") -> FastMCP:
    config = load_config()
    classification = load_classification()  # fail closed on invalid classification config
    auditor = make_ch_auditor(config)

    schema = "ssdf_public" if tier == "public" else "ssdf"
    client = ClickHouseClient(config)
    tools = Tools(client)
    graph_store = ClickHouseGraphStore(client, tenant="t_main", schema=schema)
    topo = TopoTools(graph_store)
    entity_store = ClickHouseEntityStore(client, tenant="t_main")
    access = AccessTools(entity_store, topo)

    verifier_tokens: dict[str, dict] = {}
    for token, tp in config.tokens.items():
        payload = {
            "sub": tp.principal,
            "client_id": "ssdf",
            "tier": tier,
            "principal": tp.principal,
        }
        if tp.allowed_tools is not None:
            payload["allowed_tools"] = sorted(tp.allowed_tools)
        verifier_tokens[token] = payload
    auth = StaticTokenVerifier(tokens=verifier_tokens)
    mcp = FastMCP("ssdf-mcp-query", auth=auth)

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

    def describe_schema() -> dict:
        """Return ssdf.events columns/types, distinct enum values, row count and time range."""
        return tools.describe_schema()

    def top_talkers(by: str = "bytes", side: str = "src", since: str | None = None,
                    until: str | None = None, limit: int = 10) -> dict:
        """Top source/destination IPs by bytes or flow count over a time window."""
        return tools.top_talkers(by=by, side=side, since=since, until=until, limit=limit)

    def run_sql(query: str) -> dict:
        """Run a guarded read-only SELECT against ssdf.* (single statement, enforced LIMIT)."""
        return tools.run_sql(query)

    def get_entity(identifier: str) -> dict:
        """Resolve a canonical entity (host/device/identity) from any alias: ip, mac, hostname, or name."""
        return topo.get_entity(identifier)

    def locate(identifier: str) -> dict:
        """Where does an entity attach? Returns switch/AP (or hypervisor bridge), port, and VLAN."""
        return topo.locate(identifier)

    def neighbors(identifier: str, layer: str | None = None, depth: int = 1,
                  since_hours: int | None = None) -> dict:
        """Adjacent nodes/edges around an entity, optionally filtered by layer (l2|l3|flow|virt)."""
        return topo.neighbors(identifier, layer=layer, depth=depth, since_hours=since_hours)

    def find_path(src: str, dst: str, layer: str = "any") -> dict:
        """Shortest path between two entities. layer: 'physical' (l1/l2), 'flow' (l3/flow), or 'any'."""
        return topo.find_path(src, dst, layer=layer)

    def enforcement_points(src: str, dst: str) -> dict:
        """Read-only: firewall device(s), zone(s), and rule(s) governing traffic between two entities."""
        return topo.enforcement_points(src, dst)

    def topology_snapshot(layer: str | None = None, since_hours: int | None = None) -> dict:
        """Bounded nodes+edges subgraph for visualization/LLM context; reports truncation."""
        return topo.topology_snapshot(layer=layer, since_hours=since_hours)

    def explain_access(client: str, server: str, since_hours: int | None = None) -> dict:
        """End-to-end view: observed flows + observed controls + CONFIGURED rules (from each
        firewall's ruleset) + topology path between a client and a server. Accepts ip/mac/name.
        `configured_controls` lists rules on the path firewalls (no match-scoring); `coverage`
        reports observed (bool) and configured (rule count). Firewall attribution is from
        topology; `configured_basis` flags no_path_firewall / firewall_name_unmatched."""
        return access.explain_access(client, server, since_hours=since_hours)

    raw_tools = {
        "query_flows": query_flows,
        "describe_schema": describe_schema,
        "top_talkers": top_talkers,
        "run_sql": run_sql,
        "get_entity": get_entity,
        "locate": locate,
        "neighbors": neighbors,
        "find_path": find_path,
        "enforcement_points": enforcement_points,
        "topology_snapshot": topology_snapshot,
        "explain_access": explain_access,
    }
    if tier == "public":
        selected = public_tool_names(classification, list(raw_tools))
        if not selected:
            print("[public] no shareable classes configured; 0 tools exposed",
                  file=sys.stderr)
    else:
        selected = list(raw_tools)

    for name in selected:
        mcp.tool(name=name)(audited_tool(name, raw_tools[name], auditor, tier=tier))

    return mcp


def main() -> None:
    config = load_config()
    tier = os.environ.get("MCP_TIER", "sovereign")
    app = build_app(tier)
    app.run(transport="http", host=config.mcp_bind, port=config.mcp_port)


if __name__ == "__main__":
    main()
