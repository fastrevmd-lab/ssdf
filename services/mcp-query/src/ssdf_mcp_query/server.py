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
    auditor = make_ch_auditor(config, tier)

    schema = "ssdf_public" if tier == "public" else "ssdf"
    client = ClickHouseClient(config)
    tools = Tools(client)
    graph_store = ClickHouseGraphStore(client, tenant="t_main", schema=schema)
    topo = TopoTools(graph_store)
    # L5: the entity store/access tools are sovereign-only (hard-coded ssdf.*
    # reads, never exposed publicly) — don't even construct them on public.
    access = None
    if tier != "public":
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
        if tp.not_after is not None:
            payload["not_after"] = tp.not_after.isoformat()
        verifier_tokens[token] = payload
    auth = StaticTokenVerifier(tokens=verifier_tokens)
    mcp = FastMCP("ssdf-mcp-query", auth=auth)

    def query_flows(src_ip: str | None = None, dst_ip: str | None = None,
                    dst_port: int | None = None, action: str | None = None,
                    outcome: str | None = None, provider: str | None = None,
                    zone: str | None = None, since: str | None = None,
                    until: str | None = None, limit: int = 100) -> dict:
        """Query RAW normalized flow events (one row per event) with optional filters and a
        time window. `provider` is a VENDOR string (e.g. "paloalto"/"juniper"), NOT a
        firewall device identity — for "which firewall" questions use explain_access or
        observed_by. Times accept ISO-8601 or relative ("now-1h"); default window 24h.
        Returns rows plus {row_count, truncated, elapsed_ms} or {error, detail}."""
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
        """Where an entity is ATTACHED at L2: switch/AP (or hypervisor bridge), port, VLAN.
        This is physical attachment, NOT firewall observation — for "which firewall sees
        this IP" use observed_by."""
        return topo.locate(identifier)

    def neighbors(identifier: str, layer: str | None = None, depth: int = 1,
                  since_hours: int | None = None) -> dict:
        """L2/L3-adjacent nodes/edges around an entity, optionally filtered by layer
        (l2|l3|flow|virt). Adjacency only — for firewall attribution use explain_access
        (which rule/firewall) or observed_by (which firewall logged it)."""
        return topo.neighbors(identifier, layer=layer, depth=depth, since_hours=since_hours)

    def find_path(src: str, dst: str, layer: str = "any") -> dict:
        """Shortest path between two entities. layer: 'physical' (l1/l2), 'flow' (l3/flow), or 'any'."""
        return topo.find_path(src, dst, layer=layer)

    def enforcement_points(src: str, dst: str) -> dict:
        """Read-only: firewall device(s), zone(s), and rule(s) governing traffic between two entities."""
        return topo.enforcement_points(src, dst)

    def topology_snapshot(layer: str | None = None, since_hours: int | None = None,
                          role: str | None = None, kind: str | None = None) -> dict:
        """Bounded nodes+edges subgraph for visualization/LLM context; reports truncation.
        Filter with `role` (e.g. "firewall") or `kind` (e.g. "device") to enumerate just
        those nodes — use role="firewall" to list the firewalls in the topology."""
        return topo.topology_snapshot(layer=layer, since_hours=since_hours,
                                      role=role, kind=kind)

    def explain_access(client: str, server: str, since_hours: int | None = None) -> dict:
        """End-to-end view for a client->server pair: observed flows + observed controls +
        CONFIGURED rules + topology path. Owns "which rule / which firewall" questions; its
        `firewalls` are DEVICE NAMES (not vendor strings). `configured_controls` lists rules
        on the path firewalls (no match-scoring); `coverage` reports observed (bool) and
        configured (rule count); `firewall_basis` is provenance|topology|no_path_firewall.
        Accepts ip/mac/name."""
        return access.explain_access(client, server, since_hours=since_hours)

    def configured_policies(firewall) -> dict:
        """Configured security rules on the named firewall(s) (e.g. "panosvm" or a list).
        Returns {firewalls:[{firewall, rules:[{rule,action,from_zone,to_zone,position,
        enabled,source}], count}]}. `count` is the de-duplicated configured-policy count
        for that firewall — use this to answer "how many rules does firewall X have"."""
        return access.configured_policies(firewall)

    def observed_by(identifier: str, since_hours: int | None = None) -> dict:
        """Which firewall(s) actually LOGGED traffic for this IP/asset (L3 provenance).
        Accepts ip/mac/name. Returns {entity, firewalls:[<device names>]} — device names,
        not vendor strings, and multiple when several firewalls observed the flow. Use this
        for "which firewall sees/observes traffic from X", NOT locate (which is L2 attach)."""
        return access.observed_by(identifier, since_hours=since_hours)

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
    }
    if access is not None:  # sovereign-only (L5): never a candidate on public
        raw_tools["explain_access"] = explain_access
        raw_tools["configured_policies"] = configured_policies
        raw_tools["observed_by"] = observed_by
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
