# src/ssdf_mcp_query/server.py
"""FastMCP streamable-HTTP server exposing the read-only query tools."""

from __future__ import annotations

from fastmcp import FastMCP
from fastmcp.server.auth import StaticTokenVerifier

from .config import load_config
from .clickhouse import ClickHouseClient
from .tools import Tools


def build_app() -> FastMCP:
    config = load_config()
    client = ClickHouseClient(config)
    tools = Tools(client)
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

    return mcp


def main() -> None:
    config = load_config()
    app = build_app()
    app.run(transport="http", host=config.mcp_bind, port=config.mcp_port)


if __name__ == "__main__":
    main()
