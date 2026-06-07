# src/ssdf_topo/mcp_client.py
"""Minimal synchronous MCP client wrapper for collectors (bearer-auth HTTP)."""

from __future__ import annotations

import asyncio
import json
from typing import Any

from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport

from .config import McpEndpoint


def extract_text(result: Any) -> str:
    """Reduce an MCP tool result to a single text payload for parsing."""
    structured = getattr(result, "structured_content", None)
    if structured:
        return json.dumps(structured, default=str)
    blocks = getattr(result, "content", None) or []
    texts = [getattr(b, "text", "") for b in blocks if getattr(b, "text", "")]
    return "\n".join(texts)


class McpToolClient:
    """Calls a single tool on one MCP server and returns its text payload."""

    def __init__(self, endpoint: McpEndpoint):
        headers = {"Authorization": f"Bearer {endpoint.token}"} if endpoint.token else {}
        self._transport = StreamableHttpTransport(url=endpoint.url, headers=headers)

    def call_tool(self, name: str, args: dict | None = None) -> str:
        return asyncio.run(self._call(name, args or {}))

    async def _call(self, name: str, args: dict) -> str:
        async with Client(self._transport) as client:
            result = await client.call_tool(name, args)
            return extract_text(result)
