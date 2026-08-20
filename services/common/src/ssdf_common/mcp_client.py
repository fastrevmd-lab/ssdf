"""Minimal synchronous MCP client wrapper for collectors (bearer-auth HTTP)."""

from __future__ import annotations

import asyncio
import json
import os
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


# A vendor MCP that accepts a request and never answers used to hang the caller
# forever: one unanswered call left a collector running 91 minutes, and because
# collectors run in ExecStartPre — bounded by TimeoutStartSec, not RuntimeMaxSec —
# systemd never killed it and the graph stopped updating. Every call is now bounded.
DEFAULT_CALL_TIMEOUT_SECS = 60.0


def _default_timeout() -> float:
    raw = os.environ.get("MCP_CALL_TIMEOUT_SECS", "").strip()
    if not raw:
        return DEFAULT_CALL_TIMEOUT_SECS
    try:
        value = float(raw)
    except ValueError:
        return DEFAULT_CALL_TIMEOUT_SECS
    return value if value > 0 else DEFAULT_CALL_TIMEOUT_SECS


class McpToolClient:
    """Calls a single tool on one MCP server and returns its text payload."""

    def __init__(self, endpoint: McpEndpoint, timeout_secs: float | None = None):
        headers = {"Authorization": f"Bearer {endpoint.token}"} if endpoint.token else {}
        self._transport = StreamableHttpTransport(url=endpoint.url, headers=headers)
        self._timeout = timeout_secs if timeout_secs is not None else _default_timeout()

    def call_tool(self, name: str, args: dict | None = None) -> str:
        """Call one tool, raising TimeoutError rather than blocking indefinitely.

        Callers already treat a raised exception as "this device did not answer"
        and continue, so a timeout degrades to the same per-device skip as an
        unreachable host instead of stalling the whole run.
        """
        return asyncio.run(self._call_with_timeout(name, args or {}))

    async def _call_with_timeout(self, name: str, args: dict) -> str:
        return await asyncio.wait_for(self._call(name, args), timeout=self._timeout)

    async def _call(self, name: str, args: dict) -> str:
        async with Client(self._transport) as client:
            result = await client.call_tool(name, args)
            return extract_text(result)
