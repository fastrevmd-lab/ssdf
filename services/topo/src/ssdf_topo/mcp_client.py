# src/ssdf_topo/mcp_client.py
"""Minimal synchronous MCP client wrapper for collectors (bearer-auth HTTP).

Re-exports from ssdf_common.mcp_client to preserve existing import paths.
"""

from __future__ import annotations

from ssdf_common.mcp_client import McpToolClient, extract_text

__all__ = ["McpToolClient", "extract_text"]
