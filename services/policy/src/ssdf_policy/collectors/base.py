"""Collector protocol + a name->class registry (rules, not topology observations).

Re-exports REGISTRY, register, get_collector from ssdf_common.collectors.
"""

from __future__ import annotations

from typing import Protocol

from ssdf_common.collectors import REGISTRY, register, get_collector
from ..mcp_client import McpToolClient


class Collector(Protocol):
    name: str

    def collect(self, client: McpToolClient, now: str) -> list[dict]:
        """Pull the configured security ruleset via MCP; return normalized rule dicts."""
        ...


__all__ = ["REGISTRY", "register", "get_collector", "Collector"]
