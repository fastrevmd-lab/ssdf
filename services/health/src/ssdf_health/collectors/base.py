"""Collector protocol, a name->class registry, and the fault-isolated runner.

Re-exports REGISTRY, register, get_collector, run_collectors from ssdf_common.collectors.
"""

from __future__ import annotations

from typing import Protocol

from ssdf_common.collectors import REGISTRY, register, get_collector, run_collectors
from ..gauge import Gauge
from ..mcp_client import McpToolClient


class Collector(Protocol):
    name: str

    def collect(self, client: McpToolClient, now: str) -> list[Gauge]:
        """Pull read-only telemetry via the MCP client; return normalized gauges."""
        ...


__all__ = ["REGISTRY", "register", "get_collector", "run_collectors", "Collector"]
