"""Collector protocol, a name->class registry, and the fault-isolated runner."""

from __future__ import annotations

import logging
from typing import Callable, Protocol

from ..gauge import Gauge
from ..mcp_client import McpToolClient

logger = logging.getLogger(__name__)

REGISTRY: dict[str, type] = {}


class Collector(Protocol):
    name: str

    def collect(self, client: McpToolClient, now: str) -> list[Gauge]:
        """Pull read-only telemetry via the MCP client; return normalized gauges."""
        ...


def register(name: str) -> Callable[[type], type]:
    def _wrap(cls: type) -> type:
        REGISTRY[name] = cls
        return cls
    return _wrap


def get_collector(name: str) -> type:
    if name not in REGISTRY:
        raise KeyError(f"unknown collector: {name}")
    return REGISTRY[name]


def run_collectors(enabled, client_factory, collector_factory, writer, now: str) -> int:
    """Run each enabled collector; skip any that raise, log a warning, and continue.

    Returns the total number of gauges written.
    """
    total = 0
    for name in enabled:
        try:
            collector = collector_factory(name)
            client = client_factory(name)
            gauges = collector.collect(client, now)
            if not gauges:
                logger.warning("collector %r returned 0 gauges", name)
            total += writer.insert_gauges(gauges, now)
        except Exception:
            logger.warning("collector %r failed; skipping", name, exc_info=True)
    return total
