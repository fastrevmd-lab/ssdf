"""Collector protocol + a name->class registry (rules, not topology observations)."""

from __future__ import annotations

from typing import Callable, Protocol

from ..mcp_client import McpToolClient

REGISTRY: dict[str, type] = {}


class Collector(Protocol):
    name: str

    def collect(self, client: McpToolClient, now: str) -> list[dict]:
        """Pull the configured security ruleset via MCP; return normalized rule dicts."""
        ...


def register(name: str) -> Callable[[type], type]:
    def _wrap(cls: type) -> type:
        REGISTRY[name] = cls
        return cls
    return _wrap
