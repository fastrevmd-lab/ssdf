# src/ssdf_topo/collectors/base.py
"""Collector protocol + a name->class registry."""

from __future__ import annotations

from typing import Callable, Protocol

from ..mcp_client import McpToolClient
from ..models import Observation

REGISTRY: dict[str, type] = {}


class Collector(Protocol):
    name: str

    def collect(self, client: McpToolClient, now: str) -> list[Observation]:
        """Pull read-only state via the MCP client; return normalized observations."""
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
