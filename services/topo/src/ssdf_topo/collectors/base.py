# src/ssdf_topo/collectors/base.py
"""Collector protocol + a name->class registry."""

from __future__ import annotations

from typing import Callable, Protocol

from ..mcp_client import McpToolClient
from ..models import Observation

def firewall_inventory(collector: str, source_device: str, now: str) -> Observation:
    """Build a device_inventory observation tagging `source_device` as a firewall.

    Emitted by collectors whose target device is inherently a firewall (SRX, PAN-OS)
    so the resolver tags the resulting device node `attrs.role="firewall"`, which
    `enforcement_points` requires to attribute the firewall to a path.
    """
    return Observation(
        observed_at=now,
        collector=collector,
        source_device=source_device,
        layer="l2",
        observation_type="device_inventory",
        subj_kind="device",
        subj_id=f"device:{source_device}",
        attrs={"role": "firewall", "name": source_device},
    )


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
