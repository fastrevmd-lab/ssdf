# src/ssdf_topo/collectors/base.py
"""Collector protocol + a name->class registry.

Re-exports REGISTRY, register, get_collector from ssdf_common.collectors.
"""

from __future__ import annotations

from typing import Protocol

from ssdf_common.collectors import REGISTRY, register, get_collector
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


class Collector(Protocol):
    name: str

    def collect(self, client: McpToolClient, now: str) -> list[Observation]:
        """Pull read-only state via the MCP client; return normalized observations."""
        ...


__all__ = ["REGISTRY", "register", "get_collector", "Collector", "firewall_inventory"]
