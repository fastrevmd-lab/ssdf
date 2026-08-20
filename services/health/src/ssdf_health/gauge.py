"""The normalized unit every collector emits: one numeric gauge reading."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Gauge:
    provider: str  # proxmox|juniper|paloalto|unifi
    device: str  # node/router/host/device name (same name topo/policy use)
    scope: str  # device|guest|node
    metric_class: str  # cpu|memory|temperature
    sensor: str  # '' for a device-scalar reading; label for multi-sensor
    metric_name: str  # cpu_util_pct|mem_util_pct|temp_celsius
    value: float
    unit: str  # percent|celsius
    raw: str  # source line/snippet for provenance/debug
