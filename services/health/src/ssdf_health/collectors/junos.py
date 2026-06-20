"""Junos health collector: routing-engine CPU%/mem% + chassis-environment temps."""

from __future__ import annotations

import re

from ..gauge import Gauge
from .base import register

_MEM_RE = re.compile(r"Memory utilization\s+(\d+)\s+percent", re.IGNORECASE)
_IDLE_RE = re.compile(r"Idle\s+(\d+)\s+percent", re.IGNORECASE)
# "Temp  <name...>  <STATUS>  NN degrees C ..."
_TEMP_RE = re.compile(
    r"^Temp\s+(?P<name>.+?)\s+\S+\s+(?P<c>-?\d+)\s+degrees C", re.IGNORECASE
)


def parse_routing_engine(text: str, device: str, now: str) -> list[Gauge]:
    """Build device-scope CPU/mem gauges from 'show chassis routing-engine'."""
    gauges: list[Gauge] = []
    mem = _MEM_RE.search(text)
    if mem:
        gauges.append(Gauge(
            provider="juniper", device=device, scope="device", metric_class="memory",
            sensor="", metric_name="mem_util_pct", value=float(mem.group(1)),
            unit="percent", raw=mem.group(0),
        ))
    idle = _IDLE_RE.search(text)
    if idle:
        gauges.append(Gauge(
            provider="juniper", device=device, scope="device", metric_class="cpu",
            sensor="", metric_name="cpu_util_pct",
            value=max(0.0, 100.0 - float(idle.group(1))),
            unit="percent", raw=idle.group(0),
        ))
    return gauges


def parse_environment(text: str, device: str, now: str) -> list[Gauge]:
    """Build per-sensor temperature gauges from 'show chassis environment'."""
    gauges: list[Gauge] = []
    for line in text.splitlines():
        match = _TEMP_RE.match(line.strip())
        if not match:
            continue
        gauges.append(Gauge(
            provider="juniper", device=device, scope="device",
            metric_class="temperature", sensor=match.group("name").strip(),
            metric_name="temp_celsius", value=float(match.group("c")),
            unit="celsius", raw=line.strip(),
        ))
    return gauges


@register("junos")
class JunosCollector:
    """Collects CPU/mem + temps from one or more Junos devices via rust-junosmcp."""

    name = "junos"

    def __init__(self, devices: list[str] | None = None):
        self.devices = devices or []

    def collect(self, client, now: str) -> list[Gauge]:
        gauges: list[Gauge] = []
        for dev in self.devices:
            re_text = client.call_tool(
                "execute_junos_command",
                {"router_name": dev, "command": "show chassis routing-engine"},
            )
            gauges.extend(parse_routing_engine(re_text, dev, now))
            env_text = client.call_tool(
                "execute_junos_command",
                {"router_name": dev, "command": "show chassis environment"},
            )
            gauges.extend(parse_environment(env_text, dev, now))
        return gauges
