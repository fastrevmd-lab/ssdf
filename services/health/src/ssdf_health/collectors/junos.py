"""Junos health collector: routing-engine CPU%/mem% + chassis-environment temps."""

from __future__ import annotations

import logging

import re

from ..gauge import Gauge
from .base import register

logger = logging.getLogger(__name__)

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


def _is_unreachable(exc: Exception) -> bool:
    """True if the error means the device is down rather than the command bad.

    rust-junosmcp surfaces reachability problems as "netconf error: transport
    error: ..." (connection refused, no route to host, host key mismatch). Those
    are worth short-circuiting; a command the platform simply does not support
    is not, because the device's other probes may still answer.
    """
    text = str(exc).lower()
    return "transport error" in text or "connection failed" in text


@register("junos")
class JunosCollector:
    """Collects CPU/mem + temps from one or more Junos devices via rust-junosmcp."""

    name = "junos"

    def __init__(self, devices: list[str] | None = None):
        self.devices = devices or []

    def collect(self, client, now: str) -> list[Gauge]:
        """Poll each device, skipping only the probes that actually fail.

        Per-device resilient: run_collectors catches at collector granularity, so
        an uncaught error here would discard every other device's gauges too.
        The two commands are independent and are attempted independently — a
        platform that rejects one still yields the other's gauges, so neither is
        treated as a reachability gate for the device.
        """
        gauges: list[Gauge] = []
        for dev in self.devices:
            for command, parser in (
                ("show chassis routing-engine", parse_routing_engine),
                ("show chassis environment", parse_environment),
            ):
                try:
                    text = client.call_tool(
                        "execute_junos_command", {"router_name": dev, "command": command}
                    )
                    gauges.extend(parser(text, dev, now))
                except Exception as exc:
                    if _is_unreachable(exc):
                        logger.warning("junos device %r unreachable; skipping", dev, exc_info=True)
                        break
                    logger.warning(
                        "junos %r: command %r failed; continuing", dev, command, exc_info=True
                    )
        return gauges
