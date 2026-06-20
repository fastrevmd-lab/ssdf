"""Proxmox health collector: node + guest CPU%/mem% from proxmox-mcp.

proxmox-mcp returns human-formatted TEXT (not JSON), so this collector parses
the displayed percentages. Only what the MCP shows is emitted: every ONLINE
node and RUNNING guest yields a memory gauge; CPU% is exposed for containers
only (nodes/VMs do not expose it in this MCP), so node/VM CPU gauges are simply
absent rather than fabricated.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from ..gauge import Gauge
from .base import register

_MEM_PCT = re.compile(r"Memory:[^()]*\(([\d.]+)%\)")
_CPU_PCT = re.compile(r"(?m)^\s*-\s*CPU:\s*([\d.]+)%")
_STATUS = re.compile(r"Status:\s*(\S+)")


def clamp_pct(value: float) -> float:
    """Clamp a percentage into [0, 100]."""
    return max(0.0, min(100.0, value))


def _name_from_header(header: str) -> str:
    """Extract a device name from a stanza header line.

    Handles the three proxmox-mcp header shapes:
      "[node] pve3", "[node] Node: pve3", "[vm] ProductionSRX (ID: 103)",
      "ssdf-topo (ID: 109)".
    """
    name = re.sub(r"^\[\w+\]\s*", "", header).strip()
    name = re.sub(r"^Node:\s*", "", name).strip()
    name = re.sub(r"\s*\(ID:[^)]*\)\s*$", "", name).strip()
    return name


def _stanzas(text: str) -> Iterator[tuple[str, str]]:
    """Yield (device_name, block) for each blank-line-separated stanza."""
    for block in text.split("\n\n"):
        block = block.strip()
        if not block:
            continue
        header = block.splitlines()[0].strip()
        yield _name_from_header(header), block


def _mem_pct(block: str) -> float | None:
    match = _MEM_PCT.search(block)
    return float(match.group(1)) if match else None


def _cpu_pct(block: str) -> float | None:
    match = _CPU_PCT.search(block)
    return float(match.group(1)) if match else None


def _status(block: str) -> str:
    match = _STATUS.search(block)
    return match.group(1) if match else ""


def parse_nodes(text: str) -> list[Gauge]:
    """Build node-scope memory gauges from get_nodes text (ONLINE nodes only)."""
    gauges: list[Gauge] = []
    for name, block in _stanzas(text):
        if not name or _status(block).upper() != "ONLINE":
            continue
        mem = _mem_pct(block)
        if mem is not None:
            gauges.append(Gauge(
                provider="proxmox", device=name, scope="node", metric_class="memory",
                sensor="", metric_name="mem_util_pct", value=clamp_pct(mem),
                unit="percent", raw=f"mem={mem}%",
            ))
    return gauges


def parse_guests(text: str, scope: str = "guest") -> list[Gauge]:
    """Build guest CPU/mem gauges from get_vms/get_containers text (RUNNING only)."""
    gauges: list[Gauge] = []
    for name, block in _stanzas(text):
        if not name or _status(block).upper() != "RUNNING":
            continue
        cpu = _cpu_pct(block)
        if cpu is not None:
            gauges.append(Gauge(
                provider="proxmox", device=name, scope=scope, metric_class="cpu",
                sensor="", metric_name="cpu_util_pct", value=clamp_pct(cpu),
                unit="percent", raw=f"cpu={cpu}%",
            ))
        mem = _mem_pct(block)
        if mem is not None:
            gauges.append(Gauge(
                provider="proxmox", device=name, scope=scope, metric_class="memory",
                sensor="", metric_name="mem_util_pct", value=clamp_pct(mem),
                unit="percent", raw=f"mem={mem}%",
            ))
    return gauges


@register("proxmox")
class ProxmoxCollector:
    """Collects node + guest CPU/mem utilization from proxmox-mcp."""

    name = "proxmox"

    def collect(self, client, now: str) -> list[Gauge]:
        gauges: list[Gauge] = []
        gauges.extend(parse_nodes(client.call_tool("get_nodes", {})))
        gauges.extend(parse_guests(client.call_tool("get_vms", {})))
        gauges.extend(parse_guests(client.call_tool("get_containers", {})))
        return gauges
