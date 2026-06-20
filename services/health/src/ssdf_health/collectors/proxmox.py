"""Proxmox health collector: node + guest CPU%/mem%. No temperature via this API."""

from __future__ import annotations

import json

from ..gauge import Gauge
from .base import register

_ENVELOPE_KEYS = ("result", "data", "items")


def clamp_pct(value: float) -> float:
    """Clamp a percentage into [0, 100]."""
    return max(0.0, min(100.0, value))


def _obj(text: str) -> dict:
    """Decode MCP text to a single dict, unwrapping a known envelope key."""
    data = json.loads(text)
    if isinstance(data, dict):
        for key in _ENVELOPE_KEYS:
            val = data.get(key)
            if isinstance(val, dict):
                return val
        return data
    return {}


def _rows(text: str) -> list[dict]:
    """Decode MCP text to a list of dicts, unwrapping a known envelope key."""
    data = json.loads(text)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in _ENVELOPE_KEYS:
            val = data.get(key)
            if isinstance(val, list):
                return val
    return []


def parse_node_status(status: dict, node: str, now: str) -> list[Gauge]:
    """Build node-scope CPU/mem gauges from a get_node_status dict."""
    gauges: list[Gauge] = []
    cpu = status.get("cpu")
    if isinstance(cpu, (int, float)):
        gauges.append(Gauge(
            provider="proxmox", device=node, scope="node", metric_class="cpu",
            sensor="", metric_name="cpu_util_pct", value=clamp_pct(float(cpu) * 100.0),
            unit="percent", raw=f"cpu={cpu}",
        ))
    memory = status.get("memory") or {}
    used, total = memory.get("used"), memory.get("total")
    if isinstance(used, (int, float)) and isinstance(total, (int, float)) and total:
        gauges.append(Gauge(
            provider="proxmox", device=node, scope="node", metric_class="memory",
            sensor="", metric_name="mem_util_pct",
            value=clamp_pct(float(used) / float(total) * 100.0),
            unit="percent", raw=f"mem={used}/{total}",
        ))
    return gauges


def parse_guests(guests: list[dict], now: str) -> list[Gauge]:
    """Build guest-scope CPU/mem gauges from a get_vms/get_containers list (running only)."""
    gauges: list[Gauge] = []
    for guest in guests:
        if str(guest.get("status") or "").lower() != "running":
            continue
        device = str(guest.get("name") or guest.get("vmid") or "").strip()
        if not device:
            continue
        cpu = guest.get("cpu")
        if isinstance(cpu, (int, float)):
            gauges.append(Gauge(
                provider="proxmox", device=device, scope="guest", metric_class="cpu",
                sensor="", metric_name="cpu_util_pct",
                value=clamp_pct(float(cpu) * 100.0), unit="percent", raw=f"cpu={cpu}",
            ))
        mem, maxmem = guest.get("mem"), guest.get("maxmem")
        if isinstance(mem, (int, float)) and isinstance(maxmem, (int, float)) and maxmem:
            gauges.append(Gauge(
                provider="proxmox", device=device, scope="guest", metric_class="memory",
                sensor="", metric_name="mem_util_pct",
                value=clamp_pct(float(mem) / float(maxmem) * 100.0),
                unit="percent", raw=f"mem={mem}/{maxmem}",
            ))
    return gauges


@register("proxmox")
class ProxmoxCollector:
    """Collects node + guest CPU/mem utilization from proxmox-mcp."""

    name = "proxmox"

    def collect(self, client, now: str) -> list[Gauge]:
        gauges: list[Gauge] = []
        nodes = _rows(client.call_tool("get_nodes", {}))
        for node in nodes:
            node_name = str(node.get("node") or node.get("name") or "").strip()
            if not node_name:
                continue
            status = _obj(client.call_tool("get_node_status", {"node": node_name}))
            gauges.extend(parse_node_status(status, node_name, now))
        gauges.extend(parse_guests(_rows(client.call_tool("get_vms", {})), now))
        gauges.extend(parse_guests(_rows(client.call_tool("get_containers", {})), now))
        return gauges
