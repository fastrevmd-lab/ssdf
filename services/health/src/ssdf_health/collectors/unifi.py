"""UniFi health collector: per-device CPU%/mem% + multi-sensor temperatures."""

from __future__ import annotations

import json

from ..gauge import Gauge
from .base import register

_ENVELOPE_KEYS = ("result", "data", "device", "item")


def _obj(text: str) -> dict:
    data = json.loads(text)
    if isinstance(data, dict):
        for key in _ENVELOPE_KEYS:
            val = data.get(key)
            if isinstance(val, dict):
                return val
        return data
    return {}


def _pct_gauge(value_str, device, metric_class, metric_name) -> Gauge | None:
    try:
        value = float(value_str)
    except (TypeError, ValueError):
        return None
    return Gauge(
        provider="unifi", device=device, scope="device", metric_class=metric_class,
        sensor="", metric_name=metric_name, value=max(0.0, min(100.0, value)),
        unit="percent", raw=str(value_str),
    )


def parse_device(device_obj: dict, device: str, now: str) -> list[Gauge]:
    """Build CPU/mem + per-sensor temperature gauges from a get_device_by_mac dict."""
    gauges: list[Gauge] = []
    stats = device_obj.get("system-stats") or {}
    cpu = _pct_gauge(stats.get("cpu"), device, "cpu", "cpu_util_pct")
    if cpu:
        gauges.append(cpu)
    mem = _pct_gauge(stats.get("mem"), device, "memory", "mem_util_pct")
    if mem:
        gauges.append(mem)
    for temp in device_obj.get("temperatures") or []:
        try:
            value = float(temp.get("value"))
        except (TypeError, ValueError):
            continue
        gauges.append(Gauge(
            provider="unifi", device=device, scope="device",
            metric_class="temperature", sensor=str(temp.get("name") or ""),
            metric_name="temp_celsius", value=value, unit="celsius",
            raw=json.dumps(temp, default=str),
        ))
    return gauges


@register("unifi")
class UnifiCollector:
    """Collects CPU/mem + temps from UniFi devices (by MAC) via unifi-mcp."""

    name = "unifi"

    def __init__(self, macs: list[str] | None = None, site_id: str = "default"):
        self.macs = macs or []
        self.site_id = site_id

    def collect(self, client, now: str) -> list[Gauge]:
        gauges: list[Gauge] = []
        for mac in self.macs:
            device_obj = _obj(client.call_tool(
                "get_device_by_mac", {"site_id": self.site_id, "mac": mac},
            ))
            device = str(device_obj.get("name") or mac)
            gauges.extend(parse_device(device_obj, device, now))
        return gauges
