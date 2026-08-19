"""PAN-OS health collector: system resources CPU%/mem% + environmentals temps."""

from __future__ import annotations

import re

from defusedxml.ElementTree import fromstring as _xml_fromstring, ParseError as _XmlParseError

from ..gauge import Gauge
from ssdf_common.mcp_envelope import unwrap_mcp_text

from .base import register

_IDLE_RE = re.compile(r"([\d.]+)\s*id", re.IGNORECASE)
_MEM_RE = re.compile(
    r"MiB Mem\s*:\s*([\d.]+)\s+total,\s*[\d.]+\s+free,\s*([\d.]+)\s+used",
    re.IGNORECASE,
)


def _result_text(text: str) -> str:
    """Unwrap the MCP response envelope around a tool's text payload."""
    return unwrap_mcp_text(text)


def parse_resources(text: str, device: str, now: str) -> list[Gauge]:
    """Build device-scope CPU/mem gauges from the <resources> top snapshot."""
    body = _result_text(text)
    gauges: list[Gauge] = []
    idle = _IDLE_RE.search(body)
    if idle:
        gauges.append(Gauge(
            provider="paloalto", device=device, scope="device", metric_class="cpu",
            sensor="", metric_name="cpu_util_pct",
            value=max(0.0, 100.0 - float(idle.group(1))),
            unit="percent", raw=idle.group(0),
        ))
    mem = _MEM_RE.search(body)
    if mem:
        total, used = float(mem.group(1)), float(mem.group(2))
        if total:
            gauges.append(Gauge(
                provider="paloalto", device=device, scope="device",
                metric_class="memory", sensor="", metric_name="mem_util_pct",
                value=max(0.0, min(100.0, used / total * 100.0)),
                unit="percent", raw=mem.group(0),
            ))
    return gauges


def parse_environmentals(text: str, device: str, now: str) -> list[Gauge]:
    """Build per-sensor temperature gauges from the <environmentals> XML."""
    body = _result_text(text)
    try:
        root = _xml_fromstring(body)
    except (_XmlParseError, Exception):
        return []
    gauges: list[Gauge] = []
    for entry in root.findall(".//entry"):
        deg_el = entry.find("DegreesC")
        if deg_el is None or not deg_el.text:
            continue
        desc_el = entry.find("description")
        sensor = desc_el.text.strip() if (desc_el is not None and desc_el.text) else ""
        try:
            value = float(deg_el.text.strip())
        except ValueError:
            continue
        gauges.append(Gauge(
            provider="paloalto", device=device, scope="device",
            metric_class="temperature", sensor=sensor, metric_name="temp_celsius",
            value=value, unit="celsius", raw=deg_el.text.strip(),
        ))
    return gauges


@register("panos")
class PanosCollector:
    """Collects CPU/mem + temps from a PAN-OS firewall via panos-mcp."""

    name = "panos"

    def __init__(self, device: str = "panosvm"):
        self.device = device

    def collect(self, client, now: str) -> list[Gauge]:
        resources = client.call_tool(
            "execute_panos_op",
            {"device": self.device,
             "command": "<show><system><resources></resources></system></show>"},
        )
        environmentals = client.call_tool(
            "execute_panos_op",
            {"device": self.device,
             "command": "<show><system><environmentals></environmentals></system></show>"},
        )
        return (parse_resources(resources, self.device, now)
                + parse_environmentals(environmentals, self.device, now))
