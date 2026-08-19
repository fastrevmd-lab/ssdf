# src/ssdf_topo/collectors/panos.py
"""PAN-OS topology collector: ARP + LLDP via XML-inside-JSON envelope."""

from __future__ import annotations

import xml.etree.ElementTree as ET  # serialization only (ET.tostring)
from defusedxml.ElementTree import fromstring as _xml_fromstring, ParseError as _XmlParseError

from ssdf_common.mcp_envelope import unwrap_mcp_text

from ..models import Observation
from .base import firewall_inventory, register


def _entries(text: str) -> list[ET.Element]:
    """Unwrap the MCP response envelope and return all <entry> elements found."""
    xml_text = unwrap_mcp_text(text)
    try:
        root = _xml_fromstring(xml_text)
    except (_XmlParseError, Exception):  # ParseError + defused EntitiesForbidden/DTDForbidden
        return []
    return root.findall(".//entry")


def _f(entry: ET.Element, tag: str) -> str:
    """Extract stripped text from a child element; return empty string if absent."""
    el = entry.find(tag)
    if el is not None and el.text:
        return el.text.strip()
    return ""


def parse_arp_xml(text: str, source_device: str, now: str) -> list[Observation]:
    """Parse PAN-OS ARP table from JSON-wrapped XML; emit one arp_entry per valid entry."""
    observations: list[Observation] = []
    for entry in _entries(text):
        ip = _f(entry, "ip")
        mac = _f(entry, "mac").lower()
        iface = _f(entry, "interface")
        if not (ip and mac):
            continue
        if mac in ("(incomplete)", "incomplete"):
            continue
        observations.append(Observation(
            observed_at=now,
            collector="panos",
            source_device=source_device,
            layer="l3",
            observation_type="arp_entry",
            subj_kind="host",
            subj_id=f"ip:{ip}",
            obj_kind="host",
            obj_id=f"mac:{mac}",
            attrs={"interface": iface},
            raw=ET.tostring(entry, encoding="unicode"),
        ))
    return observations


def parse_lldp_xml(text: str, source_device: str, now: str) -> list[Observation]:
    """Parse PAN-OS LLDP neighbor table from JSON-wrapped XML; emit one lldp_neighbor per entry."""
    observations: list[Observation] = []
    for entry in _entries(text):
        local = _f(entry, "local-port") or entry.get("name", "")
        remote_sys = _f(entry, "system-name")
        remote_port = _f(entry, "port-id") or _f(entry, "port-description")
        if not (local and (remote_sys or remote_port)):
            continue
        observations.append(Observation(
            observed_at=now,
            collector="panos",
            source_device=source_device,
            layer="l2",
            observation_type="lldp_neighbor",
            subj_kind="interface",
            subj_id=f"if:{source_device}:{local}",
            obj_kind="interface",
            obj_id=f"if:{remote_sys or 'unknown'}:{remote_port}",
            attrs={
                "local_port": local,
                "remote_port": remote_port,
                "remote_system": remote_sys,
            },
            raw=ET.tostring(entry, encoding="unicode"),
        ))
    return observations


@register("panos")
class PanosCollector:
    """Collects ARP and LLDP topology data from a PAN-OS firewall via the panos-mcp server."""

    name = "panos"

    def __init__(self, device: str = "panosvm"):
        self.device = device

    def collect(self, client, now: str) -> list[Observation]:
        """Pull LLDP neighbors and ARP table from PAN-OS via the MCP client."""
        lldp_text = client.call_tool(
            "execute_panos_op",
            {"device": self.device, "command": "<show><lldp><neighbors>all</neighbors></lldp></show>"},
        )
        arp_text = client.call_tool(
            "execute_panos_op",
            {"device": self.device, "command": "<show><arp><entry name='all'/></arp></show>"},
        )
        return (
            parse_lldp_xml(lldp_text, self.device, now)
            + parse_arp_xml(arp_text, self.device, now)
            + [firewall_inventory("panos", self.device, now)]
        )
