# src/ssdf_topo/collectors/junos.py
"""Junos topology collector: ARP, LLDP neighbors, and MAC table (CLI text parsers)."""

from __future__ import annotations

import re

from ..models import Observation
from .base import firewall_inventory, register

_MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$", re.IGNORECASE)


def parse_arp(text: str, source_device: str, now: str) -> list[Observation]:
    """Parse Junos 'show arp no-resolve' CLI text; emit one arp_entry per data row."""
    observations: list[Observation] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        # Skip header
        if stripped.startswith("MAC Address"):
            continue
        # Skip footer
        if stripped.startswith("Total entries"):
            continue
        tokens = stripped.split()
        if len(tokens) < 3:
            continue
        mac = tokens[0].lower()
        ip = tokens[1]
        iface = tokens[2]
        observations.append(Observation(
            observed_at=now,
            collector="junos",
            source_device=source_device,
            layer="l3",
            observation_type="arp_entry",
            subj_kind="host",
            subj_id=f"ip:{ip}",
            obj_kind="host",
            obj_id=f"mac:{mac}",
            attrs={"interface": iface},
            raw=line,
        ))
    return observations


def parse_lldp_neighbors(text: str, source_device: str, now: str) -> list[Observation]:
    """Parse Junos 'show lldp neighbors' CLI text; emit one lldp_neighbor per data row.

    Columns: Local Interface, Parent Interface, Chassis Id, Port info, System Name.
    Port info may be multi-word; System Name is always the last token.
    """
    observations: list[Observation] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        # Skip header line
        if stripped.startswith("Local Interface"):
            continue
        tokens = stripped.split()
        # Need at least: local, parent, chassis, port_or_system, system
        if len(tokens) < 4:
            continue
        local = tokens[0]
        # token[1] is parent interface (often "-")
        chassis = tokens[2]
        # Remaining tokens: port info + system name
        remaining = tokens[3:]
        remote_system = remaining[-1]
        remote_port = " ".join(remaining[:-1]) if len(remaining) > 1 else ""
        observations.append(Observation(
            observed_at=now,
            collector="junos",
            source_device=source_device,
            layer="l2",
            observation_type="lldp_neighbor",
            subj_kind="interface",
            subj_id=f"if:{source_device}:{local}",
            obj_kind="interface",
            obj_id=f"if:{remote_system}:{remote_port or 'unknown'}",
            attrs={
                "local_port": local,
                "remote_port": remote_port,
                "remote_system": remote_system,
                "remote_chassis": chassis,
            },
            raw=line,
        ))
    return observations


def parse_mac_table(text: str, source_device: str, now: str) -> list[Observation]:
    """Parse Junos 'show ethernet-switching table' CLI text; emit one mac_entry per MAC row.

    Identifies data rows by detecting a MAC address in position 1 (vlan mac flags age port ...).
    """
    observations: list[Observation] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        tokens = stripped.split()
        if len(tokens) < 5:
            continue
        # Data rows have a MAC address as their second token
        if not _MAC_RE.match(tokens[1]):
            continue
        vlan = tokens[0]
        mac = tokens[1].lower()
        port = tokens[4]
        observations.append(Observation(
            observed_at=now,
            collector="junos",
            source_device=source_device,
            layer="l2",
            observation_type="mac_entry",
            subj_kind="host",
            subj_id=f"mac:{mac}",
            obj_kind="device",
            obj_id=f"device:{source_device}",
            attrs={"vlan": vlan, "port": port},
            raw=line,
        ))
    return observations


@register("junos")
class JunosCollector:
    """Collects ARP, LLDP, and MAC table data from one or more Junos devices."""

    name = "junos"

    def __init__(self, devices: list[str] | None = None):
        self.devices = devices or []

    def collect(self, client, now: str) -> list[Observation]:
        """Pull topology facts from each configured Junos device via the MCP client."""
        observations: list[Observation] = []
        for dev in self.devices:
            lldp_text = client.call_tool(
                "execute_junos_command",
                {"router_name": dev, "command": "show lldp neighbors"},
            )
            observations.extend(parse_lldp_neighbors(lldp_text, dev, now))

            mac_text = client.call_tool(
                "execute_junos_command",
                {"router_name": dev, "command": "show ethernet-switching table"},
            )
            observations.extend(parse_mac_table(mac_text, dev, now))

            arp_text = client.call_tool(
                "execute_junos_command",
                {"router_name": dev, "command": "show arp no-resolve"},
            )
            observations.extend(parse_arp(arp_text, dev, now))
            observations.append(firewall_inventory("junos", dev, now))
        return observations
