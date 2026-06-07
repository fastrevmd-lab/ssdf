# src/ssdf_topo/collectors/unifi.py
"""UniFi topology collector: active clients + device inventory (JSON envelope parsers)."""

from __future__ import annotations

import json

from ..models import Observation
from .base import register

_ENVELOPE_KEYS = ("result", "data", "clients", "devices", "items")


def _rows(text: str) -> list[dict]:
    """Unwrap a JSON envelope and return the first list found under known keys.

    If the parsed value is already a list, return it directly.
    If it is a dict, try each known envelope key; fall back to wrapping in a list.
    """
    data = json.loads(text)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in _ENVELOPE_KEYS:
            val = data.get(key)
            if isinstance(val, list):
                return val
        return [data]
    return [data]


def parse_clients(text: str, source_device: str, now: str) -> list[Observation]:
    """Parse UniFi active clients JSON; emit mac_entry/wlan_assoc + arp_entry per client."""
    observations: list[Observation] = []
    for row in _rows(text):
        mac = str(row.get("mac") or "").strip().lower()
        if not mac:
            continue
        is_wired = bool(row.get("is_wired", True))
        sw_mac = str(row.get("sw_mac") or "").strip().lower()
        ap_mac = str(row.get("ap_mac") or "").strip().lower()
        vlan_raw = row.get("vlan")
        vlan = str(vlan_raw) if vlan_raw is not None else ""
        connected_device = sw_mac or ap_mac or source_device

        obs_type = "mac_entry" if is_wired else "wlan_assoc"
        observations.append(Observation(
            observed_at=now,
            collector="unifi",
            source_device=source_device,
            layer="l2",
            observation_type=obs_type,
            subj_kind="host",
            subj_id=f"mac:{mac}",
            obj_kind="device",
            obj_id=f"device:{connected_device}",
            attrs={"vlan": vlan, "port": "", "wired": str(is_wired)},
            raw=json.dumps(row),
        ))

        ip = str(row.get("ip") or "").strip()
        if ip:
            observations.append(Observation(
                observed_at=now,
                collector="unifi",
                source_device=source_device,
                layer="l3",
                observation_type="arp_entry",
                subj_kind="host",
                subj_id=f"ip:{ip}",
                obj_kind="host",
                obj_id=f"mac:{mac}",
                attrs={"source": "unifi_client"},
                raw="",
            ))
    return observations


_ROLE_MAP = {"usw": "switch", "uap": "ap", "ugw": "router", "udm": "router"}


def parse_devices(text: str, source_device: str, now: str) -> list[Observation]:
    """Parse UniFi device list JSON; emit device_inventory per device."""
    observations: list[Observation] = []
    for row in _rows(text):
        mac = str(row.get("mac") or "").strip().lower()
        if not mac:
            continue
        model = str(row.get("type") or row.get("model") or "").lower()
        role = next(
            (role_val for key, role_val in _ROLE_MAP.items() if key in model),
            "device",
        )
        observations.append(Observation(
            observed_at=now,
            collector="unifi",
            source_device=source_device,
            layer="l2",
            observation_type="device_inventory",
            subj_kind="device",
            subj_id=f"device:{mac}",
            obj_kind="",
            obj_id="",
            attrs={
                "role": role,
                "name": str(row.get("name") or ""),
                "mac": mac,
                "ip": str(row.get("ip") or ""),
            },
            raw=json.dumps(row),
        ))
    return observations


@register("unifi")
class UnifiCollector:
    """Collects device inventory and active client data from a UniFi site."""

    name = "unifi"

    def collect(self, client, now: str) -> list[Observation]:
        """Pull device list and active clients from the UniFi MCP server."""
        devices_text = client.call_tool("list_devices_by_type", {})
        clients_text = client.call_tool("list_active_clients", {})
        return parse_devices(devices_text, "unifi-site", now) + parse_clients(clients_text, "unifi-site", now)
