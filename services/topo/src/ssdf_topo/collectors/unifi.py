# src/ssdf_topo/collectors/unifi.py
"""UniFi topology collector: active clients + device inventory (JSON envelope parsers)."""

from __future__ import annotations

import json
import logging

from ..models import Observation
from .base import register

logger = logging.getLogger(__name__)

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
        sw_port = str(row.get("sw_port", "") or "")
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
            attrs={"vlan": vlan, "port": sw_port, "wired": str(is_wired)},
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


# UniFi device `type` codes -> SSDF role. The Gateway Max reports `uxg`
# (model UXGB); `ugw` is the older Security Gateway and returns nothing on this
# site. Without a uxg entry the gateway fell through to the generic "device"
# role and could not be picked out of the graph.
_ROLE_MAP = {
    "usw": "switch",
    "uap": "ap",
    "uxg": "gateway",
    "ugw": "gateway",
    "udm": "gateway",
}


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


# unifi-mcp has no "list every device" tool: list_devices_by_type requires an
# explicit type, so inventory means asking for each type we care about.
DEVICE_TYPES = ("uxg", "ugw", "udm", "usw", "uap")


@register("unifi")
class UnifiCollector:
    """Collects device inventory and active client data from a UniFi site."""

    name = "unifi"

    def __init__(self, site_id: str = "default",
                 device_types: tuple[str, ...] = DEVICE_TYPES):
        self.site_id = site_id
        self.device_types = device_types

    def collect(self, client, now: str) -> list[Observation]:
        """Pull device inventory and active clients from the UniFi MCP server.

        `site_id` is mandatory on both tools and `device_type` on the first; the
        collector previously called them with `{}` and every run failed validation,
        which run_collectors swallowed — UniFi topology went silently missing while
        UniFi health telemetry kept working.
        """
        observations: list[Observation] = []
        for device_type in self.device_types:
            try:
                devices_text = client.call_tool(
                    "list_devices_by_type",
                    {"site_id": self.site_id, "device_type": device_type},
                )
                observations.extend(parse_devices(devices_text, "unifi-site", now))
            except Exception:
                logger.warning(
                    "unifi: device type %r query failed; continuing", device_type, exc_info=True
                )
        try:
            clients_text = client.call_tool("list_active_clients", {"site_id": self.site_id})
            observations.extend(parse_clients(clients_text, "unifi-site", now))
        except Exception:
            logger.warning("unifi: active-client query failed; continuing", exc_info=True)
        return observations
