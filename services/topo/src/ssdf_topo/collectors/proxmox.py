# src/ssdf_topo/collectors/proxmox.py
"""Proxmox topology collector: VM text listing + per-VM NIC config parsers."""

from __future__ import annotations

import json
import re

from ..models import Observation
from .base import register

_MAC_RE = re.compile(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})")

# Matches lines like: [vm] vSRX-test10 (ID: 210)
_VM_HEADER_RE = re.compile(r"^\[vm\]\s+(.+?)\s+\(ID:\s*(\d+)\)")
_NODE_RE = re.compile(r"-\s*Node:\s*(\S+)")
_STATUS_RE = re.compile(r"-\s*Status:\s*(\S+)")


def parse_vm_nic(nic: str) -> dict:
    """Parse a Proxmox netN string and return mac, bridge, and vlan (tag) as strings."""
    mac_match = _MAC_RE.search(nic)
    mac = mac_match.group(1).lower() if mac_match else ""
    bridge = ""
    vlan = ""
    for part in nic.split(","):
        if "=" not in part:
            continue
        key, _, val = part.partition("=")
        key = key.strip()
        val = val.strip()
        if key == "bridge":
            bridge = val
        elif key == "tag":
            vlan = val
    return {"mac": mac, "bridge": bridge, "vlan": vlan}


def parse_vms(vms: list[dict], now: str) -> list[Observation]:
    """Build vm_host and vm_nic observations from a list of VM dicts (with optional config)."""
    observations: list[Observation] = []
    for vm in vms:
        vmid = str(vm.get("vmid") or "").strip()
        if not vmid:
            continue
        node = str(vm.get("node") or "")
        name = str(vm.get("name") or "")
        host_id = f"vm:{node}/{vmid}"

        observations.append(
            Observation(
                observed_at=now,
                collector="proxmox",
                source_device=node,
                layer="virt",
                observation_type="vm_host",
                subj_kind="device",
                subj_id=f"device:{node}",
                obj_kind="host",
                obj_id=host_id,
                attrs={"vmid": vmid, "name": name},
                raw=json.dumps(vm, default=str),
            )
        )

        config = vm.get("config") or {}
        for key, val in config.items():
            if not key.startswith("net"):
                continue
            nic = parse_vm_nic(str(val))
            if not nic["mac"]:
                continue
            observations.append(
                Observation(
                    observed_at=now,
                    collector="proxmox",
                    source_device=node,
                    layer="l2",
                    observation_type="vm_nic",
                    subj_kind="host",
                    subj_id=f"mac:{nic['mac']}",
                    obj_kind="device",
                    obj_id=f"device:{node}:{nic['bridge']}",
                    attrs={
                        "bridge": nic["bridge"],
                        "vlan": nic["vlan"],
                        "vmid": vmid,
                        "vm": host_id,
                        "name": name,
                    },
                    raw=str(val),
                )
            )
    return observations


def _vms_from_text(text: str) -> list[dict]:
    """Parse the Proxmox VM text listing (blocks starting with '[vm] NAME (ID: N)')."""
    vms: list[dict] = []
    current: dict | None = None
    for line in text.splitlines():
        header_match = _VM_HEADER_RE.match(line)
        if header_match:
            if current is not None:
                vms.append(current)
            current = {
                "name": header_match.group(1),
                "vmid": header_match.group(2),
                "node": "",
                "status": "",
            }
            continue
        if current is None:
            continue
        node_match = _NODE_RE.search(line)
        if node_match:
            current["node"] = node_match.group(1)
            continue
        status_match = _STATUS_RE.search(line)
        if status_match:
            current["status"] = status_match.group(1)
    if current is not None:
        vms.append(current)
    return vms


@register("proxmox")
class ProxmoxCollector:
    """Collects VM inventory and NIC topology from Proxmox via the proxmox-mcp server."""

    name = "proxmox"

    def collect(self, client, now: str) -> list[Observation]:
        """Pull the VM list, fetch per-VM config, and return vm_host + vm_nic observations."""
        vms_text = client.call_tool("get_vms", {})
        vms = _vms_from_text(vms_text)
        for vm in vms:
            if not vm.get("node"):
                continue
            if "config" in vm:
                continue
            try:
                cfg_text = client.call_tool(
                    "get_vm_config",
                    {"node": vm["node"], "vmid": vm["vmid"]},
                )
                vm["config"] = json.loads(cfg_text)
            except json.JSONDecodeError:
                vm["config"] = {}
        return parse_vms(vms, now)
