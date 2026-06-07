# tests/test_collector_proxmox.py
"""Tests for the Proxmox topology collector (VM text listing + NIC config parsers)."""

import pathlib

from ssdf_topo.collectors.proxmox import _vms_from_text, parse_vm_nic, parse_vms

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
NOW = "2026-06-07T00:00:00+00:00"


def _load(name: str) -> str:
    return (FIXTURES / name).read_text()


def test_parse_vm_nic_extracts_mac_bridge_vlan():
    result = parse_vm_nic("virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,tag=10")
    assert result["mac"] == "aa:bb:cc:dd:ee:ff"
    assert result["bridge"] == "vmbr0"
    assert result["vlan"] == "10"


def test_parse_vms_emits_hosts_and_vm_nic():
    vms = [
        {
            "vmid": "105",
            "name": "web1",
            "node": "pve3",
            "config": {"net0": "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,tag=10"},
        }
    ]
    obs = parse_vms(vms, NOW)
    types = {o.observation_type for o in obs}
    assert "vm_host" in types
    assert "vm_nic" in types
    nic_obs = [o for o in obs if o.observation_type == "vm_nic"]
    assert len(nic_obs) == 1
    nic = nic_obs[0]
    assert nic.subj_id == "mac:aa:bb:cc:dd:ee:ff"
    assert nic.attrs["bridge"] == "vmbr0"
    assert nic.attrs["vlan"] == "10"


def test_vms_from_text_parses_listing():
    vms = _vms_from_text(_load("proxmox_vms.txt"))
    assert len(vms) >= 3
    first = vms[0]
    # First block in fixture: vSRX-test10 (ID: 210) on pve3
    assert first["vmid"] == "210"
    assert first["name"] == "vSRX-test10"
    assert first["node"] == "pve3"
    assert isinstance(first["vmid"], str)
    assert isinstance(first["name"], str)
    assert isinstance(first["node"], str)
