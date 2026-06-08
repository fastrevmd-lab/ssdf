# tests/test_collector_junos.py
"""Tests for the Junos topology collector (ARP, LLDP, MAC table parsers)."""

import pathlib

import pytest

from ssdf_topo.collectors.junos import parse_arp, parse_lldp_neighbors, parse_mac_table

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
NOW = "2026-06-07T00:00:00+00:00"
SOURCE = "vSRX-test10"


def _load(name: str) -> str:
    return (FIXTURES / name).read_text()


def test_parse_arp_emits_has_address():
    obs = parse_arp(_load("junos_arp.txt"), SOURCE, NOW)
    assert len(obs) == 16, f"expected 16 arp entries, got {len(obs)}"
    first = obs[0]
    assert first.observation_type == "arp_entry"
    assert first.layer == "l3"
    assert first.subj_id.startswith("ip:")
    assert first.obj_id.startswith("mac:")
    assert first.collector == "junos"
    assert first.source_device == SOURCE


def test_parse_lldp_neighbors_emits_physical_link():
    obs = parse_lldp_neighbors(_load("junos_lldp_neighbors.txt"), SOURCE, NOW)
    assert len(obs) > 0
    first = obs[0]
    assert first.observation_type == "lldp_neighbor"
    assert first.layer == "l2"
    assert "local_port" in first.attrs
    assert "remote_port" in first.attrs
    # Check multi-word Port info row
    port8_obs = [o for o in obs if o.attrs.get("remote_port") == "Port 8"]
    assert len(port8_obs) == 1, "expected exactly one row with remote_port=='Port 8'"
    assert port8_obs[0].attrs["remote_system"] == "USW-Pro-XG-8"


def test_parse_mac_table_emits_attaches_to():
    obs = parse_mac_table(_load("junos_eth_switching_table.txt"), SOURCE, NOW)
    # Fixture has 4 data rows (MAC entries)
    assert len(obs) == 4, f"expected 4 mac entries, got {len(obs)}"
    first = obs[0]
    assert first.observation_type == "mac_entry"
    assert first.subj_kind == "host"
    assert first.subj_id.startswith("mac:")
    assert "vlan" in first.attrs
    assert "port" in first.attrs


def test_collect_emits_firewall_inventory_per_device():
    from ssdf_topo.collectors.junos import JunosCollector

    class _EmptyClient:
        def call_tool(self, name, args=None):
            return ""  # parsers yield no rows on empty text

    obs = JunosCollector(["vSRX-test10", "vSRX-test11"]).collect(_EmptyClient(), NOW)

    inv = [o for o in obs if o.observation_type == "device_inventory"]
    assert {o.source_device for o in inv} == {"vSRX-test10", "vSRX-test11"}
    assert all(o.attrs["role"] == "firewall" for o in inv)
    assert all(o.collector == "junos" for o in inv)
    assert len(inv) == 2
