# tests/test_collector_unifi.py
"""Tests for the UniFi topology collector (client + device inventory parsers)."""

import pathlib

from ssdf_topo.collectors.unifi import parse_clients, parse_devices

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
NOW = "2026-06-07T00:00:00+00:00"
SOURCE = "unifi-site"


def _load(name: str) -> str:
    return (FIXTURES / name).read_text()


def test_parse_clients_emits_attach_and_address():
    obs = parse_clients(_load("unifi_active_clients.json"), SOURCE, NOW)
    types = {o.observation_type for o in obs}
    assert "mac_entry" in types
    assert "arp_entry" in types
    mac_obs = [o for o in obs if o.observation_type == "mac_entry"]
    first_mac = mac_obs[0]
    assert first_mac.subj_id.startswith("mac:")
    assert "port" in first_mac.attrs


def test_parse_devices_emits_inventory():
    obs = parse_devices(_load("unifi_devices_usw.json"), SOURCE, NOW)
    assert len(obs) > 0
    first = obs[0]
    assert first.observation_type == "device_inventory"
    assert first.subj_kind == "device"
    assert "role" in first.attrs
    # All fixtures are type "usw" → role should be "switch"
    for ob in obs:
        assert ob.attrs["role"] == "switch"
