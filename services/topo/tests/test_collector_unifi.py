# tests/test_collector_unifi.py
"""Tests for the UniFi topology collector (client + device inventory parsers)."""

import json
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



def test_collect_supplies_the_required_site_and_type_arguments():
    """unifi-mcp requires site_id (and device_type); the collector passed {}.

    Both tools reject the empty call with a validation error, which run_collectors
    catches and skips — so UniFi topology silently produced nothing while UniFi
    health telemetry kept working, and the gateway never got a device node.
    """
    from ssdf_topo.collectors.unifi import UnifiCollector

    calls: list[tuple[str, dict]] = []

    class _RecordingClient:
        def call_tool(self, name, args=None):
            calls.append((name, args or {}))
            return '{"result": []}'

    UnifiCollector(site_id="default").collect(_RecordingClient(), NOW)

    device_calls = [a for n, a in calls if n == "list_devices_by_type"]
    client_calls = [a for n, a in calls if n == "list_active_clients"]
    assert device_calls, "must query device inventory"
    assert client_calls == [{"site_id": "default"}]
    for args in device_calls:
        assert args["site_id"] == "default"
        assert args["device_type"], "device_type is required by the tool"
    # The gateway is type uxg, which must be among the types queried.
    assert "uxg" in {a["device_type"] for a in device_calls}


def test_collect_survives_one_failing_device_type():
    """A type that errors must not discard the other types' inventory."""
    from ssdf_topo.collectors.unifi import UnifiCollector

    gateway = json.dumps({"result": [
        {"mac": "02:00:01:27:fb:2b", "name": "Gateway Max", "type": "uxg",
         "model": "UXGB", "ip": "198.51.100.1"}]})

    class _FlakyClient:
        def call_tool(self, name, args=None):
            if name == "list_active_clients":
                return '{"result": []}'
            if (args or {}).get("device_type") == "usw":
                raise RuntimeError("boom")
            if (args or {}).get("device_type") == "uxg":
                return gateway
            return '{"result": []}'

    obs = UnifiCollector(site_id="default").collect(_FlakyClient(), NOW)

    macs = {o.attrs.get("mac") for o in obs if o.observation_type == "device_inventory"}
    assert "02:00:01:27:fb:2b" in macs


def test_uxg_gateway_resolves_to_a_gateway_role():
    """The Gateway Max reports type `uxg`; without a mapping it fell through to
    the generic `device` role and could never be picked out of the graph."""
    from ssdf_topo.collectors.unifi import parse_devices

    payload = json.dumps([
        {"mac": "02:00:01:27:fb:2b", "name": "Gateway Max", "type": "uxg",
         "model": "UXGB", "ip": "198.51.100.1"}])

    obs = parse_devices(payload, SOURCE, NOW)
    assert len(obs) == 1
    assert obs[0].attrs["role"] == "gateway"
    assert obs[0].attrs["name"] == "Gateway Max"
