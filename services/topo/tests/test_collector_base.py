# tests/test_collector_base.py
import pytest
from ssdf_topo.collectors.base import Collector, register, get_collector, REGISTRY


def test_register_and_lookup():
    @register("dummy")
    class Dummy(Collector):
        name = "dummy"

        def collect(self, client, now):
            return []

    assert "dummy" in REGISTRY
    assert get_collector("dummy") is Dummy


def test_unknown_collector_raises():
    with pytest.raises(KeyError):
        get_collector("nope")


def test_firewall_inventory_builds_role_tagged_observation():
    from ssdf_topo.collectors.base import firewall_inventory

    obs = firewall_inventory("junos", "vSRX-test10", "2026-06-08T00:00:00+00:00")

    assert obs.observation_type == "device_inventory"
    assert obs.collector == "junos"
    assert obs.source_device == "vSRX-test10"
    assert obs.layer == "l2"
    assert obs.subj_kind == "device"
    assert obs.subj_id == "device:vSRX-test10"
    assert obs.attrs["role"] == "firewall"
    assert obs.attrs["name"] == "vSRX-test10"
