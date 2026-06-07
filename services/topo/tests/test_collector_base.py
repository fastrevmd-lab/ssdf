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
