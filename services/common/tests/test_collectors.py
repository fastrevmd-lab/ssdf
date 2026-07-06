"""Unit tests for ssdf_common.collectors."""

import pytest

from ssdf_common.collectors import REGISTRY, register, get_collector, run_collectors


def test_register_decorator():
    """register decorator adds a class to REGISTRY."""
    # Clear any previous test state
    REGISTRY.clear()

    @register("test_collector")
    class TestCollector:
        name = "test_collector"

        def collect(self, client, now: str):
            return []

    assert "test_collector" in REGISTRY
    assert REGISTRY["test_collector"] is TestCollector


def test_get_collector_success():
    """get_collector retrieves a registered collector."""
    REGISTRY.clear()

    @register("foo")
    class Foo:
        pass

    assert get_collector("foo") is Foo


def test_get_collector_unknown():
    """get_collector raises KeyError for unknown collector."""
    REGISTRY.clear()
    with pytest.raises(KeyError, match="unknown collector: bar"):
        get_collector("bar")


def test_run_collectors_success():
    """run_collectors orchestrates enabled collectors and aggregates counts."""
    REGISTRY.clear()

    @register("c1")
    class C1:
        name = "c1"

        def collect(self, client, now):
            return ["item1", "item2"]

    @register("c2")
    class C2:
        name = "c2"

        def collect(self, client, now):
            return ["item3"]

    class FakeWriter:
        def __init__(self):
            self.items = []

        def insert_observations(self, items):
            self.items.extend(items)
            return len(items)

    writer = FakeWriter()
    total = run_collectors(
        enabled=["c1", "c2"],
        client_factory=lambda name: None,
        collector_factory=lambda name: get_collector(name)(),
        writer=writer,
        now="2026-01-01T00:00:00Z",
    )
    assert total == 3
    assert writer.items == ["item1", "item2", "item3"]


def test_run_collectors_skips_failures():
    """run_collectors logs and skips a collector that raises."""
    REGISTRY.clear()

    @register("good")
    class Good:
        name = "good"

        def collect(self, client, now):
            return ["ok"]

    @register("bad")
    class Bad:
        name = "bad"

        def collect(self, client, now):
            raise RuntimeError("collector boom")

    class FakeWriter:
        def __init__(self):
            self.count = 0

        def insert_observations(self, items):
            self.count += len(items)
            return len(items)

    writer = FakeWriter()
    total = run_collectors(
        enabled=["good", "bad"],
        client_factory=lambda name: None,
        collector_factory=lambda name: get_collector(name)(),
        writer=writer,
        now="now",
    )
    assert total == 1  # only the good collector's item
    assert writer.count == 1


def test_run_collectors_health_insert_gauges():
    """run_collectors detects insert_gauges method (health signature)."""
    REGISTRY.clear()

    @register("health_c")
    class HealthC:
        name = "health_c"

        def collect(self, client, now):
            return ["gauge1"]

    class HealthWriter:
        def __init__(self):
            self.gauges = []

        def insert_gauges(self, gauges, now):
            self.gauges.extend(gauges)
            return len(gauges)

    writer = HealthWriter()
    total = run_collectors(
        enabled=["health_c"],
        client_factory=lambda name: None,
        collector_factory=lambda name: get_collector(name)(),
        writer=writer,
        now="now",
    )
    assert total == 1
    assert writer.gauges == ["gauge1"]
