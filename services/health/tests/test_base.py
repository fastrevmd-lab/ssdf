from ssdf_health.collectors.base import REGISTRY, register, get_collector, run_collectors
from ssdf_health.gauge import Gauge


def test_register_adds_to_registry():
    @register("dummy_reg")
    class _Dummy:
        name = "dummy_reg"

    assert REGISTRY["dummy_reg"] is _Dummy
    assert get_collector("dummy_reg") is _Dummy


def test_get_collector_unknown_raises():
    try:
        get_collector("nope")
        assert False
    except KeyError:
        pass


def _gauge(metric_name):
    return Gauge("p", "d", "device", "cpu", "", metric_name, 1.0, "percent", "")


def test_run_collectors_skips_failing_collector(caplog):
    class _Good:
        name = "good"

        def collect(self, client, now):
            return [_gauge("cpu_util_pct")]

    class _Bad:
        name = "bad"

        def collect(self, client, now):
            raise RuntimeError("boom")

    factories = {"good": _Good(), "bad": _Bad()}
    written = []

    class _Writer:
        def insert_gauges(self, gauges, now):
            written.extend(gauges)
            return len(gauges)

    total = run_collectors(
        enabled=["bad", "good"],
        client_factory=lambda name: None,
        collector_factory=lambda name: factories[name],
        writer=_Writer(),
        now="2026-06-20T00:00:00Z",
    )
    # bad raised and was skipped; good still produced one gauge
    assert total == 1
    assert len(written) == 1
    assert written[0].metric_name == "cpu_util_pct"
