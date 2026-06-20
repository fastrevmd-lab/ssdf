from ssdf_health.gauge import Gauge


def test_gauge_is_frozen_and_holds_all_fields():
    gauge = Gauge(
        provider="juniper",
        device="vSRX-test10",
        scope="device",
        metric_class="cpu",
        sensor="",
        metric_name="cpu_util_pct",
        value=12.5,
        unit="percent",
        raw="Idle 87 percent",
    )
    assert gauge.provider == "juniper"
    assert gauge.metric_name == "cpu_util_pct"
    assert gauge.value == 12.5
    assert gauge.sensor == ""


def test_gauge_is_immutable():
    import dataclasses
    gauge = Gauge("unifi", "ap1", "device", "temperature", "CPU",
                  "temp_celsius", 41.0, "celsius", "")
    try:
        gauge.value = 99.0  # type: ignore[misc]
        assert False, "Gauge should be frozen"
    except dataclasses.FrozenInstanceError:
        pass
