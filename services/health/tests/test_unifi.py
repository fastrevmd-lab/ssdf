from ssdf_health.collectors.unifi import parse_device

_DEVICE = {
    "name": "UDM-Pro",
    "system-stats": {"cpu": "23.1", "mem": "72.6"},
    "temperatures": [
        {"name": "CPU", "value": 52.0},
        {"name": "PHY", "value": 48.5},
    ],
}


def test_parse_device_cpu_mem_and_temps():
    gauges = parse_device(_DEVICE, "UDM-Pro", "2026-06-20T00:00:00Z")
    by_name = {(g.metric_name, g.sensor): g for g in gauges}
    assert by_name[("cpu_util_pct", "")].value == 23.1
    assert by_name[("cpu_util_pct", "")].provider == "unifi"
    assert by_name[("mem_util_pct", "")].value == 72.6
    assert by_name[("temp_celsius", "CPU")].value == 52.0
    assert by_name[("temp_celsius", "PHY")].value == 48.5


def test_parse_device_missing_stats_is_safe():
    gauges = parse_device({"name": "x"}, "x", "2026-06-20T00:00:00Z")
    assert gauges == []


def test_parse_device_bad_cpu_string_skipped():
    device = {"system-stats": {"cpu": "n/a", "mem": "50.0"}}
    gauges = parse_device(device, "d", "2026-06-20T00:00:00Z")
    names = {g.metric_name for g in gauges}
    assert "cpu_util_pct" not in names  # unparseable -> skipped
    assert "mem_util_pct" in names
