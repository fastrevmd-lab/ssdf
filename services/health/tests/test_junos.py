from ssdf_health.collectors.junos import parse_routing_engine, parse_environment

_RE_TEXT = """Routing Engine status:
    DRAM                      2048 MB
    Memory utilization          14 percent
    CPU utilization:
      User                       2 percent
      Background                 0 percent
      Kernel                     3 percent
      Interrupt                  0 percent
      Idle                      95 percent
"""

_ENV_TEXT = """Class Item                           Status     Measurement
Temp  Routing Engine                 OK         39 degrees C / 102 degrees F
Temp  CPU                            OK         42 degrees C / 107 degrees F
Fans  Fan 1                          OK         Spinning at normal speed
"""


def test_parse_routing_engine_cpu_and_mem():
    gauges = parse_routing_engine(_RE_TEXT, "vSRX-test10", "2026-06-20T00:00:00Z")
    by_name = {g.metric_name: g for g in gauges}
    assert by_name["mem_util_pct"].value == 14.0
    assert by_name["cpu_util_pct"].value == 5.0  # 100 - 95 idle
    assert by_name["cpu_util_pct"].provider == "juniper"
    assert by_name["cpu_util_pct"].device == "vSRX-test10"
    assert all(g.sensor == "" and g.unit == "percent" for g in gauges)


def test_parse_environment_multi_sensor_temps():
    gauges = parse_environment(_ENV_TEXT, "vSRX-test10", "2026-06-20T00:00:00Z")
    temps = {g.sensor: g for g in gauges}
    assert set(temps) == {"Routing Engine", "CPU"}  # Fans line ignored
    assert temps["Routing Engine"].value == 39.0
    assert temps["CPU"].value == 42.0
    assert all(g.metric_class == "temperature" and g.metric_name == "temp_celsius"
               and g.unit == "celsius" for g in gauges)


def test_parse_routing_engine_garbage_returns_empty():
    assert parse_routing_engine("nonsense", "d", "2026-06-20T00:00:00Z") == []
