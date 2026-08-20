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
    assert all(
        g.metric_class == "temperature" and g.metric_name == "temp_celsius" and g.unit == "celsius"
        for g in gauges
    )


def test_parse_routing_engine_garbage_returns_empty():
    assert parse_routing_engine("nonsense", "d", "2026-06-20T00:00:00Z") == []


def test_collect_skips_unreachable_device_and_keeps_the_rest():
    """One unreachable vSRX must not zero the whole fleet's health gauges."""
    from ssdf_health.collectors.junos import JunosCollector

    class _FlakyClient:
        def call_tool(self, name, args=None):
            args = args or {}
            if args.get("router_name") == "vsrx-down":
                raise RuntimeError("netconf error: host key mismatch")
            return _RE_TEXT if "routing-engine" in args.get("command", "") else _ENV_TEXT

    gauges = JunosCollector(["vsrx-down", "vsrx-up"]).collect(
        _FlakyClient(), "2026-08-19T00:00:00Z"
    )

    assert {g.device for g in gauges} == {"vsrx-up"}
    assert "cpu_util_pct" in {g.metric_name for g in gauges}


def test_collect_continues_when_one_command_fails():
    """A device answering routing-engine but not environment still yields gauges."""
    from ssdf_health.collectors.junos import JunosCollector

    class _PartialClient:
        def call_tool(self, name, args=None):
            args = args or {}
            if "environment" in args.get("command", ""):
                raise RuntimeError("unsupported command")
            return _RE_TEXT

    gauges = JunosCollector(["vsrx-up"]).collect(_PartialClient(), "2026-08-19T00:00:00Z")

    assert {g.metric_name for g in gauges} == {"mem_util_pct", "cpu_util_pct"}


def test_collect_still_probes_environment_when_routing_engine_fails():
    """The two commands are independent; a routing-engine failure must not
    suppress the temperature probe on a device that is plainly reachable."""
    from ssdf_health.collectors.junos import JunosCollector

    class _NoRoutingEngineClient:
        def call_tool(self, name, args=None):
            args = args or {}
            if "routing-engine" in args.get("command", ""):
                raise RuntimeError("unsupported command on this platform")
            return _ENV_TEXT

    gauges = JunosCollector(["vsrx-up"]).collect(_NoRoutingEngineClient(), "2026-08-19T00:00:00Z")

    assert {g.metric_class for g in gauges} == {"temperature"}
    assert {g.device for g in gauges} == {"vsrx-up"}


def test_collect_stops_probing_a_device_that_is_unreachable():
    """A transport failure means the device is down: don't pay a second timeout.

    Most of the lab fleet is powered off, so probing every command against every
    dead device would push a pass past its 5-minute timer interval.
    """
    from ssdf_health.collectors.junos import JunosCollector

    calls: list[str] = []

    class _UnreachableClient:
        def call_tool(self, name, args=None):
            calls.append((args or {}).get("command", ""))
            raise RuntimeError("netconf error: transport error: connection failed")

    gauges = JunosCollector(["vsrx-down"]).collect(_UnreachableClient(), "2026-08-19T00:00:00Z")

    assert gauges == []
    assert len(calls) == 1, "unreachable device should not be probed twice"


def test_collect_treats_a_timeout_as_unreachable():
    """A timeout is a down device, not a bad command.

    Most of the lab fleet is powered off and fails with 'operation timed out'
    rather than a transport error. Probing twice per dead device can exhaust the
    unit's RuntimeMaxSec=600 before later devices or collectors ever run.
    """
    from ssdf_health.collectors.junos import JunosCollector

    calls: list[str] = []

    class _TimingOutClient:
        def call_tool(self, name, args=None):
            calls.append((args or {}).get("command", ""))
            raise RuntimeError("netconf error: operation timed out after 30s")

    gauges = JunosCollector(["vsrx-down"]).collect(_TimingOutClient(), "2026-08-19T00:00:00Z")

    assert gauges == []
    assert len(calls) == 1, "a timed-out device must not be probed a second time"


def test_host_key_mismatch_is_unreachable():
    """Stale known_hosts is a reachability problem, and the docstring says so."""
    from ssdf_health.collectors.junos import _is_unreachable

    assert _is_unreachable(RuntimeError("netconf error: host key mismatch for 198.51.100.235"))


_ALARMS_TEXT = """
1 alarms currently active
Alarm time               Class  Description
2026-08-18 23:05:33 UTC  Minor  AAMWD control channel down, it will impact AAMW functionality
"""

_ALARMS_NONE = "\nNo alarms currently active\n"

_ALARMS_MULTI = """
2 alarms currently active
Alarm time               Class  Description
2026-08-18 23:05:33 UTC  Minor  AAMWD control channel down, it will impact AAMW functionality
2026-08-19 04:11:02 UTC  Major  Host 0 fan failure
"""


def test_parse_alarms_emits_count_and_one_gauge_per_alarm():
    from ssdf_health.collectors.junos import parse_alarms

    gauges = parse_alarms(_ALARMS_MULTI, "vsrx-prod", "2026-08-20T00:00:00Z")
    by_name = {}
    for g in gauges:
        by_name.setdefault(g.metric_name, []).append(g)

    count = by_name["active_alarm_count"][0]
    assert count.value == 2.0
    assert count.metric_class == "alarm"
    assert count.provider == "juniper"
    assert count.device == "vsrx-prod"

    alarms = by_name["alarm"]
    assert len(alarms) == 2
    # severity rides the `sensor` axis, which M13a designed as a discovery axis
    assert {a.sensor for a in alarms} == {"minor", "major"}
    # the description and raise time must survive for an operator to act on
    assert any("AAMWD control channel down" in a.raw for a in alarms)
    assert any("2026-08-18 23:05:33" in a.raw for a in alarms)


def test_parse_alarms_reports_zero_when_none_active():
    """A device with no alarms must still report a count of 0 — absence of rows
    would be indistinguishable from a collector that stopped running."""
    from ssdf_health.collectors.junos import parse_alarms

    gauges = parse_alarms(_ALARMS_NONE, "vsrx-prod", "2026-08-20T00:00:00Z")
    assert len(gauges) == 1
    assert gauges[0].metric_name == "active_alarm_count"
    assert gauges[0].value == 0.0


def test_parse_alarms_ignores_header_and_banner_lines():
    from ssdf_health.collectors.junos import parse_alarms

    gauges = parse_alarms(_ALARMS_TEXT, "vsrx-prod", "2026-08-20T00:00:00Z")
    alarms = [g for g in gauges if g.metric_name == "alarm"]
    assert len(alarms) == 1, "the 'Alarm time Class Description' header is not an alarm"
    assert alarms[0].sensor == "minor"


def test_parse_alarms_garbage_returns_empty():
    from ssdf_health.collectors.junos import parse_alarms

    assert parse_alarms("nonsense", "d", "2026-08-20T00:00:00Z") == []


def test_collect_dedupes_alarms_reported_by_both_commands():
    """vSRX reports the same alarm under `show system alarms` AND
    `show chassis alarms`; counting it twice would overstate every device."""
    from ssdf_health.collectors.junos import JunosCollector

    class _AlarmClient:
        def call_tool(self, name, args=None):
            cmd = (args or {}).get("command", "")
            if "alarms" in cmd:
                return _ALARMS_TEXT
            if "routing-engine" in cmd:
                return _RE_TEXT
            return _ENV_TEXT

    gauges = JunosCollector(["vsrx-prod"]).collect(_AlarmClient(), "2026-08-20T00:00:00Z")
    alarms = [g for g in gauges if g.metric_class == "alarm" and g.metric_name == "alarm"]
    counts = [g for g in gauges if g.metric_name == "active_alarm_count"]

    assert len(alarms) == 1, "the same alarm from two commands is one alarm"
    assert len(counts) == 1 and counts[0].value == 1.0
