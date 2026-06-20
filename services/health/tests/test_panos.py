from ssdf_health.collectors.panos import (
    _result_text, parse_resources, parse_environmentals,
)

_RESOURCES = (
    '{"result": "top - 12:00:00 up 1 day\\n'
    'Tasks: 200 total\\n'
    '%Cpu(s):  3.2 us,  1.0 sy,  0.0 ni, 95.0 id,  0.8 wa\\n'
    'MiB Mem :  16000.0 total,  4000.0 free,  8000.0 used,  4000.0 buff\\n"}'
)

_ENVIRONMENTALS = (
    "<response><result><thermal>"
    "<entry><slot>1</slot><description>Temperature @ MP</description>"
    "<DegreesC>38.5</DegreesC><alarm>False</alarm></entry>"
    "<entry><slot>2</slot><description>Temperature @ DP</description>"
    "<DegreesC>44.0</DegreesC><alarm>False</alarm></entry>"
    "</thermal></result></response>"
)


def test_result_text_unwraps_json_result():
    assert _result_text('{"result": "hello"}') == "hello"
    assert _result_text("plain") == "plain"


def test_parse_resources_cpu_and_mem():
    gauges = parse_resources(_RESOURCES, "panosvm", "2026-06-20T00:00:00Z")
    by_name = {g.metric_name: g for g in gauges}
    assert by_name["cpu_util_pct"].value == 5.0          # 100 - 95.0 id
    assert by_name["mem_util_pct"].value == 50.0         # 8000/16000
    assert by_name["cpu_util_pct"].provider == "paloalto"
    assert all(g.sensor == "" for g in gauges)


def test_parse_environmentals_multi_sensor():
    gauges = parse_environmentals(_ENVIRONMENTALS, "panosvm", "2026-06-20T00:00:00Z")
    temps = {g.sensor: g.value for g in gauges}
    assert temps == {"Temperature @ MP": 38.5, "Temperature @ DP": 44.0}
    assert all(g.metric_name == "temp_celsius" and g.unit == "celsius" for g in gauges)


def test_parse_resources_garbage_returns_empty():
    assert parse_resources('{"result": "no cpu line here"}', "d",
                           "2026-06-20T00:00:00Z") == []
