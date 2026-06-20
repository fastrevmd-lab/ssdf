from ssdf_health.collectors.proxmox import (
    parse_node_status, parse_guests, clamp_pct, _obj, _rows,
)


def test_clamp_pct_bounds():
    assert clamp_pct(150.0) == 100.0
    assert clamp_pct(-5.0) == 0.0
    assert clamp_pct(42.5) == 42.5


def test_parse_node_status_cpu_and_mem():
    status = {"cpu": 0.25, "memory": {"used": 3, "total": 4}}
    gauges = parse_node_status(status, "pve3", "2026-06-20T00:00:00Z")
    by_name = {g.metric_name: g for g in gauges}
    assert by_name["cpu_util_pct"].value == 25.0
    assert by_name["cpu_util_pct"].scope == "node"
    assert by_name["cpu_util_pct"].provider == "proxmox"
    assert by_name["mem_util_pct"].value == 75.0
    assert all(g.sensor == "" for g in gauges)


def test_parse_node_status_skips_zero_total_mem():
    status = {"cpu": 0.1, "memory": {"used": 5, "total": 0}}
    gauges = parse_node_status(status, "pve3", "2026-06-20T00:00:00Z")
    names = {g.metric_name for g in gauges}
    assert "cpu_util_pct" in names
    assert "mem_util_pct" not in names  # zero total -> skipped, not a crash


def test_parse_guests_running_only():
    guests = [
        {"vmid": 198, "name": "ssdf-ep-srx", "status": "running",
         "cpu": 0.5, "mem": 1, "maxmem": 2},
        {"vmid": 900, "name": "panosvm", "status": "stopped",
         "cpu": 0.0, "mem": 0, "maxmem": 4},
    ]
    gauges = parse_guests(guests, "2026-06-20T00:00:00Z")
    devices = {g.device for g in gauges}
    assert "ssdf-ep-srx" in devices       # running guest present
    assert "panosvm" not in devices       # stopped guest skipped
    running = [g for g in gauges if g.device == "ssdf-ep-srx"]
    assert {g.metric_name for g in running} == {"cpu_util_pct", "mem_util_pct"}
    assert all(g.scope == "guest" for g in running)
    cpu = next(g for g in running if g.metric_name == "cpu_util_pct")
    assert cpu.value == 50.0


def test_obj_unwraps_envelope():
    assert _obj('{"cpu": 0.1}') == {"cpu": 0.1}
    assert _obj('{"result": {"cpu": 0.2}}') == {"cpu": 0.2}


def test_rows_unwraps_list_envelope():
    assert _rows('[{"vmid": 1}]') == [{"vmid": 1}]
    assert _rows('{"data": [{"vmid": 2}]}') == [{"vmid": 2}]
