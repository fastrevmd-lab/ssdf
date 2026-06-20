from ssdf_health.collectors.proxmox import (
    parse_nodes, parse_guests, clamp_pct, _name_from_header,
)

# Real proxmox-mcp text payloads (captured live on ct109, 2026-06-20).
NODES_TEXT = (
    "[node] Proxmox Nodes\n\n"
    "[node] pve3\n  - Status: ONLINE\n  - Uptime: [uptime] 1d 5h 18m\n"
    "  - CPU Cores: 88\n  - Memory: 42.76 GB / 235.77 GB (18.1%)\n\n"
    "[node] pve2\n  - Status: OFFLINE\n  - Uptime: 0m\n"
    "  - CPU Cores: N/A\n  - Memory: 0.00 B / 0.00 B (0.0%)\n\n"
    "[node] pve1\n  - Status: ONLINE\n  - Uptime: [uptime] 1d 6h 5m\n"
    "  - CPU Cores: 32\n  - Memory: 84.45 GB / 91.99 GB (91.8%)"
)

VMS_TEXT = (
    "[vm] Virtual Machines\n\n"
    "[vm] vSRX-test3 (ID: 101)\n  - Status: STOPPED\n  - Node: pve3\n"
    "  - CPU Cores: 2\n  - Memory: 0.00 B / 4.00 GB (0.0%)\n\n"
    "[vm] ProductionSRX (ID: 103)\n  - Status: RUNNING\n  - Node: pve3\n"
    "  - CPU Cores: 2\n  - Memory: 4.02 GB / 4.00 GB (100.4%)"
)

CONTAINERS_TEXT = (
    "Containers\n\n"
    "ssdf-topo (ID: 109)\n  - Status: RUNNING\n  - Node: pve3\n"
    "  - CPU: 7.2%\n  - CPU Cores: 1\n  - Memory: 57.40 MiB / 512.00 MiB (11.2%)\n\n"
    "wifi-ap (ID: 143)\n  - Status: STOPPED\n  - Node: pve1\n"
    "  - CPU: 0.0%\n  - CPU Cores: 1\n  - Memory: 0.00 B / 256.00 MiB (0.0%)"
)


def test_clamp_pct_bounds():
    assert clamp_pct(150.0) == 100.0
    assert clamp_pct(-5.0) == 0.0
    assert clamp_pct(42.5) == 42.5


def test_name_from_header_variants():
    assert _name_from_header("[node] pve3") == "pve3"
    assert _name_from_header("[node] Node: pve3") == "pve3"
    assert _name_from_header("[vm] ProductionSRX (ID: 103)") == "ProductionSRX"
    assert _name_from_header("ssdf-topo (ID: 109)") == "ssdf-topo"


def test_parse_nodes_online_only_memory():
    gauges = parse_nodes(NODES_TEXT)
    by_device = {g.device: g for g in gauges}
    assert "pve2" not in by_device          # OFFLINE node skipped
    assert "Proxmox Nodes" not in by_device  # title stanza yields nothing
    assert by_device["pve3"].metric_class == "memory"
    assert by_device["pve3"].scope == "node"
    assert by_device["pve3"].value == 18.1
    assert by_device["pve1"].value == 91.8
    assert all(g.sensor == "" and g.provider == "proxmox" for g in gauges)


def test_parse_vms_running_only_mem_no_cpu():
    gauges = parse_guests(VMS_TEXT)
    devices = {g.device for g in gauges}
    assert "vSRX-test3" not in devices       # STOPPED skipped
    assert "ProductionSRX" in devices        # RUNNING present
    running = [g for g in gauges if g.device == "ProductionSRX"]
    # VMs expose no CPU% in this MCP -> memory only, clamped to 100
    assert {g.metric_name for g in running} == {"mem_util_pct"}
    assert running[0].value == 100.0
    assert running[0].scope == "guest"


def test_parse_containers_running_only_cpu_and_mem():
    gauges = parse_guests(CONTAINERS_TEXT)
    devices = {g.device for g in gauges}
    assert "wifi-ap" not in devices          # STOPPED skipped
    running = [g for g in gauges if g.device == "ssdf-topo"]
    assert {g.metric_name for g in running} == {"cpu_util_pct", "mem_util_pct"}
    cpu = next(g for g in running if g.metric_name == "cpu_util_pct")
    mem = next(g for g in running if g.metric_name == "mem_util_pct")
    assert cpu.value == 7.2
    assert mem.value == 11.2
    assert "CPU Cores" not in cpu.raw        # "CPU Cores: 1" must not match CPU%
