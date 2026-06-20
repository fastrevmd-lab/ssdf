# M13a — Host Resource-Pressure Ingest Implementation Plan (Part 2)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax. This continues `2026-06-20-ssdf-m13a-host-resource-pressure-ingest.md` (Part 1, Tasks 1–5). Start here only after Part 1 is merged/complete.

**Context recap:** `Gauge` dataclass fields are `(provider, device, scope, metric_class, sensor, metric_name, value, unit, raw)`. Collectors are registered via `@register(name)` from `ssdf_health.collectors.base` and return `list[Gauge]`. Each collector receives an `McpToolClient` (with `.call_tool(name, args) -> str`) and an ISO `now` string. Parsers take **already-decoded Python objects or raw text** and are unit-tested with fixtures so no live MCP is needed.

**Shared parser helper convention:** percent metrics clamp to `[0, 100]`; a single unparseable reading is skipped (never raises). Each collector is defensive — malformed vendor output yields `[]` + the warning that `run_collectors` already logs.

---

## Task 6: Proxmox collector (node + guest CPU/mem)

**Files:**
- Create: `services/health/src/ssdf_health/collectors/proxmox.py`
- Test: `services/health/tests/test_proxmox.py`

**Source paths:** `get_nodes()` → per node `get_node_status(node)` (returns `{"cpu": <0..1 fraction>, "memory": {"used": N, "total": M}}`); guests via `get_vms()`/`get_containers()` (each item `{"vmid", "name", "node", "status", "cpu": <fraction>, "mem": N, "maxmem": M}`). No temperature. The collector decodes the MCP text to JSON and hands parsed objects to pure parser functions.

- [ ] **Step 1: Write the failing test**

Create `services/health/tests/test_proxmox.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd services/health && uv run pytest tests/test_proxmox.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'ssdf_health.collectors.proxmox'`

- [ ] **Step 3: Write the implementation**

Create `services/health/src/ssdf_health/collectors/proxmox.py`:

```python
"""Proxmox health collector: node + guest CPU%/mem%. No temperature via this API."""

from __future__ import annotations

import json

from ..gauge import Gauge
from .base import register

_ENVELOPE_KEYS = ("result", "data", "items")


def clamp_pct(value: float) -> float:
    """Clamp a percentage into [0, 100]."""
    return max(0.0, min(100.0, value))


def _obj(text: str) -> dict:
    """Decode MCP text to a single dict, unwrapping a known envelope key."""
    data = json.loads(text)
    if isinstance(data, dict):
        for key in _ENVELOPE_KEYS:
            val = data.get(key)
            if isinstance(val, dict):
                return val
        return data
    return {}


def _rows(text: str) -> list[dict]:
    """Decode MCP text to a list of dicts, unwrapping a known envelope key."""
    data = json.loads(text)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in _ENVELOPE_KEYS:
            val = data.get(key)
            if isinstance(val, list):
                return val
    return []


def parse_node_status(status: dict, node: str, now: str) -> list[Gauge]:
    """Build node-scope CPU/mem gauges from a get_node_status dict."""
    gauges: list[Gauge] = []
    cpu = status.get("cpu")
    if isinstance(cpu, (int, float)):
        gauges.append(Gauge(
            provider="proxmox", device=node, scope="node", metric_class="cpu",
            sensor="", metric_name="cpu_util_pct", value=clamp_pct(float(cpu) * 100.0),
            unit="percent", raw=f"cpu={cpu}",
        ))
    memory = status.get("memory") or {}
    used, total = memory.get("used"), memory.get("total")
    if isinstance(used, (int, float)) and isinstance(total, (int, float)) and total:
        gauges.append(Gauge(
            provider="proxmox", device=node, scope="node", metric_class="memory",
            sensor="", metric_name="mem_util_pct",
            value=clamp_pct(float(used) / float(total) * 100.0),
            unit="percent", raw=f"mem={used}/{total}",
        ))
    return gauges


def parse_guests(guests: list[dict], now: str) -> list[Gauge]:
    """Build guest-scope CPU/mem gauges from a get_vms/get_containers list (running only)."""
    gauges: list[Gauge] = []
    for guest in guests:
        if str(guest.get("status") or "").lower() != "running":
            continue
        device = str(guest.get("name") or guest.get("vmid") or "").strip()
        if not device:
            continue
        cpu = guest.get("cpu")
        if isinstance(cpu, (int, float)):
            gauges.append(Gauge(
                provider="proxmox", device=device, scope="guest", metric_class="cpu",
                sensor="", metric_name="cpu_util_pct",
                value=clamp_pct(float(cpu) * 100.0), unit="percent", raw=f"cpu={cpu}",
            ))
        mem, maxmem = guest.get("mem"), guest.get("maxmem")
        if isinstance(mem, (int, float)) and isinstance(maxmem, (int, float)) and maxmem:
            gauges.append(Gauge(
                provider="proxmox", device=device, scope="guest", metric_class="memory",
                sensor="", metric_name="mem_util_pct",
                value=clamp_pct(float(mem) / float(maxmem) * 100.0),
                unit="percent", raw=f"mem={mem}/{maxmem}",
            ))
    return gauges


@register("proxmox")
class ProxmoxCollector:
    """Collects node + guest CPU/mem utilization from proxmox-mcp."""

    name = "proxmox"

    def collect(self, client, now: str) -> list[Gauge]:
        gauges: list[Gauge] = []
        nodes = _rows(client.call_tool("get_nodes", {}))
        for node in nodes:
            node_name = str(node.get("node") or node.get("name") or "").strip()
            if not node_name:
                continue
            status = _obj(client.call_tool("get_node_status", {"node": node_name}))
            gauges.extend(parse_node_status(status, node_name, now))
        gauges.extend(parse_guests(_rows(client.call_tool("get_vms", {})), now))
        gauges.extend(parse_guests(_rows(client.call_tool("get_containers", {})), now))
        return gauges
```

> NOTE: `collectors/__init__.py` is still empty at this point (restored in Task 9), so importing `ssdf_health.collectors.proxmox` directly works without triggering the other (not-yet-created) modules.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd services/health && uv run pytest tests/test_proxmox.py -v`
Expected: PASS (6 passed)

- [ ] **Step 5: Commit**

```bash
git add services/health/src/ssdf_health/collectors/proxmox.py services/health/tests/test_proxmox.py
git commit -m "feat(m13a): proxmox health collector (node + guest cpu/mem)"
```

---

## Task 7: Junos collector (RE CPU/mem + chassis-environment temps)

**Files:**
- Create: `services/health/src/ssdf_health/collectors/junos.py`
- Test: `services/health/tests/test_junos.py`

**Source paths:** `execute_junos_command(router_name, "show chassis routing-engine")` → `Memory utilization NN percent` + CPU `Idle NN percent` (cpu = 100 − idle). `execute_junos_command(router_name, "show chassis environment")` → `Temp <name> <status> NN degrees C` rows (multi-sensor).

- [ ] **Step 1: Write the failing test**

Create `services/health/tests/test_junos.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd services/health && uv run pytest tests/test_junos.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write the implementation**

Create `services/health/src/ssdf_health/collectors/junos.py`:

```python
"""Junos health collector: routing-engine CPU%/mem% + chassis-environment temps."""

from __future__ import annotations

import re

from ..gauge import Gauge
from .base import register

_MEM_RE = re.compile(r"Memory utilization\s+(\d+)\s+percent", re.IGNORECASE)
_IDLE_RE = re.compile(r"Idle\s+(\d+)\s+percent", re.IGNORECASE)
# "Temp  <name...>  <STATUS>  NN degrees C ..."
_TEMP_RE = re.compile(
    r"^Temp\s+(?P<name>.+?)\s+\S+\s+(?P<c>-?\d+)\s+degrees C", re.IGNORECASE
)


def parse_routing_engine(text: str, device: str, now: str) -> list[Gauge]:
    """Build device-scope CPU/mem gauges from 'show chassis routing-engine'."""
    gauges: list[Gauge] = []
    mem = _MEM_RE.search(text)
    if mem:
        gauges.append(Gauge(
            provider="juniper", device=device, scope="device", metric_class="memory",
            sensor="", metric_name="mem_util_pct", value=float(mem.group(1)),
            unit="percent", raw=mem.group(0),
        ))
    idle = _IDLE_RE.search(text)
    if idle:
        gauges.append(Gauge(
            provider="juniper", device=device, scope="device", metric_class="cpu",
            sensor="", metric_name="cpu_util_pct",
            value=max(0.0, 100.0 - float(idle.group(1))),
            unit="percent", raw=idle.group(0),
        ))
    return gauges


def parse_environment(text: str, device: str, now: str) -> list[Gauge]:
    """Build per-sensor temperature gauges from 'show chassis environment'."""
    gauges: list[Gauge] = []
    for line in text.splitlines():
        match = _TEMP_RE.match(line.strip())
        if not match:
            continue
        gauges.append(Gauge(
            provider="juniper", device=device, scope="device",
            metric_class="temperature", sensor=match.group("name").strip(),
            metric_name="temp_celsius", value=float(match.group("c")),
            unit="celsius", raw=line.strip(),
        ))
    return gauges


@register("junos")
class JunosCollector:
    """Collects CPU/mem + temps from one or more Junos devices via rust-junosmcp."""

    name = "junos"

    def __init__(self, devices: list[str] | None = None):
        self.devices = devices or []

    def collect(self, client, now: str) -> list[Gauge]:
        gauges: list[Gauge] = []
        for dev in self.devices:
            re_text = client.call_tool(
                "execute_junos_command",
                {"router_name": dev, "command": "show chassis routing-engine"},
            )
            gauges.extend(parse_routing_engine(re_text, dev, now))
            env_text = client.call_tool(
                "execute_junos_command",
                {"router_name": dev, "command": "show chassis environment"},
            )
            gauges.extend(parse_environment(env_text, dev, now))
        return gauges
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd services/health && uv run pytest tests/test_junos.py -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Commit**

```bash
git add services/health/src/ssdf_health/collectors/junos.py services/health/tests/test_junos.py
git commit -m "feat(m13a): junos health collector (RE cpu/mem + chassis temps)"
```

---

## Task 8: PAN-OS collector (resources CPU/mem + environmentals temps)

**Files:**
- Create: `services/health/src/ssdf_health/collectors/panos.py`
- Test: `services/health/tests/test_panos.py`

**Source paths:** `execute_pan_op(host, "<show><system><resources></resources></system></show>")` → JSON-wrapped `top` text: `%Cpu(s): ... NN.N id` (cpu = 100 − id), `MiB Mem : T total, F free, U used` (mem = U/T·100). `execute_pan_op(host, "<show><system><environmentals></environmentals></system></show>")` → XML with thermal `<entry>` carrying `<description>` + `<DegreesC>`.

- [ ] **Step 1: Write the failing test**

Create `services/health/tests/test_panos.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd services/health && uv run pytest tests/test_panos.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write the implementation**

Create `services/health/src/ssdf_health/collectors/panos.py`:

```python
"""PAN-OS health collector: system resources CPU%/mem% + environmentals temps."""

from __future__ import annotations

import json
import re

from defusedxml.ElementTree import fromstring as _xml_fromstring, ParseError as _XmlParseError

from ..gauge import Gauge
from .base import register

_IDLE_RE = re.compile(r"([\d.]+)\s*id", re.IGNORECASE)
_MEM_RE = re.compile(
    r"MiB Mem\s*:\s*([\d.]+)\s+total,\s*[\d.]+\s+free,\s*([\d.]+)\s+used",
    re.IGNORECASE,
)


def _result_text(text: str) -> str:
    """Unwrap a JSON {'result': '<text>'} or XML <result>...</result> envelope."""
    stripped = text.strip()
    try:
        data = json.loads(stripped)
        if isinstance(data, dict) and isinstance(data.get("result"), str):
            return data["result"]
        if isinstance(data, str):
            return data
    except json.JSONDecodeError:
        pass
    return stripped


def parse_resources(text: str, device: str, now: str) -> list[Gauge]:
    """Build device-scope CPU/mem gauges from the <resources> top snapshot."""
    body = _result_text(text)
    gauges: list[Gauge] = []
    idle = _IDLE_RE.search(body)
    if idle:
        gauges.append(Gauge(
            provider="paloalto", device=device, scope="device", metric_class="cpu",
            sensor="", metric_name="cpu_util_pct",
            value=max(0.0, 100.0 - float(idle.group(1))),
            unit="percent", raw=idle.group(0),
        ))
    mem = _MEM_RE.search(body)
    if mem:
        total, used = float(mem.group(1)), float(mem.group(2))
        if total:
            gauges.append(Gauge(
                provider="paloalto", device=device, scope="device",
                metric_class="memory", sensor="", metric_name="mem_util_pct",
                value=max(0.0, min(100.0, used / total * 100.0)),
                unit="percent", raw=mem.group(0),
            ))
    return gauges


def parse_environmentals(text: str, device: str, now: str) -> list[Gauge]:
    """Build per-sensor temperature gauges from the <environmentals> XML."""
    body = _result_text(text)
    try:
        root = _xml_fromstring(body)
    except (_XmlParseError, Exception):
        return []
    gauges: list[Gauge] = []
    for entry in root.findall(".//entry"):
        deg_el = entry.find("DegreesC")
        if deg_el is None or not deg_el.text:
            continue
        desc_el = entry.find("description")
        sensor = desc_el.text.strip() if (desc_el is not None and desc_el.text) else ""
        try:
            value = float(deg_el.text.strip())
        except ValueError:
            continue
        gauges.append(Gauge(
            provider="paloalto", device=device, scope="device",
            metric_class="temperature", sensor=sensor, metric_name="temp_celsius",
            value=value, unit="celsius", raw=deg_el.text.strip(),
        ))
    return gauges


@register("panos")
class PanosCollector:
    """Collects CPU/mem + temps from a PAN-OS firewall via panos-mcp."""

    name = "panos"

    def __init__(self, device: str = "panosvm"):
        self.device = device

    def collect(self, client, now: str) -> list[Gauge]:
        resources = client.call_tool(
            "execute_pan_op",
            {"host": self.device,
             "cmd": "<show><system><resources></resources></system></show>"},
        )
        environmentals = client.call_tool(
            "execute_pan_op",
            {"host": self.device,
             "cmd": "<show><system><environmentals></environmentals></system></show>"},
        )
        return (parse_resources(resources, self.device, now)
                + parse_environmentals(environmentals, self.device, now))
```

> Add `defusedxml` to `pyproject.toml` dependencies (mirrors `services/topo`): in `services/health/pyproject.toml`, change the `dependencies` list to include `"defusedxml>=0.7"`.

- [ ] **Step 4: Add defusedxml dependency, run test to verify it passes**

Edit `services/health/pyproject.toml` `dependencies` to:

```toml
dependencies = [
    "clickhouse-connect>=0.8",
    "fastmcp>=2.0",
    "defusedxml>=0.7",
]
```

Run: `cd services/health && uv run pytest tests/test_panos.py -v`
Expected: PASS (4 passed)

- [ ] **Step 5: Commit**

```bash
git add services/health/src/ssdf_health/collectors/panos.py services/health/tests/test_panos.py services/health/pyproject.toml
git commit -m "feat(m13a): panos health collector (resources cpu/mem + environmentals temps)"
```

---

## Task 9: UniFi collector (system-stats CPU/mem + temperatures[]) + restore __init__

**Files:**
- Create: `services/health/src/ssdf_health/collectors/unifi.py`
- Modify: `services/health/src/ssdf_health/collectors/__init__.py` (restore the 4 imports)
- Test: `services/health/tests/test_unifi.py`

**Source paths:** enumerate device MACs from config (`UNIFI_DEVICE_MACS`); per MAC `get_device_by_mac(site_id, mac)` → `{"name", "system-stats": {"cpu": "23.1", "mem": "72.6"}, "temperatures": [{"name": "CPU", "value": 52.0}, ...]}`. cpu/mem are percent strings.

- [ ] **Step 1: Write the failing test**

Create `services/health/tests/test_unifi.py`:

```python
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
    assert "cpu_util_pct" not in names   # unparseable -> skipped
    assert "mem_util_pct" in names
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd services/health && uv run pytest tests/test_unifi.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write the implementation**

Create `services/health/src/ssdf_health/collectors/unifi.py`:

```python
"""UniFi health collector: per-device CPU%/mem% + multi-sensor temperatures."""

from __future__ import annotations

import json

from ..gauge import Gauge
from .base import register

_ENVELOPE_KEYS = ("result", "data", "device", "item")


def _obj(text: str) -> dict:
    data = json.loads(text)
    if isinstance(data, dict):
        for key in _ENVELOPE_KEYS:
            val = data.get(key)
            if isinstance(val, dict):
                return val
        return data
    return {}


def _pct_gauge(value_str, device, metric_class, metric_name) -> Gauge | None:
    try:
        value = float(value_str)
    except (TypeError, ValueError):
        return None
    return Gauge(
        provider="unifi", device=device, scope="device", metric_class=metric_class,
        sensor="", metric_name=metric_name, value=max(0.0, min(100.0, value)),
        unit="percent", raw=str(value_str),
    )


def parse_device(device_obj: dict, device: str, now: str) -> list[Gauge]:
    """Build CPU/mem + per-sensor temperature gauges from a get_device_by_mac dict."""
    gauges: list[Gauge] = []
    stats = device_obj.get("system-stats") or {}
    cpu = _pct_gauge(stats.get("cpu"), device, "cpu", "cpu_util_pct")
    if cpu:
        gauges.append(cpu)
    mem = _pct_gauge(stats.get("mem"), device, "memory", "mem_util_pct")
    if mem:
        gauges.append(mem)
    for temp in device_obj.get("temperatures") or []:
        try:
            value = float(temp.get("value"))
        except (TypeError, ValueError):
            continue
        gauges.append(Gauge(
            provider="unifi", device=device, scope="device",
            metric_class="temperature", sensor=str(temp.get("name") or ""),
            metric_name="temp_celsius", value=value, unit="celsius",
            raw=json.dumps(temp, default=str),
        ))
    return gauges


@register("unifi")
class UnifiCollector:
    """Collects CPU/mem + temps from UniFi devices (by MAC) via unifi-mcp."""

    name = "unifi"

    def __init__(self, macs: list[str] | None = None, site_id: str = "default"):
        self.macs = macs or []
        self.site_id = site_id

    def collect(self, client, now: str) -> list[Gauge]:
        gauges: list[Gauge] = []
        for mac in self.macs:
            device_obj = _obj(client.call_tool(
                "get_device_by_mac", {"site_id": self.site_id, "mac": mac},
            ))
            device = str(device_obj.get("name") or mac)
            gauges.extend(parse_device(device_obj, device, now))
        return gauges
```

- [ ] **Step 4: Restore the collectors package imports**

Replace `services/health/src/ssdf_health/collectors/__init__.py` (was empty) with:

```python
"""Importing this package registers every collector via @register decorators."""

from . import proxmox  # noqa: F401
from . import junos    # noqa: F401
from . import panos    # noqa: F401
from . import unifi    # noqa: F401
```

- [ ] **Step 5: Run the full collector suite to verify registration + all parsers pass**

Run: `cd services/health && uv run pytest tests/test_unifi.py tests/test_base.py tests/test_proxmox.py tests/test_junos.py tests/test_panos.py -v`
Expected: PASS (all collector tests green; importing `collectors` no longer errors)

- [ ] **Step 6: Commit**

```bash
git add services/health/src/ssdf_health/collectors/unifi.py services/health/src/ssdf_health/collectors/__init__.py services/health/tests/test_unifi.py
git commit -m "feat(m13a): unifi health collector (system-stats cpu/mem + temps) + register all"
```

---

## Task 10: HealthWriter (typed insert to ssdf.health_metrics)

**Files:**
- Create: `services/health/src/ssdf_health/chwriter.py`
- Test: `services/health/tests/test_chwriter.py`

**Note:** the writer stamps every gauge in a batch with the single poll `now` (a timezone-aware `datetime` for the `DateTime64(3,'UTC')` column). The `client_kwargs` TLS helper is copied from `services/topo/src/ssdf_topo/chwriter.py`.

- [ ] **Step 1: Write the failing test**

Create `services/health/tests/test_chwriter.py`:

```python
from datetime import datetime, timezone

from ssdf_health.config import Config
from ssdf_health.chwriter import client_kwargs, health_rows, HEALTH_COLUMNS
from ssdf_health.gauge import Gauge


def _config(**over):
    base = dict(
        ch_host="h", ch_port=8443, ch_user="ssdf_health", ch_password="p",
        ch_database="ssdf", tenant_id="t_main", enabled_collectors=("proxmox",),
        junos_devices=[], panos_device="panosvm", unifi_macs=[], unifi_site_id="default",
    )
    base.update(over)
    return Config(**base)


def test_client_kwargs_adds_tls_when_secure():
    kwargs = client_kwargs(_config(ch_secure=True, ch_ca_file="/ca.crt"))
    assert kwargs["interface"] == "https"
    assert kwargs["ca_cert"] == "/ca.crt"


def test_client_kwargs_plain_when_not_secure():
    kwargs = client_kwargs(_config())
    assert "interface" not in kwargs


def test_health_rows_maps_gauge_fields_in_column_order():
    now = datetime(2026, 6, 20, tzinfo=timezone.utc)
    gauge = Gauge("juniper", "vSRX-test10", "device", "cpu", "",
                  "cpu_util_pct", 5.0, "percent", "Idle 95 percent")
    rows = health_rows([gauge], now, "t_main")
    assert len(rows) == 1
    row = dict(zip(HEALTH_COLUMNS, rows[0]))
    assert row["timestamp"] == now
    assert row["tenant_id"] == "t_main"
    assert row["provider"] == "juniper"
    assert row["device"] == "vSRX-test10"
    assert row["scope"] == "device"
    assert row["metric_class"] == "cpu"
    assert row["sensor"] == ""
    assert row["metric_name"] == "cpu_util_pct"
    assert row["metric_value"] == 5.0
    assert row["unit"] == "percent"
    assert row["raw"] == "Idle 95 percent"


def test_health_rows_empty():
    assert health_rows([], datetime.now(timezone.utc), "t_main") == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd services/health && uv run pytest tests/test_chwriter.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'ssdf_health.chwriter'`

- [ ] **Step 3: Write the implementation**

Create `services/health/src/ssdf_health/chwriter.py`:

```python
"""ClickHouse writer for health gauges (the storage seam, write side)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Iterable

import clickhouse_connect

from .config import Config
from .gauge import Gauge

HEALTH_COLUMNS = [
    "timestamp", "tenant_id", "provider", "device", "scope",
    "metric_class", "sensor", "metric_name", "metric_value", "unit", "raw",
]


def client_kwargs(config: Config) -> dict[str, Any]:
    """get_client kwargs from config; adds TLS (interface/ca_cert) when ch_secure."""
    kwargs: dict[str, Any] = dict(
        host=config.ch_host, port=config.ch_port, username=config.ch_user,
        password=config.ch_password, database=config.ch_database,
    )
    if config.ch_secure:
        kwargs["interface"] = "https"
        if config.ch_ca_file:
            kwargs["ca_cert"] = config.ch_ca_file
    return kwargs


def health_rows(gauges: Iterable[Gauge], now: datetime, tenant_id: str) -> list[list[Any]]:
    """Stamp each gauge with the batch timestamp + tenant and order fields by column."""
    return [
        [now, tenant_id, g.provider, g.device, g.scope, g.metric_class,
         g.sensor, g.metric_name, g.value, g.unit, g.raw]
        for g in gauges
    ]


class HealthWriter:
    """Insert health gauges into ssdf.health_metrics as the ssdf_health user."""

    def __init__(self, config: Config):
        self._config = config
        self._client = clickhouse_connect.get_client(**client_kwargs(config))

    def insert_gauges(self, gauges: list[Gauge], now: datetime) -> int:
        if not gauges:
            return 0
        rows = health_rows(gauges, now, self._config.tenant_id)
        self._client.insert("ssdf.health_metrics", rows, column_names=HEALTH_COLUMNS)
        return len(gauges)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd services/health && uv run pytest tests/test_chwriter.py -v`
Expected: PASS (4 passed)

- [ ] **Step 5: Commit**

```bash
git add services/health/src/ssdf_health/chwriter.py services/health/tests/test_chwriter.py
git commit -m "feat(m13a): HealthWriter typed insert to ssdf.health_metrics"
```

---

## Task 11: collect_main entrypoint + live integration test

**Files:**
- Create: `services/health/src/ssdf_health/collect_main.py`
- Test: `services/health/tests/test_collect_main.py`
- Test: `services/health/tests/test_health_metrics_integration.py`

**Note:** `run_collectors` expects `writer.insert_gauges(gauges, now)`. The entrypoint computes a single timezone-aware `datetime` `now`, builds per-collector instances (passing device lists from config), and uses `McpToolClient` per endpoint. `run_collectors` (Task 5) currently passes a `now` string into `insert_gauges`; the writer's `insert_gauges` takes a `datetime`. Reconcile by having `collect_main` pass a `datetime` as `now` through `run_collectors` (it is opaque to `run_collectors`, only forwarded to `insert_gauges`). Update the `test_base.py` fake writer already accepts any `now` — no change needed.

- [ ] **Step 1: Write the failing unit test**

Create `services/health/tests/test_collect_main.py`:

```python
from datetime import datetime, timezone

from ssdf_health import collect_main
from ssdf_health.config import Config
from ssdf_health.gauge import Gauge


def _config(**over):
    base = dict(
        ch_host="h", ch_port=8443, ch_user="ssdf_health", ch_password="p",
        ch_database="ssdf", tenant_id="t_main",
        enabled_collectors=("junos", "panos", "unifi", "proxmox"),
        junos_devices=["vSRX-test10"], panos_device="panosvm",
        unifi_macs=["aa:bb:cc:dd:ee:ff"], unifi_site_id="default",
    )
    base.update(over)
    return Config(**base)


def test_build_collector_passes_device_config():
    config = _config()
    junos = collect_main.build_collector("junos", config)
    assert junos.devices == ["vSRX-test10"]
    panos = collect_main.build_collector("panos", config)
    assert panos.device == "panosvm"
    unifi = collect_main.build_collector("unifi", config)
    assert unifi.macs == ["aa:bb:cc:dd:ee:ff"]
    assert unifi.site_id == "default"
    proxmox = collect_main.build_collector("proxmox", config)
    assert proxmox.name == "proxmox"


def test_run_with_fakes_writes_all_gauges():
    config = _config(enabled_collectors=("fake",))

    class _Fake:
        name = "fake"
        def collect(self, client, now):
            return [Gauge("p", "d", "device", "cpu", "", "cpu_util_pct",
                          1.0, "percent", "")]

    captured = []

    class _Writer:
        def insert_gauges(self, gauges, now):
            captured.extend(gauges)
            return len(gauges)

    total = collect_main.run(
        config,
        client_factory=lambda name: None,
        collector_factory=lambda name: _Fake(),
        writer=_Writer(),
        now=datetime(2026, 6, 20, tzinfo=timezone.utc),
    )
    assert total == 1
    assert captured[0].metric_name == "cpu_util_pct"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd services/health && uv run pytest tests/test_collect_main.py -v`
Expected: FAIL with `AttributeError`/`ImportError` (collect_main has no `build_collector`/`run`)

- [ ] **Step 3: Write the implementation**

Create `services/health/src/ssdf_health/collect_main.py`:

```python
"""Entrypoint: run all enabled health collectors and insert gauges into ClickHouse."""

from __future__ import annotations

import datetime
import logging

from .chwriter import HealthWriter
from . import collectors  # noqa: F401 — triggers @register for all collectors
from .collectors.base import REGISTRY, run_collectors
from .config import Config, load_config
from .mcp_client import McpToolClient

logger = logging.getLogger(__name__)


def _now() -> datetime.datetime:
    """Current UTC time as a timezone-aware datetime (for the DateTime64 column)."""
    return datetime.datetime.now(datetime.timezone.utc)


def build_collector(name: str, config: Config):
    """Instantiate the named collector, passing device config from `config`."""
    cls = REGISTRY[name]
    if name == "junos":
        return cls(devices=config.junos_devices)
    if name == "panos":
        return cls(device=config.panos_device)
    if name == "unifi":
        return cls(macs=config.unifi_macs, site_id=config.unifi_site_id)
    return cls()


def run(config: Config, client_factory, collector_factory, writer, now) -> int:
    """Run all enabled collectors against the given factories/writer; return total written."""
    return run_collectors(
        enabled=config.enabled_collectors,
        client_factory=client_factory,
        collector_factory=collector_factory,
        writer=writer,
        now=now,
    )


def main() -> None:
    """Load config, run all enabled collectors, log the total inserted count."""
    logging.basicConfig(level=logging.INFO)
    config = load_config()
    writer = HealthWriter(config)
    total = run(
        config,
        client_factory=lambda name: McpToolClient(config.mcp_endpoint(name)),
        collector_factory=lambda name: build_collector(name, config),
        writer=writer,
        now=_now(),
    )
    logger.info("collect_main: inserted %d health gauges", total)


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run unit test to verify it passes**

Run: `cd services/health && uv run pytest tests/test_collect_main.py -v`
Expected: PASS (2 passed)

- [ ] **Step 5: Write the live integration test**

Create `services/health/tests/test_health_metrics_integration.py`:

```python
"""Live integration: a real poll cycle writes valid rows to ssdf.health_metrics.

Run: cd services/health && CH_HOST=<ip> CH_PORT=8443 CH_SECURE=1 CH_CA_FILE=... \
  CH_USER=ssdf_health CH_PASSWORD=<pw> \
  JUNOS_MCP_URL=... JUNOS_MCP_TOKEN=... JUNOS_DEVICES=vSRX-test10 \
  PANOS_MCP_URL=... PANOS_MCP_TOKEN=... PANOS_DEVICE=panosvm \
  PROXMOX_MCP_URL=... PROXMOX_MCP_TOKEN=... \
  UNIFI_MCP_URL=... UNIFI_MCP_TOKEN=... UNIFI_DEVICE_MACS=<mac> \
  uv run pytest tests/test_health_metrics_integration.py -m integration -v
"""

from __future__ import annotations

import os

import pytest

from ssdf_health.chwriter import HealthWriter, client_kwargs
from ssdf_health.collect_main import _now, build_collector, run
from ssdf_health.config import load_config
from ssdf_health.mcp_client import McpToolClient

import clickhouse_connect

pytestmark = pytest.mark.integration


def _require(*names):
    missing = [n for n in names if not os.environ.get(n)]
    if missing:
        pytest.skip(f"missing env: {', '.join(missing)}")


def test_live_poll_writes_valid_rows():
    _require("CH_HOST", "CH_PASSWORD")
    config = load_config()
    writer = HealthWriter(config)
    total = run(
        config,
        client_factory=lambda name: McpToolClient(config.mcp_endpoint(name)),
        collector_factory=lambda name: build_collector(name, config),
        writer=writer,
        now=_now(),
    )
    assert total > 0, "expected at least one gauge from a live poll"

    ro = clickhouse_connect.get_client(**client_kwargs(config))
    result = ro.query(
        "SELECT metric_name, unit, metric_value FROM ssdf.health_metrics "
        "WHERE metric_name = 'cpu_util_pct' ORDER BY timestamp DESC LIMIT 5"
    )
    assert result.result_rows, "no cpu_util_pct rows landed"
    for _name, unit, value in result.result_rows:
        assert unit == "percent"
        assert 0.0 <= float(value) <= 100.0
```

- [ ] **Step 6: Run the full non-integration suite**

Run: `cd services/health && uv run pytest -m "not integration" -v`
Expected: PASS (all unit tests across all modules green)

- [ ] **Step 7: Commit**

```bash
git add services/health/src/ssdf_health/collect_main.py services/health/tests/test_collect_main.py services/health/tests/test_health_metrics_integration.py
git commit -m "feat(m13a): collect_main entrypoint + live health_metrics integration test"
```

---

## Task 12: systemd units + ENV.local.example

**Files:**
- Create: `services/health/infra/ssdf-health.service`
- Create: `services/health/infra/ssdf-health.timer`
- Create: `services/health/infra/ENV.local.example`

These mirror `services/public-metrics/infra/*` (the proven ct109 hardening subset). NOT applied here — deployment is an operator step recorded in Task 13's CLAUDE.md block.

- [ ] **Step 1: Create the service unit**

Create `services/health/infra/ssdf-health.service`:

```ini
[Unit]
Description=SSDF M13a health poller (host/device CPU/mem/temperature -> ssdf.health_metrics)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
DynamicUser=yes
EnvironmentFile=/etc/ssdf-health/ENV.local
WorkingDirectory=/opt/ssdf-health
ExecStart=/opt/ssdf-health/bin/python -m ssdf_health.collect_main
# hardening (subset proven to work in the unprivileged LXC on ct109 — matches the
# sibling ssdf-topo/entity/policy/public-metrics units)
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
CapabilityBoundingSet=
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
LockPersonality=yes
MemoryDenyWriteExecute=yes
```

- [ ] **Step 2: Create the timer unit**

Create `services/health/infra/ssdf-health.timer`:

```ini
[Unit]
Description=Run SSDF health poller every 5 minutes

[Timer]
OnBootSec=4min
OnUnitActiveSec=5min
AccuracySec=30s
Persistent=true

[Install]
WantedBy=timers.target
```

- [ ] **Step 3: Create the env example**

Create `services/health/infra/ENV.local.example`:

```bash
# /etc/ssdf-health/ENV.local (mode 600) — M13a health poller config on ct109.
# ClickHouse (TLS to ct104)
CH_HOST=198.51.100.151
CH_PORT=8443
CH_SECURE=1
CH_CA_FILE=/opt/ssdf-health/ssdf-ca.crt
CH_USER=ssdf_health
CH_PASSWORD=__set_me__
CH_DATABASE=ssdf

# Which collectors run (default: all four)
HEALTH_COLLECTORS=proxmox,junos,panos,unifi
HEALTH_TENANT=t_main

# Cadence is set by the systemd timer (OnUnitActiveSec). Per-vendor cadence is a
# future TODO; today all collectors share the one timer.

# Junos (rust-junosmcp) — same device names topo/policy use
JUNOS_MCP_URL=http://198.51.100.194:30031/mcp
JUNOS_MCP_TOKEN=__set_me__
JUNOS_DEVICES=vSRX-test10,vSRX-Production

# PAN-OS (panos-mcp)
PANOS_MCP_URL=__set_me__
PANOS_MCP_TOKEN=__set_me__
PANOS_DEVICE=panosvm

# Proxmox (proxmox-mcp)
PROXMOX_MCP_URL=__set_me__
PROXMOX_MCP_TOKEN=__set_me__

# UniFi (unifi-mcp) — device MACs to poll via get_device_by_mac
UNIFI_MCP_URL=__set_me__
UNIFI_MCP_TOKEN=__set_me__
UNIFI_SITE_ID=default
UNIFI_DEVICE_MACS=__set_me__
```

- [ ] **Step 4: Commit**

```bash
git add services/health/infra/ssdf-health.service services/health/infra/ssdf-health.timer services/health/infra/ENV.local.example
git commit -m "feat(m13a): systemd unit/timer + ENV.local example for ct109 health poller"
```

---

## Task 13: M7c seam comment + CLAUDE.md + STATUS.md docs

**Files:**
- Modify: `services/public-metrics/src/ssdf_pubmetrics/measures.py` (comment only)
- Modify: `CLAUDE.md`
- Modify: `docs/superpowers/STATUS.md`

- [ ] **Step 1: Update the M7c catalog seam comment**

In `services/public-metrics/src/ssdf_pubmetrics/measures.py`, change the Tier-3 comment block (currently lines ~45-50) so the placeholders record their new source. Replace:

```python
	# Tier 3 — operational health, gated on M13 ingest (disabled placeholders)
```

with:

```python
	# Tier 3 — operational health (disabled placeholders). M13a now lands the
	# source data in ssdf.health_metrics (NOT ssdf.events); flipping these to
	# enabled + adding a health-table AGG_VALUE_EXPR branch + the pseudonym
	# pipeline is the M13a -> public-metrics follow-on, deliberately deferred.
```

(No code/behavior change — `enabled=False` stays; this is the documented seam.)

- [ ] **Step 2: Verify the comment edit did not change behavior**

Run: `cd services/public-metrics && uv run pytest -m "not integration" -q`
Expected: PASS (unchanged count — comment-only edit)

- [ ] **Step 3: Add the M13a commands block to CLAUDE.md**

In `CLAUDE.md`, after the `### M7c (...)` section, add:

```markdown
### M13a (host resource-pressure ingest — services/health → ssdf.health_metrics)
- SSDF's first **operational-health** source: host/device CPU%/mem% + multi-sensor
  temperature across Proxmox (node+guests), vSRX/Junos, PAN-OS, UniFi — all via existing
  vendor MCP op-commands (NO SNMP, no device-side log enablement). A 5th ct109 poller role.
- Unit tests: `cd services/health && uv run pytest -m "not integration"`; live:
  `CH_HOST=… CH_PORT=8443 CH_SECURE=1 CH_CA_FILE=… CH_USER=ssdf_health CH_PASSWORD=<pw>
  JUNOS_MCP_URL=… JUNOS_MCP_TOKEN=… JUNOS_DEVICES=… PANOS_MCP_URL=… PANOS_MCP_TOKEN=…
  PROXMOX_MCP_URL=… UNIFI_MCP_URL=… UNIFI_DEVICE_MACS=… uv run pytest -m integration`.
- One pass: `cd services/health && uv run python -m ssdf_health.collect_main`.
- Apply migrations: `HEALTH_TTL_DAYS=30 envsubst < infra/clickhouse/014_health_metrics.sql
  | clickhouse-client --host <ct104> --multiquery`; `HEALTH_PW=<pw> envsubst <
  infra/clickhouse/015_health_user.sql | clickhouse-client --multiquery`.
- **Storage:** new EAV-style table `ssdf.health_metrics` (one row per device/metric/sensor/
  timestamp) — `metric_class` (cpu|memory|temperature) + `sensor` are the two discovery
  axes, so a new sensor lands as new rows with NO schema change. Typed `metric_value Float64`
  (NOT the ext Map) so M7c's catalog can aggregate it. TTL 30d default (`HEALTH_TTL_DAYS`).
- **Collectors (`services/health`, mirrors services/topo):** `Gauge` normalized unit; thin
  per-vendor modules (proxmox/junos/panos/unifi) each return `list[Gauge]`; `run_collectors`
  catches+skips a failing collector (one flaky MCP can't zero the pass). Device names match
  topo/policy so a future health↔topology join bridges by name.
- **Per-vendor paths:** Proxmox `get_node_status`/`get_vms`/`get_containers` (cpu fraction →
  %); Junos `show chassis routing-engine` (mem %, cpu=100−idle) + `show chassis environment`
  (per-sensor temps); PAN-OS `<show><system><resources>` (top idle/MiB Mem) +
  `<environmentals>` (thermal entries); UniFi `get_device_by_mac` `system-stats.cpu/.mem` +
  `temperatures[]` (the legacy stat path — integration `get_device_statistics` returns null).
- **Sovereign-only:** queryable immediately via the generic `run_sql`/`describe_schema`
  tools (M11 precedent — no new MCP tool). Public de-id exposure + flipping the M7c
  `mem_util_pct`/`cpu_util_pct` placeholders + the `honesty-device-metrics` eval update are
  deliberate follow-ons (NOT M13a). **Live dependency:** panosvm VMID 900 stopped ⇒ panos
  health rows go stale (flag the operator; do not start/stop VMID 900).
- Deploy: rsync `services/health` to ct109 venv `/opt/ssdf-health`, env
  `/etc/ssdf-health/ENV.local` (mode 600), install `ssdf-health.{service,timer}`, enable timer.
```

- [ ] **Step 4: Add the M13a entry to STATUS.md**

In `docs/superpowers/STATUS.md`, update "Last updated:" to `2026-06-20` and add a milestone-ledger bullet:

```markdown
- **M13a — host resource-pressure ingest** 🔨 Built (code + tests; pending deploy + live
  proof on ct109). First operational-health source: CPU%/mem%/temperature across Proxmox,
  vSRX, PAN-OS, UniFi via existing MCP op-commands (no SNMP). New EAV-style
  `ssdf.health_metrics` table (migration 014) + `ssdf_health` user (015); `services/health`
  poller (5th ct109 role). Sovereign-only (run_sql); public de-id + M7c catalog flip +
  honesty-device-metrics eval update deferred as follow-ons.
```

- [ ] **Step 5: Verify the docs edits**

Run: `grep -c "M13a" CLAUDE.md docs/superpowers/STATUS.md`
Expected: both non-zero.

- [ ] **Step 6: Commit**

```bash
git add services/public-metrics/src/ssdf_pubmetrics/measures.py CLAUDE.md docs/superpowers/STATUS.md
git commit -m "docs(m13a): record health-ingest commands, M7c seam, STATUS entry"
```

---

## Final verification (after all tasks)

- [ ] **Run the complete unit suite**

Run: `cd services/health && uv run pytest -m "not integration" -v`
Expected: PASS (all modules green)

- [ ] **Confirm no placeholder/registration regressions**

Run: `cd services/health && uv run python -c "from ssdf_health import collectors; from ssdf_health.collectors.base import REGISTRY; print(sorted(REGISTRY))"`
Expected: `['junos', 'panos', 'proxmox', 'unifi']`

- [ ] **Deploy + live proof (operator step, follow the CLAUDE.md M13a block):** apply
  migrations 014/015 on ct104, rsync `services/health` to ct109, set
  `/etc/ssdf-health/ENV.local`, enable `ssdf-health.timer`, then run the integration test
  and confirm `SELECT count() FROM ssdf.health_metrics` is non-zero with
  `cpu_util_pct ∈ [0,100]`.
```
