# SSDF M4 — Phase 3: Collectors

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development or superpowers:executing-plans. Prerequisite: Phases 0–2 of `2026-06-07-ssdf-m4-topology-graph.md` complete (schema, models, config, chwriter, mcp_client, collector base).

**Goal:** Four read-only collectors (junos, unifi, panos, proxmox) that pull L2/L3 state via the deployed MCPs and emit normalized `Observation`s into `ssdf.topo_observations`.

**Critical method — fixture-first:** MCP tool output shapes are not fully known until observed. For each collector: **(a)** capture the real tool output into `tests/fixtures/<name>_<cmd>.json` from the live MCP, **(b)** write the parser test from that captured fixture, **(c)** implement the parser to satisfy it. The sample payloads below are representative; **if a captured fixture differs, the fixture is authoritative — adjust field paths so the test (built from the real fixture) passes.** Never weaken a test to match a buggy parser; fix the parser.

All collectors call only `show`/GET tools — the read-only boundary holds.

**MCP endpoints (set in env for capture):**
- `JUNOS_MCP_URL=http://198.51.100.194:30031/mcp`, `JUNOS_MCP_TOKEN=<bearer>`
- `UNIFI_MCP_URL=<unifi-mcp ct603 url>`, `UNIFI_MCP_TOKEN=<bearer>`
- `PANOS_MCP_URL=http://198.51.100.199:.../mcp`, `PANOS_MCP_TOKEN=<bearer>`
- `PROXMOX_MCP_URL=<proxmox-mcp ct604 url>`, `PROXMOX_MCP_TOKEN=<bearer>`

---

## Task 3.1: Junos collector — capture fixtures

**Files:**
- Create: `services/topo/tests/fixtures/junos_lldp_neighbors.json`
- Create: `services/topo/tests/fixtures/junos_eth_switching_table.json`
- Create: `services/topo/tests/fixtures/junos_arp.json`
- Create: `services/topo/scripts/capture_junos.py`

- [ ] **Step 1: Write the capture helper**

```python
# services/topo/scripts/capture_junos.py
"""One-off: capture real junos-mcp tool output into tests/fixtures/. Read-only."""
import json, pathlib, sys
from ssdf_topo.config import McpEndpoint
from ssdf_topo.mcp_client import McpToolClient
import os

FIX = pathlib.Path(__file__).resolve().parent.parent / "tests" / "fixtures"
DEVICE = sys.argv[1] if len(sys.argv) > 1 else "vSRX-test10"
ep = McpEndpoint(url=os.environ["JUNOS_MCP_URL"], token=os.environ.get("JUNOS_MCP_TOKEN", ""))
client = McpToolClient(ep)
cmds = {
    "junos_lldp_neighbors": "show lldp neighbors | display json",
    "junos_eth_switching_table": "show ethernet-switching table | display json",
    "junos_arp": "show arp no-resolve | display json",
}
for fname, cmd in cmds.items():
    text = client.call_tool("execute_junos_command", {"router": DEVICE, "command": cmd})
    (FIX / f"{fname}.json").write_text(text, encoding="utf-8")
    print(f"wrote {fname}.json ({len(text)} bytes)")
```

- [ ] **Step 2: Run capture against the live MCP**

Run: `cd services/topo && JUNOS_MCP_URL=... JUNOS_MCP_TOKEN=... uv run python scripts/capture_junos.py vSRX-test10`
Expected: three fixture files written. **Inspect each** — note the exact JSON key path to the neighbor list, MAC table, and ARP entries. (Junos wraps replies like `{"lldp-neighbors-information":[{"lldp-neighbor-information":[...]}]}`; the `execute_junos_command` MCP may further wrap in its own envelope. The fixture is authoritative.)

- [ ] **Step 3: Commit fixtures**

```bash
git add services/topo/tests/fixtures/junos_*.json services/topo/scripts/capture_junos.py
git commit -m "test(m4): capture live junos-mcp topology fixtures"
```

## Task 3.2: Junos collector — parser

**Files:**
- Create: `services/topo/src/ssdf_topo/collectors/junos.py`
- Test: `services/topo/tests/test_collector_junos.py`

- [ ] **Step 1: Write the failing test** (build assertions from the *captured* fixtures; the inline samples below show the expected normalized output — adapt the input-loading to the real fixture key paths)

```python
# tests/test_collector_junos.py
import json, pathlib
from ssdf_topo.collectors.junos import (
    parse_lldp_neighbors, parse_mac_table, parse_arp,
)
from ssdf_topo.models import PHYSICAL_LINK, ATTACHES_TO, HAS_ADDRESS

FIX = pathlib.Path(__file__).parent / "fixtures"

def test_parse_lldp_neighbors_emits_physical_link():
    text = (FIX / "junos_lldp_neighbors.json").read_text()
    obs = parse_lldp_neighbors(text, source_device="vSRX-test10", now="2026-06-07T00:00:00+00:00")
    assert obs, "expected at least one lldp neighbor"
    o = obs[0]
    assert o.collector == "junos" and o.observation_type == "lldp_neighbor"
    assert o.layer == "l2" and o.subj_kind == "interface" and o.obj_kind == "interface"
    # local + remote port captured in attrs
    assert "local_port" in o.attrs and "remote_port" in o.attrs

def test_parse_mac_table_emits_attaches_to():
    text = (FIX / "junos_eth_switching_table.json").read_text()
    obs = parse_mac_table(text, source_device="vSRX-test10", now="2026-06-07T00:00:00+00:00")
    assert obs
    o = obs[0]
    assert o.observation_type == "mac_entry" and o.subj_kind == "host"
    assert o.subj_id.startswith("mac:")
    assert "vlan" in o.attrs and "port" in o.attrs

def test_parse_arp_emits_has_address():
    text = (FIX / "junos_arp.json").read_text()
    obs = parse_arp(text, source_device="vSRX-test10", now="2026-06-07T00:00:00+00:00")
    assert obs
    o = obs[0]
    assert o.observation_type == "arp_entry" and o.layer == "l3"
    assert o.subj_id.startswith("ip:") and o.obj_id.startswith("mac:")
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd services/topo && uv run pytest tests/test_collector_junos.py -v`
Expected: FAIL (ImportError)

- [ ] **Step 3: Implement junos.py** (reconcile `_dig` paths against the captured fixtures)

```python
# src/ssdf_topo/collectors/junos.py
"""Junos collector: LLDP neighbors, ethernet-switching MAC table, ARP (read-only)."""

from __future__ import annotations

import json
from typing import Any

from .base import Collector, register
from ..mcp_client import McpToolClient
from ..models import Observation


def _loads(text: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {}


def _first_list(node: Any, key: str) -> list[dict]:
    """Junos JSON wraps lists as [{...}] under hyphenated keys; dig to the inner list."""
    if isinstance(node, dict):
        if key in node:
            val = node[key]
            return val if isinstance(val, list) else [val]
        for v in node.values():
            found = _first_list(v, key)
            if found:
                return found
    if isinstance(node, list):
        for item in node:
            found = _first_list(item, key)
            if found:
                return found
    return []


def _txt(entry: dict, key: str) -> str:
    """Junos JSON leaf values are often [{"data": "..."}]; normalize to str."""
    val = entry.get(key)
    if isinstance(val, list) and val and isinstance(val[0], dict):
        return str(val[0].get("data", "")).strip()
    if isinstance(val, dict):
        return str(val.get("data", "")).strip()
    return str(val or "").strip()


def parse_lldp_neighbors(text: str, source_device: str, now: str) -> list[Observation]:
    data = _loads(text)
    out: list[Observation] = []
    for n in _first_list(data, "lldp-neighbor-information"):
        local = _txt(n, "lldp-local-port-id") or _txt(n, "lldp-local-interface")
        remote_sys = _txt(n, "lldp-remote-system-name")
        remote_port = _txt(n, "lldp-remote-port-id")
        if not (local and remote_sys):
            continue
        out.append(Observation(
            observed_at=now, collector="junos", source_device=source_device,
            layer="l2", observation_type="lldp_neighbor",
            subj_kind="interface", subj_id=f"if:{source_device}:{local}",
            obj_kind="interface", obj_id=f"if:{remote_sys}:{remote_port}",
            attrs={"local_port": local, "remote_port": remote_port,
                   "remote_system": remote_sys},
            raw=json.dumps(n, default=str),
        ))
    return out


def parse_mac_table(text: str, source_device: str, now: str) -> list[Observation]:
    data = _loads(text)
    out: list[Observation] = []
    # key varies by platform: l2ng (newer) vs mac-table-entry (older)
    entries = (_first_list(data, "l2ng-mac-entry")
               or _first_list(data, "mac-table-entry"))
    for e in entries:
        mac = (_txt(e, "l2ng-l2-mac-address") or _txt(e, "mac-address")).lower()
        vlan = _txt(e, "l2ng-l2-vlan-name") or _txt(e, "mac-vlan")
        port = _txt(e, "l2ng-l2-mac-logical-interface") or _txt(e, "mac-interfaces-list")
        if not mac:
            continue
        out.append(Observation(
            observed_at=now, collector="junos", source_device=source_device,
            layer="l2", observation_type="mac_entry",
            subj_kind="host", subj_id=f"mac:{mac}",
            obj_kind="device", obj_id=f"device:{source_device}",
            attrs={"vlan": vlan, "port": port},
            raw=json.dumps(e, default=str),
        ))
    return out


def parse_arp(text: str, source_device: str, now: str) -> list[Observation]:
    data = _loads(text)
    out: list[Observation] = []
    for e in _first_list(data, "arp-table-entry"):
        ip = _txt(e, "ip-address")
        mac = _txt(e, "mac-address").lower()
        iface = _txt(e, "interface-name")
        if not (ip and mac):
            continue
        out.append(Observation(
            observed_at=now, collector="junos", source_device=source_device,
            layer="l3", observation_type="arp_entry",
            subj_kind="host", subj_id=f"ip:{ip}",
            obj_kind="host", obj_id=f"mac:{mac}",
            attrs={"interface": iface},
            raw=json.dumps(e, default=str),
        ))
    return out


@register("junos")
class JunosCollector(Collector):
    name = "junos"
    devices: list[str] = []  # set from config/env at collect time

    def __init__(self, devices: list[str] | None = None):
        self.devices = devices or []

    def collect(self, client: McpToolClient, now: str) -> list[Observation]:
        out: list[Observation] = []
        for dev in self.devices:
            lldp = client.call_tool("execute_junos_command",
                                    {"router": dev, "command": "show lldp neighbors | display json"})
            out += parse_lldp_neighbors(lldp, dev, now)
            mac = client.call_tool("execute_junos_command",
                                   {"router": dev, "command": "show ethernet-switching table | display json"})
            out += parse_mac_table(mac, dev, now)
            arp = client.call_tool("execute_junos_command",
                                   {"router": dev, "command": "show arp no-resolve | display json"})
            out += parse_arp(arp, dev, now)
        return out
```

- [ ] **Step 4: Run to verify it passes** (reconcile `_dig`/key paths to the captured fixtures until green)

Run: `cd services/topo && uv run pytest tests/test_collector_junos.py -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add services/topo/src/ssdf_topo/collectors/junos.py services/topo/tests/test_collector_junos.py
git commit -m "feat(m4): junos topology collector (lldp/mac/arp)"
```

## Task 3.3: UniFi collector

**Files:**
- Create: `services/topo/tests/fixtures/unifi_active_clients.json`
- Create: `services/topo/tests/fixtures/unifi_devices.json`
- Create: `services/topo/src/ssdf_topo/collectors/unifi.py`
- Test: `services/topo/tests/test_collector_unifi.py`

- [ ] **Step 1: Capture fixtures from live unifi-mcp**

Use a capture snippet (mirror `capture_junos.py`) calling `list_active_clients` and `list_devices_by_type` (or `get_site_inventory`). Save raw JSON text to the two fixture files. **Inspect** for the client fields: `mac`, `ip`, `network`/`vlan`, `uplink`/`sw_mac`/`sw_port` or `ap_mac`. The fixture is authoritative.

- [ ] **Step 2: Write the failing test**

```python
# tests/test_collector_unifi.py
import pathlib
from ssdf_topo.collectors.unifi import parse_clients, parse_devices

FIX = pathlib.Path(__file__).parent / "fixtures"

def test_parse_clients_emits_attach_and_address():
    text = (FIX / "unifi_active_clients.json").read_text()
    obs = parse_clients(text, source_device="unifi-site", now="2026-06-07T00:00:00+00:00")
    types = {o.observation_type for o in obs}
    assert "mac_entry" in types          # client attached to switch/AP port
    assert "arp_entry" in types          # client mac<->ip
    mac_obs = next(o for o in obs if o.observation_type == "mac_entry")
    assert mac_obs.subj_id.startswith("mac:") and "port" in mac_obs.attrs

def test_parse_devices_emits_inventory():
    text = (FIX / "unifi_devices.json").read_text()
    obs = parse_devices(text, source_device="unifi-site", now="2026-06-07T00:00:00+00:00")
    assert obs and obs[0].observation_type == "device_inventory"
    assert obs[0].subj_kind == "device" and "role" in obs[0].attrs
```

- [ ] **Step 3: Run to verify it fails**

Run: `cd services/topo && uv run pytest tests/test_collector_unifi.py -v`
Expected: FAIL (ImportError)

- [ ] **Step 4: Implement unifi.py** (UniFi tools return structured JSON; field names per the captured fixture)

```python
# src/ssdf_topo/collectors/unifi.py
"""UniFi collector: active clients (attach + address) + device inventory (read-only)."""

from __future__ import annotations

import json
from typing import Any

from .base import Collector, register
from ..mcp_client import McpToolClient
from ..models import Observation


def _rows(text: str) -> list[dict]:
    data = json.loads(text) if text.strip() else {}
    if isinstance(data, dict):
        for key in ("result", "data", "clients", "devices", "items"):
            if isinstance(data.get(key), list):
                return data[key]
        return [data]
    return data if isinstance(data, list) else []


def parse_clients(text: str, source_device: str, now: str) -> list[Observation]:
    out: list[Observation] = []
    for c in _rows(text):
        mac = str(c.get("mac", "")).lower()
        ip = str(c.get("ip", "") or c.get("last_ip", ""))
        vlan = str(c.get("vlan", "") or c.get("network_id", ""))
        is_wired = bool(c.get("is_wired", True))
        sw_mac = str(c.get("sw_mac", "") or c.get("ap_mac", ""))
        sw_port = str(c.get("sw_port", "") or c.get("channel", ""))
        if not mac:
            continue
        out.append(Observation(
            observed_at=now, collector="unifi", source_device=source_device,
            layer="l2",
            observation_type="mac_entry" if is_wired else "wlan_assoc",
            subj_kind="host", subj_id=f"mac:{mac}",
            obj_kind="device", obj_id=f"device:{sw_mac or source_device}",
            attrs={"vlan": vlan, "port": sw_port, "wired": str(is_wired)},
            raw=json.dumps(c, default=str),
        ))
        if ip:
            out.append(Observation(
                observed_at=now, collector="unifi", source_device=source_device,
                layer="l3", observation_type="arp_entry",
                subj_kind="host", subj_id=f"ip:{ip}",
                obj_kind="host", obj_id=f"mac:{mac}",
                attrs={"source": "unifi_client"},
                raw="",
            ))
    return out


def parse_devices(text: str, source_device: str, now: str) -> list[Observation]:
    out: list[Observation] = []
    role_map = {"usw": "switch", "uap": "ap", "ugw": "router", "udm": "router"}
    for d in _rows(text):
        mac = str(d.get("mac", "")).lower()
        model = str(d.get("type", "") or d.get("model", "")).lower()
        name = str(d.get("name", "") or d.get("model", ""))
        if not mac:
            continue
        role = next((r for k, r in role_map.items() if k in model), "device")
        out.append(Observation(
            observed_at=now, collector="unifi", source_device=source_device,
            layer="l2", observation_type="device_inventory",
            subj_kind="device", subj_id=f"device:{mac}",
            obj_kind="", obj_id="",
            attrs={"role": role, "name": name, "mac": mac,
                   "ip": str(d.get("ip", ""))},
            raw=json.dumps(d, default=str),
        ))
    return out


@register("unifi")
class UnifiCollector(Collector):
    name = "unifi"

    def collect(self, client: McpToolClient, now: str) -> list[Observation]:
        devices = client.call_tool("list_devices_by_type", {})
        clients = client.call_tool("list_active_clients", {})
        return parse_devices(devices, "unifi-site", now) + parse_clients(clients, "unifi-site", now)
```

- [ ] **Step 5: Run to verify it passes**

Run: `cd services/topo && uv run pytest tests/test_collector_unifi.py -v`
Expected: PASS (2 tests)

- [ ] **Step 6: Commit**

```bash
git add services/topo/src/ssdf_topo/collectors/unifi.py services/topo/tests/test_collector_unifi.py services/topo/tests/fixtures/unifi_*.json
git commit -m "feat(m4): unifi topology collector (clients + device inventory)"
```

## Task 3.4: PAN-OS collector

**Files:**
- Create: `services/topo/tests/fixtures/panos_lldp.xml`
- Create: `services/topo/tests/fixtures/panos_arp.xml`
- Create: `services/topo/src/ssdf_topo/collectors/panos.py`
- Test: `services/topo/tests/test_collector_panos.py`

- [ ] **Step 1: Capture fixtures from live panos-mcp**

Capture via `execute_pan_op` for `<show><lldp><neighbors></neighbors></lldp></show>` and `<show><arp><entry name='all'/></arp></show>`. Save the XML text. **Inspect** the element paths (`<result><entry>...`). Fixture is authoritative.

- [ ] **Step 2: Write the failing test**

```python
# tests/test_collector_panos.py
import pathlib
from ssdf_topo.collectors.panos import parse_lldp_xml, parse_arp_xml

FIX = pathlib.Path(__file__).parent / "fixtures"

def test_parse_lldp_xml():
    text = (FIX / "panos_lldp.xml").read_text()
    obs = parse_lldp_xml(text, source_device="panosvm", now="2026-06-07T00:00:00+00:00")
    assert obs and obs[0].observation_type == "lldp_neighbor"
    assert "local_port" in obs[0].attrs

def test_parse_arp_xml():
    text = (FIX / "panos_arp.xml").read_text()
    obs = parse_arp_xml(text, source_device="panosvm", now="2026-06-07T00:00:00+00:00")
    assert obs and obs[0].observation_type == "arp_entry"
    assert obs[0].subj_id.startswith("ip:") and obs[0].obj_id.startswith("mac:")
```

- [ ] **Step 3: Run to verify it fails**

Run: `cd services/topo && uv run pytest tests/test_collector_panos.py -v`
Expected: FAIL (ImportError)

- [ ] **Step 4: Implement panos.py** (stdlib `xml.etree`; reconcile tag paths to fixtures)

```python
# src/ssdf_topo/collectors/panos.py
"""PAN-OS collector: LLDP neighbors + ARP via execute_pan_op (XML, read-only)."""

from __future__ import annotations

import xml.etree.ElementTree as ET

from .base import Collector, register
from ..mcp_client import McpToolClient
from ..models import Observation


def _entries(text: str) -> list[ET.Element]:
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []
    # results live under .//result//entry across PAN-OS op replies
    return root.findall(".//entry")


def _f(entry: ET.Element, tag: str) -> str:
    el = entry.find(tag)
    return (el.text or "").strip() if el is not None and el.text else ""


def parse_lldp_xml(text: str, source_device: str, now: str) -> list[Observation]:
    out: list[Observation] = []
    for e in _entries(text):
        local = _f(e, "local-port") or e.get("name", "")
        remote_sys = _f(e, "system-name")
        remote_port = _f(e, "port-id") or _f(e, "port-description")
        if not (local and (remote_sys or remote_port)):
            continue
        out.append(Observation(
            observed_at=now, collector="panos", source_device=source_device,
            layer="l2", observation_type="lldp_neighbor",
            subj_kind="interface", subj_id=f"if:{source_device}:{local}",
            obj_kind="interface", obj_id=f"if:{remote_sys or 'unknown'}:{remote_port}",
            attrs={"local_port": local, "remote_port": remote_port,
                   "remote_system": remote_sys},
            raw=ET.tostring(e, encoding="unicode"),
        ))
    return out


def parse_arp_xml(text: str, source_device: str, now: str) -> list[Observation]:
    out: list[Observation] = []
    for e in _entries(text):
        ip = _f(e, "ip")
        mac = _f(e, "mac").lower()
        iface = _f(e, "interface")
        if not (ip and mac) or mac in ("(incomplete)", "incomplete"):
            continue
        out.append(Observation(
            observed_at=now, collector="panos", source_device=source_device,
            layer="l3", observation_type="arp_entry",
            subj_kind="host", subj_id=f"ip:{ip}",
            obj_kind="host", obj_id=f"mac:{mac}",
            attrs={"interface": iface},
            raw=ET.tostring(e, encoding="unicode"),
        ))
    return out


@register("panos")
class PanosCollector(Collector):
    name = "panos"
    device = "panosvm"

    def collect(self, client: McpToolClient, now: str) -> list[Observation]:
        lldp = client.call_tool("execute_pan_op",
                                {"cmd": "<show><lldp><neighbors>all</neighbors></lldp></show>"})
        arp = client.call_tool("execute_pan_op",
                               {"cmd": "<show><arp><entry name='all'/></arp></show>"})
        return parse_lldp_xml(lldp, self.device, now) + parse_arp_xml(arp, self.device, now)
```

- [ ] **Step 5: Run to verify it passes**

Run: `cd services/topo && uv run pytest tests/test_collector_panos.py -v`
Expected: PASS (2 tests)

- [ ] **Step 6: Commit**

```bash
git add services/topo/src/ssdf_topo/collectors/panos.py services/topo/tests/test_collector_panos.py services/topo/tests/fixtures/panos_*.xml
git commit -m "feat(m4): panos topology collector (lldp/arp via execute_pan_op)"
```

## Task 3.5: Proxmox collector

**Files:**
- Create: `services/topo/tests/fixtures/proxmox_vms.json`
- Create: `services/topo/src/ssdf_topo/collectors/proxmox.py`
- Test: `services/topo/tests/test_collector_proxmox.py`

- [ ] **Step 1: Capture fixtures from live proxmox-mcp**

Capture `get_nodes` and `get_vms` output, plus one `get_vm_config` sample (for the `netN` line e.g. `virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,tag=10`). Save to fixtures. Fixture authoritative.

- [ ] **Step 2: Write the failing test**

```python
# tests/test_collector_proxmox.py
from ssdf_topo.collectors.proxmox import parse_vm_nic, parse_vms

def test_parse_vm_nic_extracts_mac_bridge_vlan():
    nic = "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,tag=10"
    parsed = parse_vm_nic(nic)
    assert parsed["mac"] == "aa:bb:cc:dd:ee:ff"
    assert parsed["bridge"] == "vmbr0"
    assert parsed["vlan"] == "10"

def test_parse_vms_emits_hosts_and_vm_nic():
    vms = [{"vmid": 105, "name": "web1", "node": "pve3",
            "config": {"net0": "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,tag=10"}}]
    obs = parse_vms(vms, now="2026-06-07T00:00:00+00:00")
    types = {o.observation_type for o in obs}
    assert "vm_host" in types and "vm_nic" in types
    nic = next(o for o in obs if o.observation_type == "vm_nic")
    assert nic.subj_id == "mac:aa:bb:cc:dd:ee:ff"
    assert nic.attrs["bridge"] == "vmbr0" and nic.attrs["vlan"] == "10"
```

- [ ] **Step 3: Run to verify it fails**

Run: `cd services/topo && uv run pytest tests/test_collector_proxmox.py -v`
Expected: FAIL (ImportError)

- [ ] **Step 4: Implement proxmox.py**

```python
# src/ssdf_topo/collectors/proxmox.py
"""Proxmox collector: hypervisor->VM hosting + vNIC bridge/vlan attach (read-only)."""

from __future__ import annotations

import json
import re

from .base import Collector, register
from ..mcp_client import McpToolClient
from ..models import Observation

_MAC_RE = re.compile(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})")


def parse_vm_nic(nic: str) -> dict:
    """Parse a Proxmox netN string: 'model=MAC,bridge=vmbrX,tag=VLAN,...'."""
    out: dict[str, str] = {"mac": "", "bridge": "", "vlan": ""}
    mac_m = _MAC_RE.search(nic)
    if mac_m:
        out["mac"] = mac_m.group(1).lower()
    for part in nic.split(","):
        if "=" not in part:
            continue
        key, _, val = part.partition("=")
        key = key.strip()
        if key == "bridge":
            out["bridge"] = val.strip()
        elif key == "tag":
            out["vlan"] = val.strip()
    return out


def parse_vms(vms: list[dict], now: str) -> list[Observation]:
    out: list[Observation] = []
    for vm in vms:
        vmid = str(vm.get("vmid", ""))
        node = str(vm.get("node", ""))
        name = str(vm.get("name", ""))
        if not vmid:
            continue
        host_id = f"vm:{node}/{vmid}"
        out.append(Observation(
            observed_at=now, collector="proxmox", source_device=node,
            layer="virt", observation_type="vm_host",
            subj_kind="device", subj_id=f"device:{node}",
            obj_kind="host", obj_id=host_id,
            attrs={"vmid": vmid, "name": name},
            raw=json.dumps(vm, default=str),
        ))
        config = vm.get("config", {}) or {}
        for key, val in config.items():
            if not key.startswith("net"):
                continue
            nic = parse_vm_nic(str(val))
            if not nic["mac"]:
                continue
            out.append(Observation(
                observed_at=now, collector="proxmox", source_device=node,
                layer="l2", observation_type="vm_nic",
                subj_kind="host", subj_id=f"mac:{nic['mac']}",
                obj_kind="device", obj_id=f"device:{node}:{nic['bridge']}",
                attrs={"bridge": nic["bridge"], "vlan": nic["vlan"],
                       "vmid": vmid, "vm": host_id, "name": name},
                raw=str(val),
            ))
    return out


def _vms_from_text(text: str) -> list[dict]:
    data = json.loads(text) if text.strip() else []
    if isinstance(data, dict):
        for key in ("result", "data", "vms"):
            if isinstance(data.get(key), list):
                return data[key]
    return data if isinstance(data, list) else []


@register("proxmox")
class ProxmoxCollector(Collector):
    name = "proxmox"

    def collect(self, client: McpToolClient, now: str) -> list[Observation]:
        vms_text = client.call_tool("get_vms", {})
        vms = _vms_from_text(vms_text)
        for vm in vms:
            if "config" not in vm and vm.get("vmid") is not None:
                cfg_text = client.call_tool("get_vm_config",
                                            {"node": vm.get("node", ""), "vmid": vm["vmid"]})
                try:
                    vm["config"] = json.loads(cfg_text).get("result", json.loads(cfg_text))
                except json.JSONDecodeError:
                    vm["config"] = {}
        return parse_vms(vms, now)
```

- [ ] **Step 5: Run to verify it passes**

Run: `cd services/topo && uv run pytest tests/test_collector_proxmox.py -v`
Expected: PASS (2 tests)

- [ ] **Step 6: Commit**

```bash
git add services/topo/src/ssdf_topo/collectors/proxmox.py services/topo/tests/test_collector_proxmox.py services/topo/tests/fixtures/proxmox_*.json
git commit -m "feat(m4): proxmox topology collector (vm host + vnic bridge/vlan)"
```

## Task 3.6: `collect-all` entrypoint

**Files:**
- Create: `services/topo/src/ssdf_topo/collect_all.py`
- Test: `services/topo/tests/test_collect_all.py`

- [ ] **Step 1: Write the failing test** (inject a fake client + writer; assert orchestration, not network)

```python
# tests/test_collect_all.py
from ssdf_topo.collect_all import run_collectors
from ssdf_topo.models import Observation

class FakeClient:
    def call_tool(self, name, args=None): return "[]"

class RecordingWriter:
    def __init__(self): self.inserted = []
    def insert_observations(self, obs): self.inserted += obs; return len(obs)

def test_run_collectors_skips_failing_and_inserts(monkeypatch):
    from ssdf_topo.collectors.base import REGISTRY, Collector, register
    @register("ok")
    class Ok(Collector):
        name = "ok"
        def collect(self, client, now):
            return [Observation(observed_at=now, collector="ok", source_device="d",
                                layer="l2", observation_type="t", subj_kind="host", subj_id="mac:x")]
    @register("boom")
    class Boom(Collector):
        name = "boom"
        def collect(self, client, now):
            raise RuntimeError("device down")

    writer = RecordingWriter()
    count = run_collectors(
        enabled=("ok", "boom"), client_factory=lambda name: FakeClient(),
        collector_factory=lambda name: REGISTRY[name](), writer=writer,
        now="2026-06-07T00:00:00+00:00",
    )
    assert count == 1               # ok inserted, boom skipped (logged)
    assert writer.inserted[0].collector == "ok"
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd services/topo && uv run pytest tests/test_collect_all.py -v`
Expected: FAIL (ImportError)

- [ ] **Step 3: Implement collect_all.py**

```python
# src/ssdf_topo/collect_all.py
"""Run all enabled collectors once and insert their observations into ClickHouse."""

from __future__ import annotations

import datetime as _dt
import logging
import os
from typing import Callable

from . import collectors as _collectors  # noqa: F401  (registers collectors)
from .chwriter import ClickHouseWriter
from .collectors import junos, unifi, panos, proxmox  # noqa: F401  (force registration)
from .collectors.base import REGISTRY
from .config import Config, load_config
from .mcp_client import McpToolClient

log = logging.getLogger("ssdf_topo.collect")


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="milliseconds")


def _build_collector(name: str):
    cls = REGISTRY[name]
    if name == "junos":
        devices = [d.strip() for d in os.environ.get("JUNOS_DEVICES", "").split(",") if d.strip()]
        return cls(devices=devices)
    return cls()


def run_collectors(enabled, client_factory: Callable[[str], McpToolClient],
                   collector_factory: Callable[[str], object], writer, now: str) -> int:
    total = 0
    for name in enabled:
        try:
            collector = collector_factory(name)
            client = client_factory(name)
            obs = collector.collect(client, now)
            total += writer.insert_observations(obs)
            log.info("collector %s: %d observations", name, len(obs))
        except Exception as exc:  # noqa: BLE001 - one source must not abort the run
            log.warning("collector %s failed, skipping: %s", name, exc)
    return total


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    config: Config = load_config()
    writer = ClickHouseWriter(config)
    inserted = run_collectors(
        enabled=config.enabled_collectors,
        client_factory=lambda name: McpToolClient(config.mcp_endpoint(name)),
        collector_factory=_build_collector,
        writer=writer,
        now=_now(),
    )
    log.info("collect-all complete: %d observations inserted", inserted)


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd services/topo && uv run pytest tests/test_collect_all.py -v`
Expected: PASS (1 test)

- [ ] **Step 5: Run full unit suite**

Run: `cd services/topo && uv run pytest -m "not integration" -v`
Expected: all green.

- [ ] **Step 6: Commit**

```bash
git add services/topo/src/ssdf_topo/collect_all.py services/topo/tests/test_collect_all.py
git commit -m "feat(m4): collect-all entrypoint (run collectors, skip failures, insert)"
```

---

**Phase 3 done.** Next: `2026-06-07-ssdf-m4-topology-graph-resolver.md`.
