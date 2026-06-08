# SSDF M6b — Configured Policy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ingest each firewall's *configured* security ruleset (PAN-OS + vSRX) read-only as
`source='configured'` Policy entities with per-firewall identity, and enrich `explain_access` to
list rules governing a path even with no observed traffic, flipping `coverage.configured`.

**Architecture:** New Python service `services/policy/` (mirrors `services/topo/` collector
pattern + `services/entity/` resolver/writer pattern) collects rules via the read-only vendor
MCPs, a pure resolver produces Firewall + configured-Policy entities and
`Firewall ──GOVERNED_BY(configured)──► Policy` edges into the existing
`ssdf.entities`/`ssdf.entity_edges` (no schema change), and the `explain_access` tool on
`ssdf-mcp-query` (ct106) reads them via the `EntityStore` seam. Deployed on ct109 (third role)
with its own hourly systemd timer.

**Tech Stack:** Python 3.11, `clickhouse-connect`, `fastmcp` client, pytest, uv; Proxmox LXC
(no Docker), systemd oneshot+timer.

**Spec:** `docs/superpowers/specs/2026-06-08-ssdf-m6b-configured-policy-design.md`.

**Key invariants (carry into every task):**
- Configured Policy canonical key = `f"{provider}:{device_name}:{rule_name}"`; observed stays
  `f"{provider}:{rule_name}"` → distinct `entity_id` (no collision). `source` is a column, NOT
  part of `entity_id`.
- `entity_id`/`edge_id` hashing in `services/policy/models.py` MUST be byte-identical to
  `services/entity/src/ssdf_entity/models.py` so ids share one namespace.
- Policy collector device names MUST match M4 `source_device` names (`panosvm`, `vSRX-test10`,
  …) so `explain_access` can bridge topology firewalls → Firewall entities by name.
- `attrs` is `Map(String,String)`: lists → comma-joined strings, ints → str, bools →
  `"true"`/`"false"`.
- ClickHouse `toString(col) AS col` alias trap: qualify columns (e.g. `entities.last_seen`) in
  any new WHERE/ORDER BY.

---

## File Structure

```
services/policy/                                   # NEW service
  pyproject.toml
  src/ssdf_policy/
    __init__.py
    models.py            # FIREWALL/POLICY/GOVERNED_BY consts + entity_id/edge_id (copied)
    config.py            # env-driven Config + mcp_endpoint + device lists
    mcp_client.py        # sync bearer-auth MCP client (copied from topo)
    resolve_policies.py  # PURE: normalized rules -> (entities, edges)
    chwriter.py          # ClickHouse writer (entities/entity_edges insert)
    collect_resolve.py   # entrypoint: collect -> resolve -> write
    collectors/
      __init__.py        # imports panos+junos to register
      base.py            # Collector Protocol + REGISTRY + register()
      panos.py           # get_pan_config -> parse security rulebase XML
      junos.py           # show configuration security policies | display set -> parse
  tests/
    test_panos_rules.py
    test_junos_rules.py
    test_resolve_policies.py
  infra/
    ssdf-policy.service
    ssdf-policy.timer
    ENV.local.example

services/mcp-query/src/ssdf_mcp_query/
    entitystore.py       # MODIFY: + firewall/configured-governed builders + method
    access_tools.py      # MODIFY: + configured_controls block + coverage.configured count
    server.py            # MODIFY: explain_access docstring
services/mcp-query/tests/
    test_entitystore.py  # MODIFY: + configured-policy lookup tests
    test_access_tools.py # MODIFY: + configured_controls tests

CLAUDE.md                # MODIFY: M6b commands subsection
docs/superpowers/STATUS.md  # MODIFY: M6b as-built row + roadmap update
```

---

## Task 1: Scaffold `services/policy` package + models

**Files:**
- Create: `services/policy/pyproject.toml`
- Create: `services/policy/src/ssdf_policy/__init__.py` (empty)
- Create: `services/policy/src/ssdf_policy/models.py`
- Test: `services/policy/tests/test_models.py`

- [ ] **Step 1: Write `pyproject.toml`**

```toml
[project]
name = "ssdf-policy"
version = "0.1.0"
description = "SSDF M6b configured-policy collector + resolver (firewall rulesets -> entities)"
requires-python = ">=3.11"
dependencies = [
    "clickhouse-connect>=0.8",
    "fastmcp>=2.0",
]

[project.optional-dependencies]
dev = ["pytest>=8.0"]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/ssdf_policy"]

[tool.pytest.ini_options]
testpaths = ["tests"]
pythonpath = ["src"]
markers = ["integration: requires live ClickHouse + MCPs (deselect with -m 'not integration')"]
```

- [ ] **Step 2: Create empty `src/ssdf_policy/__init__.py`** (zero bytes).

- [ ] **Step 3: Write the failing test** `tests/test_models.py`

```python
from ssdf_policy.models import (
    FIREWALL, POLICY, GOVERNED_BY, CONFIGURED, entity_id, edge_id,
)


def test_ids_match_entity_service_namespace():
    # Must be byte-identical to services/entity/src/ssdf_entity/models.py.
    assert entity_id("t_main", POLICY, "paloalto:panosvm:rule1") == \
        entity_id("t_main", POLICY, "paloalto:panosvm:rule1")
    # configured key differs from observed key -> different id (no collision)
    assert entity_id("t_main", POLICY, "paloalto:panosvm:rule1") != \
        entity_id("t_main", POLICY, "paloalto:rule1")


def test_edge_id_is_provenance_tagged():
    a = edge_id("t_main", "fw1", "pol1", GOVERNED_BY, CONFIGURED)
    b = edge_id("t_main", "fw1", "pol1", GOVERNED_BY, "observed")
    assert a != b
    assert FIREWALL == "firewall"
```

- [ ] **Step 4: Run test to verify it fails**

Run: `cd services/policy && uv run pytest tests/test_models.py -v`
Expected: FAIL (`ModuleNotFoundError: ssdf_policy.models`).

- [ ] **Step 5: Write `src/ssdf_policy/models.py`**

```python
"""Entity taxonomy + deterministic id hashing for the configured-policy layer.

The id functions are BYTE-IDENTICAL to services/entity/src/ssdf_entity/models.py so
configured entities/edges share one id namespace with the M6a observed entities.
"""

from __future__ import annotations

import hashlib

# --- entity kinds ---
ASSET = "asset"
POLICY = "policy"
FIREWALL = "firewall"   # NEW in M6b: a device whose configured ruleset we ingest

# --- edge types ---
GOVERNED_BY = "governed_by"

# --- provenance ---
OBSERVED = "observed"
CONFIGURED = "configured"


def _hash16(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest()[:16]


def entity_id(tenant: str, kind: str, canonical_key: str) -> str:
    """Stable 16-hex id for an entity, namespaced by tenant + kind + 'entity'."""
    return _hash16(f"{tenant}|entity|{kind}|{canonical_key}")


def edge_id(tenant: str, src_id: str, dst_id: str, edge_type: str, source: str) -> str:
    """Stable 16-hex id for a directed, typed, provenance-tagged entity edge."""
    return _hash16(f"{tenant}|entity_edge|{src_id}|{dst_id}|{edge_type}|{source}")
```

- [ ] **Step 6: Run test to verify it passes**

Run: `cd services/policy && uv run pytest tests/test_models.py -v`
Expected: PASS (2 passed).

- [ ] **Step 7: Cross-check id parity with the entity service**

Run:
```bash
cd services/policy && uv run python -c "from ssdf_policy.models import entity_id as a; import sys; sys.path.insert(0,'../entity/src'); from ssdf_entity.models import entity_id as b; print(a('t_main','policy','x')==b('t_main','policy','x'))"
```
Expected: `True`. If `False`, the hashing drifted — fix `models.py` before continuing.

- [ ] **Step 8: Commit**

```bash
git add services/policy/pyproject.toml services/policy/src/ssdf_policy/__init__.py services/policy/src/ssdf_policy/models.py services/policy/tests/test_models.py
git commit -m "feat(m6b): scaffold ssdf-policy package + id models"
```

---

## Task 2: Env-driven config

**Files:**
- Create: `services/policy/src/ssdf_policy/config.py`
- Test: `services/policy/tests/test_config.py`

- [ ] **Step 1: Write the failing test** `tests/test_config.py`

```python
import pytest
from ssdf_policy.config import load_config, ConfigError


def test_load_config_requires_password(monkeypatch):
    monkeypatch.delenv("CH_PASSWORD", raising=False)
    with pytest.raises(ConfigError):
        load_config()


def test_load_config_defaults_and_devices(monkeypatch):
    monkeypatch.setenv("CH_PASSWORD", "pw")
    monkeypatch.setenv("POLICY_COLLECTORS", "panos,junos")
    monkeypatch.setenv("JUNOS_DEVICES", "vSRX-test10, vSRX-test11")
    cfg = load_config()
    assert cfg.ch_user == "ssdf_entity"          # reuses the M6a writer user
    assert cfg.enabled_collectors == ("panos", "junos")
    assert cfg.junos_devices == ("vSRX-test10", "vSRX-test11")
    assert cfg.panos_device == "panosvm"


def test_mcp_endpoint_requires_url(monkeypatch):
    monkeypatch.setenv("CH_PASSWORD", "pw")
    monkeypatch.delenv("PANOS_MCP_URL", raising=False)
    with pytest.raises(ConfigError):
        load_config().mcp_endpoint("panos")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd services/policy && uv run pytest tests/test_config.py -v`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Write `src/ssdf_policy/config.py`**

```python
"""Runtime config for the configured-policy collector + resolver (env-driven).

Mirrors ssdf_topo.config (mcp_endpoint) and ssdf_entity.config (ClickHouse). Writes
ClickHouse as the existing M6a `ssdf_entity` user into the shared entity tables.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

ALL_COLLECTORS = ("panos", "junos")


class ConfigError(RuntimeError):
    """Raised when required configuration is missing."""


@dataclass(frozen=True)
class McpEndpoint:
    url: str
    token: str


@dataclass(frozen=True)
class Config:
    ch_host: str
    ch_port: int
    ch_user: str
    ch_password: str
    ch_database: str
    tenant_id: str
    enabled_collectors: tuple[str, ...]
    junos_devices: tuple[str, ...]
    panos_device: str

    def mcp_endpoint(self, name: str) -> McpEndpoint:
        prefix = name.upper()
        url = os.environ.get(f"{prefix}_MCP_URL")
        token = os.environ.get(f"{prefix}_MCP_TOKEN", "")
        if not url:
            raise ConfigError(f"missing {prefix}_MCP_URL for collector '{name}'")
        return McpEndpoint(url=url, token=token)


def _csv(name: str, default: str = "") -> tuple[str, ...]:
    raw = os.environ.get(name, default)
    return tuple(item.strip() for item in raw.split(",") if item.strip())


def load_config() -> Config:
    password = os.environ.get("CH_PASSWORD")
    if password is None:
        raise ConfigError("CH_PASSWORD is required")
    enabled = _csv("POLICY_COLLECTORS", ",".join(ALL_COLLECTORS))
    return Config(
        ch_host=os.environ.get("CH_HOST", "127.0.0.1"),
        ch_port=int(os.environ.get("CH_PORT", "8123")),
        ch_user=os.environ.get("CH_USER", "ssdf_entity"),
        ch_password=password,
        ch_database=os.environ.get("CH_DATABASE", "ssdf"),
        tenant_id=os.environ.get("POLICY_TENANT", "t_main"),
        enabled_collectors=enabled,
        junos_devices=_csv("JUNOS_DEVICES"),
        panos_device=os.environ.get("PANOS_DEVICE", "panosvm"),
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd services/policy && uv run pytest tests/test_config.py -v`
Expected: PASS (3 passed).

- [ ] **Step 5: Commit**

```bash
git add services/policy/src/ssdf_policy/config.py services/policy/tests/test_config.py
git commit -m "feat(m6b): env-driven config for policy collector"
```

---

## Task 3: MCP client + collector registry

**Files:**
- Create: `services/policy/src/ssdf_policy/mcp_client.py`
- Create: `services/policy/src/ssdf_policy/collectors/__init__.py`
- Create: `services/policy/src/ssdf_policy/collectors/base.py`
- Test: `services/policy/tests/test_registry.py`

- [ ] **Step 1: Write `src/ssdf_policy/mcp_client.py`** (copied verbatim from `services/topo/src/ssdf_topo/mcp_client.py`, import path adjusted)

```python
"""Minimal synchronous MCP client wrapper for collectors (bearer-auth HTTP)."""

from __future__ import annotations

import asyncio
import json
from typing import Any

from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport

from .config import McpEndpoint


def extract_text(result: Any) -> str:
    """Reduce an MCP tool result to a single text payload for parsing."""
    structured = getattr(result, "structured_content", None)
    if structured:
        return json.dumps(structured, default=str)
    blocks = getattr(result, "content", None) or []
    texts = [getattr(b, "text", "") for b in blocks if getattr(b, "text", "")]
    return "\n".join(texts)


class McpToolClient:
    """Calls a single tool on one MCP server and returns its text payload."""

    def __init__(self, endpoint: McpEndpoint):
        headers = {"Authorization": f"Bearer {endpoint.token}"} if endpoint.token else {}
        self._transport = StreamableHttpTransport(url=endpoint.url, headers=headers)

    def call_tool(self, name: str, args: dict | None = None) -> str:
        return asyncio.run(self._call(name, args or {}))

    async def _call(self, name: str, args: dict) -> str:
        async with Client(self._transport) as client:
            result = await client.call_tool(name, args)
            return extract_text(result)
```

- [ ] **Step 2: Write `src/ssdf_policy/collectors/base.py`**

```python
"""Collector protocol + a name->class registry (rules, not topology observations)."""

from __future__ import annotations

from typing import Callable, Protocol

from ..mcp_client import McpToolClient

REGISTRY: dict[str, type] = {}


class Collector(Protocol):
    name: str

    def collect(self, client: McpToolClient, now: str) -> list[dict]:
        """Pull the configured security ruleset via MCP; return normalized rule dicts."""
        ...


def register(name: str) -> Callable[[type], type]:
    def _wrap(cls: type) -> type:
        REGISTRY[name] = cls
        return cls
    return _wrap
```

- [ ] **Step 3: Write `src/ssdf_policy/collectors/__init__.py`**

```python
"""Importing this package registers all collectors via their @register decorators."""

from . import panos  # noqa: F401
from . import junos  # noqa: F401
```

- [ ] **Step 4: Write the failing test** `tests/test_registry.py`

```python
def test_registry_has_both_vendors():
    from ssdf_policy import collectors  # noqa: F401  (triggers registration)
    from ssdf_policy.collectors.base import REGISTRY
    assert set(REGISTRY) == {"panos", "junos"}
```

- [ ] **Step 5: Run test to verify it fails**

Run: `cd services/policy && uv run pytest tests/test_registry.py -v`
Expected: FAIL (`ModuleNotFoundError: ssdf_policy.collectors.panos` — created in Tasks 4–5).

- [ ] **Step 6: Note** — this test stays red until Tasks 4 and 5 create `panos.py`/`junos.py`.
  That is expected; do not stub them here. Commit the infrastructure now.

```bash
git add services/policy/src/ssdf_policy/mcp_client.py services/policy/src/ssdf_policy/collectors/base.py services/policy/src/ssdf_policy/collectors/__init__.py services/policy/tests/test_registry.py
git commit -m "feat(m6b): MCP client + collector registry"
```

---

## Task 4: PAN-OS collector + security-rulebase parser

**Files:**
- Create: `services/policy/src/ssdf_policy/collectors/panos.py`
- Create: `services/policy/tests/fixtures/panos_security_rules.xml`
- Test: `services/policy/tests/test_panos_rules.py`

**Normalized rule contract** (every collector returns a list of these dicts):
`provider, device_name, rule_name, action, from_zone, to_zone, source_addresses,
dest_addresses, application, service, position (int), enabled (bool), vendor_extras (dict),
collected_at`. List-valued fields are Python `list[str]`.

- [ ] **Step 1: Capture a live fixture (confirms tool signature + real shape)**

Run (adjust token/url from `services/policy/infra/ENV.local`):
```bash
# Confirm the exact get_pan_config arg name and capture the security rulebase XML.
# If get_pan_config takes a different arg, note it here and in panos.py's collect().
cd services/policy && uv run python - <<'PY'
from ssdf_policy.config import McpEndpoint
from ssdf_policy.mcp_client import McpToolClient
import os
ep = McpEndpoint(os.environ["PANOS_MCP_URL"], os.environ.get("PANOS_MCP_TOKEN",""))
xpath = ("/config/devices/entry[@name='localhost.localdomain']"
         "/vsys/entry[@name='vsys1']/rulebase/security/rules")
print(McpToolClient(ep).call_tool("get_pan_config", {"xpath": xpath}))
PY
```
Save representative output (a `<rules>...<entry name=...>` tree, JSON-wrapped or raw) to
`services/policy/tests/fixtures/panos_security_rules.xml`. If `get_pan_config` rejects the
`xpath` arg, fall back to `execute_pan_op` with
`<show><config><running><xpath>…</xpath></running></config></show>` and record the working call
in `panos.py`.

- [ ] **Step 2: Write the failing test** `tests/test_panos_rules.py`

```python
from pathlib import Path
from ssdf_policy.collectors.panos import parse_security_rules

FIXTURE = Path(__file__).parent / "fixtures" / "panos_security_rules.xml"


def _sample() -> str:
    # Minimal representative payload (matches the captured fixture shape).
    return (
        "<rules>"
        "<entry name='allow-web' uuid='u-1'>"
        "<from><member>trust</member></from>"
        "<to><member>untrust</member></to>"
        "<source><member>any</member></source>"
        "<destination><member>any</member></destination>"
        "<application><member>web-browsing</member></application>"
        "<service><member>application-default</member></service>"
        "<action>allow</action>"
        "</entry>"
        "<entry name='deny-all' uuid='u-2'>"
        "<from><member>any</member></from><to><member>any</member></to>"
        "<source><member>any</member></source><destination><member>any</member></destination>"
        "<application><member>any</member></application><service><member>any</member></service>"
        "<action>deny</action><disabled>yes</disabled>"
        "</entry>"
        "</rules>"
    )


def test_parses_rules_with_position_and_enabled():
    rules = parse_security_rules(_sample(), "panosvm", "2026-06-08T00:00:00")
    assert [r["rule_name"] for r in rules] == ["allow-web", "deny-all"]
    first = rules[0]
    assert first["provider"] == "paloalto"
    assert first["device_name"] == "panosvm"
    assert first["action"] == "allow"
    assert first["from_zone"] == ["trust"] and first["to_zone"] == ["untrust"]
    assert first["application"] == ["web-browsing"]
    assert first["position"] == 0 and first["enabled"] is True
    assert first["vendor_extras"]["panw.panos.uuid"] == "u-1"
    assert rules[1]["enabled"] is False and rules[1]["position"] == 1


def test_handles_json_wrapped_payload():
    import json
    wrapped = json.dumps({"result": _sample()})
    rules = parse_security_rules(wrapped, "panosvm", "2026-06-08T00:00:00")
    assert len(rules) == 2


def test_real_fixture_parses_nonempty():
    rules = parse_security_rules(FIXTURE.read_text(), "panosvm", "2026-06-08T00:00:00")
    assert len(rules) >= 1
    assert all(r["rule_name"] and r["action"] for r in rules)
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd services/policy && uv run pytest tests/test_panos_rules.py -v`
Expected: FAIL (`ModuleNotFoundError: ssdf_policy.collectors.panos`).

- [ ] **Step 4: Write `src/ssdf_policy/collectors/panos.py`**

```python
"""PAN-OS configured-policy collector: security rulebase via get_pan_config (XML/JSON)."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET

from .base import register

PROVIDER = "paloalto"
# vsys1 security rulebase; pinned to PAN-OS 12.1 config shape (see CLAUDE.md M5 note).
RULES_XPATH = ("/config/devices/entry[@name='localhost.localdomain']"
               "/vsys/entry[@name='vsys1']/rulebase/security/rules")


def _root(text: str) -> ET.Element | None:
    """Unwrap an optional JSON envelope and parse to an XML root element."""
    xml_text = text
    try:
        data = json.loads(text)
        if isinstance(data, dict) and isinstance(data.get("result"), str):
            xml_text = data["result"]
        elif isinstance(data, str):
            xml_text = data
    except json.JSONDecodeError:
        pass
    try:
        return ET.fromstring(xml_text)
    except ET.ParseError:
        return None


def _members(entry: ET.Element, tag: str) -> list[str]:
    el = entry.find(tag)
    if el is None:
        return []
    return [m.text.strip() for m in el.findall("member") if m.text and m.text.strip()]


def _text(entry: ET.Element, tag: str) -> str:
    el = entry.find(tag)
    return el.text.strip() if el is not None and el.text else ""


def parse_security_rules(text: str, device_name: str, now: str) -> list[dict]:
    """Parse a PAN-OS security rulebase into normalized rule dicts (order preserved)."""
    root = _root(text)
    if root is None:
        return []
    entries = root.findall(".//entry")
    rules: list[dict] = []
    for position, entry in enumerate(entries):
        name = entry.get("name", "").strip()
        if not name:
            continue
        rules.append({
            "provider": PROVIDER,
            "device_name": device_name,
            "rule_name": name,
            "action": _text(entry, "action"),
            "from_zone": _members(entry, "from"),
            "to_zone": _members(entry, "to"),
            "source_addresses": _members(entry, "source"),
            "dest_addresses": _members(entry, "destination"),
            "application": _members(entry, "application"),
            "service": _members(entry, "service"),
            "position": position,
            "enabled": _text(entry, "disabled").lower() != "yes",
            "vendor_extras": {"panw.panos.uuid": entry.get("uuid", "")},
            "collected_at": now,
        })
    return rules


@register("panos")
class PanosPolicyCollector:
    """Collects the configured security rulebase from one PAN-OS firewall."""

    name = "panos"

    def __init__(self, device: str = "panosvm"):
        self.device = device

    def collect(self, client, now: str) -> list[dict]:
        text = client.call_tool("get_pan_config", {"xpath": RULES_XPATH})
        return parse_security_rules(text, self.device, now)
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd services/policy && uv run pytest tests/test_panos_rules.py -v`
Expected: PASS (3 passed).

- [ ] **Step 6: Commit**

```bash
git add services/policy/src/ssdf_policy/collectors/panos.py services/policy/tests/test_panos_rules.py services/policy/tests/fixtures/panos_security_rules.xml
git commit -m "feat(m6b): PAN-OS security-rulebase collector + parser"
```

---

## Task 5: vSRX collector + security-policy parser

**Files:**
- Create: `services/policy/src/ssdf_policy/collectors/junos.py`
- Create: `services/policy/tests/fixtures/junos_security_policies.set`
- Test: `services/policy/tests/test_junos_rules.py`

**Implementation note (documented refinement of spec §3.2):** the collector reads configured
policies via `execute_junos_command` with `show configuration security policies | display set`
— a read-only config retrieval that yields deterministic `set`-format lines, easier to parse
than the native `get_junos_config` envelope. This satisfies the spec's "read configured rules
read-only" intent.

- [ ] **Step 1: Capture a live fixture**

Run (adjust device/url/token):
```bash
cd services/policy && uv run python - <<'PY'
from ssdf_policy.config import McpEndpoint
from ssdf_policy.mcp_client import McpToolClient
import os
ep = McpEndpoint(os.environ["JUNOS_MCP_URL"], os.environ.get("JUNOS_MCP_TOKEN",""))
cmd = "show configuration security policies | display set"
print(McpToolClient(ep).call_tool("execute_junos_command",
      {"router": os.environ.get("JUNOS_DEVICES","vSRX-test10").split(",")[0], "command": cmd}))
PY
```
Save representative `set security policies …` lines to
`services/policy/tests/fixtures/junos_security_policies.set`.

- [ ] **Step 2: Write the failing test** `tests/test_junos_rules.py`

```python
from pathlib import Path
from ssdf_policy.collectors.junos import parse_security_policies

FIXTURE = Path(__file__).parent / "fixtures" / "junos_security_policies.set"

SAMPLE = """
set security policies from-zone trust to-zone untrust policy ALLOW-WEB match source-address any
set security policies from-zone trust to-zone untrust policy ALLOW-WEB match destination-address any
set security policies from-zone trust to-zone untrust policy ALLOW-WEB match application junos-http
set security policies from-zone trust to-zone untrust policy ALLOW-WEB then permit
set security policies from-zone trust to-zone untrust policy DENY-ALL match source-address any
set security policies from-zone trust to-zone untrust policy DENY-ALL match destination-address any
set security policies from-zone trust to-zone untrust policy DENY-ALL match application any
set security policies from-zone trust to-zone untrust policy DENY-ALL then deny
""".strip()


def test_groups_terms_into_rules_with_action_and_zones():
    rules = parse_security_policies(SAMPLE, "vSRX-test10", "2026-06-08T00:00:00")
    by_name = {r["rule_name"]: r for r in rules}
    assert set(by_name) == {"ALLOW-WEB", "DENY-ALL"}
    web = by_name["ALLOW-WEB"]
    assert web["provider"] == "juniper"
    assert web["device_name"] == "vSRX-test10"
    assert web["action"] == "allow"            # permit -> allow
    assert web["from_zone"] == ["trust"] and web["to_zone"] == ["untrust"]
    assert web["application"] == ["junos-http"]
    assert web["enabled"] is True
    assert by_name["DENY-ALL"]["action"] == "deny"


def test_position_follows_first_appearance_order():
    rules = parse_security_policies(SAMPLE, "vSRX-test10", "2026-06-08T00:00:00")
    assert [r["rule_name"] for r in sorted(rules, key=lambda r: r["position"])] == \
        ["ALLOW-WEB", "DENY-ALL"]


def test_real_fixture_parses_nonempty():
    text = FIXTURE.read_text()
    rules = parse_security_policies(text, "vSRX-test10", "2026-06-08T00:00:00")
    assert len(rules) >= 1
    assert all(r["rule_name"] and r["action"] for r in rules)
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd services/policy && uv run pytest tests/test_junos_rules.py -v`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 4: Write `src/ssdf_policy/collectors/junos.py`**

```python
"""vSRX configured-policy collector: security policies via `| display set` text parser."""

from __future__ import annotations

import re

from .base import register

PROVIDER = "juniper"
_ACTION_MAP = {"permit": "allow", "deny": "deny", "reject": "reject"}
# Captures: from-zone, to-zone, policy name, and the trailing remainder.
_POLICY_RE = re.compile(
    r"security policies from-zone (\S+) to-zone (\S+) policy (\S+) (.*)$"
)


def parse_security_policies(text: str, device_name: str, now: str) -> list[dict]:
    """Parse Junos `set security policies … | display set` output into rule dicts.

    Terms for the same (from-zone, to-zone, policy) accumulate into one rule. Lines
    prefixed `inactive:` mark the rule disabled. `position` follows first appearance.
    """
    rules: dict[tuple, dict] = {}
    order = 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        inactive = line.startswith("inactive:")
        if inactive:
            line = line[len("inactive:"):].strip()
        if not line.startswith("set ") and not line.startswith("deactivate "):
            continue
        match = _POLICY_RE.search(line)
        if not match:
            continue
        from_zone, to_zone, name, remainder = match.groups()
        key = (from_zone, to_zone, name)
        rule = rules.get(key)
        if rule is None:
            rule = {
                "provider": PROVIDER, "device_name": device_name, "rule_name": name,
                "action": "", "from_zone": [from_zone], "to_zone": [to_zone],
                "source_addresses": [], "dest_addresses": [], "application": [],
                "service": [], "position": order, "enabled": True,
                "vendor_extras": {}, "collected_at": now,
            }
            rules[key] = rule
            order += 1
        if inactive:
            rule["enabled"] = False
        tokens = remainder.split()
        if tokens[:2] == ["match", "source-address"] and len(tokens) > 2:
            rule["source_addresses"].append(tokens[2])
        elif tokens[:2] == ["match", "destination-address"] and len(tokens) > 2:
            rule["dest_addresses"].append(tokens[2])
        elif tokens[:2] == ["match", "application"] and len(tokens) > 2:
            rule["application"].append(tokens[2])
            rule["service"].append(tokens[2])
        elif tokens[:1] == ["then"] and len(tokens) > 1:
            rule["action"] = _ACTION_MAP.get(tokens[1], tokens[1])
    return list(rules.values())


@register("junos")
class JunosPolicyCollector:
    """Collects configured security policies from one or more vSRX devices."""

    name = "junos"

    def __init__(self, devices: list[str] | None = None):
        self.devices = devices or []

    def collect(self, client, now: str) -> list[dict]:
        rules: list[dict] = []
        for dev in self.devices:
            text = client.call_tool(
                "execute_junos_command",
                {"router": dev, "command": "show configuration security policies | display set"},
            )
            rules.extend(parse_security_policies(text, dev, now))
        return rules
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd services/policy && uv run pytest tests/test_junos_rules.py tests/test_registry.py -v`
Expected: PASS (test_registry now green too).

- [ ] **Step 6: Commit**

```bash
git add services/policy/src/ssdf_policy/collectors/junos.py services/policy/tests/test_junos_rules.py services/policy/tests/fixtures/junos_security_policies.set
git commit -m "feat(m6b): vSRX security-policy collector + set-format parser"
```

---

## Task 6: Pure resolver — rules → Firewall + Policy entities + edges

**Files:**
- Create: `services/policy/src/ssdf_policy/resolve_policies.py`
- Test: `services/policy/tests/test_resolve_policies.py`

- [ ] **Step 1: Write the failing test** `tests/test_resolve_policies.py`

```python
from ssdf_policy.resolve_policies import resolve_policies
from ssdf_policy.models import entity_id, ASSET, POLICY, FIREWALL


def _rule(device, name, provider="paloalto", action="allow"):
    return {
        "provider": provider, "device_name": device, "rule_name": name, "action": action,
        "from_zone": ["trust"], "to_zone": ["untrust"], "source_addresses": ["any"],
        "dest_addresses": ["10.64.0.0/24"], "application": ["web-browsing"], "service": ["http"],
        "position": 0, "enabled": True, "vendor_extras": {"panw.panos.uuid": "u-1"},
        "collected_at": "2026-06-08T00:00:00",
    }


def test_same_rule_name_on_two_firewalls_does_not_collapse():
    rules = [_rule("fwA", "ALLOW-WEB", provider="juniper"),
             _rule("fwB", "ALLOW-WEB", provider="juniper")]
    entities, _ = resolve_policies(rules, "t_main")
    policies = [e for e in entities if e["kind"] == POLICY]
    assert len({p["entity_id"] for p in policies}) == 2   # the M6a collapse is fixed


def test_emits_firewall_entity_and_governed_by_edge():
    entities, edges = resolve_policies([_rule("panosvm", "allow-web")], "t_main")
    kinds = {e["kind"] for e in entities}
    assert kinds == {FIREWALL, POLICY}
    fw = next(e for e in entities if e["kind"] == FIREWALL)
    pol = next(e for e in entities if e["kind"] == POLICY)
    assert fw["entity_id"] == entity_id("t_main", FIREWALL, "device:panosvm")
    assert fw["identifiers"]["device_name"] == "panosvm"
    assert pol["entity_id"] == entity_id("t_main", POLICY, "paloalto:panosvm:allow-web")
    assert pol["source"] == "configured"
    assert pol["attrs"]["action"] == "allow"
    assert pol["attrs"]["from_zone"] == "trust"
    assert pol["attrs"]["dest_addresses"] == "10.64.0.0/24"
    assert pol["attrs"]["enabled"] == "true"
    assert pol["attrs"]["position"] == "0"
    assert len(edges) == 1
    edge = edges[0]
    assert edge["edge_type"] == "governed_by" and edge["source"] == "configured"
    assert edge["src_id"] == fw["entity_id"] and edge["dst_id"] == pol["entity_id"]


def test_idempotent_ids_across_runs():
    rules = [_rule("panosvm", "allow-web")]
    e1, _ = resolve_policies(rules, "t_main")
    e2, _ = resolve_policies(rules, "t_main")
    assert {e["entity_id"] for e in e1} == {e["entity_id"] for e in e2}


def test_no_asset_entities_emitted():
    entities, _ = resolve_policies([_rule("panosvm", "allow-web")], "t_main")
    assert not any(e["kind"] == ASSET for e in entities)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd services/policy && uv run pytest tests/test_resolve_policies.py -v`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Write `src/ssdf_policy/resolve_policies.py`**

```python
"""Resolve normalized firewall rules into Firewall + configured-Policy entities and edges.

Pure, deterministic. Snapshot semantics: first_seen == last_seen == collected_at (latest
config pull wins under ReplacingMergeTree(last_seen); no rule-version history — see spec §6).
"""

from __future__ import annotations

from .models import (
    FIREWALL, POLICY, GOVERNED_BY, CONFIGURED, entity_id, edge_id,
)


def _join(values: list[str]) -> str:
    """Comma-join a list for storage in a Map(String, String) attr."""
    return ",".join(v for v in values if v)


def resolve_policies(rules: list[dict], tenant: str) -> tuple[list[dict], list[dict]]:
    entities: dict[str, dict] = {}
    edges: dict[str, dict] = {}

    def firewall_for(provider: str, device: str, seen: str) -> dict:
        eid = entity_id(tenant, FIREWALL, f"device:{device}")
        fw = entities.get(eid)
        if fw is None:
            fw = {
                "entity_id": eid, "tenant_id": tenant, "kind": FIREWALL,
                "name": device, "identifiers": {"device_name": device},
                "source": CONFIGURED, "identity_basis": "device_name", "confidence": 1.0,
                "attrs": {"provider": provider, "rule_count": "0"},
                "first_seen": seen, "last_seen": seen,
            }
            entities[eid] = fw
        fw["attrs"]["rule_count"] = str(int(fw["attrs"]["rule_count"]) + 1)
        return fw

    for rule in rules:
        provider = rule["provider"]
        device = rule["device_name"]
        name = rule["rule_name"]
        seen = rule["collected_at"]
        fw = firewall_for(provider, device, seen)

        pol_eid = entity_id(tenant, POLICY, f"{provider}:{device}:{name}")
        attrs = {
            "provider": provider, "device_name": device, "action": rule["action"],
            "from_zone": _join(rule["from_zone"]), "to_zone": _join(rule["to_zone"]),
            "source_addresses": _join(rule["source_addresses"]),
            "dest_addresses": _join(rule["dest_addresses"]),
            "application": _join(rule["application"]), "service": _join(rule["service"]),
            "position": str(rule["position"]), "enabled": "true" if rule["enabled"] else "false",
        }
        attrs.update(rule.get("vendor_extras") or {})
        policy = {
            "entity_id": pol_eid, "tenant_id": tenant, "kind": POLICY, "name": name,
            "identifiers": {"rule": name, "provider": provider, "device_name": device},
            "source": CONFIGURED, "identity_basis": "", "confidence": 1.0,
            "attrs": attrs, "first_seen": seen, "last_seen": seen,
        }
        entities[pol_eid] = policy

        gov_eid = edge_id(tenant, fw["entity_id"], pol_eid, GOVERNED_BY, CONFIGURED)
        edges[gov_eid] = {
            "edge_id": gov_eid, "tenant_id": tenant, "src_id": fw["entity_id"],
            "dst_id": pol_eid, "edge_type": GOVERNED_BY, "source": CONFIGURED,
            "confidence": 1.0, "attrs": {"rule": name, "provider": provider},
            "first_seen": seen, "last_seen": seen,
        }

    return list(entities.values()), list(edges.values())
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd services/policy && uv run pytest tests/test_resolve_policies.py -v`
Expected: PASS (4 passed).

- [ ] **Step 5: Commit**

```bash
git add services/policy/src/ssdf_policy/resolve_policies.py services/policy/tests/test_resolve_policies.py
git commit -m "feat(m6b): pure resolver for firewall + configured-policy entities"
```

---

## Task 7: ClickHouse writer

**Files:**
- Create: `services/policy/src/ssdf_policy/chwriter.py`
- Test: `services/policy/tests/test_chwriter.py`

- [ ] **Step 1: Write the failing test** `tests/test_chwriter.py`

```python
from ssdf_policy.chwriter import entity_rows, edge_rows, ENTITY_COLUMNS, ENTITY_EDGE_COLUMNS


def test_entity_rows_match_m6a_column_order():
    # Must equal services/entity ENTITY_COLUMNS so inserts target the shared table layout.
    assert ENTITY_COLUMNS == [
        "entity_id", "tenant_id", "kind", "name", "identifiers", "source",
        "identity_basis", "confidence", "attrs", "first_seen", "last_seen",
    ]
    assert ENTITY_EDGE_COLUMNS == [
        "edge_id", "tenant_id", "src_id", "dst_id", "edge_type", "source",
        "confidence", "attrs", "first_seen", "last_seen",
    ]
    ent = {c: c for c in ENTITY_COLUMNS}
    assert entity_rows([ent]) == [[c for c in ENTITY_COLUMNS]]
    edge = {c: c for c in ENTITY_EDGE_COLUMNS}
    assert edge_rows([edge]) == [[c for c in ENTITY_EDGE_COLUMNS]]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd services/policy && uv run pytest tests/test_chwriter.py -v`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Write `src/ssdf_policy/chwriter.py`** (write-only; mirrors the M6a writer's column lists and insert calls — no flow-agg read needed here)

```python
"""ClickHouse writer for configured entities/edges into the shared M6a tables."""

from __future__ import annotations

from typing import Any, Iterable

import clickhouse_connect

from .config import Config

# Byte-identical to services/entity/src/ssdf_entity/chwriter.py column orders.
ENTITY_COLUMNS = [
    "entity_id", "tenant_id", "kind", "name", "identifiers", "source",
    "identity_basis", "confidence", "attrs", "first_seen", "last_seen",
]
ENTITY_EDGE_COLUMNS = [
    "edge_id", "tenant_id", "src_id", "dst_id", "edge_type", "source",
    "confidence", "attrs", "first_seen", "last_seen",
]


def entity_rows(entities: Iterable[dict]) -> list[list[Any]]:
    return [[e[c] for c in ENTITY_COLUMNS] for e in entities]


def edge_rows(edges: Iterable[dict]) -> list[list[Any]]:
    return [[e[c] for c in ENTITY_EDGE_COLUMNS] for e in edges]


class ClickHouseEntityWriter:
    """Upserts configured entities/edges (ReplacingMergeTree dedups by id on merge)."""

    def __init__(self, config: Config):
        self._config = config
        self._client = clickhouse_connect.get_client(
            host=config.ch_host, port=config.ch_port, username=config.ch_user,
            password=config.ch_password, database=config.ch_database,
        )

    def replace_entities(self, entities: list[dict]) -> int:
        if not entities:
            return 0
        self._client.insert("entities", entity_rows(entities), column_names=ENTITY_COLUMNS)
        return len(entities)

    def replace_edges(self, edges: list[dict]) -> int:
        if not edges:
            return 0
        self._client.insert("entity_edges", edge_rows(edges), column_names=ENTITY_EDGE_COLUMNS)
        return len(edges)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd services/policy && uv run pytest tests/test_chwriter.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add services/policy/src/ssdf_policy/chwriter.py services/policy/tests/test_chwriter.py
git commit -m "feat(m6b): ClickHouse writer for configured entities/edges"
```

---

## Task 8: Entrypoint — collect → resolve → write

**Files:**
- Create: `services/policy/src/ssdf_policy/collect_resolve.py`
- Test: `services/policy/tests/test_collect_resolve.py`

- [ ] **Step 1: Write the failing test** `tests/test_collect_resolve.py`

```python
from ssdf_policy.collect_resolve import run_once


class _FakeCollector:
    def __init__(self, rules):
        self._rules = rules

    def collect(self, client, now):
        return self._rules


class _FakeWriter:
    def __init__(self):
        self.entities = None
        self.edges = None

    def replace_entities(self, entities):
        self.entities = entities
        return len(entities)

    def replace_edges(self, edges):
        self.edges = edges
        return len(edges)


def _rule(device, name):
    return {
        "provider": "paloalto", "device_name": device, "rule_name": name, "action": "allow",
        "from_zone": ["trust"], "to_zone": ["untrust"], "source_addresses": ["any"],
        "dest_addresses": ["any"], "application": ["any"], "service": ["any"],
        "position": 0, "enabled": True, "vendor_extras": {}, "collected_at": "2026-06-08T00:00:00",
    }


def test_run_once_collects_resolves_writes():
    writer = _FakeWriter()
    n_ent, n_edge = run_once(
        enabled=["panos"],
        collector_factory=lambda name: _FakeCollector([_rule("panosvm", "allow-web")]),
        client_factory=lambda name: object(),
        writer=writer,
        tenant="t_main",
        now="2026-06-08T00:00:00",
    )
    assert n_ent == 2 and n_edge == 1            # firewall + policy, 1 governed_by
    assert {e["kind"] for e in writer.entities} == {"firewall", "policy"}


def test_run_once_skips_failing_collector():
    class _Boom:
        def collect(self, client, now):
            raise RuntimeError("mcp down")
    writer = _FakeWriter()
    n_ent, _ = run_once(
        enabled=["panos", "junos"],
        collector_factory=lambda name: (_Boom() if name == "panos"
                                        else _FakeCollector([_rule("vSRX-test10", "P1")])),
        client_factory=lambda name: object(),
        writer=writer, tenant="t_main", now="2026-06-08T00:00:00",
    )
    assert n_ent == 2                             # only junos's firewall+policy survived
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd services/policy && uv run pytest tests/test_collect_resolve.py -v`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Write `src/ssdf_policy/collect_resolve.py`**

```python
"""Entrypoint: collect configured rules from each firewall, resolve, upsert entities/edges."""

from __future__ import annotations

import datetime
import logging
import os

from . import collectors  # noqa: F401 — triggers @register for panos+junos
from .chwriter import ClickHouseEntityWriter
from .collectors.base import REGISTRY
from .config import Config, load_config
from .mcp_client import McpToolClient
from .resolve_policies import resolve_policies

log = logging.getLogger("ssdf_policy.collect_resolve")


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds")


def _build_collector(name: str):
    cls = REGISTRY[name]
    if name == "junos":
        raw = os.environ.get("JUNOS_DEVICES", "")
        return cls(devices=[d.strip() for d in raw.split(",") if d.strip()])
    if name == "panos":
        return cls(device=os.environ.get("PANOS_DEVICE", "panosvm"))
    return cls()


def run_once(enabled, collector_factory, client_factory, writer, tenant: str,
             now: str) -> tuple[int, int]:
    """Collect rules from each enabled firewall (skipping failures), resolve, write."""
    all_rules: list[dict] = []
    for name in enabled:
        try:
            collector = collector_factory(name)
            client = client_factory(name)
            all_rules.extend(collector.collect(client, now))
        except Exception:
            log.warning("policy collector %r failed; skipping", name, exc_info=True)
    entities, edges = resolve_policies(all_rules, tenant)
    n_ent = writer.replace_entities(entities)
    n_edge = writer.replace_edges(edges)
    log.info("policy resolver: %d entities, %d edges upserted", n_ent, n_edge)
    return n_ent, n_edge


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    config: Config = load_config()
    writer = ClickHouseEntityWriter(config)
    run_once(
        enabled=config.enabled_collectors,
        collector_factory=_build_collector,
        client_factory=lambda name: McpToolClient(config.mcp_endpoint(name)),
        writer=writer,
        tenant=config.tenant_id,
        now=_now(),
    )


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run test to verify it passes, then the whole suite**

Run: `cd services/policy && uv run pytest -m "not integration" -v`
Expected: PASS (all unit tests across the package green).

- [ ] **Step 5: Commit**

```bash
git add services/policy/src/ssdf_policy/collect_resolve.py services/policy/tests/test_collect_resolve.py
git commit -m "feat(m6b): collect->resolve->write entrypoint"
```

---

## Task 9: EntityStore — configured-policy lookup (mcp-query)

**Files:**
- Modify: `services/mcp-query/src/ssdf_mcp_query/entitystore.py`
- Modify: `services/mcp-query/tests/test_entitystore.py`

- [ ] **Step 1: Write the failing tests** — append to `tests/test_entitystore.py`

```python
from ssdf_mcp_query.entitystore import (
    build_firewall_match_sql, build_configured_governed_sql,
)


def test_firewall_match_sql_filters_kind_and_device_names():
    sql, params = build_firewall_match_sql(["panosvm", "vSRX-test10"], tenant="t_main")
    assert "ssdf.entities FINAL" in sql
    assert "kind = 'firewall'" in sql
    assert "identifiers['device_name'] IN {names:Array(String)}" in sql
    assert params["names"] == ["panosvm", "vSRX-test10"]
    assert params["tenant"] == "t_main"


def test_configured_governed_sql_filters_source_and_src_ids():
    sql, params = build_configured_governed_sql(["fw1"], tenant="t_main")
    assert "edge_type = 'governed_by'" in sql
    assert "source = 'configured'" in sql
    assert "src_id IN {ids:Array(String)}" in sql
    assert params["ids"] == ["fw1"]


def test_configured_policies_for_firewalls_joins_fw_edge_policy():
    # rows popped in call order: firewalls, governed edges, policies
    ch = _FakeCH([
        [{"entity_id": "fwid", "identifiers": {"device_name": "panosvm"}, "name": "panosvm"}],
        [{"edge_id": "g1", "src_id": "fwid", "dst_id": "polid", "attrs": {}}],
        [{"entity_id": "polid", "name": "allow-web", "attrs": {"action": "allow"}}],
    ])
    store = ClickHouseEntityStore(ch, tenant="t_main")
    result = store.configured_policies_for_firewalls(["panosvm"])
    assert result == [{"firewall": "panosvm",
                       "policy": {"entity_id": "polid", "name": "allow-web",
                                  "attrs": {"action": "allow"}}}]


def test_configured_policies_for_firewalls_empty_input():
    store = ClickHouseEntityStore(_FakeCH([]), tenant="t_main")
    assert store.configured_policies_for_firewalls([]) == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd services/mcp-query && uv run pytest tests/test_entitystore.py -v`
Expected: FAIL (`ImportError: build_firewall_match_sql`).

- [ ] **Step 3: Add builders to `entitystore.py`** — insert after `build_entities_by_id_sql`

```python
def build_firewall_match_sql(device_names: list[str], tenant: str) -> tuple[str, dict]:
    sql = (
        f"SELECT {_ENTITY_COLS} FROM ssdf.entities FINAL "
        "WHERE tenant_id = {tenant:String} AND kind = 'firewall' "
        "AND identifiers['device_name'] IN {names:Array(String)}"
    )
    return sql, {"tenant": tenant, "names": device_names}


def build_configured_governed_sql(firewall_ids: list[str], tenant: str) -> tuple[str, dict]:
    sql = (
        f"SELECT {_EDGE_COLS} FROM ssdf.entity_edges FINAL "
        "WHERE tenant_id = {tenant:String} AND edge_type = 'governed_by' "
        "AND source = 'configured' AND src_id IN {ids:Array(String)}"
    )
    return sql, {"tenant": tenant, "ids": firewall_ids}
```

- [ ] **Step 4: Extend the `EntityStore` Protocol and `ClickHouseEntityStore`**

In the `EntityStore` Protocol, add:

```python
    def configured_policies_for_firewalls(self, firewall_names: list[str]) -> list[dict]: ...
```

In `ClickHouseEntityStore`, add the method (after `governed_policies`):

```python
    def configured_policies_for_firewalls(self, firewall_names: list[str]) -> list[dict]:
        """Return [{firewall: <device_name>, policy: <entity>}] for configured rules on the
        named firewalls (matched to Firewall entities by identifiers['device_name'])."""
        if not firewall_names:
            return []
        fw_sql, fw_params = build_firewall_match_sql(firewall_names, self._tenant)
        firewalls = self._ch.run(fw_sql, fw_params)["rows"]
        fw_by_id = {f["entity_id"]: f for f in firewalls}
        if not fw_by_id:
            return []
        gov_sql, gov_params = build_configured_governed_sql(list(fw_by_id), self._tenant)
        gov_edges = self._ch.run(gov_sql, gov_params)["rows"]
        policy_ids = sorted({e["dst_id"] for e in gov_edges})
        if not policy_ids:
            return []
        pol_sql, pol_params = build_entities_by_id_sql(policy_ids, self._tenant)
        policies = {p["entity_id"]: p for p in self._ch.run(pol_sql, pol_params)["rows"]}
        result = []
        for edge in gov_edges:
            fw = fw_by_id.get(edge["src_id"])
            policy = policies.get(edge["dst_id"])
            if fw and policy:
                name = fw["identifiers"].get("device_name") or fw.get("name", "")
                result.append({"firewall": name, "policy": policy})
        return result
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd services/mcp-query && uv run pytest tests/test_entitystore.py -v`
Expected: PASS (all entitystore tests green).

- [ ] **Step 6: Commit**

```bash
git add services/mcp-query/src/ssdf_mcp_query/entitystore.py services/mcp-query/tests/test_entitystore.py
git commit -m "feat(m6b): EntityStore configured-policy-by-firewall lookup"
```

---

## Task 10: explain_access — configured_controls + coverage count

**Files:**
- Modify: `services/mcp-query/src/ssdf_mcp_query/access_tools.py`
- Modify: `services/mcp-query/tests/test_access_tools.py`

- [ ] **Step 1: Write the failing tests** — append to `tests/test_access_tools.py`

```python
class _StoreWithConfigured:
    """Minimal EntityStore double exercising the configured path."""

    def __init__(self, configured):
        self._configured = configured

    def find_entity(self, ident):
        return {"entity_id": ident, "name": ident, "identity_basis": "mac"}

    def communicated_edges(self, a, b, since):
        return []

    def governed_policies(self, ids):
        return []

    def configured_policies_for_firewalls(self, names):
        return self._configured


class _TopoOneFw:
    def enforcement_points(self, src, dst):
        return {"firewalls": ["panosvm"]}

    def find_path(self, src, dst):
        return {"path": []}


def test_explain_access_lists_configured_controls_and_counts():
    from ssdf_mcp_query.access_tools import AccessTools
    configured = [{"firewall": "panosvm",
                   "policy": {"name": "allow-web",
                              "attrs": {"action": "allow", "from_zone": "trust",
                                        "to_zone": "untrust", "position": "0",
                                        "enabled": "true"}}}]
    access = AccessTools(_StoreWithConfigured(configured), _TopoOneFw())
    out = access.explain_access("10.64.0.1", "10.64.0.2")
    assert out["coverage"]["configured"] == 1
    assert out["configured_basis"] == "topology"
    ctrl = out["configured_controls"][0]
    assert ctrl["firewall"] == "panosvm" and ctrl["rule"] == "allow-web"
    assert ctrl["action"] == "allow" and ctrl["enabled"] is True
    assert ctrl["source"] == "configured"


def test_explain_access_no_path_firewall_sets_basis():
    from ssdf_mcp_query.access_tools import AccessTools

    class _TopoNoFw:
        def enforcement_points(self, src, dst):
            return {"firewalls": []}

        def find_path(self, src, dst):
            return {"path": []}

    access = AccessTools(_StoreWithConfigured([]), _TopoNoFw())
    out = access.explain_access("10.64.0.1", "10.64.0.2")
    assert out["coverage"]["configured"] == 0
    assert out["configured_basis"] == "no_path_firewall"
    assert out["configured_controls"] == []


def test_explain_access_unmatched_firewall_basis():
    from ssdf_mcp_query.access_tools import AccessTools
    # topology names a firewall, but no configured Policy entities match it
    access = AccessTools(_StoreWithConfigured([]), _TopoOneFw())
    out = access.explain_access("10.64.0.1", "10.64.0.2")
    assert out["coverage"]["configured"] == 0
    assert out["configured_basis"] == "firewall_name_unmatched"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd services/mcp-query && uv run pytest tests/test_access_tools.py -v`
Expected: FAIL (`KeyError: 'configured_controls'` / `coverage.configured` still `"pending_m6b"`).

- [ ] **Step 3: Edit `access_tools.py`** — replace the controls/return block

Find (the firewall-attribution + return section):

```python
        # Firewall attribution comes from topology, NOT the event stream (see spec §3).
        enforcement = self._topo.enforcement_points(client, server)
        firewalls = enforcement.get("firewalls", [])
        attributed_fw = firewalls[0] if len(firewalls) == 1 else None
```

Insert immediately AFTER that block:

```python
        # M6b: configured rules on the firewalls topology places on the path. We list rules
        # present on those firewalls — no match-scoring, no drift verdicts (honesty contract).
        configured_controls: list[dict] = []
        configured_basis = "topology"
        if not firewalls:
            configured_basis = "no_path_firewall"
        else:
            for item in self._store.configured_policies_for_firewalls(firewalls):
                policy = item["policy"]
                attrs = policy.get("attrs", {})
                configured_controls.append({
                    "firewall": item["firewall"],
                    "rule": policy.get("name", ""),
                    "action": attrs.get("action", ""),
                    "from_zone": attrs.get("from_zone", ""),
                    "to_zone": attrs.get("to_zone", ""),
                    "position": attrs.get("position", ""),
                    "enabled": attrs.get("enabled", "") == "true",
                    "source": "configured",
                })
            if not configured_controls:
                configured_basis = "firewall_name_unmatched"
```

Then in the returned dict, change the `coverage` line and add two keys:

```python
            "controls": controls,
            "configured_controls": configured_controls,
            "configured_basis": configured_basis,
            "firewalls": firewalls,
            "topology_path": self._topo.find_path(client, server),
            "coverage": {"observed": sessions > 0,
                         "configured": len(configured_controls)},
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd services/mcp-query && uv run pytest tests/test_access_tools.py -v`
Expected: PASS (new + existing access tests green; existing tests that asserted
`coverage.configured == "pending_m6b"` must be updated to the integer count — update them now
if any fail).

- [ ] **Step 5: Run the full mcp-query unit suite**

Run: `cd services/mcp-query && uv run pytest -m "not integration" -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add services/mcp-query/src/ssdf_mcp_query/access_tools.py services/mcp-query/tests/test_access_tools.py
git commit -m "feat(m6b): explain_access lists configured controls + coverage count"
```

---

## Task 11: Update the explain_access tool docstring (server.py)

**Files:**
- Modify: `services/mcp-query/src/ssdf_mcp_query/server.py:94-98`

- [ ] **Step 1: Replace the docstring** so the tool contract reflects M6b

```python
    @mcp.tool
    def explain_access(client: str, server: str, since_hours: int | None = None) -> dict:
        """End-to-end view: observed flows + observed controls + CONFIGURED rules (from each
        firewall's ruleset) + topology path between a client and a server. Accepts ip/mac/name.
        `configured_controls` lists rules on the path firewalls (no match-scoring); `coverage`
        reports observed (bool) and configured (rule count). Firewall attribution is from
        topology; `configured_basis` flags no_path_firewall / firewall_name_unmatched."""
        return access.explain_access(client, server, since_hours=since_hours)
```

- [ ] **Step 2: Verify import/build still works**

Run: `cd services/mcp-query && uv run python -c "from ssdf_mcp_query.server import build_app"`
Expected: no error (config may require env; if it raises a ConfigError that's fine — the import
itself must succeed).

- [ ] **Step 3: Commit**

```bash
git add services/mcp-query/src/ssdf_mcp_query/server.py
git commit -m "docs(m6b): explain_access tool docstring covers configured controls"
```

---

## Task 12: systemd unit + timer + ENV example

**Files:**
- Create: `services/policy/infra/ssdf-policy.service`
- Create: `services/policy/infra/ssdf-policy.timer`
- Create: `services/policy/infra/ENV.local.example`

- [ ] **Step 1: Write `infra/ssdf-policy.service`**

```ini
# services/policy/infra/ssdf-policy.service
[Unit]
Description=SSDF M6b configured-policy collector + resolver (one-shot)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
EnvironmentFile=/etc/ssdf-policy/ENV.local
ExecStart=/opt/ssdf-policy/bin/python -m ssdf_policy.collect_resolve
SuccessExitStatus=0
```

- [ ] **Step 2: Write `infra/ssdf-policy.timer`** (hourly — configs change rarely; spec §7)

```ini
# services/policy/infra/ssdf-policy.timer
[Unit]
Description=Run SSDF M6b configured-policy resolver hourly

[Timer]
OnBootSec=8min
OnUnitActiveSec=1h
AccuracySec=2min
Persistent=true

[Install]
WantedBy=timers.target
```

- [ ] **Step 3: Write `infra/ENV.local.example`** (copy to `/etc/ssdf-policy/ENV.local`, mode 600 — real `ENV.local` is gitignored)

```bash
# services/policy/infra/ENV.local.example — copy to /etc/ssdf-policy/ENV.local (mode 600) on ct109
# Writes the shared M6a entity tables as the ssdf_entity user (reused; no new CH user).
CH_HOST=198.51.100.151
CH_PORT=8123
CH_USER=ssdf_entity
CH_PASSWORD=__set_me__
CH_DATABASE=ssdf
POLICY_TENANT=t_main

# Which firewalls to pull this cycle (subset of: panos,junos)
POLICY_COLLECTORS=panos,junos

# Device names MUST match M4 source_device names so explain_access can bridge by name.
PANOS_DEVICE=panosvm
JUNOS_DEVICES=vSRX-test10

# Read-only vendor MCP endpoints + bearer tokens.
PANOS_MCP_URL=http://198.51.100.199:30032/mcp
PANOS_MCP_TOKEN=__set_me__
JUNOS_MCP_URL=http://198.51.100.194:30031/mcp
JUNOS_MCP_TOKEN=__set_me__
```

- [ ] **Step 4: Confirm `infra/ENV.local` is gitignored**

Run: `git check-ignore services/policy/infra/ENV.local || echo "NOT IGNORED — add it"`
If not ignored, add `services/policy/infra/ENV.local` to `.gitignore` (match the topo/entity
entries) before committing.

- [ ] **Step 5: Commit**

```bash
git add services/policy/infra/ssdf-policy.service services/policy/infra/ssdf-policy.timer services/policy/infra/ENV.local.example
git commit -m "feat(m6b): systemd oneshot+hourly timer + ENV example"
```

---

## Task 13: Deploy to ct109 (third role) + live integration

> Deployment touches live lab infra (ct109 on pve3.example.com). ct109 already runs the M4 topo
> and M6a entity timers; M6b adds a third independent timer. Do NOT disturb the existing two.

**Files:** none (operational task; record as-built coords in gitignored
`services/policy/infra/ENV.local`).

- [ ] **Step 1: Sync source to ct109**

```bash
ssh root@pve3.example.com "pct exec 109 -- mkdir -p /opt/src/policy"
rsync -az -e "ssh root@pve3.example.com 'pct exec 109 --'" \
  services/policy/ /opt/src/policy/    # if rsync-over-pct is unavailable, scp to pve3 then `pct push`
```
(If `rsync` through `pct` is not available: `scp -r services/policy root@pve3.example.com:/tmp/ssdf-policy`
then `ssh root@pve3.example.com "tar -C /tmp -cf - ssdf-policy | pct exec 109 -- tar -C /opt/src -xf -"`
and rename to `/opt/src/policy`.)

- [ ] **Step 2: Create the venv and install**

```bash
ssh root@pve3.example.com "pct exec 109 -- python3.11 -m venv /opt/ssdf-policy"
ssh root@pve3.example.com "pct exec 109 -- /opt/ssdf-policy/bin/pip install -e /opt/src/policy"
```

- [ ] **Step 3: Write `/etc/ssdf-policy/ENV.local` (mode 600)** with the real CH password
  (`ssdf_entity`), the real MCP bearer tokens, and the device lists. Base it on
  `infra/ENV.local.example`.

```bash
ssh root@pve3.example.com "pct exec 109 -- mkdir -p /etc/ssdf-policy && pct exec 109 -- chmod 600 /etc/ssdf-policy/ENV.local"
```

- [ ] **Step 4: Run one pass by hand and confirm it writes**

```bash
ssh root@pve3.example.com "pct exec 109 -- bash -lc 'set -a; . /etc/ssdf-policy/ENV.local; set +a; /opt/ssdf-policy/bin/python -m ssdf_policy.collect_resolve'"
```
Expected log: `policy resolver: N entities, M edges upserted` with N ≥ 2, M ≥ 1.

- [ ] **Step 5: Verify rows in ClickHouse (ct104)**

```bash
ssh root@pve3.example.com "pct exec 104 -- clickhouse-client --query \"SELECT kind, source, count() FROM ssdf.entities FINAL WHERE source='configured' GROUP BY kind, source\""
ssh root@pve3.example.com "pct exec 104 -- clickhouse-client --query \"SELECT edge_type, source, count() FROM ssdf.entity_edges FINAL WHERE source='configured' GROUP BY edge_type, source\""
```
Expected: `firewall`/`configured` and `policy`/`configured` counts > 0; `governed_by`/`configured`
edges > 0.

- [ ] **Step 6: Install + enable the timer**

```bash
ssh root@pve3.example.com "pct push 109 /tmp/ssdf-policy.service /etc/systemd/system/ssdf-policy.service"   # push both unit files first
ssh root@pve3.example.com "pct push 109 /tmp/ssdf-policy.timer   /etc/systemd/system/ssdf-policy.timer"
ssh root@pve3.example.com "pct exec 109 -- systemctl daemon-reload && pct exec 109 -- systemctl enable --now ssdf-policy.timer"
ssh root@pve3.example.com "pct exec 109 -- systemctl list-timers ssdf-policy.timer --no-pager"
```
Expected: three SSDF timers active on ct109 (`ssdf-topo`, `ssdf-entity`, `ssdf-policy`).

- [ ] **Step 7: Record as-built coords** in `services/policy/infra/ENV.local` (gitignored) — venv
  path, env path, MCP endpoints. No commit (file is ignored).

---

## Task 14: Live integration test (against deployed CH + MCPs)

**Files:**
- Create: `services/policy/tests/test_live_integration.py`

- [ ] **Step 1: Write the integration test** (marked `integration`, deselected by default)

```python
import os
import pytest

pytestmark = pytest.mark.integration


def _env(name):
    val = os.environ.get(name)
    if not val:
        pytest.skip(f"{name} not set")
    return val


def test_panos_collector_returns_rules_live():
    from ssdf_policy.config import McpEndpoint
    from ssdf_policy.mcp_client import McpToolClient
    from ssdf_policy.collectors.panos import PanosPolicyCollector
    ep = McpEndpoint(_env("PANOS_MCP_URL"), os.environ.get("PANOS_MCP_TOKEN", ""))
    rules = PanosPolicyCollector(os.environ.get("PANOS_DEVICE", "panosvm")).collect(
        McpToolClient(ep), "2026-06-08T00:00:00")
    assert rules, "expected at least one configured PAN-OS rule"
    assert all(r["rule_name"] and r["device_name"] for r in rules)


def test_resolve_and_write_live():
    from ssdf_policy.config import load_config
    from ssdf_policy.chwriter import ClickHouseEntityWriter
    from ssdf_policy.collect_resolve import run_once, _build_collector
    from ssdf_policy.mcp_client import McpToolClient
    cfg = load_config()
    writer = ClickHouseEntityWriter(cfg)
    n_ent, n_edge = run_once(
        enabled=cfg.enabled_collectors,
        collector_factory=_build_collector,
        client_factory=lambda name: McpToolClient(cfg.mcp_endpoint(name)),
        writer=writer, tenant=cfg.tenant_id, now="2026-06-08T00:00:00",
    )
    assert n_ent >= 2 and n_edge >= 1
```

- [ ] **Step 2: Run the integration test on ct109** (where env + network reach the MCPs/CH)

```bash
ssh root@pve3.example.com "pct exec 109 -- bash -lc 'set -a; . /etc/ssdf-policy/ENV.local; set +a; cd /opt/src/policy && /opt/ssdf-policy/bin/pip install pytest >/dev/null && /opt/ssdf-policy/bin/python -m pytest -m integration -v'"
```
Expected: PASS (skips only if an MCP URL is unset).

- [ ] **Step 3: Validate explain_access end-to-end via the live MCP (ct106)**

Call the `explain_access` tool on `ssdf-mcp-query` for a client/server pair whose M4 topology
path crosses a firewall (use `enforcement_points` first to pick a pair). Assert the response has
a non-empty `configured_controls` block and `coverage.configured > 0`. Record the JSON snippet
in the PR description as proof.

- [ ] **Step 4: Commit**

```bash
git add services/policy/tests/test_live_integration.py
git commit -m "test(m6b): live integration for collector + resolver + explain_access"
```

---

## Task 15: Documentation (CLAUDE.md + STATUS.md)

**Files:**
- Modify: `CLAUDE.md` (Commands section)
- Modify: `docs/superpowers/STATUS.md`

- [ ] **Step 1: Add an M6b Commands subsection to `CLAUDE.md`** after the M6a block

```markdown
### M6b (configured policy — services/policy + explain_access configured_controls)
- Policy unit tests: `cd services/policy && uv run pytest -m "not integration"`
- Live integration (needs CH + vendor MCPs): `cd services/policy && CH_PASSWORD=<pw> PANOS_MCP_URL=… PANOS_MCP_TOKEN=… JUNOS_MCP_URL=… JUNOS_MCP_TOKEN=… JUNOS_DEVICES=vSRX-test10 uv run pytest -m integration`
- One pass: `cd services/policy && uv run python -m ssdf_policy.collect_resolve`
- Deployed: collector+resolver on ct109 (third role alongside topo+entity; venv /opt/ssdf-policy, env /etc/ssdf-policy/ENV.local mode 600) on an HOURLY systemd timer (`ssdf-policy.timer` → oneshot `ssdf-policy.service`); writes CH ct104 as `ssdf_entity` into the shared `ssdf.entities`/`ssdf.entity_edges` (kind='firewall'|'policy', source='configured'). `explain_access` (ct106) gains `configured_controls` + integer `coverage.configured`.
- Device names in `JUNOS_DEVICES`/`PANOS_DEVICE` MUST match M4 `source_device` names so explain_access can bridge topology firewalls → Firewall entities by name.
- Junos rules read via `execute_junos_command "show configuration security policies | display set"`; PAN-OS via `get_pan_config` (vsys1 security rulebase, pinned to 12.1 config shape).
```

- [ ] **Step 2: Update `docs/superpowers/STATUS.md`** — add an M6b as-built row to the
  milestone table and flip the M6b forward-roadmap entry from "Deferred" to Done, noting:
  configured Policy keyed `(provider, device, rule_name)` (fixes same-name collapse); Firewall
  entities + `GOVERNED_BY(configured)` edges; hourly timer on ct109; `coverage.configured` now
  an integer count. Keep the M6c entry as the next deferred milestone.

- [ ] **Step 3: Commit**

```bash
git add CLAUDE.md docs/superpowers/STATUS.md
git commit -m "docs(m6b): record configured-policy commands + status"
```

---

## Final review

- [ ] Run the full unit suites: `cd services/policy && uv run pytest -m "not integration"`
  and `cd services/mcp-query && uv run pytest -m "not integration"` — all green.
- [ ] Dispatch a code-reviewer over the whole M6b branch against this plan + the spec.
- [ ] Use superpowers:finishing-a-development-branch to open the PR (include the live
  `explain_access` JSON proof from Task 14 Step 3).

---

## Execution Handoff

Plan complete and saved to
`docs/superpowers/plans/2026-06-08-ssdf-m6b-configured-policy.md`. Two execution options:

1. **Subagent-Driven (recommended)** — fresh subagent per task, two-stage review between tasks.
2. **Inline Execution** — execute tasks in this session with checkpoints.

Which approach?
