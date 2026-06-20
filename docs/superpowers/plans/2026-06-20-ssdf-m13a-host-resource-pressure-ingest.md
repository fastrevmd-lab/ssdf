# M13a — Host Resource-Pressure Ingest Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a 5th ct109 poller role (`services/health`) that collects CPU%/mem%/temperature from Proxmox, vSRX/Junos, PAN-OS, and UniFi via existing MCP paths and writes them to a new `ssdf.health_metrics` table for sovereign querying.

**Architecture:** One unified Python poller mirroring `services/topo`'s collector pattern — a `Gauge` dataclass as the normalized unit, a thin per-vendor collector module each returning `list[Gauge]`, a fault-isolated `run_collectors`, and a vendor-agnostic ClickHouse writer. New EAV-style table `ssdf.health_metrics` (migration 014) + INSERT-only `ssdf_health` user (015). 5-min systemd timer on ct109. Sovereign-only; public de-id deferred.

**Tech Stack:** Python 3.11 (uv), `clickhouse-connect`, `fastmcp` client, ClickHouse, systemd timer on Proxmox LXC ct109.

**Spec:** `docs/superpowers/specs/2026-06-20-ssdf-m13a-host-resource-pressure-ingest-design.md`

**Reference implementations to mirror (read these first):**
- `services/topo/src/ssdf_topo/collectors/base.py` — collector protocol + registry
- `services/topo/src/ssdf_topo/collect_all.py` — `run_collectors` fault isolation
- `services/topo/src/ssdf_topo/mcp_client.py` — `McpToolClient` + `extract_text`
- `services/topo/src/ssdf_topo/config.py` — env-driven `Config` + `McpEndpoint`
- `services/topo/src/ssdf_topo/chwriter.py` — `client_kwargs` (TLS) + typed insert
- `services/public-metrics/infra/ssdf-public-metrics.{service,timer}` — deploy shape

---

## File Structure

```
services/health/
  pyproject.toml                          # package + pytest config
  src/ssdf_health/
    __init__.py
    gauge.py                              # Gauge dataclass (normalized unit)
    config.py                             # env-driven Config + McpEndpoint
    mcp_client.py                         # McpToolClient + extract_text (copied from topo)
    chwriter.py                           # HealthWriter (typed insert to ssdf.health_metrics)
    collect_main.py                       # entrypoint: collect → write one batch
    collectors/
      __init__.py                         # imports all modules to trigger @register
      base.py                             # Collector protocol + REGISTRY + run_collectors
      proxmox.py
      junos.py
      panos.py
      unifi.py
  tests/
    test_gauge.py
    test_config.py
    test_mcp_client.py
    test_base.py
    test_proxmox.py
    test_junos.py
    test_panos.py
    test_unifi.py
    test_chwriter.py
    test_collect_main.py
    test_health_metrics_integration.py    # -m integration (live CH + MCPs)
  infra/
    ssdf-health.service
    ssdf-health.timer
    ENV.local.example
infra/clickhouse/
  014_health_metrics.sql                  # table (envsubst HEALTH_TTL_DAYS)
  015_health_user.sql                     # ssdf_health user (envsubst HEALTH_PW)
```

Modify:
- `services/public-metrics/src/ssdf_pubmetrics/measures.py` — update the Tier-3 comment to record the `ssdf.health_metrics` source seam (no behavior change).
- `CLAUDE.md` — add the M13a commands block.
- `docs/superpowers/STATUS.md` — add the M13a milestone entry.

---

This plan is delivered in parts. The tasks below (Part 1) cover scaffolding, storage, and the shared infrastructure (Gauge, config, mcp_client, base/run_collectors). Parts 2–4 (the four collectors, writer, entrypoint, deploy, docs) follow in subsequent plan files committed alongside this one, OR appended here — see "Remaining parts" at the end.

---

## Task 1: Scaffold package + Gauge dataclass

**Files:**
- Create: `services/health/pyproject.toml`
- Create: `services/health/src/ssdf_health/__init__.py`
- Create: `services/health/src/ssdf_health/gauge.py`
- Test: `services/health/tests/test_gauge.py`

- [ ] **Step 1: Create the package layout and pyproject.toml**

Create `services/health/pyproject.toml`:

```toml
[project]
name = "ssdf-health"
version = "0.1.0"
description = "SSDF M13a host resource-pressure poller (MCP -> ssdf.health_metrics)"
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
packages = ["src/ssdf_health"]

[tool.pytest.ini_options]
testpaths = ["tests"]
pythonpath = ["src"]
markers = ["integration: requires live ClickHouse + MCP servers (deselect with -m 'not integration')"]

[dependency-groups]
dev = ["pytest>=8.0"]
```

Create empty `services/health/src/ssdf_health/__init__.py` (zero bytes).

- [ ] **Step 2: Write the failing test**

Create `services/health/tests/test_gauge.py`:

```python
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
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd services/health && uv run pytest tests/test_gauge.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'ssdf_health.gauge'`

- [ ] **Step 4: Write the minimal implementation**

Create `services/health/src/ssdf_health/gauge.py`:

```python
"""The normalized unit every collector emits: one numeric gauge reading."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Gauge:
    provider: str       # proxmox|juniper|paloalto|unifi
    device: str         # node/router/host/device name (same name topo/policy use)
    scope: str          # device|guest|node
    metric_class: str   # cpu|memory|temperature
    sensor: str         # '' for a device-scalar reading; label for multi-sensor
    metric_name: str    # cpu_util_pct|mem_util_pct|temp_celsius
    value: float
    unit: str           # percent|celsius
    raw: str            # source line/snippet for provenance/debug
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd services/health && uv run pytest tests/test_gauge.py -v`
Expected: PASS (2 passed)

- [ ] **Step 6: Commit**

```bash
git add services/health/pyproject.toml services/health/src/ssdf_health/__init__.py services/health/src/ssdf_health/gauge.py services/health/tests/test_gauge.py
git commit -m "feat(m13a): scaffold ssdf-health package + Gauge dataclass"
```

---

## Task 2: ClickHouse migrations (014 table + 015 user)

**Files:**
- Create: `infra/clickhouse/014_health_metrics.sql`
- Create: `infra/clickhouse/015_health_user.sql`

These are SQL DDL applied with `envsubst` (the established pattern — see `005_entity_user.sql`, `013_public_metrics.sql`). They are verified live in Task 11 (integration). This task only creates and structurally checks them.

- [ ] **Step 1: Create the table migration**

Create `infra/clickhouse/014_health_metrics.sql`:

```sql
-- infra/clickhouse/014_health_metrics.sql
-- M13a host resource-pressure ingest: a narrow long-format (EAV-style) gauge table.
-- One row per (device, metric, sensor, timestamp) reading; a vendor exposing a new
-- sensor lands as new rows with a new `sensor` value -- zero schema change.
-- TTL is configurable; substitute before applying (default 30 days):
--   HEALTH_TTL_DAYS=30 envsubst < 014_health_metrics.sql \
--     | clickhouse-client --host <ct104> --multiquery
CREATE TABLE IF NOT EXISTS ssdf.health_metrics (
    timestamp     DateTime64(3,'UTC'),
    tenant_id     LowCardinality(String) DEFAULT 't_main',
    provider      LowCardinality(String),
    device        LowCardinality(String),
    scope         LowCardinality(String) DEFAULT 'device',
    metric_class  LowCardinality(String),
    sensor        LowCardinality(String) DEFAULT '',
    metric_name   LowCardinality(String),
    metric_value  Float64,
    unit          LowCardinality(String),
    raw           String DEFAULT ''
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (tenant_id, provider, device, metric_class, sensor, timestamp)
TTL toDateTime(timestamp) + INTERVAL ${HEALTH_TTL_DAYS:-30} DAY;

-- Sovereign read access (run_sql / describe_schema surface this immediately).
GRANT SELECT ON ssdf.health_metrics TO ssdf_ro;
```

- [ ] **Step 2: Create the user migration**

Create `infra/clickhouse/015_health_user.sql`:

```sql
-- infra/clickhouse/015_health_user.sql
-- Least-privilege writer for the M13a health poller. Run as CH admin.
-- ClickHouse does NOT expand {name:Type} params inside CREATE USER ... BY '...',
-- so inject the password before applying (never commit the real value):
--   HEALTH_PW="$CH_HEALTH_PASSWORD" envsubst < 015_health_user.sql \
--     | clickhouse-client --host <ct104> --multiquery
CREATE USER IF NOT EXISTS ssdf_health IDENTIFIED WITH sha256_password BY '${HEALTH_PW}';
GRANT INSERT ON ssdf.health_metrics TO ssdf_health;
```

- [ ] **Step 3: Structurally verify both files**

Run: `grep -c "health_metrics" infra/clickhouse/014_health_metrics.sql infra/clickhouse/015_health_user.sql`
Expected: `014_...:3` (table name, ORDER BY uses columns not the table, GRANT) and `015_...:2` — both non-zero. Confirm `014` contains `ENGINE = MergeTree` and `TTL`, and `015` contains `GRANT INSERT`.

- [ ] **Step 4: Commit**

```bash
git add infra/clickhouse/014_health_metrics.sql infra/clickhouse/015_health_user.sql
git commit -m "feat(m13a): add health_metrics table (014) + ssdf_health user (015)"
```

---

## Task 3: Config (env-driven)

**Files:**
- Create: `services/health/src/ssdf_health/config.py`
- Test: `services/health/tests/test_config.py`

- [ ] **Step 1: Write the failing test**

Create `services/health/tests/test_config.py`:

```python
import pytest

from ssdf_health.config import Config, ConfigError, load_config


def test_load_config_requires_ch_password(monkeypatch):
    monkeypatch.delenv("CH_PASSWORD", raising=False)
    with pytest.raises(ConfigError):
        load_config()


def test_load_config_defaults_and_device_lists(monkeypatch):
    monkeypatch.setenv("CH_PASSWORD", "secret")
    monkeypatch.setenv("JUNOS_DEVICES", "vSRX-test10, vSRX-Production")
    monkeypatch.setenv("UNIFI_DEVICE_MACS", "aa:bb:cc:dd:ee:ff")
    monkeypatch.delenv("HEALTH_COLLECTORS", raising=False)
    config = load_config()
    assert config.ch_user == "ssdf_health"
    assert config.ch_port == 8123
    assert config.junos_devices == ["vSRX-test10", "vSRX-Production"]
    assert config.unifi_macs == ["aa:bb:cc:dd:ee:ff"]
    assert config.enabled_collectors == ("proxmox", "junos", "panos", "unifi")


def test_mcp_endpoint_requires_url(monkeypatch):
    monkeypatch.setenv("CH_PASSWORD", "secret")
    monkeypatch.delenv("JUNOS_MCP_URL", raising=False)
    config = load_config()
    with pytest.raises(ConfigError):
        config.mcp_endpoint("junos")


def test_ch_secure_parsed(monkeypatch):
    monkeypatch.setenv("CH_PASSWORD", "secret")
    monkeypatch.setenv("CH_SECURE", "1")
    monkeypatch.setenv("CH_CA_FILE", "/etc/ca.crt")
    config = load_config()
    assert config.ch_secure is True
    assert config.ch_ca_file == "/etc/ca.crt"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd services/health && uv run pytest tests/test_config.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'ssdf_health.config'`

- [ ] **Step 3: Write the implementation**

Create `services/health/src/ssdf_health/config.py`:

```python
"""Runtime configuration for the M13a health poller (env-driven).

Writes ClickHouse as the ssdf_health user. Device lists name the same devices
topo/policy use so health rows bridge to topology identity later.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

ALL_COLLECTORS = ("proxmox", "junos", "panos", "unifi")


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
    junos_devices: list[str]
    panos_device: str
    unifi_macs: list[str]
    unifi_site_id: str
    ch_secure: bool = False
    ch_ca_file: str = ""

    def mcp_endpoint(self, name: str) -> McpEndpoint:
        prefix = name.upper()
        url = os.environ.get(f"{prefix}_MCP_URL")
        token = os.environ.get(f"{prefix}_MCP_TOKEN", "")
        if not url:
            raise ConfigError(f"missing {prefix}_MCP_URL for collector '{name}'")
        return McpEndpoint(url=url, token=token)


def _csv(name: str) -> list[str]:
    return [item.strip() for item in os.environ.get(name, "").split(",") if item.strip()]


def load_config() -> Config:
    password = os.environ.get("CH_PASSWORD")
    if password is None:
        raise ConfigError("CH_PASSWORD is required")
    raw = os.environ.get("HEALTH_COLLECTORS", ",".join(ALL_COLLECTORS))
    enabled = tuple(c.strip() for c in raw.split(",") if c.strip())
    return Config(
        ch_host=os.environ.get("CH_HOST", "127.0.0.1"),
        ch_port=int(os.environ.get("CH_PORT", "8123")),
        ch_user=os.environ.get("CH_USER", "ssdf_health"),
        ch_password=password,
        ch_database=os.environ.get("CH_DATABASE", "ssdf"),
        tenant_id=os.environ.get("HEALTH_TENANT", "t_main"),
        enabled_collectors=enabled,
        junos_devices=_csv("JUNOS_DEVICES"),
        panos_device=os.environ.get("PANOS_DEVICE", "panosvm"),
        unifi_macs=_csv("UNIFI_DEVICE_MACS"),
        unifi_site_id=os.environ.get("UNIFI_SITE_ID", "default"),
        ch_secure=os.environ.get("CH_SECURE", "0").strip().lower() in ("1", "true"),
        ch_ca_file=os.environ.get("CH_CA_FILE", ""),
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd services/health && uv run pytest tests/test_config.py -v`
Expected: PASS (4 passed)

- [ ] **Step 5: Commit**

```bash
git add services/health/src/ssdf_health/config.py services/health/tests/test_config.py
git commit -m "feat(m13a): env-driven config for the health poller"
```

---

## Task 4: MCP client (copied from topo)

**Files:**
- Create: `services/health/src/ssdf_health/mcp_client.py`
- Test: `services/health/tests/test_mcp_client.py`

The `McpToolClient` + `extract_text` are copied verbatim from `services/topo/src/ssdf_topo/mcp_client.py` (each service owns its copy — there is no shared lib). Only the `config` import path changes.

- [ ] **Step 1: Write the failing test**

Create `services/health/tests/test_mcp_client.py`:

```python
from ssdf_health.mcp_client import extract_text


class _Block:
    def __init__(self, text):
        self.text = text


class _Result:
    def __init__(self, structured=None, content=None):
        self.structured_content = structured
        self.content = content


def test_extract_text_prefers_structured_content():
    result = _Result(structured={"cpu": 12.5})
    assert extract_text(result) == '{"cpu": 12.5}'


def test_extract_text_joins_text_blocks():
    result = _Result(content=[_Block("line1"), _Block("line2")])
    assert extract_text(result) == "line1\nline2"


def test_extract_text_empty():
    result = _Result()
    assert extract_text(result) == ""
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd services/health && uv run pytest tests/test_mcp_client.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'ssdf_health.mcp_client'`

- [ ] **Step 3: Write the implementation**

Create `services/health/src/ssdf_health/mcp_client.py`:

```python
"""Minimal synchronous MCP client wrapper for collectors (bearer-auth HTTP).

Copied from services/topo/src/ssdf_topo/mcp_client.py -- each service owns its copy.
"""

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

- [ ] **Step 4: Run test to verify it passes**

Run: `cd services/health && uv run pytest tests/test_mcp_client.py -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Commit**

```bash
git add services/health/src/ssdf_health/mcp_client.py services/health/tests/test_mcp_client.py
git commit -m "feat(m13a): MCP tool client wrapper (copied from topo)"
```

---

## Task 5: Collector base — protocol, registry, fault-isolated run_collectors

**Files:**
- Create: `services/health/src/ssdf_health/collectors/base.py`
- Test: `services/health/tests/test_base.py`

- [ ] **Step 1: Write the failing test**

Create `services/health/tests/test_base.py`:

```python
from ssdf_health.collectors.base import REGISTRY, register, get_collector, run_collectors
from ssdf_health.gauge import Gauge


def test_register_adds_to_registry():
    @register("dummy_reg")
    class _Dummy:
        name = "dummy_reg"
    assert REGISTRY["dummy_reg"] is _Dummy
    assert get_collector("dummy_reg") is _Dummy


def test_get_collector_unknown_raises():
    try:
        get_collector("nope")
        assert False
    except KeyError:
        pass


def _gauge(metric_name):
    return Gauge("p", "d", "device", "cpu", "", metric_name, 1.0, "percent", "")


def test_run_collectors_skips_failing_collector(caplog):
    class _Good:
        name = "good"
        def collect(self, client, now):
            return [_gauge("cpu_util_pct")]

    class _Bad:
        name = "bad"
        def collect(self, client, now):
            raise RuntimeError("boom")

    factories = {"good": _Good(), "bad": _Bad()}
    written = []

    class _Writer:
        def insert_gauges(self, gauges, now):
            written.extend(gauges)
            return len(gauges)

    total = run_collectors(
        enabled=["bad", "good"],
        client_factory=lambda name: None,
        collector_factory=lambda name: factories[name],
        writer=_Writer(),
        now="2026-06-20T00:00:00Z",
    )
    # bad raised and was skipped; good still produced one gauge
    assert total == 1
    assert len(written) == 1
    assert written[0].metric_name == "cpu_util_pct"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd services/health && uv run pytest tests/test_base.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'ssdf_health.collectors'`

- [ ] **Step 3: Write the implementation**

Create `services/health/src/ssdf_health/collectors/__init__.py`:

```python
"""Importing this package registers every collector via @register decorators."""

from . import proxmox  # noqa: F401
from . import junos    # noqa: F401
from . import panos    # noqa: F401
from . import unifi    # noqa: F401
```

> NOTE: the four imports will fail until Tasks 6–9 create those modules. Until then, temporarily make `__init__.py` empty (zero bytes) so `base.py` is importable, and restore the four imports in Task 9. The `base.py` tests do not import the package's `__init__`.

For THIS task, create `services/health/src/ssdf_health/collectors/__init__.py` as an **empty file** (zero bytes). Then create `services/health/src/ssdf_health/collectors/base.py`:

```python
"""Collector protocol, a name->class registry, and the fault-isolated runner."""

from __future__ import annotations

import logging
from typing import Callable, Protocol

from ..gauge import Gauge
from ..mcp_client import McpToolClient

logger = logging.getLogger(__name__)

REGISTRY: dict[str, type] = {}


class Collector(Protocol):
    name: str

    def collect(self, client: McpToolClient, now: str) -> list[Gauge]:
        """Pull read-only telemetry via the MCP client; return normalized gauges."""
        ...


def register(name: str) -> Callable[[type], type]:
    def _wrap(cls: type) -> type:
        REGISTRY[name] = cls
        return cls
    return _wrap


def get_collector(name: str) -> type:
    if name not in REGISTRY:
        raise KeyError(f"unknown collector: {name}")
    return REGISTRY[name]


def run_collectors(enabled, client_factory, collector_factory, writer, now: str) -> int:
    """Run each enabled collector; skip any that raise, log a warning, and continue.

    Returns the total number of gauges written.
    """
    total = 0
    for name in enabled:
        try:
            collector = collector_factory(name)
            client = client_factory(name)
            gauges = collector.collect(client, now)
            if not gauges:
                logger.warning("collector %r returned 0 gauges", name)
            total += writer.insert_gauges(gauges, now)
        except Exception:
            logger.warning("collector %r failed; skipping", name, exc_info=True)
    return total
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd services/health && uv run pytest tests/test_base.py -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Commit**

```bash
git add services/health/src/ssdf_health/collectors/__init__.py services/health/src/ssdf_health/collectors/base.py services/health/tests/test_base.py
git commit -m "feat(m13a): collector protocol + registry + fault-isolated run_collectors"
```

---

## Remaining parts

Part 1 (Tasks 1–5: scaffold, migrations, config, mcp_client, base) is complete above. The remaining tasks are detailed in the companion plan file committed alongside this one:

- **Task 6:** Proxmox collector (node + guest CPU/mem) — `collectors/proxmox.py`
- **Task 7:** Junos collector (RE CPU/mem + chassis-environment temps) — `collectors/junos.py`
- **Task 8:** PAN-OS collector (resources CPU/mem + environmentals temps) — `collectors/panos.py`
- **Task 9:** UniFi collector (system-stats CPU/mem + temperatures[]) — `collectors/unifi.py`; restore `collectors/__init__.py` imports
- **Task 10:** `HealthWriter` (typed insert to `ssdf.health_metrics`) — `chwriter.py`
- **Task 11:** `collect_main` entrypoint + live integration test
- **Task 12:** systemd units + `ENV.local.example`
- **Task 13:** M7c `measures.py` seam comment + `CLAUDE.md` + `STATUS.md` docs

See `2026-06-20-ssdf-m13a-host-resource-pressure-ingest-part2.md`.
```
