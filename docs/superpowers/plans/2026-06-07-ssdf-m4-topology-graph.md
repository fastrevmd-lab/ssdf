# SSDF M4 — Topology / Connectivity Graph Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Derive a provider-agnostic connectivity/topology graph from ClickHouse so an LLM/human can see how the network is wired, how traffic flows, and where an enforcement point sits — read-only.

**Architecture:** Read-only Python collectors (MCP clients to deployed junos/unifi/panos/proxmox MCPs) land LLDP/MAC/ARP/iface observations into `ssdf.topo_observations`. A periodic stateless resolver fuses those with flow aggregates from `ssdf.events` into `ssdf.graph_nodes` / `ssdf.graph_edges` (ReplacingMergeTree upsert). New read-only topology tools in the existing `ssdf-mcp-query` service load the small subgraph into memory (networkx) for `locate`/`find_path`/`enforcement_points`.

**Tech Stack:** Python 3.11+, `uv`, `clickhouse-connect`, `fastmcp`, `networkx`, MCP client (`fastmcp.Client`), pytest (`-m integration` for live). ClickHouse on ct104; new `services/topo` on ct107; topology tools added to `ssdf-mcp-query` on ct106.

**Spec:** `docs/superpowers/specs/2026-06-07-ssdf-m4-topology-graph-design.md`

**Phasing:** Each phase ends green + committable. Phase 0 (schema) → 1 (scaffold/models/writer) → 2 (MCP client + collector base) → 3 (4 collectors) → 4 (resolver) → 5 (MCP topology tools) → 6 (deploy + docs).

---

## Phase 0 — ClickHouse schema + writer user

### Task 0.1: Topology DDL

**Files:**
- Create: `infra/clickhouse/002_topology.sql`

- [ ] **Step 1: Write the DDL**

```sql
-- infra/clickhouse/002_topology.sql
-- M4 topology graph: append-only observations + materialized node/edge projection.

CREATE TABLE IF NOT EXISTS ssdf.topo_observations
(
    observed_at      DateTime64(3, 'UTC'),
    collector        LowCardinality(String),
    source_device    String,
    tenant_id        LowCardinality(String) DEFAULT 't_main',
    layer            LowCardinality(String),
    observation_type LowCardinality(String),
    subj_kind        LowCardinality(String),
    subj_id          String,
    obj_kind         LowCardinality(String),
    obj_id           String,
    attrs            Map(String, String),
    raw              String
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(observed_at)
ORDER BY (tenant_id, collector, observed_at)
TTL toDateTime(observed_at) + INTERVAL 30 DAY;

CREATE TABLE IF NOT EXISTS ssdf.graph_nodes
(
    node_id     String,
    tenant_id   LowCardinality(String) DEFAULT 't_main',
    kind        LowCardinality(String),
    name        String,
    identifiers Map(String, String),
    first_seen  DateTime64(3, 'UTC'),
    last_seen   DateTime64(3, 'UTC'),
    attrs       Map(String, String)
)
ENGINE = ReplacingMergeTree(last_seen)
ORDER BY (tenant_id, node_id);

CREATE TABLE IF NOT EXISTS ssdf.graph_edges
(
    edge_id    String,
    tenant_id  LowCardinality(String) DEFAULT 't_main',
    src_id     String,
    dst_id     String,
    edge_type  LowCardinality(String),
    layer      LowCardinality(String),
    first_seen DateTime64(3, 'UTC'),
    last_seen  DateTime64(3, 'UTC'),
    confidence Float32,
    attrs      Map(String, String)
)
ENGINE = ReplacingMergeTree(last_seen)
ORDER BY (tenant_id, edge_id);
```

- [ ] **Step 2: Apply against live CH and verify**

Run: `CH_HOST=<ct104-ip> clickhouse-client --host "$CH_HOST" --multiquery < infra/clickhouse/002_topology.sql`
Then: `clickhouse-client --host "$CH_HOST" --query "SELECT name FROM system.tables WHERE database='ssdf' AND name IN ('topo_observations','graph_nodes','graph_edges') ORDER BY name"`
Expected output (3 lines): `graph_edges` / `graph_nodes` / `topo_observations`

- [ ] **Step 3: Commit**

```bash
git add infra/clickhouse/002_topology.sql
git commit -m "feat(m4): clickhouse topology graph schema (observations + nodes/edges)"
```

### Task 0.2: Apply-schema script + writer-user doc

**Files:**
- Create: `scripts/apply_topology_schema.sh`
- Create: `infra/clickhouse/003_topo_user.sql`

- [ ] **Step 1: Write the writer-user DDL** (run manually as CH admin; password injected, never committed)

```sql
-- infra/clickhouse/003_topo_user.sql
-- Least-privilege writer for the M4 topo service. Run as CH admin.
-- Usage: clickhouse-client --host <ct104> --param_pw "$TOPO_PW" --multiquery < 003_topo_user.sql
CREATE USER IF NOT EXISTS ssdf_topo IDENTIFIED WITH sha256_password BY '{pw:String}';
GRANT INSERT, SELECT ON ssdf.topo_observations TO ssdf_topo;
GRANT INSERT, SELECT ON ssdf.graph_nodes TO ssdf_topo;
GRANT INSERT, SELECT ON ssdf.graph_edges TO ssdf_topo;
GRANT SELECT ON ssdf.events TO ssdf_topo;
```

- [ ] **Step 2: Write the apply script**

```bash
#!/usr/bin/env bash
# Applies the topology DDL and asserts the three tables exist.
# Usage: CH_HOST=<ip> ./scripts/apply_topology_schema.sh
set -euo pipefail
CH_HOST="${CH_HOST:-127.0.0.1}"
SQL_FILE="$(dirname "$0")/../infra/clickhouse/002_topology.sql"

clickhouse-client --host "$CH_HOST" --multiquery < "$SQL_FILE"

N=$(clickhouse-client --host "$CH_HOST" --query \
  "SELECT count() FROM system.tables WHERE database='ssdf' AND name IN ('topo_observations','graph_nodes','graph_edges')")
if [ "$N" -ne 3 ]; then
  echo "FAIL: expected 3 topology tables, found $N"; exit 1
fi
echo "OK: topology tables present"
```

- [ ] **Step 3: Make executable + run**

Run: `chmod +x scripts/apply_topology_schema.sh && CH_HOST=<ct104-ip> ./scripts/apply_topology_schema.sh`
Expected: `OK: topology tables present`

- [ ] **Step 4: Commit**

```bash
git add scripts/apply_topology_schema.sh infra/clickhouse/003_topo_user.sql
git commit -m "feat(m4): topology schema apply script + ssdf_topo writer user DDL"
```

---

## Phase 1 — Service scaffold, models, ClickHouse writer

### Task 1.1: Package scaffold

**Files:**
- Create: `services/topo/pyproject.toml`
- Create: `services/topo/src/ssdf_topo/__init__.py`
- Create: `services/topo/tests/__init__.py`

- [ ] **Step 1: Write pyproject.toml**

```toml
[project]
name = "ssdf-topo"
version = "0.1.0"
description = "SSDF M4 topology collectors + resolver (ClickHouse-derived connectivity graph)"
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
packages = ["src/ssdf_topo"]

[tool.pytest.ini_options]
testpaths = ["tests"]
markers = ["integration: requires live ClickHouse and/or live MCP servers (deselect with -m 'not integration')"]
```

- [ ] **Step 2: Create empty package files**

`services/topo/src/ssdf_topo/__init__.py` and `services/topo/tests/__init__.py` are empty files.

- [ ] **Step 3: Verify install**

Run: `cd services/topo && uv sync --extra dev`
Expected: resolves and installs without error.

- [ ] **Step 4: Commit**

```bash
git add services/topo/pyproject.toml services/topo/src/ssdf_topo/__init__.py services/topo/tests/__init__.py
git commit -m "chore(m4): scaffold ssdf-topo python package"
```

### Task 1.2: Core models (Observation + id hashing + taxonomy constants)

**Files:**
- Create: `services/topo/src/ssdf_topo/models.py`
- Test: `services/topo/tests/test_models.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_models.py
from ssdf_topo.models import (
    Observation, node_id, edge_id, NODE_KINDS, EDGE_TYPES, LAYERS,
    HOST, DEVICE, PHYSICAL_LINK,
)

def test_node_id_is_deterministic_and_keyed():
    a = node_id("t_main", HOST, "mac:aa:bb:cc:dd:ee:ff")
    b = node_id("t_main", HOST, "mac:aa:bb:cc:dd:ee:ff")
    c = node_id("t_main", HOST, "mac:11:22:33:44:55:66")
    assert a == b and a != c
    assert len(a) == 16

def test_node_id_kind_separates_namespace():
    assert node_id("t_main", HOST, "x") != node_id("t_main", DEVICE, "x")

def test_edge_id_is_directional_and_typed():
    e1 = edge_id("t_main", "n1", "n2", PHYSICAL_LINK, "l2")
    e2 = edge_id("t_main", "n2", "n1", PHYSICAL_LINK, "l2")
    assert e1 != e2 and len(e1) == 16

def test_observation_defaults():
    obs = Observation(
        observed_at="2026-06-07T00:00:00+00:00", collector="junos",
        source_device="vSRX-test10", layer="l2", observation_type="lldp_neighbor",
        subj_kind="interface", subj_id="if:vSRX-test10:ge-0/0/0",
        obj_kind="interface", obj_id="if:sw1:ge-1",
    )
    assert obs.tenant_id == "t_main" and obs.attrs == {} and obs.raw == ""

def test_taxonomy_constants():
    assert HOST in NODE_KINDS and DEVICE in NODE_KINDS
    assert PHYSICAL_LINK in EDGE_TYPES
    assert "l2" in LAYERS and "flow" in LAYERS
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd services/topo && uv run pytest tests/test_models.py -v`
Expected: FAIL (ModuleNotFoundError: ssdf_topo.models)

- [ ] **Step 3: Write models.py**

```python
# src/ssdf_topo/models.py
"""Topology graph value types, taxonomy constants, and deterministic id hashing."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

# --- node kinds ---
DEVICE = "device"
INTERFACE = "interface"
HOST = "host"
IDENTITY = "identity"
SEGMENT = "segment"
ZONE = "zone"
RULE = "rule"
NODE_KINDS = {DEVICE, INTERFACE, HOST, IDENTITY, SEGMENT, ZONE, RULE}

# --- edge types ---
PHYSICAL_LINK = "physical_link"
ATTACHES_TO = "attaches_to"
HAS_ADDRESS = "has_address"
MEMBER_OF = "member_of"
ROUTES_TO = "routes_to"
TUNNEL = "tunnel"
HOSTS = "hosts"
TALKED_TO = "talked_to"
GOVERNED_BY = "governed_by"
IN_ZONE = "in_zone"
AUTHENTICATED_AS = "authenticated_as"
EDGE_TYPES = {
    PHYSICAL_LINK, ATTACHES_TO, HAS_ADDRESS, MEMBER_OF, ROUTES_TO, TUNNEL,
    HOSTS, TALKED_TO, GOVERNED_BY, IN_ZONE, AUTHENTICATED_AS,
}

LAYERS = {"l1", "l2", "l3", "virt", "flow"}


@dataclass(frozen=True)
class Observation:
    """One normalized fact a collector observed about the topology."""

    observed_at: str            # ISO-8601 UTC, e.g. "2026-06-07T12:00:00+00:00"
    collector: str
    source_device: str
    layer: str
    observation_type: str
    subj_kind: str
    subj_id: str
    obj_kind: str = ""
    obj_id: str = ""
    attrs: dict[str, str] = field(default_factory=dict)
    raw: str = ""
    tenant_id: str = "t_main"


def _hash16(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest()[:16]


def node_id(tenant: str, kind: str, canonical_key: str) -> str:
    """Stable 16-hex id for a node, namespaced by tenant + kind."""
    return _hash16(f"{tenant}|{kind}|{canonical_key}")


def edge_id(tenant: str, src_id: str, dst_id: str, edge_type: str, layer: str) -> str:
    """Stable 16-hex id for a directed, typed, layered edge."""
    return _hash16(f"{tenant}|{src_id}|{dst_id}|{edge_type}|{layer}")
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd services/topo && uv run pytest tests/test_models.py -v`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add services/topo/src/ssdf_topo/models.py services/topo/tests/test_models.py
git commit -m "feat(m4): topology models (Observation, taxonomy, id hashing)"
```

### Task 1.3: Config

**Files:**
- Create: `services/topo/src/ssdf_topo/config.py`
- Test: `services/topo/tests/test_config.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_config.py
import pytest
from ssdf_topo.config import load_config, ConfigError, McpEndpoint

def _base_env(monkeypatch):
    monkeypatch.setenv("CH_PASSWORD", "secret")
    monkeypatch.setenv("CH_HOST", "10.64.0.151")

def test_requires_ch_password(monkeypatch):
    monkeypatch.delenv("CH_PASSWORD", raising=False)
    with pytest.raises(ConfigError):
        load_config()

def test_defaults_and_writer_user(monkeypatch):
    _base_env(monkeypatch)
    cfg = load_config()
    assert cfg.ch_user == "ssdf_topo"     # writer, not ssdf_ro
    assert cfg.ch_host == "10.64.0.151"
    assert cfg.tenant_id == "t_main"
    assert cfg.window_hours == 24

def test_enabled_collectors_parsed(monkeypatch):
    _base_env(monkeypatch)
    monkeypatch.setenv("TOPO_COLLECTORS", "junos,unifi")
    cfg = load_config()
    assert cfg.enabled_collectors == ("junos", "unifi")

def test_mcp_endpoint_lookup(monkeypatch):
    _base_env(monkeypatch)
    monkeypatch.setenv("JUNOS_MCP_URL", "http://198.51.100.194:30031/mcp")
    monkeypatch.setenv("JUNOS_MCP_TOKEN", "tok123")
    cfg = load_config()
    ep = cfg.mcp_endpoint("junos")
    assert ep == McpEndpoint(url="http://198.51.100.194:30031/mcp", token="tok123")

def test_mcp_endpoint_missing_raises(monkeypatch):
    _base_env(monkeypatch)
    cfg = load_config()
    with pytest.raises(ConfigError):
        cfg.mcp_endpoint("junos")
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd services/topo && uv run pytest tests/test_config.py -v`
Expected: FAIL (ModuleNotFoundError)

- [ ] **Step 3: Write config.py**

```python
# src/ssdf_topo/config.py
"""Runtime configuration for the topo collectors + resolver (env-driven)."""

from __future__ import annotations

import os
from dataclasses import dataclass

ALL_COLLECTORS = ("junos", "unifi", "panos", "proxmox")


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
    window_hours: int
    enabled_collectors: tuple[str, ...]

    def mcp_endpoint(self, name: str) -> McpEndpoint:
        prefix = name.upper()
        url = os.environ.get(f"{prefix}_MCP_URL")
        token = os.environ.get(f"{prefix}_MCP_TOKEN", "")
        if not url:
            raise ConfigError(f"missing {prefix}_MCP_URL for collector '{name}'")
        return McpEndpoint(url=url, token=token)


def load_config() -> Config:
    password = os.environ.get("CH_PASSWORD")
    if password is None:
        raise ConfigError("CH_PASSWORD is required")
    raw = os.environ.get("TOPO_COLLECTORS", ",".join(ALL_COLLECTORS))
    enabled = tuple(c.strip() for c in raw.split(",") if c.strip())
    return Config(
        ch_host=os.environ.get("CH_HOST", "127.0.0.1"),
        ch_port=int(os.environ.get("CH_PORT", "8123")),
        ch_user=os.environ.get("CH_USER", "ssdf_topo"),
        ch_password=password,
        ch_database=os.environ.get("CH_DATABASE", "ssdf"),
        tenant_id=os.environ.get("TOPO_TENANT", "t_main"),
        window_hours=int(os.environ.get("TOPO_WINDOW_HOURS", "24")),
        enabled_collectors=enabled,
    )
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd services/topo && uv run pytest tests/test_config.py -v`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add services/topo/src/ssdf_topo/config.py services/topo/tests/test_config.py
git commit -m "feat(m4): topo service config (CH writer + per-MCP endpoints)"
```

### Task 1.4: ClickHouse writer (insert observations, upsert nodes/edges, read window)

**Files:**
- Create: `services/topo/src/ssdf_topo/chwriter.py`
- Test: `services/topo/tests/test_chwriter.py`

- [ ] **Step 1: Write the failing test** (unit-tests the row-shaping pure functions; live insert covered in integration)

```python
# tests/test_chwriter.py
from ssdf_topo.models import Observation
from ssdf_topo.chwriter import obs_rows, OBS_COLUMNS, node_rows, edge_rows, NODE_COLUMNS, EDGE_COLUMNS

def test_obs_rows_match_column_order():
    obs = Observation(
        observed_at="2026-06-07T00:00:00+00:00", collector="junos",
        source_device="vSRX-test10", layer="l3", observation_type="arp_entry",
        subj_kind="host", subj_id="ip:10.64.0.5", obj_kind="host", obj_id="mac:aa:bb:cc:dd:ee:ff",
        attrs={"interface": "ge-0/0/0"}, raw="10.64.0.5 aa:bb:cc:dd:ee:ff",
    )
    rows = obs_rows([obs])
    assert len(rows) == 1
    assert len(rows[0]) == len(OBS_COLUMNS)
    # column order: observed_at first, attrs/raw/tenant near end
    idx = {c: i for i, c in enumerate(OBS_COLUMNS)}
    assert rows[0][idx["collector"]] == "junos"
    assert rows[0][idx["attrs"]] == {"interface": "ge-0/0/0"}
    assert rows[0][idx["tenant_id"]] == "t_main"

def test_node_rows_shape():
    node = {
        "node_id": "abc", "tenant_id": "t_main", "kind": "host", "name": "h1",
        "identifiers": {"mac": "aa:bb"}, "first_seen": "2026-06-07T00:00:00+00:00",
        "last_seen": "2026-06-07T01:00:00+00:00", "attrs": {"unresolved": "l3_only"},
    }
    rows = node_rows([node])
    assert len(rows[0]) == len(NODE_COLUMNS)
    assert rows[0][NODE_COLUMNS.index("kind")] == "host"

def test_edge_rows_shape():
    edge = {
        "edge_id": "e1", "tenant_id": "t_main", "src_id": "n1", "dst_id": "n2",
        "edge_type": "physical_link", "layer": "l2",
        "first_seen": "2026-06-07T00:00:00+00:00", "last_seen": "2026-06-07T01:00:00+00:00",
        "confidence": 1.0, "attrs": {},
    }
    rows = edge_rows([edge])
    assert len(rows[0]) == len(EDGE_COLUMNS)
    assert rows[0][EDGE_COLUMNS.index("confidence")] == 1.0
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd services/topo && uv run pytest tests/test_chwriter.py -v`
Expected: FAIL (ModuleNotFoundError)

- [ ] **Step 3: Write chwriter.py**

```python
# src/ssdf_topo/chwriter.py
"""ClickHouse writer for topology data (the storage seam, write side)."""

from __future__ import annotations

from typing import Any, Iterable

import clickhouse_connect

from .config import Config
from .models import Observation

OBS_COLUMNS = [
    "observed_at", "collector", "source_device", "tenant_id", "layer",
    "observation_type", "subj_kind", "subj_id", "obj_kind", "obj_id", "attrs", "raw",
]
NODE_COLUMNS = [
    "node_id", "tenant_id", "kind", "name", "identifiers",
    "first_seen", "last_seen", "attrs",
]
EDGE_COLUMNS = [
    "edge_id", "tenant_id", "src_id", "dst_id", "edge_type", "layer",
    "first_seen", "last_seen", "confidence", "attrs",
]


def obs_rows(observations: Iterable[Observation]) -> list[list[Any]]:
    return [
        [
            o.observed_at, o.collector, o.source_device, o.tenant_id, o.layer,
            o.observation_type, o.subj_kind, o.subj_id, o.obj_kind, o.obj_id,
            o.attrs, o.raw,
        ]
        for o in observations
    ]


def node_rows(nodes: Iterable[dict]) -> list[list[Any]]:
    return [[n[c] for c in NODE_COLUMNS] for n in nodes]


def edge_rows(edges: Iterable[dict]) -> list[list[Any]]:
    return [[e[c] for c in EDGE_COLUMNS] for e in edges]


class ClickHouseWriter:
    """Insert observations and upsert nodes/edges; read the resolver input window."""

    def __init__(self, config: Config):
        self._config = config
        self._client = clickhouse_connect.get_client(
            host=config.ch_host, port=config.ch_port, username=config.ch_user,
            password=config.ch_password, database=config.ch_database,
        )

    def insert_observations(self, observations: list[Observation]) -> int:
        if not observations:
            return 0
        self._client.insert("topo_observations", obs_rows(observations), column_names=OBS_COLUMNS)
        return len(observations)

    def replace_nodes(self, nodes: list[dict]) -> int:
        if not nodes:
            return 0
        self._client.insert("graph_nodes", node_rows(nodes), column_names=NODE_COLUMNS)
        return len(nodes)

    def replace_edges(self, edges: list[dict]) -> int:
        if not edges:
            return 0
        self._client.insert("graph_edges", edge_rows(edges), column_names=EDGE_COLUMNS)
        return len(edges)

    def query(self, sql: str, params: dict | None = None) -> list[dict]:
        result = self._client.query(sql, parameters=params or {})
        cols = list(result.column_names)
        return [dict(zip(cols, row)) for row in result.result_rows]
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd services/topo && uv run pytest tests/test_chwriter.py -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add services/topo/src/ssdf_topo/chwriter.py services/topo/tests/test_chwriter.py
git commit -m "feat(m4): clickhouse writer (insert observations, upsert nodes/edges)"
```

---

## Phase 2 — MCP client wrapper + collector base

### Task 2.1: MCP client wrapper

**Files:**
- Create: `services/topo/src/ssdf_topo/mcp_client.py`
- Test: `services/topo/tests/test_mcp_client.py`

**Context:** `fastmcp.Client` connects to a streamable-HTTP MCP server with a bearer token and calls a tool. We wrap it so collectors call `call_tool(name, args) -> text`, with the result text extracted from the MCP content blocks. The wrapper is sync (collectors run in a one-shot batch) and hides the asyncio detail.

- [ ] **Step 1: Write the failing test** (no network: inject a fake async caller)

```python
# tests/test_mcp_client.py
from ssdf_topo.mcp_client import extract_text

def test_extract_text_joins_text_blocks():
    class Block:
        def __init__(self, text): self.text = text
    class Result:
        content = [Block("line1"), Block("line2")]
        structured_content = None
    assert extract_text(Result()) == "line1\nline2"

def test_extract_text_prefers_structured_content():
    class Result:
        content = []
        structured_content = {"result": [{"a": 1}]}
    out = extract_text(Result())
    assert '"a": 1' in out  # structured content serialized to JSON text
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd services/topo && uv run pytest tests/test_mcp_client.py -v`
Expected: FAIL (ModuleNotFoundError)

- [ ] **Step 3: Write mcp_client.py**

```python
# src/ssdf_topo/mcp_client.py
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

- [ ] **Step 4: Run to verify it passes**

Run: `cd services/topo && uv run pytest tests/test_mcp_client.py -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add services/topo/src/ssdf_topo/mcp_client.py services/topo/tests/test_mcp_client.py
git commit -m "feat(m4): synchronous MCP tool client wrapper for collectors"
```

### Task 2.2: Collector base + registry

**Files:**
- Create: `services/topo/src/ssdf_topo/collectors/__init__.py`
- Create: `services/topo/src/ssdf_topo/collectors/base.py`
- Test: `services/topo/tests/test_collector_base.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_collector_base.py
import pytest
from ssdf_topo.collectors.base import Collector, register, get_collector, REGISTRY

def test_register_and_lookup():
    @register("dummy")
    class Dummy(Collector):
        name = "dummy"
        def collect(self, client, now):
            return []
    assert "dummy" in REGISTRY
    assert get_collector("dummy") is Dummy

def test_unknown_collector_raises():
    with pytest.raises(KeyError):
        get_collector("nope")
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd services/topo && uv run pytest tests/test_collector_base.py -v`
Expected: FAIL (ModuleNotFoundError)

- [ ] **Step 3: Write base.py and the package __init__**

`collectors/__init__.py`:
```python
# src/ssdf_topo/collectors/__init__.py
"""Collector implementations register themselves on import."""
from . import base  # noqa: F401
```

`collectors/base.py`:
```python
# src/ssdf_topo/collectors/base.py
"""Collector protocol + a name->class registry."""

from __future__ import annotations

from typing import Callable, Protocol

from ..mcp_client import McpToolClient
from ..models import Observation

REGISTRY: dict[str, type] = {}


class Collector(Protocol):
    name: str

    def collect(self, client: McpToolClient, now: str) -> list[Observation]:
        """Pull read-only state via the MCP client; return normalized observations."""
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
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd services/topo && uv run pytest tests/test_collector_base.py -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add services/topo/src/ssdf_topo/collectors/
git add services/topo/tests/test_collector_base.py
git commit -m "feat(m4): collector protocol + registry"
```

---

> **NOTE for the implementer:** Phases 3–6 are specified in companion plan files to keep each file focused. Implement them in order:
> - `2026-06-07-ssdf-m4-topology-graph-collectors.md` (Phase 3)
> - `2026-06-07-ssdf-m4-topology-graph-resolver.md` (Phase 4)
> - `2026-06-07-ssdf-m4-topology-graph-mcp-tools.md` (Phase 5)
> - `2026-06-07-ssdf-m4-topology-graph-deploy.md` (Phase 6)
>
> Each begins with a real fixture-capture step against the live MCP, since exact tool output shapes must be reconciled before parser assertions are frozen.
