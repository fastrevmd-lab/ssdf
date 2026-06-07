# SSDF M6a — Entity / Correlation Layer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Resolve `ssdf.events` flows (enriched by M4 topology) into deduped **Asset** and observed
**Policy** entities behind a swappable `EntityStore` seam, and ship an `explain_access(client,
server)` MCP tool that answers "show me the end-to-end flow and security controls for this client →
server" with an explicit observed/configured honesty contract.

**Architecture:** A new Python service `services/entity/` (mirrors `services/topo/`) reads a flow
window from `ssdf.events` + M4 `graph_nodes` (host MAC↔IP), runs a deterministic in-memory resolver,
and projects entities/edges into two new ClickHouse tables (`ssdf.entities`, `ssdf.entity_edges`).
The read side adds an `EntityStore` seam + `explain_access` tool to the existing `ssdf-mcp-query`
server (ct106), reusing M4's `TopoTools` for path + firewall attribution.

**Tech Stack:** Python 3.11, `clickhouse-connect`, `fastmcp`, `pytest`, ClickHouse
(ReplacingMergeTree), Proxmox LXC + systemd (no Docker).

**Spec:** `docs/superpowers/specs/2026-06-07-ssdf-m6-entity-correlation-design.md` (M6a scope only;
M6b configured-policy and M6c L3 stitching are later plans).

---

## File structure

**New — entity service (`services/entity/`):**
- `pyproject.toml` — package metadata (mirror `services/topo/pyproject.toml`).
- `src/ssdf_entity/__init__.py` — empty package marker.
- `src/ssdf_entity/models.py` — entity/edge kinds, source constants, deterministic id hashing.
- `src/ssdf_entity/resolve_entities.py` — the pure resolver (core logic).
- `src/ssdf_entity/config.py` — env-driven runtime config.
- `src/ssdf_entity/chwriter.py` — read flow-agg + topo hosts; write entities/edges.
- `src/ssdf_entity/resolve_main.py` — entrypoint (read window → resolve → upsert).
- `tests/__init__.py`, `tests/test_models.py`, `tests/test_resolve_entities.py`,
  `tests/test_chwriter.py`, `tests/test_config.py`, `tests/test_integration.py`.
- `infra/ENV.example`, `infra/ssdf-entity.service`, `infra/ssdf-entity.timer`.

**New — ClickHouse schema:**
- `infra/clickhouse/004_entities.sql` — `ssdf.entities` + `ssdf.entity_edges` DDL.
- `infra/clickhouse/005_entity_user.sql` — least-privilege `ssdf_entity` writer.

**New + modified — read/tool side (`services/mcp-query/`):**
- Create `src/ssdf_mcp_query/entitystore.py` — `EntityStore` Protocol + `ClickHouseEntityStore` +
  SQL builders.
- Create `src/ssdf_mcp_query/access_tools.py` — `AccessTools.explain_access`.
- Modify `src/ssdf_mcp_query/server.py` — construct the store/tools, register `explain_access`.
- Create `tests/test_entitystore.py`, `tests/test_access_tools.py`, `tests/test_server_entity.py`.

**Modified — docs:**
- `CLAUDE.md` — add an "M6a (entity layer)" Commands subsection.
- `docs/superpowers/STATUS.md` — mark M6a built once deployed (final task).

---

## Task 1: ClickHouse schema for entities

**Files:**
- Create: `infra/clickhouse/004_entities.sql`
- Create: `infra/clickhouse/005_entity_user.sql`

- [ ] **Step 1: Write `004_entities.sql`**

```sql
-- infra/clickhouse/004_entities.sql
-- M6a entity/correlation layer: resolved Asset/Policy entities + their edges.
-- Separate from M4 graph_nodes/graph_edges so the entity store can relocate
-- (Postgres-as-graph in M6c) without touching the topology graph.

CREATE TABLE IF NOT EXISTS ssdf.entities
(
    entity_id      String,
    tenant_id      LowCardinality(String) DEFAULT 't_main',
    kind           LowCardinality(String),              -- asset | policy | identity
    name           String,
    identifiers    Map(String, String),                 -- mac, ip, ip2, rule, provider, ...
    source         LowCardinality(String) DEFAULT 'observed',  -- observed | configured
    identity_basis LowCardinality(String) DEFAULT '',   -- mac | ip_only | ''
    confidence     Float32,
    attrs          Map(String, String),
    first_seen     DateTime64(3, 'UTC'),
    last_seen      DateTime64(3, 'UTC')
)
ENGINE = ReplacingMergeTree(last_seen)
ORDER BY (tenant_id, entity_id)
TTL toDateTime(last_seen) + INTERVAL 30 DAY;

CREATE TABLE IF NOT EXISTS ssdf.entity_edges
(
    edge_id    String,
    tenant_id  LowCardinality(String) DEFAULT 't_main',
    src_id     String,
    dst_id     String,
    edge_type  LowCardinality(String),                  -- communicated_with | governed_by | authenticated_as
    source     LowCardinality(String) DEFAULT 'observed',
    confidence Float32,
    attrs      Map(String, String),
    first_seen DateTime64(3, 'UTC'),
    last_seen  DateTime64(3, 'UTC')
)
ENGINE = ReplacingMergeTree(last_seen)
ORDER BY (tenant_id, edge_id)
TTL toDateTime(last_seen) + INTERVAL 30 DAY;
```

- [ ] **Step 2: Write `005_entity_user.sql`**

```sql
-- infra/clickhouse/005_entity_user.sql
-- Least-privilege writer for the M6 entity service. Run as CH admin.
-- ClickHouse does NOT expand {name:Type} params inside CREATE USER ... BY '...',
-- so inject the password before applying (never commit the real value):
--   ENTITY_PW="$CH_ENTITY_PASSWORD" envsubst < 005_entity_user.sql \
--     | clickhouse-client --host <ct104> --multiquery
CREATE USER IF NOT EXISTS ssdf_entity IDENTIFIED WITH sha256_password BY '${ENTITY_PW}';
GRANT INSERT, SELECT ON ssdf.entities TO ssdf_entity;
GRANT INSERT, SELECT ON ssdf.entity_edges TO ssdf_entity;
GRANT SELECT ON ssdf.events TO ssdf_entity;
GRANT SELECT ON ssdf.graph_nodes TO ssdf_entity;
```

Also grant the existing read-only MCP user (`ssdf_ro`) SELECT on the new tables so the tool can read
them:

```sql
GRANT SELECT ON ssdf.entities TO ssdf_ro;
GRANT SELECT ON ssdf.entity_edges TO ssdf_ro;
```

- [ ] **Step 3: Validate SQL syntax locally**

Run: `python -c "import pathlib; [pathlib.Path(p).read_text() for p in ['infra/clickhouse/004_entities.sql','infra/clickhouse/005_entity_user.sql']]; print('readable')"`
Expected: `readable` (live apply happens in the deployment task, Task 11).

- [ ] **Step 4: Commit**

```bash
git add infra/clickhouse/004_entities.sql infra/clickhouse/005_entity_user.sql
git commit -m "feat(m6a): ClickHouse entities + entity_edges schema and least-priv user"
```

---

## Task 2: Entity service scaffold

**Files:**
- Create: `services/entity/pyproject.toml`
- Create: `services/entity/src/ssdf_entity/__init__.py`
- Create: `services/entity/tests/__init__.py`

- [ ] **Step 1: Write `pyproject.toml`**

```toml
[project]
name = "ssdf-entity"
version = "0.1.0"
description = "SSDF M6 entity/correlation resolver (Asset + observed Policy from ssdf.events + topology)"
requires-python = ">=3.11"
dependencies = [
    "clickhouse-connect>=0.8",
]

[project.optional-dependencies]
dev = ["pytest>=8.0"]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/ssdf_entity"]

[tool.pytest.ini_options]
testpaths = ["tests"]
pythonpath = ["src"]
markers = ["integration: requires live ClickHouse (deselect with -m 'not integration')"]
```

- [ ] **Step 2: Create empty package + test markers**

Create `services/entity/src/ssdf_entity/__init__.py` (empty) and
`services/entity/tests/__init__.py` (empty).

- [ ] **Step 3: Verify the package imports**

Run: `cd services/entity && uv run python -c "import ssdf_entity; print('ok')"`
Expected: `ok`

- [ ] **Step 4: Commit**

```bash
git add services/entity/pyproject.toml services/entity/src/ssdf_entity/__init__.py services/entity/tests/__init__.py
git commit -m "chore(m6a): scaffold ssdf-entity package"
```

---

## Task 3: Entity models (taxonomy + id hashing)

**Files:**
- Create: `services/entity/src/ssdf_entity/models.py`
- Test: `services/entity/tests/test_models.py`

- [ ] **Step 1: Write the failing test**

```python
# services/entity/tests/test_models.py
from ssdf_entity.models import (
    ASSET, POLICY, IDENTITY, COMMUNICATED_WITH, GOVERNED_BY, OBSERVED, CONFIGURED,
    entity_id, edge_id,
)


def test_entity_id_is_stable_and_namespaced():
    a = entity_id("t_main", ASSET, "mac:aa:bb")
    b = entity_id("t_main", ASSET, "mac:aa:bb")
    c = entity_id("t_main", ASSET, "ip:10.64.0.5")
    assert a == b and a != c
    assert len(a) == 16


def test_edge_id_distinguishes_source_and_type():
    base = ("t_main", "s", "d")
    assert edge_id(*base, COMMUNICATED_WITH, OBSERVED) != edge_id(*base, GOVERNED_BY, OBSERVED)
    assert edge_id(*base, COMMUNICATED_WITH, OBSERVED) != edge_id(*base, COMMUNICATED_WITH, CONFIGURED)


def test_constants_exist():
    assert {ASSET, POLICY, IDENTITY} == {"asset", "policy", "identity"}
    assert OBSERVED == "observed" and CONFIGURED == "configured"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd services/entity && uv run pytest tests/test_models.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'ssdf_entity.models'`

- [ ] **Step 3: Write `models.py`**

```python
# src/ssdf_entity/models.py
"""Entity/correlation taxonomy constants and deterministic id hashing.

Mirrors services/topo/src/ssdf_topo/models.py but for the semantic entity layer:
the id namespace is separate so entity ids never collide with topology node ids.
"""

from __future__ import annotations

import hashlib

# --- entity kinds ---
ASSET = "asset"
POLICY = "policy"
IDENTITY = "identity"   # seam only in M6a (populated when an IDaaS source lands)
ENTITY_KINDS = {ASSET, POLICY, IDENTITY}

# --- edge types ---
COMMUNICATED_WITH = "communicated_with"
GOVERNED_BY = "governed_by"
AUTHENTICATED_AS = "authenticated_as"   # seam only in M6a
EDGE_TYPES = {COMMUNICATED_WITH, GOVERNED_BY, AUTHENTICATED_AS}

# --- provenance ---
OBSERVED = "observed"
CONFIGURED = "configured"   # reserved; populated in M6b


def _hash16(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest()[:16]


def entity_id(tenant: str, kind: str, canonical_key: str) -> str:
    """Stable 16-hex id for an entity, namespaced by tenant + kind + 'entity'."""
    return _hash16(f"{tenant}|entity|{kind}|{canonical_key}")


def edge_id(tenant: str, src_id: str, dst_id: str, edge_type: str, source: str) -> str:
    """Stable 16-hex id for a directed, typed, provenance-tagged entity edge."""
    return _hash16(f"{tenant}|entity_edge|{src_id}|{dst_id}|{edge_type}|{source}")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd services/entity && uv run pytest tests/test_models.py -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add services/entity/src/ssdf_entity/models.py services/entity/tests/test_models.py
git commit -m "feat(m6a): entity taxonomy constants + deterministic id hashing"
```

---

## Task 4: The entity resolver (core)

**Files:**
- Create: `services/entity/src/ssdf_entity/resolve_entities.py`
- Test: `services/entity/tests/test_resolve_entities.py`

The resolver is a pure function. Input `flow_aggregates` is a list of dicts shaped exactly like the
rows returned by the SQL in Task 6 (keys: `src_ip`, `dst_ip`, `bytes`, `flows`, `ports`,
`rule_name`, `provider`, `transport`, `first_seen`, `last_seen`). Input `topo_hosts` is a list of
dicts with an `identifiers` dict (from M4 `graph_nodes` where `kind='host'`).

- [ ] **Step 1: Write the failing tests**

```python
# services/entity/tests/test_resolve_entities.py
from ssdf_entity.models import ASSET, POLICY, COMMUNICATED_WITH, GOVERNED_BY, entity_id
from ssdf_entity.resolve_entities import resolve_entities

NOW1 = "2026-06-07 00:00:00.000"
NOW2 = "2026-06-07 01:00:00.000"


def _flow(**kw):
    base = dict(src_ip="10.64.0.5", dst_ip="8.8.8.8", bytes=1000, flows=3, ports=[443],
                rule_name="trust-to-untrust", provider="juniper", transport="tcp",
                first_seen=NOW1, last_seen=NOW2)
    base.update(kw)
    return base


def test_ip_only_endpoints_become_singleton_assets():
    entities, edges = resolve_entities([_flow()], topo_hosts=[], tenant="t_main")
    assets = [e for e in entities if e["kind"] == ASSET]
    assert len(assets) == 2
    for a in assets:
        assert a["identity_basis"] == "ip_only"
        assert a["confidence"] == 0.5
        assert a["source"] == "observed"


def test_mac_known_endpoint_is_mac_anchored():
    topo = [{"identifiers": {"mac": "aa:bb:cc:dd:ee:ff", "ip": "10.64.0.5"}}]
    entities, _ = resolve_entities([_flow()], topo_hosts=topo, tenant="t_main")
    src = next(e for e in entities if e["kind"] == ASSET
               and e["identifiers"].get("mac") == "aa:bb:cc:dd:ee:ff")
    assert src["identity_basis"] == "mac"
    assert src["confidence"] == 1.0
    assert src["identifiers"]["ip"] == "10.64.0.5"


def test_two_ips_sharing_a_mac_collapse_to_one_asset():
    topo = [{"identifiers": {"mac": "aa:aa:aa:aa:aa:aa", "ip": "10.64.0.5"}},
            {"identifiers": {"mac": "aa:aa:aa:aa:aa:aa", "ip": "10.64.0.6"}}]
    flows = [_flow(src_ip="10.64.0.5"), _flow(src_ip="10.64.0.6")]
    entities, _ = resolve_entities(flows, topo_hosts=topo, tenant="t_main")
    macs = [e for e in entities if e["kind"] == ASSET
            and e["identifiers"].get("mac") == "aa:aa:aa:aa:aa:aa"]
    assert len(macs) == 1
    ips = {v for k, v in macs[0]["identifiers"].items() if k.startswith("ip")}
    assert ips == {"10.64.0.5", "10.64.0.6"}


def test_distinct_ips_never_merge():
    flows = [_flow(src_ip="10.64.0.5"), _flow(src_ip="10.64.0.6")]
    entities, _ = resolve_entities(flows, topo_hosts=[], tenant="t_main")
    src_ips = {v for e in entities if e["kind"] == ASSET
               for k, v in e["identifiers"].items() if k.startswith("ip")}
    assert "10.64.0.5" in src_ips and "10.64.0.6" in src_ips
    assert len([e for e in entities if e["kind"] == ASSET]) == 3  # two srcs + shared dst


def test_observed_policy_keyed_by_provider_and_rule():
    entities, edges = resolve_entities([_flow()], topo_hosts=[], tenant="t_main")
    policies = [e for e in entities if e["kind"] == POLICY]
    assert len(policies) == 1
    assert policies[0]["name"] == "trust-to-untrust"
    assert policies[0]["identifiers"]["provider"] == "juniper"
    assert policies[0]["source"] == "observed"


def test_same_rule_name_different_vendor_is_distinct_policy():
    flows = [_flow(rule_name="allow-web", provider="juniper"),
             _flow(rule_name="allow-web", provider="paloalto", dst_ip="9.9.9.9")]
    entities, _ = resolve_entities(flows, topo_hosts=[], tenant="t_main")
    assert len([e for e in entities if e["kind"] == POLICY]) == 2


def test_communicated_with_and_governed_by_edges():
    entities, edges = resolve_entities([_flow()], topo_hosts=[], tenant="t_main")
    comm = [e for e in edges if e["edge_type"] == COMMUNICATED_WITH]
    gov = [e for e in edges if e["edge_type"] == GOVERNED_BY]
    assert len(comm) == 1 and len(gov) == 1
    assert comm[0]["attrs"]["sessions"] == "3"
    assert comm[0]["attrs"]["bytes"] == "1000"
    assert "443" in comm[0]["attrs"]["ports"]
    assert gov[0]["src_id"] == comm[0]["edge_id"]


def test_empty_rule_produces_no_governed_by():
    entities, edges = resolve_entities([_flow(rule_name="")], topo_hosts=[], tenant="t_main")
    assert [e for e in entities if e["kind"] == POLICY] == []
    assert [e for e in edges if e["edge_type"] == GOVERNED_BY] == []
    assert [e for e in edges if e["edge_type"] == COMMUNICATED_WITH]  # flow still recorded


def test_flow_stats_accumulate_across_rows_for_same_pair():
    flows = [_flow(flows=3, bytes=1000, ports=[443], first_seen=NOW1, last_seen=NOW1),
             _flow(flows=2, bytes=500, ports=[80], first_seen=NOW2, last_seen=NOW2)]
    _, edges = resolve_entities(flows, topo_hosts=[], tenant="t_main")
    comm = next(e for e in edges if e["edge_type"] == COMMUNICATED_WITH)
    assert comm["attrs"]["sessions"] == "5"
    assert comm["attrs"]["bytes"] == "1500"
    assert set(comm["attrs"]["ports"].split(",")) == {"80", "443"}
    assert comm["first_seen"] == NOW1 and comm["last_seen"] == NOW2
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd services/entity && uv run pytest tests/test_resolve_entities.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'ssdf_entity.resolve_entities'`

- [ ] **Step 3: Write `resolve_entities.py`**

```python
# src/ssdf_entity/resolve_entities.py
"""Resolve flow aggregates (+ topology MAC↔IP) into Asset/Policy entities and edges.

Pure function, deterministic. Asset identity is keyed: MAC when the topology binds
the IP→MAC, else the IP itself. Two IPs sharing a MAC collapse to one Asset; distinct
IPs never merge (no merge on IP alone). Observed Policy is keyed (provider, rule_name).
"""

from __future__ import annotations

from .models import (
    ASSET, POLICY, COMMUNICATED_WITH, GOVERNED_BY, OBSERVED,
    entity_id, edge_id,
)


def _build_ip_to_mac(topo_hosts: list[dict]) -> dict[str, str]:
    """Map IP→lowercased MAC from M4 host nodes that bind both."""
    ip_to_mac: dict[str, str] = {}
    for host in topo_hosts:
        identifiers = host.get("identifiers") or {}
        mac = identifiers.get("mac")
        ip = identifiers.get("ip")
        if mac and ip:
            ip_to_mac[ip] = mac.lower()
    return ip_to_mac


def _bump_window(record: dict, first_seen: str, last_seen: str) -> None:
    """Widen a record's [first_seen, last_seen] window (lexical ISO compare)."""
    record["first_seen"] = min(record["first_seen"], first_seen) if record["first_seen"] else first_seen
    record["last_seen"] = max(record["last_seen"], last_seen) if record["last_seen"] else last_seen


def _add_ip(entity: dict, ip: str) -> None:
    """Record an observed IP under ip / ip2 / ip3 … (deduped) so mapValues lookup matches any."""
    identifiers = entity["identifiers"]
    seen = {value for key, value in identifiers.items() if key.startswith("ip")}
    if ip in seen:
        return
    key = "ip" if "ip" not in identifiers else f"ip{len(seen) + 1}"
    identifiers[key] = ip


def _merge_set_attr(attrs: dict, key: str, values) -> None:
    """Maintain a comma-joined sorted set of string values in attrs[key]."""
    current = set(filter(None, attrs.get(key, "").split(",")))
    current.update(str(value) for value in values if str(value))
    attrs[key] = ",".join(sorted(current))


def resolve_entities(flow_aggregates: list[dict], topo_hosts: list[dict],
                     tenant: str) -> tuple[list[dict], list[dict]]:
    ip_to_mac = _build_ip_to_mac(topo_hosts)
    entities: dict[str, dict] = {}
    edges: dict[str, dict] = {}

    def asset_for(ip: str, first_seen: str, last_seen: str) -> dict:
        mac = ip_to_mac.get(ip)
        canonical = f"mac:{mac}" if mac else f"ip:{ip}"
        eid = entity_id(tenant, ASSET, canonical)
        entity = entities.get(eid)
        if entity is None:
            entity = {
                "entity_id": eid, "tenant_id": tenant, "kind": ASSET,
                "name": mac or ip, "identifiers": {}, "source": OBSERVED,
                "identity_basis": "mac" if mac else "ip_only",
                "confidence": 1.0 if mac else 0.5,
                "attrs": {}, "first_seen": "", "last_seen": "",
            }
            if mac:
                entity["identifiers"]["mac"] = mac
            entities[eid] = entity
        _add_ip(entity, ip)
        _bump_window(entity, first_seen, last_seen)
        return entity

    def policy_for(provider: str, rule: str, first_seen: str, last_seen: str) -> dict:
        eid = entity_id(tenant, POLICY, f"{provider}:{rule}")
        entity = entities.get(eid)
        if entity is None:
            entity = {
                "entity_id": eid, "tenant_id": tenant, "kind": POLICY,
                "name": rule, "identifiers": {"rule": rule, "provider": provider},
                "source": OBSERVED, "identity_basis": "", "confidence": 1.0,
                "attrs": {"provider": provider}, "first_seen": "", "last_seen": "",
            }
            entities[eid] = entity
        _bump_window(entity, first_seen, last_seen)
        return entity

    for row in flow_aggregates:
        first_seen, last_seen = row["first_seen"], row["last_seen"]
        src = asset_for(row["src_ip"], first_seen, last_seen)
        dst = asset_for(row["dst_ip"], first_seen, last_seen)

        comm_eid = edge_id(tenant, src["entity_id"], dst["entity_id"],
                           COMMUNICATED_WITH, OBSERVED)
        comm = edges.get(comm_eid)
        if comm is None:
            comm = {
                "edge_id": comm_eid, "tenant_id": tenant,
                "src_id": src["entity_id"], "dst_id": dst["entity_id"],
                "edge_type": COMMUNICATED_WITH, "source": OBSERVED, "confidence": 1.0,
                "attrs": {"sessions": "0", "bytes": "0", "ports": "", "providers": "",
                          "transports": ""},
                "first_seen": "", "last_seen": "",
            }
            edges[comm_eid] = comm
        comm["attrs"]["sessions"] = str(int(comm["attrs"]["sessions"]) + int(row.get("flows", 0)))
        comm["attrs"]["bytes"] = str(int(comm["attrs"]["bytes"]) + int(row.get("bytes", 0)))
        _merge_set_attr(comm["attrs"], "ports", row.get("ports") or [])
        _merge_set_attr(comm["attrs"], "providers", [row.get("provider", "")])
        _merge_set_attr(comm["attrs"], "transports", [row.get("transport", "")])
        _bump_window(comm, first_seen, last_seen)

        rule = (row.get("rule_name") or "").strip()
        provider = (row.get("provider") or "").strip()
        if not rule:
            continue
        policy = policy_for(provider, rule, first_seen, last_seen)
        gov_eid = edge_id(tenant, comm_eid, policy["entity_id"], GOVERNED_BY, OBSERVED)
        gov = edges.get(gov_eid)
        if gov is None:
            gov = {
                "edge_id": gov_eid, "tenant_id": tenant,
                "src_id": comm_eid, "dst_id": policy["entity_id"],
                "edge_type": GOVERNED_BY, "source": OBSERVED, "confidence": 1.0,
                "attrs": {"rule": rule, "provider": provider},
                "first_seen": "", "last_seen": "",
            }
            edges[gov_eid] = gov
        _bump_window(gov, first_seen, last_seen)

    return list(entities.values()), list(edges.values())
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd services/entity && uv run pytest tests/test_resolve_entities.py -v`
Expected: PASS (9 tests)

- [ ] **Step 5: Commit**

```bash
git add services/entity/src/ssdf_entity/resolve_entities.py services/entity/tests/test_resolve_entities.py
git commit -m "feat(m6a): deterministic Asset/Policy resolver (MAC-keyed, observed policy)"
```

---

## Task 5: Runtime config

**Files:**
- Create: `services/entity/src/ssdf_entity/config.py`
- Test: `services/entity/tests/test_config.py`

- [ ] **Step 1: Write the failing test**

```python
# services/entity/tests/test_config.py
import pytest
from ssdf_entity.config import load_config, ConfigError


def test_load_config_requires_password(monkeypatch):
    monkeypatch.delenv("CH_PASSWORD", raising=False)
    with pytest.raises(ConfigError):
        load_config()


def test_load_config_defaults(monkeypatch):
    monkeypatch.setenv("CH_PASSWORD", "secret")
    monkeypatch.delenv("CH_HOST", raising=False)
    monkeypatch.delenv("CH_USER", raising=False)
    monkeypatch.delenv("ENTITY_WINDOW_HOURS", raising=False)
    config = load_config()
    assert config.ch_host == "127.0.0.1"
    assert config.ch_user == "ssdf_entity"
    assert config.tenant_id == "t_main"
    assert config.window_hours == 24
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd services/entity && uv run pytest tests/test_config.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'ssdf_entity.config'`

- [ ] **Step 3: Write `config.py`**

```python
# src/ssdf_entity/config.py
"""Env-driven runtime config for the entity resolver (mirrors ssdf_topo.config)."""

from __future__ import annotations

import os
from dataclasses import dataclass


class ConfigError(RuntimeError):
    """Raised when required configuration is missing."""


@dataclass(frozen=True)
class Config:
    ch_host: str
    ch_port: int
    ch_user: str
    ch_password: str
    ch_database: str
    tenant_id: str
    window_hours: int


def load_config() -> Config:
    password = os.environ.get("CH_PASSWORD")
    if password is None:
        raise ConfigError("CH_PASSWORD is required")
    return Config(
        ch_host=os.environ.get("CH_HOST", "127.0.0.1"),
        ch_port=int(os.environ.get("CH_PORT", "8123")),
        ch_user=os.environ.get("CH_USER", "ssdf_entity"),
        ch_password=password,
        ch_database=os.environ.get("CH_DATABASE", "ssdf"),
        tenant_id=os.environ.get("ENTITY_TENANT", "t_main"),
        window_hours=int(os.environ.get("ENTITY_WINDOW_HOURS", "24")),
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd services/entity && uv run pytest tests/test_config.py -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add services/entity/src/ssdf_entity/config.py services/entity/tests/test_config.py
git commit -m "feat(m6a): entity service runtime config"
```

---

## Task 6: ClickHouse writer (read inputs, write entities/edges)

**Files:**
- Create: `services/entity/src/ssdf_entity/chwriter.py`
- Test: `services/entity/tests/test_chwriter.py`

- [ ] **Step 1: Write the failing tests**

```python
# services/entity/tests/test_chwriter.py
from ssdf_entity.chwriter import (
    build_flow_agg_sql, build_topo_hosts_sql, entity_rows, edge_rows,
    ENTITY_COLUMNS, ENTITY_EDGE_COLUMNS,
)


def test_flow_agg_sql_is_parameterized_and_groups_by_pair():
    sql, params = build_flow_agg_sql(window_hours=24, tenant="t_main")
    assert "{tenant:String}" in sql
    assert "{window_hours:UInt32}" in sql
    assert "GROUP BY src_ip, dst_ip" in sql
    assert "groupUniqArray(destination_port)" in sql
    assert params == {"tenant": "t_main", "window_hours": 24}


def test_topo_hosts_sql_filters_to_host_kind():
    sql, params = build_topo_hosts_sql(tenant="t_main")
    assert "ssdf.graph_nodes FINAL" in sql
    assert "kind = 'host'" in sql
    assert params == {"tenant": "t_main"}


def test_entity_rows_follow_column_order():
    entity = {c: c for c in ENTITY_COLUMNS}
    assert entity_rows([entity]) == [[c for c in ENTITY_COLUMNS]]


def test_edge_rows_follow_column_order():
    edge = {c: c for c in ENTITY_EDGE_COLUMNS}
    assert edge_rows([edge]) == [[c for c in ENTITY_EDGE_COLUMNS]]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd services/entity && uv run pytest tests/test_chwriter.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'ssdf_entity.chwriter'`

- [ ] **Step 3: Write `chwriter.py`**

```python
# src/ssdf_entity/chwriter.py
"""ClickHouse I/O for the entity layer: read flow-agg + topo hosts, write entities/edges."""

from __future__ import annotations

from typing import Any, Iterable

import clickhouse_connect

from .config import Config

ENTITY_COLUMNS = [
    "entity_id", "tenant_id", "kind", "name", "identifiers", "source",
    "identity_basis", "confidence", "attrs", "first_seen", "last_seen",
]
ENTITY_EDGE_COLUMNS = [
    "edge_id", "tenant_id", "src_id", "dst_id", "edge_type", "source",
    "confidence", "attrs", "first_seen", "last_seen",
]


def build_flow_agg_sql(window_hours: int, tenant: str) -> tuple[str, dict]:
    """Aggregate ssdf.events into per-(src_ip,dst_ip) flow rows for the resolver."""
    sql = (
        "SELECT toString(source_ip) AS src_ip, toString(destination_ip) AS dst_ip, "
        "sum(network_bytes) AS bytes, count() AS flows, "
        "groupUniqArray(destination_port) AS ports, "
        "any(rule_name) AS rule_name, any(event_provider) AS provider, "
        "any(network_transport) AS transport, "
        "toString(min(timestamp)) AS first_seen, toString(max(timestamp)) AS last_seen "
        "FROM ssdf.events "
        "WHERE tenant_id = {tenant:String} "
        "AND timestamp >= now() - INTERVAL {window_hours:UInt32} HOUR "
        "AND source_ip IS NOT NULL AND destination_ip IS NOT NULL "
        "GROUP BY src_ip, dst_ip"
    )
    return sql, {"tenant": tenant, "window_hours": window_hours}


def build_topo_hosts_sql(tenant: str) -> tuple[str, dict]:
    """Read M4 host nodes to enrich IP→MAC bindings."""
    sql = (
        "SELECT identifiers FROM ssdf.graph_nodes FINAL "
        "WHERE tenant_id = {tenant:String} AND kind = 'host'"
    )
    return sql, {"tenant": tenant}


def entity_rows(entities: Iterable[dict]) -> list[list[Any]]:
    return [[e[c] for c in ENTITY_COLUMNS] for e in entities]


def edge_rows(edges: Iterable[dict]) -> list[list[Any]]:
    return [[e[c] for c in ENTITY_EDGE_COLUMNS] for e in edges]


class ClickHouseEntityWriter:
    """Read the resolver input window and upsert entities/edges."""

    def __init__(self, config: Config):
        self._config = config
        self._client = clickhouse_connect.get_client(
            host=config.ch_host, port=config.ch_port, username=config.ch_user,
            password=config.ch_password, database=config.ch_database,
        )

    def query(self, sql: str, params: dict | None = None) -> list[dict]:
        result = self._client.query(sql, parameters=params or {})
        cols = list(result.column_names)
        return [dict(zip(cols, row)) for row in result.result_rows]

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

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd services/entity && uv run pytest tests/test_chwriter.py -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add services/entity/src/ssdf_entity/chwriter.py services/entity/tests/test_chwriter.py
git commit -m "feat(m6a): entity ClickHouse writer (flow-agg + topo-host reads, entity/edge upsert)"
```

---

## Task 7: Resolver entrypoint

**Files:**
- Create: `services/entity/src/ssdf_entity/resolve_main.py`
- Test: `services/entity/tests/test_resolve_main.py` (new file)

- [ ] **Step 1: Write the failing test**

```python
# services/entity/tests/test_resolve_main.py
from ssdf_entity.resolve_main import run_resolver


class _FakeWriter:
    def __init__(self):
        self.entities = None
        self.edges = None

    def query(self, sql, params=None):
        if "graph_nodes" in sql:
            return [{"identifiers": {"mac": "aa:aa:aa:aa:aa:aa", "ip": "10.64.0.5"}}]
        return [{"src_ip": "10.64.0.5", "dst_ip": "8.8.8.8", "bytes": 100, "flows": 1,
                 "ports": [443], "rule_name": "r1", "provider": "juniper",
                 "transport": "tcp", "first_seen": "2026-06-07 00:00:00.000",
                 "last_seen": "2026-06-07 00:00:00.000"}]

    def replace_entities(self, entities):
        self.entities = entities
        return len(entities)

    def replace_edges(self, edges):
        self.edges = edges
        return len(edges)


def test_run_resolver_reads_both_inputs_and_writes():
    writer = _FakeWriter()
    n_entities, n_edges = run_resolver(writer, tenant="t_main", window_hours=24)
    assert n_entities == 3        # mac-anchored src + ip-only dst + policy r1
    assert n_edges == 2           # communicated_with + governed_by
    src = next(e for e in writer.entities if e["identifiers"].get("mac"))
    assert src["identity_basis"] == "mac"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd services/entity && uv run pytest tests/test_resolve_main.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'ssdf_entity.resolve_main'`

- [ ] **Step 3: Write `resolve_main.py`**

```python
# src/ssdf_entity/resolve_main.py
"""Entrypoint: read CH window (flow-agg + topo hosts), resolve, upsert entities/edges."""

from __future__ import annotations

import logging

from .chwriter import ClickHouseEntityWriter, build_flow_agg_sql, build_topo_hosts_sql
from .config import Config, load_config
from .resolve_entities import resolve_entities

log = logging.getLogger("ssdf_entity.resolve")


def run_resolver(writer, tenant: str, window_hours: int) -> tuple[int, int]:
    flow_sql, flow_params = build_flow_agg_sql(window_hours, tenant)
    flow_aggregates = writer.query(flow_sql, flow_params)
    host_sql, host_params = build_topo_hosts_sql(tenant)
    topo_hosts = writer.query(host_sql, host_params)
    entities, edges = resolve_entities(flow_aggregates, topo_hosts, tenant)
    n_entities = writer.replace_entities(entities)
    n_edges = writer.replace_edges(edges)
    log.info("entity resolver: %d entities, %d edges upserted", n_entities, n_edges)
    return n_entities, n_edges


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    config: Config = load_config()
    writer = ClickHouseEntityWriter(config)
    run_resolver(writer, tenant=config.tenant_id, window_hours=config.window_hours)


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd services/entity && uv run pytest tests/test_resolve_main.py -v`
Expected: PASS (1 test)

- [ ] **Step 5: Run the whole entity-service suite**

Run: `cd services/entity && uv run pytest -m "not integration" -v`
Expected: PASS (all unit tests green)

- [ ] **Step 6: Commit**

```bash
git add services/entity/src/ssdf_entity/resolve_main.py services/entity/tests/test_resolve_main.py
git commit -m "feat(m6a): entity resolver entrypoint (read window -> resolve -> upsert)"
```

---

## Task 8: EntityStore seam (read side, in ssdf-mcp-query)

**Files:**
- Create: `services/mcp-query/src/ssdf_mcp_query/entitystore.py`
- Test: `services/mcp-query/tests/test_entitystore.py`

- [ ] **Step 1: Write the failing tests**

```python
# services/mcp-query/tests/test_entitystore.py
from ssdf_mcp_query.entitystore import (
    build_entity_match_sql, build_comm_edges_sql, build_governed_by_sql,
    build_entities_by_id_sql, ClickHouseEntityStore,
)


def test_entity_match_sql_lowercases_mac_and_matches_values():
    sql, params = build_entity_match_sql("AA:BB:CC:DD:EE:FF", tenant="t_main")
    assert "ssdf.entities FINAL" in sql
    assert "has(mapValues(identifiers), {val:String})" in sql
    assert params["val"] == "aa:bb:cc:dd:ee:ff"
    assert params["tenant"] == "t_main"


def test_entity_match_sql_preserves_non_mac():
    _, params = build_entity_match_sql("10.64.0.5", tenant="t_main")
    assert params["val"] == "10.64.0.5"


def test_comm_edges_sql_is_bidirectional_and_windowed():
    sql, params = build_comm_edges_sql("A", "B", "2026-06-07T00:00:00", tenant="t_main")
    assert "edge_type = 'communicated_with'" in sql
    assert "last_seen >= {since:String}" in sql
    assert params["a"] == "A" and params["b"] == "B"


def test_governed_by_sql_filters_by_comm_edge_ids():
    sql, params = build_governed_by_sql(["e1", "e2"], tenant="t_main")
    assert "edge_type = 'governed_by'" in sql
    assert "src_id IN {ids:Array(String)}" in sql
    assert params["ids"] == ["e1", "e2"]


class _FakeCH:
    def __init__(self, rows):
        self._rows = rows
        self.calls = []

    def run(self, sql, params=None):
        self.calls.append((sql, params))
        return {"rows": self._rows.pop(0)}


def test_store_find_entity_returns_first_row_or_none():
    ch = _FakeCH([[{"entity_id": "x"}]])
    store = ClickHouseEntityStore(ch, tenant="t_main")
    assert store.find_entity("10.64.0.5") == {"entity_id": "x"}
    ch2 = _FakeCH([[]])
    assert ClickHouseEntityStore(ch2, tenant="t_main").find_entity("nope") is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd services/mcp-query && uv run pytest tests/test_entitystore.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'ssdf_mcp_query.entitystore'`

- [ ] **Step 3: Write `entitystore.py`**

```python
# src/ssdf_mcp_query/entitystore.py
"""Read-only entity access seam over ClickHouse ssdf.entities / ssdf.entity_edges."""

from __future__ import annotations

from typing import Protocol

from .graphstore import _normalize_identifier  # reuse MAC-aware lowercasing

_ENTITY_COLS = (
    "entity_id, kind, name, identifiers, source, identity_basis, confidence, "
    "toString(first_seen) AS first_seen, toString(last_seen) AS last_seen, attrs"
)
_EDGE_COLS = (
    "edge_id, src_id, dst_id, edge_type, source, confidence, "
    "toString(first_seen) AS first_seen, toString(last_seen) AS last_seen, attrs"
)


def build_entity_match_sql(value: str, tenant: str) -> tuple[str, dict]:
    sql = (
        f"SELECT {_ENTITY_COLS} FROM ssdf.entities FINAL "
        "WHERE tenant_id = {tenant:String} AND ("
        "entity_id = {val:String} OR has(mapValues(identifiers), {val:String})) "
        "ORDER BY last_seen DESC LIMIT 1"
    )
    return sql, {"tenant": tenant, "val": _normalize_identifier(value)}


def build_comm_edges_sql(a_id: str, b_id: str, since_iso: str,
                         tenant: str) -> tuple[str, dict]:
    sql = (
        f"SELECT {_EDGE_COLS} FROM ssdf.entity_edges FINAL "
        "WHERE tenant_id = {tenant:String} AND edge_type = 'communicated_with' "
        "AND last_seen >= {since:String} AND ("
        "(src_id = {a:String} AND dst_id = {b:String}) OR "
        "(src_id = {b:String} AND dst_id = {a:String}))"
    )
    return sql, {"tenant": tenant, "a": a_id, "b": b_id, "since": since_iso}


def build_governed_by_sql(comm_edge_ids: list[str], tenant: str) -> tuple[str, dict]:
    sql = (
        f"SELECT {_EDGE_COLS} FROM ssdf.entity_edges FINAL "
        "WHERE tenant_id = {tenant:String} AND edge_type = 'governed_by' "
        "AND src_id IN {ids:Array(String)}"
    )
    return sql, {"tenant": tenant, "ids": comm_edge_ids}


def build_entities_by_id_sql(entity_ids: list[str], tenant: str) -> tuple[str, dict]:
    sql = (
        f"SELECT {_ENTITY_COLS} FROM ssdf.entities FINAL "
        "WHERE tenant_id = {tenant:String} AND entity_id IN {ids:Array(String)}"
    )
    return sql, {"tenant": tenant, "ids": entity_ids}


class EntityStore(Protocol):
    def find_entity(self, identifier: str) -> dict | None: ...
    def communicated_edges(self, a_id: str, b_id: str, since_iso: str) -> list[dict]: ...
    def governed_policies(self, comm_edge_ids: list[str]) -> list[dict]: ...


class ClickHouseEntityStore:
    """EntityStore backed by ClickHouse (the swappable storage seam)."""

    def __init__(self, ch_client, tenant: str = "t_main"):
        self._ch = ch_client
        self._tenant = tenant

    def find_entity(self, identifier: str) -> dict | None:
        sql, params = build_entity_match_sql(identifier, self._tenant)
        rows = self._ch.run(sql, params)["rows"]
        return rows[0] if rows else None

    def communicated_edges(self, a_id: str, b_id: str, since_iso: str) -> list[dict]:
        sql, params = build_comm_edges_sql(a_id, b_id, since_iso, self._tenant)
        return self._ch.run(sql, params)["rows"]

    def governed_policies(self, comm_edge_ids: list[str]) -> list[dict]:
        """Return [{policy: <entity>, edge_attrs: <governed_by attrs>}] for the given comm edges."""
        if not comm_edge_ids:
            return []
        gov_sql, gov_params = build_governed_by_sql(comm_edge_ids, self._tenant)
        gov_edges = self._ch.run(gov_sql, gov_params)["rows"]
        policy_ids = sorted({e["dst_id"] for e in gov_edges})
        if not policy_ids:
            return []
        ent_sql, ent_params = build_entities_by_id_sql(policy_ids, self._tenant)
        policies = {p["entity_id"]: p for p in self._ch.run(ent_sql, ent_params)["rows"]}
        result = []
        for edge in gov_edges:
            policy = policies.get(edge["dst_id"])
            if policy:
                result.append({"policy": policy, "edge_attrs": edge["attrs"]})
        return result
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd services/mcp-query && uv run pytest tests/test_entitystore.py -v`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add services/mcp-query/src/ssdf_mcp_query/entitystore.py services/mcp-query/tests/test_entitystore.py
git commit -m "feat(m6a): EntityStore read seam over ssdf.entities/entity_edges"
```

---

## Task 9: `explain_access` tool logic

**Files:**
- Create: `services/mcp-query/src/ssdf_mcp_query/access_tools.py`
- Test: `services/mcp-query/tests/test_access_tools.py`

- [ ] **Step 1: Write the failing tests**

```python
# services/mcp-query/tests/test_access_tools.py
from ssdf_mcp_query.access_tools import AccessTools


class _FakeStore:
    def __init__(self, entities, comm, policies):
        self._entities = entities
        self._comm = comm
        self._policies = policies

    def find_entity(self, identifier):
        return self._entities.get(identifier)

    def communicated_edges(self, a_id, b_id, since_iso):
        return self._comm

    def governed_policies(self, comm_edge_ids):
        return self._policies


class _FakeTopo:
    def __init__(self, firewalls, path):
        self._firewalls = firewalls
        self._path = path

    def enforcement_points(self, src, dst):
        return {"firewalls": self._firewalls, "rules": [], "zones": []}

    def find_path(self, src, dst, layer="any"):
        return self._path


def _client_server():
    return ({"client": {"entity_id": "C", "name": "10.64.0.5", "identity_basis": "ip_only"},
             "server": {"entity_id": "S", "name": "8.8.8.8", "identity_basis": "ip_only"}})


def test_not_found_when_endpoint_unresolved():
    store = _FakeStore({}, [], [])
    topo = _FakeTopo([], {"found": False})
    out = AccessTools(store, topo).explain_access("nope", "8.8.8.8")
    assert out["error"] == "not_found"


def test_observed_flow_with_controls_and_coverage():
    ents = _client_server()
    comm = [{"edge_id": "E1", "attrs": {"sessions": "42", "bytes": "1000",
                                        "ports": "443", "providers": "juniper",
                                        "transports": "tcp"}}]
    policies = [{"policy": {"name": "trust-to-untrust",
                            "identifiers": {"provider": "juniper", "rule": "trust-to-untrust"},
                            "source": "observed"},
                 "edge_attrs": {"rule": "trust-to-untrust", "provider": "juniper"}}]
    store = _FakeStore(ents, comm, policies)
    topo = _FakeTopo(["vSRX-test10"], {"found": True, "hops": 3, "path_nodes": ["C", "X", "S"]})
    out = AccessTools(store, topo).explain_access("10.64.0.5", "8.8.8.8")
    assert out["observed_flows"]["sessions"] == 42
    assert out["observed_flows"]["providers"] == ["juniper"]
    assert out["controls"][0]["rule"] == "trust-to-untrust"
    assert out["controls"][0]["source"] == "observed"
    assert out["controls"][0]["firewall"] == "vSRX-test10"
    assert out["controls"][0]["firewall_basis"] == "topology"
    assert out["coverage"] == {"observed": True, "configured": "pending_m6b"}
    assert out["topology_path"]["found"] is True


def test_observed_flow_without_resolved_rule_is_a_finding():
    ents = _client_server()
    comm = [{"edge_id": "E1", "attrs": {"sessions": "5", "bytes": "10",
                                        "ports": "", "providers": "paloalto", "transports": "tcp"}}]
    store = _FakeStore(ents, comm, [])    # no governed_by policies
    topo = _FakeTopo([], {"found": False})
    out = AccessTools(store, topo).explain_access("10.64.0.5", "8.8.8.8")
    assert out["controls"] == []
    assert out["observed_flows"]["sessions"] == 5
    assert out["coverage"]["observed"] is True


def test_firewall_omitted_when_topology_ambiguous():
    ents = _client_server()
    comm = [{"edge_id": "E1", "attrs": {"sessions": "1", "bytes": "1",
                                        "ports": "443", "providers": "juniper", "transports": "tcp"}}]
    policies = [{"policy": {"name": "r", "identifiers": {"provider": "juniper", "rule": "r"},
                            "source": "observed"},
                 "edge_attrs": {"rule": "r", "provider": "juniper"}}]
    store = _FakeStore(ents, comm, policies)
    topo = _FakeTopo(["fw1", "fw2"], {"found": True, "hops": 4})   # two firewalls -> ambiguous
    out = AccessTools(store, topo).explain_access("10.64.0.5", "8.8.8.8")
    assert out["controls"][0]["firewall"] is None
    assert out["firewalls"] == ["fw1", "fw2"]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd services/mcp-query && uv run pytest tests/test_access_tools.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'ssdf_mcp_query.access_tools'`

- [ ] **Step 3: Write `access_tools.py`**

```python
# src/ssdf_mcp_query/access_tools.py
"""explain_access: end-to-end flow + observed security controls for a client→server pair."""

from __future__ import annotations

import datetime as _dt

DEFAULT_WINDOW_HOURS = 24


def _since(hours: int) -> str:
    return (_dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(hours=hours)).isoformat(
        timespec="milliseconds")


def _csv_list(value: str) -> list[str]:
    return [item for item in value.split(",") if item]


class AccessTools:
    """Stateless access-explanation tool bound to an EntityStore + M4 TopoTools."""

    def __init__(self, entity_store, topo_tools, default_window_hours: int = DEFAULT_WINDOW_HOURS):
        self._store = entity_store
        self._topo = topo_tools
        self._window = default_window_hours

    def explain_access(self, client: str, server: str, since_hours: int | None = None) -> dict:
        client_entity = self._store.find_entity(client)
        server_entity = self._store.find_entity(server)
        if not client_entity or not server_entity:
            missing = client if not client_entity else server
            return {"error": "not_found", "detail": f"no entity matches '{missing}'"}

        window = since_hours or self._window
        comm_edges = self._store.communicated_edges(
            client_entity["entity_id"], server_entity["entity_id"], _since(window))

        sessions = bytes_total = 0
        ports: set[str] = set()
        providers: set[str] = set()
        for edge in comm_edges:
            attrs = edge.get("attrs", {})
            sessions += int(attrs.get("sessions", "0") or 0)
            bytes_total += int(attrs.get("bytes", "0") or 0)
            ports.update(_csv_list(attrs.get("ports", "")))
            providers.update(_csv_list(attrs.get("providers", "")))

        # Firewall attribution comes from topology, NOT the event stream (see spec §3).
        enforcement = self._topo.enforcement_points(client, server)
        firewalls = enforcement.get("firewalls", [])
        attributed_fw = firewalls[0] if len(firewalls) == 1 else None

        controls = []
        if comm_edges:
            for item in self._store.governed_policies([e["edge_id"] for e in comm_edges]):
                policy = item["policy"]
                controls.append({
                    "firewall": attributed_fw,
                    "vendor": policy["identifiers"].get("provider", ""),
                    "rule": policy.get("name", ""),
                    "source": policy.get("source", "observed"),
                    "firewall_basis": "topology",
                })

        return {
            "client": {"entity_id": client_entity["entity_id"],
                       "name": client_entity.get("name", ""),
                       "identity_basis": client_entity.get("identity_basis", "")},
            "server": {"entity_id": server_entity["entity_id"],
                       "name": server_entity.get("name", ""),
                       "identity_basis": server_entity.get("identity_basis", "")},
            "observed_flows": {"sessions": sessions, "bytes": bytes_total,
                               "ports": sorted(int(p) for p in ports),
                               "providers": sorted(providers), "window_hours": window},
            "controls": controls,
            "firewalls": firewalls,
            "topology_path": self._topo.find_path(client, server),
            "coverage": {"observed": sessions > 0, "configured": "pending_m6b"},
        }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd services/mcp-query && uv run pytest tests/test_access_tools.py -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add services/mcp-query/src/ssdf_mcp_query/access_tools.py services/mcp-query/tests/test_access_tools.py
git commit -m "feat(m6a): explain_access tool (observed flows + controls + topology path + honesty contract)"
```

---

## Task 10: Register `explain_access` on the MCP server

**Files:**
- Modify: `services/mcp-query/src/ssdf_mcp_query/server.py`
- Test: `services/mcp-query/tests/test_server_entity.py`

- [ ] **Step 1: Write the failing test**

```python
# services/mcp-query/tests/test_server_entity.py
import os
import pytest

os.environ.setdefault("CH_PASSWORD", "x")
os.environ.setdefault("MCP_AUTH_TOKEN", "t")


def test_explain_access_tool_is_registered(monkeypatch):
    # build_app constructs CH clients; patch them out so import/registration is side-effect free.
    import ssdf_mcp_query.server as server

    class _Dummy:
        def __init__(self, *a, **k):
            pass

    monkeypatch.setattr(server, "ClickHouseClient", _Dummy)
    app = server.build_app()
    assert "explain_access" in _registered_tool_names(app)


def _registered_tool_names(app):
    # fastmcp stores tools on an internal manager; support a couple of layouts.
    for attr in ("_tool_manager", "tool_manager"):
        manager = getattr(app, attr, None)
        if manager is not None:
            tools = getattr(manager, "_tools", None) or getattr(manager, "tools", None)
            if tools is not None:
                return set(tools.keys())
    raise AssertionError("could not locate fastmcp tool registry")
```

> Note for the implementer: confirm the exact fastmcp tool-registry accessor against the installed
> version (the existing `tests/test_server_topo.py` already does this — copy its proven approach
> rather than the defensive shim above if it differs).

- [ ] **Step 2: Run test to verify it fails**

Run: `cd services/mcp-query && uv run pytest tests/test_server_entity.py -v`
Expected: FAIL (`explain_access` not registered)

- [ ] **Step 3: Wire the tool into `server.py`**

Add imports near the other tool imports:

```python
from .entitystore import ClickHouseEntityStore
from .access_tools import AccessTools
```

In `build_app`, after the `topo = TopoTools(graph_store)` line, add:

```python
    entity_store = ClickHouseEntityStore(client, tenant="t_main")
    access = AccessTools(entity_store, topo)
```

And register the tool alongside the others (before `return mcp`):

```python
    @mcp.tool
    def explain_access(client: str, server: str, since_hours: int | None = None) -> dict:
        """End-to-end view: observed flows + security controls (rules/firewalls) + topology path
        between a client and a server. Accepts ip/mac/name. Controls are observed-only in M6a
        (coverage.configured = 'pending_m6b'); firewall attribution is inferred from topology."""
        return access.explain_access(client, server, since_hours=since_hours)
```

- [ ] **Step 4: Align the test with the real registry accessor**

Open `tests/test_server_topo.py`, copy how it asserts a tool is registered, and simplify
`test_server_entity.py` to use that exact pattern asserting `"explain_access"` is present.

- [ ] **Step 5: Run the test to verify it passes**

Run: `cd services/mcp-query && uv run pytest tests/test_server_entity.py -v`
Expected: PASS

- [ ] **Step 6: Run the full read-side suite**

Run: `cd services/mcp-query && uv run pytest -m "not integration" -v`
Expected: PASS (all unit tests green, including pre-existing ones)

- [ ] **Step 7: Commit**

```bash
git add services/mcp-query/src/ssdf_mcp_query/server.py services/mcp-query/tests/test_server_entity.py
git commit -m "feat(m6a): register explain_access on ssdf-mcp-query server"
```

---

## Task 11: Deployment artifacts + live bring-up

**Files:**
- Create: `services/entity/infra/ENV.example`
- Create: `services/entity/infra/ssdf-entity.service`
- Create: `services/entity/infra/ssdf-entity.timer`

> Deployment touches live lab infra (ct104 ClickHouse, ct109 resolver host, ct106 MCP server).
> Do the file creation + commit as a normal task; **pause before the live `pct`/`clickhouse-client`
> steps and confirm with the operator** (these mutate shared infra). Reuse the M4 deploy lessons:
> ct109 installs **non-editable** from `/opt/src/topo`; install the entity package the same way and
> push ALL changed source files before reinstalling.

- [ ] **Step 1: Write `infra/ENV.example`**

```bash
# services/entity/infra/ENV.example — copy to ENV.local (gitignored) on ct109
CH_HOST=198.51.100.151
CH_PORT=8123
CH_USER=ssdf_entity
CH_PASSWORD=__set_me__
CH_DATABASE=ssdf
ENTITY_TENANT=t_main
ENTITY_WINDOW_HOURS=24
```

- [ ] **Step 2: Write the systemd unit + timer** (mirror `services/topo/infra/ssdf-topo.{service,timer}`)

```ini
# services/entity/infra/ssdf-entity.service
[Unit]
Description=SSDF M6 entity resolver (oneshot)
After=network-online.target

[Service]
Type=oneshot
EnvironmentFile=/opt/ssdf-entity/ENV.local
ExecStart=/opt/ssdf-entity/venv/bin/python -m ssdf_entity.resolve_main
```

```ini
# services/entity/infra/ssdf-entity.timer
[Unit]
Description=Run SSDF entity resolver every 5 minutes

[Timer]
OnBootSec=3min
OnUnitActiveSec=5min
Unit=ssdf-entity.service

[Install]
WantedBy=timers.target
```

- [ ] **Step 3: Commit the artifacts**

```bash
git add services/entity/infra/
git commit -m "feat(m6a): entity service deployment artifacts (ENV.example, systemd unit+timer)"
```

- [ ] **Step 4: (Live, confirm first) Apply schema + user on ct104**

```bash
# from the dev host, against ct104 (198.51.100.151) as CH admin
clickhouse-client --host 198.51.100.151 --multiquery < infra/clickhouse/004_entities.sql
ENTITY_PW="$CH_ENTITY_PASSWORD" envsubst < infra/clickhouse/005_entity_user.sql \
  | clickhouse-client --host 198.51.100.151 --multiquery
```
Expected: tables `ssdf.entities`, `ssdf.entity_edges` exist; `ssdf_entity` user created; `ssdf_ro`
granted SELECT on both.

- [ ] **Step 5: (Live, confirm first) Install + enable resolver on ct109**

Push the package to `/opt/src/entity`, build a venv, non-editable install, drop `ENV.local`, install
the unit+timer, run one manual cycle:

```bash
ssh root@ct109 "python3 -m venv /opt/ssdf-entity/venv && \
  /opt/ssdf-entity/venv/bin/pip install --force-reinstall --no-deps /opt/src/entity && \
  /opt/ssdf-entity/venv/bin/pip install clickhouse-connect && \
  systemctl daemon-reload && systemctl start ssdf-entity.service && \
  journalctl -u ssdf-entity.service --no-pager | tail -5"
```
Expected: log line `entity resolver: N entities, M edges upserted` with N,M > 0.

- [ ] **Step 6: (Live) Restart the MCP server on ct106 to pick up the new tool**

```bash
ssh root@ct106 "systemctl restart ssdf-mcp-query.service && systemctl is-active ssdf-mcp-query.service"
```
Expected: `active`. (Push updated mcp-query source to `/opt/src-mcp/mcp-query` and reinstall first,
per the M4 redeploy lesson.)

- [ ] **Step 7: Enable the timer**

```bash
ssh root@ct109 "systemctl enable --now ssdf-entity.timer && systemctl list-timers ssdf-entity.timer --no-pager"
```
Expected: timer listed, next run scheduled.

---

## Task 12: Live integration test + validation

**Files:**
- Create: `services/entity/tests/test_integration.py` (live entity check lives in the entity
  service suite only; no additions to the mcp-query integration suite)

- [ ] **Step 1: Write the live integration test**

```python
# services/entity/tests/test_integration.py
import os
import pytest

pytestmark = pytest.mark.integration

from ssdf_entity.chwriter import ClickHouseEntityWriter
from ssdf_entity.config import load_config
from ssdf_entity.resolve_main import run_resolver


@pytest.fixture
def writer():
    if not os.environ.get("CH_PASSWORD"):
        pytest.skip("CH_PASSWORD not set; live integration skipped")
    return ClickHouseEntityWriter(load_config())


def test_resolver_writes_entities_against_live_ch(writer):
    n_entities, n_edges = run_resolver(writer, tenant="t_main", window_hours=720)
    assert n_entities >= 0  # may be 0 if no flows in window; assert the call path works
    rows = writer.query(
        "SELECT count() AS c FROM ssdf.entities FINAL WHERE tenant_id = {t:String}",
        {"t": "t_main"})
    assert rows[0]["c"] >= n_entities
```

- [ ] **Step 2: Run the live integration test**

Run: `cd services/entity && CH_HOST=198.51.100.151 CH_USER=ssdf_entity CH_PASSWORD=<pw> uv run pytest -m integration -v`
Expected: PASS (resolver runs end-to-end against ct104).

- [ ] **Step 3: Validate `explain_access` end-to-end via the MCP tool**

Pick a real client/server pair observed in `ssdf.events` (use `query_flows` or `top_talkers` to find
one), then call `explain_access`. Confirm it returns `observed_flows.sessions > 0`, `controls[]`
stamped `source: "observed"`, `coverage.configured == "pending_m6b"`, and a `topology_path`.

```bash
clickhouse-client --host 198.51.100.151 --query \
  "SELECT toString(source_ip), toString(destination_ip), count() FROM ssdf.events \
   WHERE source_ip IS NOT NULL AND destination_ip IS NOT NULL GROUP BY 1,2 ORDER BY 3 DESC LIMIT 3"
# then call explain_access(client=<src>, server=<dst>) through the MCP client / agent
```

- [ ] **Step 4: Run the full suite for both services + vulnerability scan**

Run: `cd services/entity && uv run pytest -m "not integration" && cd ../mcp-query && uv run pytest -m "not integration"`
Expected: all green. Confirm all ClickHouse access is parameterized (no f-string interpolation of
user input) — grep the new files for string-built SQL with user values.

- [ ] **Step 5: Update `CLAUDE.md` Commands + `STATUS.md`**

Add an M6a Commands subsection to `CLAUDE.md` (unit/integration test commands, the resolver run
command, deploy coords) and mark M6a built in `docs/superpowers/STATUS.md` (new as-built row;
update the forward-roadmap M6 bullet to "M6a done; M6b/M6c pending").

- [ ] **Step 6: Commit**

```bash
git add services/entity/tests/test_integration.py CLAUDE.md docs/superpowers/STATUS.md
git commit -m "test(m6a): live entity resolver integration + docs/status update"
```

---

## Done criteria (M6a)

- `ssdf.entities` / `ssdf.entity_edges` exist on ct104; `ssdf_entity` writes, `ssdf_ro` reads.
- The entity resolver runs on ct109 on a 5-min timer, projecting Assets + observed Policies + edges.
- `explain_access(client, server)` on ct106 returns observed flows, observed controls (with
  topology-inferred firewall), a topology path, and the `coverage.configured: "pending_m6b"`
  honesty marker — validated against a real client/server pair.
- All unit tests green for `services/entity` and `services/mcp-query`; live integration passes.
- M6b (configured policy) and M6c (L3 stitching / Postgres-as-graph) remain documented future plans.
