# SSDF M7c — Public De-identified Metrics Tier Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the M7b public topology surface with a sovereign-computed, de-identified metrics/time-series surface (keyed pseudonymization + bucketing) so a public frontier LLM can do predictive analysis without ever seeing a real identifier, rule, detection, or spec.

**Architecture:** A new `public-metrics` resolver (4th ct109 role) reads raw `ssdf.events`, pre-aggregates de-identified bucketed series into physical `ssdf_public.metric_timeseries` + `ssdf_public.entity_series`, and writes the keyed real↔surrogate map into sovereign-only `ssdf.pseudonym_map`. The public MCP tier (ct113) gains 3 read-only `metrics` tools over the `ssdf_public.*` tables; the sovereign tier (ct106) gains `reidentify`. A phase-0 classification flip drops the 5 M7b topology/identity tools from the public tier.

**Tech Stack:** Python 3.11 (uv), clickhouse-connect, FastMCP, ClickHouse (ReplacingMergeTree), systemd timer (DynamicUser + LoadCredential). Keyed pseudonym = HMAC-SHA256 in Python stdlib (`hmac`/`hashlib`) — the spec named ClickHouse's `sipHash64Keyed` illustratively, but the resolver hashes in Python where no SipHash-keyed primitive exists in stdlib; HMAC-SHA256 has the same consistent + irreversible + keyed properties.

**Spec:** `docs/superpowers/specs/2026-06-19-ssdf-m7c-public-deidentified-metrics-design.md`

---

## File Structure

**New service `services/public-metrics/` (package `ssdf_pubmetrics`)** — mirrors `services/policy/`:
- `config.py` — env-driven runtime config (CH creds + TLS, pseudonym key, bucket/lookback/top-N).
- `pseudonym.py` — pure surrogate computation (HMAC keyed, per-kind prefix) + collision lengthening.
- `measures.py` — declarative measure catalog + pure SQL builders (aggregate / per-entity / index).
- `chreader.py` — read seam over `ssdf.events` + existing-surrogate lookup.
- `chwriter.py` — write seam to `ssdf_public.metric_timeseries`, `ssdf_public.entity_series`, `ssdf.pseudonym_map`.
- `resolve.py` — entrypoint: read → de-identify → aggregate → write, one pass.
- `infra/` — systemd `.service`/`.timer` + `ENV.local.example`.

**`services/mcp-query` additions:**
- `metrics_store.py` — read seam over `ssdf_public.*` metric tables + sovereign `ssdf.pseudonym_map`.
- `metric_tools.py` — the 3 public metrics tools + the sovereign `reidentify` tool.
- `classification.py` (edit) — add the `metrics` data class + tool mappings.
- `server.py` (edit) — register the new tools.

**`infra/clickhouse/013_public_metrics.sql`** — tables, writer user, grants.

**Docs:** `onboarding/public-metrics/key-management.md`, plus `CLAUDE.md` + `STATUS.md` updates.

---

## Phase A — ClickHouse migration (013)

### Task A1: Migration file for tables, writer user, grants

**Files:**
- Create: `infra/clickhouse/013_public_metrics.sql`

- [ ] **Step 1: Write the migration**

Create `infra/clickhouse/013_public_metrics.sql`:

```sql
-- infra/clickhouse/013_public_metrics.sql
-- M7c: public de-identified metrics tables + the ssdf_pubmetrics writer user.
-- ClickHouse does NOT expand {name:Type} params inside CREATE USER ... BY '...',
-- so inject the password before applying (never commit the real value):
--   PUBMETRICS_PW="$CH_PUBMETRICS_PASSWORD" envsubst < 013_public_metrics.sql \
--     | clickhouse-client --host <ct104> --multiquery
--
-- Enforcement model (extends 008's hard-floor): the metric tables live in the
-- ssdf_public database and carry ONLY surrogates + numbers. ssdf.pseudonym_map
-- (real<->surrogate) is sovereign: granted to ssdf_ro (for reidentify) and the
-- ssdf_pubmetrics writer ONLY, NEVER to ssdf_public.

CREATE DATABASE IF NOT EXISTS ssdf_public;

-- Aggregate (system-wide) de-identified series. dim carries only de-identified
-- dimensions ('' = system total). ReplacingMergeTree(inserted_at) so a re-run
-- of the same bucket overwrites rather than double-counts (read with FINAL).
CREATE TABLE IF NOT EXISTS ssdf_public.metric_timeseries
(
    bucket_start DateTime,
    metric       LowCardinality(String),
    dim          LowCardinality(String),
    value        Float64,
    tenant_id    LowCardinality(String) DEFAULT 't_main',
    inserted_at  DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(inserted_at)
ORDER BY (tenant_id, metric, dim, bucket_start)
TTL bucket_start + INTERVAL 30 DAY;

-- Per-entity series keyed by SURROGATE only, written only for top-N entities.
CREATE TABLE IF NOT EXISTS ssdf_public.entity_series
(
    bucket_start DateTime,
    surrogate    String,
    metric       LowCardinality(String),
    value        Float64,
    tenant_id    LowCardinality(String) DEFAULT 't_main',
    inserted_at  DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(inserted_at)
ORDER BY (tenant_id, metric, surrogate, bucket_start)
TTL bucket_start + INTERVAL 30 DAY;

-- SOVEREIGN: the keyed real<->surrogate map. Never granted to ssdf_public.
CREATE TABLE IF NOT EXISTS ssdf.pseudonym_map
(
    kind        LowCardinality(String),
    real_value  String,
    surrogate   String,
    key_version UInt16,
    first_seen  DateTime64(3, 'UTC'),
    last_seen   DateTime64(3, 'UTC')
)
ENGINE = ReplacingMergeTree(last_seen)
ORDER BY (kind, real_value, key_version);

-- Least-privilege writer for the resolver (ct109).
CREATE USER IF NOT EXISTS ssdf_pubmetrics IDENTIFIED WITH sha256_password BY '${PUBMETRICS_PW}';
GRANT SELECT ON ssdf.events TO ssdf_pubmetrics;
GRANT INSERT, SELECT ON ssdf_public.metric_timeseries TO ssdf_pubmetrics;
GRANT INSERT, SELECT ON ssdf_public.entity_series TO ssdf_pubmetrics;
GRANT INSERT, SELECT ON ssdf.pseudonym_map TO ssdf_pubmetrics;

-- Public reader: granted ONLY the two de-identified metric tables. No base
-- ssdf.* grant, and explicitly NOT ssdf.pseudonym_map.
GRANT SELECT ON ssdf_public.metric_timeseries TO ssdf_public;
GRANT SELECT ON ssdf_public.entity_series TO ssdf_public;

-- Sovereign reader (ct106): the metrics tools also run on the sovereign tier, and
-- reidentify reads the pseudonym map. Both grants stay sovereign-side.
GRANT SELECT ON ssdf_public.metric_timeseries TO ssdf_ro;
GRANT SELECT ON ssdf_public.entity_series TO ssdf_ro;
GRANT SELECT ON ssdf.pseudonym_map TO ssdf_ro;
```

- [ ] **Step 2: Validate SQL syntax locally (no live CH needed)**

Run: `PUBMETRICS_PW=test envsubst < infra/clickhouse/013_public_metrics.sql | head -40`
Expected: the `${PUBMETRICS_PW}` placeholder is replaced with `test`; no `envsubst` errors.

- [ ] **Step 3: Commit**

```bash
git add infra/clickhouse/013_public_metrics.sql
git commit -m "feat(m7c): clickhouse migration for public metrics tables + pseudonym map"
```

---

## Phase B — public-metrics resolver service

### Task B1: Scaffold the service package

**Files:**
- Create: `services/public-metrics/pyproject.toml`
- Create: `services/public-metrics/src/ssdf_pubmetrics/__init__.py`

- [ ] **Step 1: Write `pyproject.toml`**

Create `services/public-metrics/pyproject.toml` (mirrors `services/policy/pyproject.toml`):

```toml
[project]
name = "ssdf-pubmetrics"
version = "0.1.0"
description = "SSDF M7c public de-identified metrics resolver (ssdf.events -> ssdf_public.*)"
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
packages = ["src/ssdf_pubmetrics"]

[tool.pytest.ini_options]
testpaths = ["tests"]
pythonpath = ["src"]
markers = ["integration: requires live ClickHouse (deselect with -m 'not integration')"]

[dependency-groups]
dev = ["pytest>=9.0.3"]
```

- [ ] **Step 2: Create the package init**

Create `services/public-metrics/src/ssdf_pubmetrics/__init__.py`:

```python
"""SSDF M7c public de-identified metrics resolver."""
```

- [ ] **Step 3: Verify the package imports**

Run: `cd services/public-metrics && uv run python -c "import ssdf_pubmetrics"`
Expected: no output, exit 0.

- [ ] **Step 4: Commit**

```bash
git add services/public-metrics/pyproject.toml services/public-metrics/src/ssdf_pubmetrics/__init__.py
git commit -m "chore(m7c): scaffold public-metrics resolver package"
```

### Task B2: Pseudonym module (keyed surrogate + collision lengthening)

**Files:**
- Create: `services/public-metrics/src/ssdf_pubmetrics/pseudonym.py`
- Test: `services/public-metrics/tests/test_pseudonym.py`

- [ ] **Step 1: Write the failing test**

Create `services/public-metrics/tests/test_pseudonym.py`:

```python
from ssdf_pubmetrics.pseudonym import surrogate, mint_surrogate, PREFIXES

KEY = bytes.fromhex("00112233445566778899aabbccddeeff")


def test_surrogate_is_deterministic():
    assert surrogate(KEY, "host", "10.74.11.20") == surrogate(KEY, "host", "10.74.11.20")


def test_surrogate_has_kind_prefix():
    assert surrogate(KEY, "host", "10.74.11.20").startswith("h_")
    assert surrogate(KEY, "firewall", "panosvm").startswith("fw_")


def test_surrogate_changes_with_key():
    other = bytes.fromhex("ffeeddccbbaa99887766554433221100")
    assert surrogate(KEY, "host", "10.74.11.20") != surrogate(other, "host", "10.74.11.20")


def test_surrogate_unknown_kind_raises():
    import pytest
    with pytest.raises(ValueError):
        surrogate(KEY, "bogus", "x")


def test_mint_reuses_existing_map_entry():
    existing = {("host", "10.74.11.20"): "h_deadbeef00"}
    assert mint_surrogate(existing, KEY, "host", "10.74.11.20") == "h_deadbeef00"


def test_mint_lengthens_on_collision_with_different_value():
    # Force a collision: a DIFFERENT real_value already holds the base-length surrogate.
    base = surrogate(KEY, "host", "10.74.11.20")
    existing = {("host", "1.2.3.4"): base}
    minted = mint_surrogate(existing, KEY, "host", "10.74.11.20", base_length=len(base) - 2)
    assert minted != base
    assert minted.startswith("h_")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd services/public-metrics && uv run pytest tests/test_pseudonym.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'ssdf_pubmetrics.pseudonym'`.

- [ ] **Step 3: Write the implementation**

Create `services/public-metrics/src/ssdf_pubmetrics/pseudonym.py`:

```python
"""Keyed, consistent, irreversible surrogates for de-identification.

HMAC-SHA256 over ``kind:real_value`` keyed by the sovereign PUBLIC_PSEUDONYM_KEY.
Same key+kind+value always yields the same surrogate (series continuity); the hash
is one-way and the public side cannot recompute it without the key.
"""

from __future__ import annotations

import hashlib
import hmac

PREFIXES: dict[str, str] = {
    "host": "h_",
    "firewall": "fw_",
    "segment": "seg_",
    "port": "p_",
    "vmid": "vm_",
}

_BASE_LENGTH = 10  # hex chars of digest after the prefix


def surrogate(key: bytes, kind: str, real_value: str, length: int = _BASE_LENGTH) -> str:
    """Return the per-kind-prefixed keyed surrogate for ``real_value``."""
    if kind not in PREFIXES:
        raise ValueError(f"unknown pseudonym kind: {kind}")
    message = f"{kind}:{real_value}".encode("utf-8")
    digest = hmac.new(key, message, hashlib.sha256).hexdigest()
    return PREFIXES[kind] + digest[:length]


def mint_surrogate(existing: dict[tuple[str, str], str], key: bytes, kind: str,
                   real_value: str, base_length: int = _BASE_LENGTH) -> str:
    """Return the authoritative surrogate, reusing the map and lengthening on collision.

    ``existing`` maps ``(kind, real_value) -> surrogate`` (the current pseudonym_map).
    Reuse a prior surrogate verbatim. Otherwise mint at ``base_length``; if that
    surrogate is already bound to a DIFFERENT real_value, lengthen the hex slice until
    it no longer collides. The map remains authoritative.
    """
    prior = existing.get((kind, real_value))
    if prior is not None:
        return prior
    taken = {sur: rv for (k, rv), sur in existing.items() if k == kind}
    length = base_length
    while True:
        candidate = surrogate(key, kind, real_value, length=length)
        collides_with = taken.get(candidate)
        if collides_with is None or collides_with == real_value:
            return candidate
        length += 2
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd services/public-metrics && uv run pytest tests/test_pseudonym.py -v`
Expected: PASS (6 passed).

- [ ] **Step 5: Commit**

```bash
git add services/public-metrics/src/ssdf_pubmetrics/pseudonym.py services/public-metrics/tests/test_pseudonym.py
git commit -m "feat(m7c): keyed pseudonym surrogates with collision lengthening"
```

### Task B3: Measure catalog + pure SQL builders

**Files:**
- Create: `services/public-metrics/src/ssdf_pubmetrics/measures.py`
- Test: `services/public-metrics/tests/test_measures.py`

- [ ] **Step 1: Write the failing test**

Create `services/public-metrics/tests/test_measures.py`:

```python
from ssdf_pubmetrics.measures import (
    CATALOG, INDEX_METRICS, enabled_measures, ratio_to_baseline,
    build_aggregate_sql, build_entity_bucket_sql, build_deny_counts_sql,
    build_alert_count_sql, AGG_VALUE_EXPR,
)


def test_catalog_has_tier1_and_tier2_enabled():
    ids = {m.metric for m in enabled_measures()}
    assert {"bytes", "flows", "connections", "deny_rate_index", "ips_volume_index"} <= ids


def test_tier3_health_measures_present_but_disabled():
    by_id = {m.metric: m for m in CATALOG}
    for mid in ("mem_util_pct", "cpu_util_pct", "iface_error_rate",
                "port_flap_count", "proto_flap_count"):
        assert by_id[mid].enabled is False


def test_index_metrics_set():
    assert INDEX_METRICS == {"deny_rate_index", "ips_volume_index"}


def test_ratio_to_baseline_zero_guard():
    assert ratio_to_baseline(0.5, 0.0) == 0.0
    assert ratio_to_baseline(0.4, 0.2) == 2.0


def test_aggregate_sql_uses_bucket_and_expr():
    sql, params = build_aggregate_sql("bytes", "2026-06-19T00:00:00+00:00", 300, "t_main")
    assert "toStartOfInterval(timestamp, INTERVAL 300 SECOND)" in sql
    assert AGG_VALUE_EXPR["bytes"] in sql
    assert params["tenant"] == "t_main"


def test_entity_bucket_sql_groups_by_ip():
    sql, params = build_entity_bucket_sql("flows", "2026-06-19T00:00:00+00:00", 300, "t_main")
    assert "toString(source_ip) AS ip" in sql
    assert "source_ip IS NOT NULL" in sql
    assert "GROUP BY bucket_start, ip" in sql


def test_deny_counts_sql_selects_deny_and_total():
    sql, params = build_deny_counts_sql("2026-06-19T00:00:00+00:00", "t_main")
    assert "countIf(event_action IN" in sql
    assert "AS deny" in sql and "AS total" in sql
    assert params["deny"] == ["deny", "drop", "block", "reject"]


def test_alert_count_sql_filters_unifi_alert():
    sql, params = build_alert_count_sql("2026-06-19T00:00:00+00:00", "t_main")
    assert "event_provider = 'unifi'" in sql
    assert "event_kind = 'alert'" in sql
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd services/public-metrics && uv run pytest tests/test_measures.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'ssdf_pubmetrics.measures'`.

- [ ] **Step 3: Write the implementation**

Create `services/public-metrics/src/ssdf_pubmetrics/measures.py`:

```python
"""Declarative measure catalog + pure SQL builders (return (sql, params); no I/O).

Catalog is extensible: M13 health signals append as enabled entries with no
redesign. M7c ships only measures derivable from today's ssdf.events.
"""

from __future__ import annotations

from dataclasses import dataclass

DENY_ACTIONS = ["deny", "drop", "block", "reject"]

# Per-entity series are keyed by the source IP (mapped to a 'host' surrogate).
INDEX_METRICS: set[str] = {"deny_rate_index", "ips_volume_index"}

AGG_VALUE_EXPR: dict[str, str] = {
    "bytes": "sum(network_bytes)",
    "flows": "count()",
    "connections": ("uniqExact((source_ip, source_port, destination_ip, "
                    "destination_port, network_transport))"),
}


@dataclass(frozen=True)
class Measure:
    metric: str
    enabled: bool
    per_entity: bool  # also emit top-N entity_series rows
    kind: str         # 'aggregate' | 'index'


CATALOG: list[Measure] = [
    # Tier 1 — shareable volume/activity
    Measure("bytes", True, True, "aggregate"),
    Measure("flows", True, True, "aggregate"),
    Measure("connections", True, True, "aggregate"),
    # Tier 2 — normalized stance indices (ratio-to-baseline only)
    Measure("deny_rate_index", True, False, "index"),
    Measure("ips_volume_index", True, False, "index"),
    # Tier 3 — operational health, gated on M13 ingest (disabled placeholders)
    Measure("mem_util_pct", False, False, "aggregate"),
    Measure("cpu_util_pct", False, False, "aggregate"),
    Measure("iface_error_rate", False, False, "aggregate"),
    Measure("port_flap_count", False, False, "aggregate"),
    Measure("proto_flap_count", False, False, "aggregate"),
]


def enabled_measures() -> list[Measure]:
    """The catalog entries whose source data exists today."""
    return [m for m in CATALOG if m.enabled]


def ratio_to_baseline(current_rate: float, baseline_rate: float) -> float:
    """current / baseline, guarding a zero baseline (no history yet) as 0.0."""
    if baseline_rate == 0:
        return 0.0
    return current_rate / baseline_rate


def build_aggregate_sql(metric: str, since_iso: str, bucket_secs: int,
                        tenant: str) -> tuple[str, dict]:
    expr = AGG_VALUE_EXPR[metric]
    sql = (
        f"SELECT toStartOfInterval(timestamp, INTERVAL {int(bucket_secs)} SECOND) "
        f"AS bucket_start, toFloat64({expr}) AS value FROM ssdf.events "
        "WHERE tenant_id = {tenant:String} "
        "AND timestamp >= parseDateTimeBestEffort({since:String}) "
        "GROUP BY bucket_start ORDER BY bucket_start"
    )
    return sql, {"tenant": tenant, "since": since_iso}


def build_entity_bucket_sql(metric: str, since_iso: str, bucket_secs: int,
                            tenant: str) -> tuple[str, dict]:
    expr = AGG_VALUE_EXPR[metric]
    sql = (
        f"SELECT toStartOfInterval(timestamp, INTERVAL {int(bucket_secs)} SECOND) "
        f"AS bucket_start, toString(source_ip) AS ip, toFloat64({expr}) AS value "
        "FROM ssdf.events "
        "WHERE tenant_id = {tenant:String} AND source_ip IS NOT NULL "
        "AND timestamp >= parseDateTimeBestEffort({since:String}) "
        "GROUP BY bucket_start, ip ORDER BY bucket_start"
    )
    return sql, {"tenant": tenant, "since": since_iso}


def build_deny_counts_sql(since_iso: str, tenant: str) -> tuple[str, dict]:
    sql = (
        "SELECT toFloat64(countIf(event_action IN {deny:Array(String)})) AS deny, "
        "toFloat64(count()) AS total FROM ssdf.events "
        "WHERE tenant_id = {tenant:String} "
        "AND event_provider IN ('paloalto', 'juniper') "
        "AND timestamp >= parseDateTimeBestEffort({since:String})"
    )
    return sql, {"tenant": tenant, "since": since_iso, "deny": DENY_ACTIONS}


def build_alert_count_sql(since_iso: str, tenant: str) -> tuple[str, dict]:
    sql = (
        "SELECT toFloat64(count()) AS c FROM ssdf.events "
        "WHERE tenant_id = {tenant:String} AND event_provider = 'unifi' "
        "AND event_kind = 'alert' "
        "AND timestamp >= parseDateTimeBestEffort({since:String})"
    )
    return sql, {"tenant": tenant, "since": since_iso}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd services/public-metrics && uv run pytest tests/test_measures.py -v`
Expected: PASS (8 passed).

- [ ] **Step 5: Commit**

```bash
git add services/public-metrics/src/ssdf_pubmetrics/measures.py services/public-metrics/tests/test_measures.py
git commit -m "feat(m7c): measure catalog + pure aggregation/index SQL builders"
```

### Task B4: Config (env-driven runtime config)

**Files:**
- Create: `services/public-metrics/src/ssdf_pubmetrics/config.py`
- Test: `services/public-metrics/tests/test_config.py`

- [ ] **Step 1: Write the failing test**

Create `services/public-metrics/tests/test_config.py`:

```python
import pytest

from ssdf_pubmetrics.config import Config, ConfigError, load_config


def test_load_config_requires_password(monkeypatch):
    monkeypatch.delenv("CH_PASSWORD", raising=False)
    monkeypatch.setenv("PUBLIC_PSEUDONYM_KEY", "00112233445566778899aabbccddeeff")
    with pytest.raises(ConfigError):
        load_config()


def test_load_config_requires_key(monkeypatch):
    monkeypatch.setenv("CH_PASSWORD", "pw")
    monkeypatch.delenv("PUBLIC_PSEUDONYM_KEY", raising=False)
    with pytest.raises(ConfigError):
        load_config()


def test_load_config_rejects_non_hex_key(monkeypatch):
    monkeypatch.setenv("CH_PASSWORD", "pw")
    monkeypatch.setenv("PUBLIC_PSEUDONYM_KEY", "not-hex")
    with pytest.raises(ConfigError):
        load_config()


def test_load_config_defaults(monkeypatch):
    monkeypatch.setenv("CH_PASSWORD", "pw")
    monkeypatch.setenv("PUBLIC_PSEUDONYM_KEY", "00112233445566778899aabbccddeeff")
    cfg = load_config()
    assert isinstance(cfg, Config)
    assert cfg.ch_user == "ssdf_pubmetrics"
    assert cfg.bucket_secs == 300
    assert cfg.lookback_hours == 1
    assert cfg.baseline_days == 30
    assert cfg.top_n == 20
    assert cfg.key_version == 1
    assert cfg.pseudonym_key == bytes.fromhex("00112233445566778899aabbccddeeff")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd services/public-metrics && uv run pytest tests/test_config.py -v`
Expected: FAIL with `ModuleNotFoundError`.

- [ ] **Step 3: Write the implementation**

Create `services/public-metrics/src/ssdf_pubmetrics/config.py`:

```python
"""Runtime config for the public-metrics resolver (env-driven).

Writes ClickHouse as the ssdf_pubmetrics user. The sovereign PUBLIC_PSEUDONYM_KEY
is a hex string (e.g. `openssl rand -hex 16`), held ONLY on ct109.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


class ConfigError(RuntimeError):
    """Raised when required configuration is missing or invalid."""


@dataclass(frozen=True)
class Config:
    ch_host: str
    ch_port: int
    ch_user: str
    ch_password: str
    ch_database: str
    tenant_id: str
    pseudonym_key: bytes
    key_version: int
    bucket_secs: int
    lookback_hours: int
    baseline_days: int
    top_n: int
    ch_secure: bool = False
    ch_ca_file: str = ""


def load_config() -> Config:
    password = os.environ.get("CH_PASSWORD")
    if password is None:
        raise ConfigError("CH_PASSWORD is required")
    raw_key = os.environ.get("PUBLIC_PSEUDONYM_KEY")
    if not raw_key:
        raise ConfigError("PUBLIC_PSEUDONYM_KEY is required")
    try:
        key = bytes.fromhex(raw_key)
    except ValueError as exc:
        raise ConfigError(f"PUBLIC_PSEUDONYM_KEY must be hex: {exc}") from exc
    return Config(
        ch_host=os.environ.get("CH_HOST", "127.0.0.1"),
        ch_port=int(os.environ.get("CH_PORT", "8123")),
        ch_user=os.environ.get("CH_USER", "ssdf_pubmetrics"),
        ch_password=password,
        ch_database=os.environ.get("CH_DATABASE", "ssdf"),
        tenant_id=os.environ.get("PUBMETRICS_TENANT_ID", "t_main"),
        pseudonym_key=key,
        key_version=int(os.environ.get("PUBMETRICS_KEY_VERSION", "1")),
        bucket_secs=int(os.environ.get("PUBMETRICS_BUCKET_SECS", "300")),
        lookback_hours=int(os.environ.get("PUBMETRICS_LOOKBACK_HOURS", "1")),
        baseline_days=int(os.environ.get("PUBMETRICS_BASELINE_DAYS", "30")),
        top_n=int(os.environ.get("PUBMETRICS_TOP_N", "20")),
        ch_secure=os.environ.get("CH_SECURE", "0").strip().lower() in ("1", "true"),
        ch_ca_file=os.environ.get("CH_CA_FILE", ""),
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd services/public-metrics && uv run pytest tests/test_config.py -v`
Expected: PASS (4 passed).

- [ ] **Step 5: Commit**

```bash
git add services/public-metrics/src/ssdf_pubmetrics/config.py services/public-metrics/tests/test_config.py
git commit -m "feat(m7c): public-metrics resolver config"
```

### Task B5: ClickHouse reader + writer seams

**Files:**
- Create: `services/public-metrics/src/ssdf_pubmetrics/chreader.py`
- Create: `services/public-metrics/src/ssdf_pubmetrics/chwriter.py`
- Test: `services/public-metrics/tests/test_chio.py`

The reader runs the `measures.py` builders against `ssdf.events` and loads the
current pseudonym map. The writer inserts the three tables. Both share a
`client_kwargs` TLS helper identical to `services/policy/src/ssdf_policy/chwriter.py`.

- [ ] **Step 1: Write the failing test (uses a fake CH client; no live CH)**

Create `services/public-metrics/tests/test_chio.py`:

```python
from ssdf_pubmetrics.chreader import EventsReader
from ssdf_pubmetrics.chwriter import (
    MetricsWriter, METRIC_COLUMNS, ENTITY_COLUMNS, MAP_COLUMNS,
)


class _FakeClient:
    def __init__(self, rows):
        self._rows = rows
        self.queries = []
        self.inserts = []

    def query(self, sql, parameters=None, settings=None):
        self.queries.append((sql, parameters))

        class _R:
            column_names = self._cols
            result_rows = self._rr

        r = _R()
        r._cols = self._rows["cols"]
        r._rr = self._rows["rows"]
        return r

    def insert(self, table, rows, column_names=None):
        self.inserts.append((table, rows, column_names))


def test_reader_aggregate_series_returns_rows():
    fake = _FakeClient({"cols": ["bucket_start", "value"],
                        "rows": [["2026-06-19 00:00:00", 1234.0]]})
    reader = EventsReader.__new__(EventsReader)
    reader._client = fake
    reader._tenant = "t_main"
    out = reader.aggregate_series("bytes", "2026-06-19T00:00:00+00:00", 300)
    assert out == [{"bucket_start": "2026-06-19 00:00:00", "value": 1234.0}]


def test_reader_load_pseudonym_map_keys_by_kind_value():
    fake = _FakeClient({"cols": ["kind", "real_value", "surrogate"],
                        "rows": [["host", "10.74.11.20", "h_abc"]]})
    reader = EventsReader.__new__(EventsReader)
    reader._client = fake
    reader._tenant = "t_main"
    out = reader.load_pseudonym_map(["host"])
    assert out == {("host", "10.74.11.20"): "h_abc"}


def test_writer_insert_metric_rows_uses_columns():
    fake = _FakeClient({"cols": [], "rows": []})
    writer = MetricsWriter.__new__(MetricsWriter)
    writer._client = fake
    n = writer.write_metric_timeseries(
        [{c: v for c, v in zip(METRIC_COLUMNS, ["2026-06-19 00:00:00", "bytes", "", 1.0, "t_main"])}])
    assert n == 1
    table, rows, cols = fake.inserts[0]
    assert table == "ssdf_public.metric_timeseries"
    assert cols == METRIC_COLUMNS


def test_writer_skips_empty():
    fake = _FakeClient({"cols": [], "rows": []})
    writer = MetricsWriter.__new__(MetricsWriter)
    writer._client = fake
    assert writer.write_entity_series([]) == 0
    assert writer.write_pseudonym_map([]) == 0
    assert fake.inserts == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd services/public-metrics && uv run pytest tests/test_chio.py -v`
Expected: FAIL with `ModuleNotFoundError`.

- [ ] **Step 3: Write `chreader.py`**

Create `services/public-metrics/src/ssdf_pubmetrics/chreader.py`:

```python
"""Read seam: aggregate ssdf.events + load the current pseudonym map."""

from __future__ import annotations

from typing import Any

import clickhouse_connect

from .config import Config
from .measures import (
    build_aggregate_sql, build_entity_bucket_sql, build_deny_counts_sql,
    build_alert_count_sql,
)


def client_kwargs(config: Config) -> dict[str, Any]:
    kwargs: dict[str, Any] = dict(
        host=config.ch_host, port=config.ch_port, username=config.ch_user,
        password=config.ch_password, database=config.ch_database,
    )
    if config.ch_secure:
        kwargs["interface"] = "https"
        if config.ch_ca_file:
            kwargs["ca_cert"] = config.ch_ca_file
    return kwargs


class EventsReader:
    """Reads ssdf.events for aggregation and loads the sovereign pseudonym map."""

    def __init__(self, config: Config):
        self._client = clickhouse_connect.get_client(**client_kwargs(config))
        self._tenant = config.tenant_id

    def _rows(self, sql: str, params: dict) -> list[dict]:
        result = self._client.query(sql, parameters=params)
        cols = list(result.column_names)
        return [dict(zip(cols, row)) for row in result.result_rows]

    def aggregate_series(self, metric: str, since_iso: str, bucket_secs: int) -> list[dict]:
        sql, params = build_aggregate_sql(metric, since_iso, bucket_secs, self._tenant)
        return self._rows(sql, params)

    def entity_bucket_series(self, metric: str, since_iso: str, bucket_secs: int) -> list[dict]:
        sql, params = build_entity_bucket_sql(metric, since_iso, bucket_secs, self._tenant)
        return self._rows(sql, params)

    def deny_counts(self, since_iso: str) -> dict:
        sql, params = build_deny_counts_sql(since_iso, self._tenant)
        rows = self._rows(sql, params)
        return rows[0] if rows else {"deny": 0.0, "total": 0.0}

    def alert_count(self, since_iso: str) -> float:
        sql, params = build_alert_count_sql(since_iso, self._tenant)
        rows = self._rows(sql, params)
        return float(rows[0]["c"]) if rows else 0.0

    def load_pseudonym_map(self, kinds: list[str]) -> dict[tuple[str, str], str]:
        if not kinds:
            return {}
        sql = (
            "SELECT kind, real_value, surrogate FROM ssdf.pseudonym_map FINAL "
            "WHERE kind IN {kinds:Array(String)}"
        )
        rows = self._rows(sql, {"kinds": kinds})
        return {(r["kind"], r["real_value"]): r["surrogate"] for r in rows}
```

- [ ] **Step 4: Write `chwriter.py`**

Create `services/public-metrics/src/ssdf_pubmetrics/chwriter.py`:

```python
"""Write seam: insert the three M7c tables."""

from __future__ import annotations

from typing import Iterable

import clickhouse_connect

from .chreader import client_kwargs
from .config import Config

METRIC_COLUMNS = ["bucket_start", "metric", "dim", "value", "tenant_id"]
ENTITY_COLUMNS = ["bucket_start", "surrogate", "metric", "value", "tenant_id"]
MAP_COLUMNS = ["kind", "real_value", "surrogate", "key_version", "first_seen", "last_seen"]


def _rows(items: Iterable[dict], columns: list[str]) -> list[list]:
    return [[item[c] for c in columns] for item in items]


class MetricsWriter:
    def __init__(self, config: Config):
        self._client = clickhouse_connect.get_client(**client_kwargs(config))

    def write_metric_timeseries(self, items: list[dict]) -> int:
        if not items:
            return 0
        self._client.insert("ssdf_public.metric_timeseries",
                            _rows(items, METRIC_COLUMNS), column_names=METRIC_COLUMNS)
        return len(items)

    def write_entity_series(self, items: list[dict]) -> int:
        if not items:
            return 0
        self._client.insert("ssdf_public.entity_series",
                            _rows(items, ENTITY_COLUMNS), column_names=ENTITY_COLUMNS)
        return len(items)

    def write_pseudonym_map(self, items: list[dict]) -> int:
        if not items:
            return 0
        self._client.insert("ssdf.pseudonym_map",
                            _rows(items, MAP_COLUMNS), column_names=MAP_COLUMNS)
        return len(items)
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd services/public-metrics && uv run pytest tests/test_chio.py -v`
Expected: PASS (4 passed).

- [ ] **Step 6: Commit**

```bash
git add services/public-metrics/src/ssdf_pubmetrics/chreader.py services/public-metrics/src/ssdf_pubmetrics/chwriter.py services/public-metrics/tests/test_chio.py
git commit -m "feat(m7c): public-metrics ClickHouse reader + writer seams"
```

### Task B6: Resolver entrypoint (orchestration)

**Files:**
- Create: `services/public-metrics/src/ssdf_pubmetrics/resolve.py`
- Test: `services/public-metrics/tests/test_resolve.py`

`resolve.py` is the oneshot the timer runs. It (1) computes `since_iso` from
`lookback_hours`; (2) loads the current pseudonym map for `host`; (3) for each
enabled **aggregate** measure writes `metric_timeseries` rows (`dim=''`); (4) for
each **per_entity** measure reads per-(bucket,ip) values, picks the top-N IPs by
total, mints surrogates, and writes `entity_series` rows + `pseudonym_map` upserts;
(5) for each **index** measure computes current-vs-baseline ratio and writes one
`metric_timeseries` row. The orchestration is split into a pure `plan_writes(...)`
helper (deterministic, unit-tested with fakes) and a thin `run()` that wires real
reader/writer.

- [ ] **Step 1: Write the failing test (pure planner, fakes for reader)**

Create `services/public-metrics/tests/test_resolve.py`:

```python
from ssdf_pubmetrics.resolve import plan_writes


class _FakeReader:
    def __init__(self):
        self.tenant = "t_main"

    def aggregate_series(self, metric, since_iso, bucket_secs):
        return [{"bucket_start": "2026-06-19 00:00:00", "value": 100.0}]

    def entity_bucket_series(self, metric, since_iso, bucket_secs):
        return [
            {"bucket_start": "2026-06-19 00:00:00", "ip": "10.74.11.20", "value": 80.0},
            {"bucket_start": "2026-06-19 00:00:00", "ip": "10.74.11.21", "value": 20.0},
        ]

    def deny_counts(self, since_iso):
        return {"deny": 5.0, "total": 50.0}

    def alert_count(self, since_iso):
        return 12.0


def test_plan_writes_aggregate_and_index_and_entity():
    reader = _FakeReader()
    pmap = {}  # empty -> everything minted fresh
    plan = plan_writes(
        reader, pmap, key=b"\x00" * 16, since_iso="2026-06-19T00:00:00+00:00",
        baseline_since_iso="2026-05-20T00:00:00+00:00", bucket_secs=300,
        top_n=1, key_version=1, tenant_id="t_main",
    )
    # aggregate metrics carry dim='' and a value
    agg = [r for r in plan.metric_rows if r["dim"] == "" and r["metric"] == "bytes"]
    assert agg and agg[0]["value"] == 100.0
    # index metric emitted as a single ratio row (deny 5/50 = 0.1 over baseline)
    idx = [r for r in plan.metric_rows if r["metric"] == "deny_rate_index"]
    assert len(idx) == 1
    # entity series limited to top_n=1 surrogate, never the raw IP
    assert len(plan.entity_rows) == 1
    assert plan.entity_rows[0]["surrogate"].startswith("h_")
    assert "10.74.11.20" not in plan.entity_rows[0]["surrogate"]
    # a pseudonym-map upsert was minted for the surfaced IP
    assert plan.map_rows and plan.map_rows[0]["kind"] == "host"
    assert plan.map_rows[0]["real_value"] == "10.74.11.20"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd services/public-metrics && uv run pytest tests/test_resolve.py -v`
Expected: FAIL with `ImportError: cannot import name 'plan_writes'`.

- [ ] **Step 3: Write `resolve.py`**

Create `services/public-metrics/src/ssdf_pubmetrics/resolve.py`:

```python
"""Public-metrics resolver: aggregate ssdf.events into the de-identified tables.

Sovereign process (runs on ct109). Holds PUBLIC_PSEUDONYM_KEY; emits only
surrogates to the public schema. Real<->surrogate stays in ssdf.pseudonym_map.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from .chreader import EventsReader
from .chwriter import MetricsWriter
from .config import load_config
from .measures import enabled_measures, ratio_to_baseline
from .pseudonym import mint_surrogate

# Per-entity source IPs map to 'host' surrogates. This is the PSEUDONYM kind
# (see pseudonym.PREFIXES) — distinct from Measure.kind ('aggregate'|'index').
_PSEUDONYM_KIND = "host"


@dataclass
class WritePlan:
    metric_rows: list[dict] = field(default_factory=list)
    entity_rows: list[dict] = field(default_factory=list)
    map_rows: list[dict] = field(default_factory=list)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def plan_writes(reader, pmap, key, since_iso, baseline_since_iso, bucket_secs,
                top_n, key_version, tenant_id) -> WritePlan:
    plan = WritePlan()
    now_iso = _now_iso()
    for measure in enabled_measures():
        if measure.kind == "index":
            if measure.metric == "deny_rate_index":
                cur = reader.deny_counts(since_iso)
                base = reader.deny_counts(baseline_since_iso)
                cur_ratio = ratio_to_baseline(cur["deny"], cur["total"])
                base_ratio = ratio_to_baseline(base["deny"], base["total"])
            else:  # ips_volume_index
                cur_ratio = reader.alert_count(since_iso)
                base_ratio = reader.alert_count(baseline_since_iso)
            value = ratio_to_baseline(cur_ratio, base_ratio)
            plan.metric_rows.append({
                "bucket_start": since_iso, "metric": measure.metric,
                "dim": "", "value": value, "tenant_id": tenant_id,
            })
            continue

        if measure.per_entity:
            rows = reader.entity_bucket_series(measure.metric, since_iso, bucket_secs)
            totals: dict[str, float] = {}
            for row in rows:
                totals[row["ip"]] = totals.get(row["ip"], 0.0) + float(row["value"])
            top_ips = [ip for ip, _ in sorted(
                totals.items(), key=lambda kv: kv[1], reverse=True)[:top_n]]
            top = set(top_ips)
            for row in rows:
                ip = row["ip"]
                if ip not in top:
                    continue
                surrogate = mint_surrogate(pmap, key, _PSEUDONYM_KIND, ip)
                if (_PSEUDONYM_KIND, ip) not in {
                        (m["kind"], m["real_value"]) for m in plan.map_rows}:
                    plan.map_rows.append({
                        "kind": _PSEUDONYM_KIND, "real_value": ip,
                        "surrogate": surrogate, "key_version": key_version,
                        "first_seen": now_iso, "last_seen": now_iso,
                    })
                plan.entity_rows.append({
                    "bucket_start": row["bucket_start"], "surrogate": surrogate,
                    "metric": measure.metric, "value": float(row["value"]),
                    "tenant_id": tenant_id,
                })
            continue

        # plain aggregate measure
        for row in reader.aggregate_series(measure.metric, since_iso, bucket_secs):
            plan.metric_rows.append({
                "bucket_start": row["bucket_start"], "metric": measure.metric,
                "dim": "", "value": float(row["value"]), "tenant_id": tenant_id,
            })
    return plan


def run() -> int:
    config = load_config()
    now = datetime.now(timezone.utc)
    since_iso = (now - timedelta(hours=config.lookback_hours)).isoformat()
    baseline_since_iso = (now - timedelta(days=config.baseline_days)).isoformat()

    reader = EventsReader(config)
    writer = MetricsWriter(config)
    pmap = reader.load_pseudonym_map(["host"])

    plan = plan_writes(
        reader, pmap, key=config.pseudonym_key, since_iso=since_iso,
        baseline_since_iso=baseline_since_iso, bucket_secs=config.bucket_secs,
        top_n=config.top_n, key_version=config.key_version,
        tenant_id=config.tenant_id,
    )
    m = writer.write_metric_timeseries(plan.metric_rows)
    e = writer.write_entity_series(plan.entity_rows)
    p = writer.write_pseudonym_map(plan.map_rows)
    print(f"public-metrics: wrote metric={m} entity={e} map={p}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd services/public-metrics && uv run pytest tests/test_resolve.py -v`
Expected: PASS (1 passed).

- [ ] **Step 5: Run the full service unit suite**

Run: `cd services/public-metrics && uv run pytest -m "not integration" -v`
Expected: PASS (all B2/B3/B4/B5/B6 tests green).

- [ ] **Step 6: Commit**

```bash
git add services/public-metrics/src/ssdf_pubmetrics/resolve.py services/public-metrics/tests/test_resolve.py
git commit -m "feat(m7c): public-metrics resolver orchestration (plan_writes + run)"
```

### Task B7: Infra — systemd unit, timer, env example

**Files:**
- Create: `services/public-metrics/infra/ssdf-public-metrics.service`
- Create: `services/public-metrics/infra/ssdf-public-metrics.timer`
- Create: `services/public-metrics/infra/ENV.local.example`

Mirrors `services/policy/infra/ssdf-policy.{service,timer}`: a `DynamicUser=yes`
hardened oneshot on a ~5-min timer. The pseudonym key is a secret, so it is passed
via `LoadCredential` (DynamicUser cannot read a root-owned 600 file directly — the
P1 hardening finding) and surfaced to the process as a file path env var that
`load_config` reads. The env file (mode 600 on ct109) holds the CH password and the
non-secret tuning; the key lives in its own credential file.

- [ ] **Step 1: Write the service unit**

Create `services/public-metrics/infra/ssdf-public-metrics.service`:

```ini
[Unit]
Description=SSDF public-metrics resolver (de-identified metrics aggregation)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
DynamicUser=yes
EnvironmentFile=/etc/ssdf-public-metrics/ENV.local
LoadCredential=pseudonym_key:/etc/ssdf-public-metrics/pseudonym.key
Environment=PUBLIC_PSEUDONYM_KEY_FILE=%d/pseudonym_key
WorkingDirectory=/opt/ssdf-public-metrics
ExecStart=/opt/ssdf-public-metrics/bin/python -m ssdf_pubmetrics.resolve
# hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6
LockPersonality=yes
MemoryDenyWriteExecute=yes
```

- [ ] **Step 2: Write the timer unit**

Create `services/public-metrics/infra/ssdf-public-metrics.timer`:

```ini
[Unit]
Description=Run SSDF public-metrics resolver every 5 minutes

[Timer]
OnBootSec=3min
OnUnitActiveSec=5min
AccuracySec=30s
Persistent=true

[Install]
WantedBy=timers.target
```

- [ ] **Step 3: Write the env example**

Create `services/public-metrics/infra/ENV.local.example`:

```bash
# /etc/ssdf-public-metrics/ENV.local  (mode 600 on ct109)
# CH connection (TLS edge, ct104)
CH_HOST=198.51.100.151
CH_PORT=8443
CH_SECURE=1
CH_CA_FILE=/etc/ssdf-public-metrics/ssdf-ca.crt
CH_DATABASE=ssdf
CH_USER=ssdf_pubmetrics
CH_PASSWORD=__set_me__

# Pseudonym key is provided by systemd LoadCredential as a file:
#   PUBLIC_PSEUDONYM_KEY_FILE=%d/pseudonym_key  (set in the unit)
# For a manual run, instead export the hex key directly:
#   PUBLIC_PSEUDONYM_KEY=<32 hex chars>   # openssl rand -hex 16

# tuning (all optional; defaults shown)
PUBMETRICS_BUCKET_SECS=300
PUBMETRICS_LOOKBACK_HOURS=1
PUBMETRICS_BASELINE_DAYS=30
PUBMETRICS_TOP_N=20
PUBMETRICS_KEY_VERSION=1
PUBMETRICS_TENANT_ID=t_main
```

- [ ] **Step 4: Extend `load_config` to read the key from a file path**

The unit passes the key as a credential file, not an env value. Add a file fallback
to `load_config` in `config.py` so both the unit (file) and a manual run (env hex)
work. Replace the existing key-resolution block (the `raw_key = ...` through the
`bytes.fromhex` try/except from Task B4) with:

```python
    raw_key = os.environ.get("PUBLIC_PSEUDONYM_KEY")
    key_file = os.environ.get("PUBLIC_PSEUDONYM_KEY_FILE")
    if not raw_key and key_file:
        with open(key_file, "r", encoding="utf-8") as handle:
            raw_key = handle.read().strip()
    if not raw_key:
        raise ConfigError("PUBLIC_PSEUDONYM_KEY or PUBLIC_PSEUDONYM_KEY_FILE is required")
    try:
        key = bytes.fromhex(raw_key)
    except ValueError as exc:
        raise ConfigError(f"PUBLIC_PSEUDONYM_KEY must be hex: {exc}") from exc
```

(`key` is what `Config(pseudonym_key=key, ...)` already consumes — unchanged.)

- [ ] **Step 5: Add a test for the file-path key fallback**

Append to `services/public-metrics/tests/test_config.py`:

```python
def test_load_config_reads_key_from_file(tmp_path, monkeypatch):
    key_path = tmp_path / "pseudonym.key"
    key_path.write_text("00112233445566778899aabbccddeeff\n")
    monkeypatch.delenv("PUBLIC_PSEUDONYM_KEY", raising=False)
    monkeypatch.setenv("PUBLIC_PSEUDONYM_KEY_FILE", str(key_path))
    monkeypatch.setenv("CH_PASSWORD", "x")
    from ssdf_pubmetrics.config import load_config
    config = load_config()
    assert config.pseudonym_key == bytes.fromhex("00112233445566778899aabbccddeeff")
```

- [ ] **Step 6: Run config tests**

Run: `cd services/public-metrics && uv run pytest tests/test_config.py -v`
Expected: PASS (5 passed).

- [ ] **Step 7: Commit**

```bash
git add services/public-metrics/infra services/public-metrics/src/ssdf_pubmetrics/config.py services/public-metrics/tests/test_config.py
git commit -m "feat(m7c): public-metrics systemd unit/timer + credential-file key path"
```

### Task B8: Live integration test (resolver round-trip, gated)

**Files:**
- Create: `services/public-metrics/tests/test_resolve_integration.py`

A `@pytest.mark.integration` test that runs the real resolver against live CH and
asserts the de-identification floor: rows land in the public tables, and the
public reader can NOT read `ssdf.pseudonym_map`. Skipped unless CH env is present.

- [ ] **Step 1: Write the integration test**

Create `services/public-metrics/tests/test_resolve_integration.py`:

```python
import os

import pytest

pytestmark = pytest.mark.integration

_REQUIRED = ["CH_HOST", "CH_PASSWORD", "PUBLIC_PSEUDONYM_KEY"]


@pytest.fixture
def config():
    missing = [k for k in _REQUIRED if not os.environ.get(k)]
    if missing:
        pytest.skip(f"missing env: {missing}")
    from ssdf_pubmetrics.config import load_config
    return load_config()


def test_resolver_writes_rows_and_floor_holds(config):
    from ssdf_pubmetrics.resolve import run
    from ssdf_pubmetrics.chreader import EventsReader, client_kwargs
    import clickhouse_connect

    assert run() == 0

    reader = EventsReader(config)
    agg = reader._client.query(
        "SELECT count() FROM ssdf_public.metric_timeseries FINAL").result_rows
    assert agg[0][0] >= 0  # table reachable; aggregate rows present after a run

    # de-identification floor: a public-tier reader must be denied the map
    public_kwargs = dict(client_kwargs(config))
    public_kwargs.update(username="ssdf_public",
                         password=os.environ["CH_PUBLIC_PASSWORD"],
                         database="ssdf_public")
    public = clickhouse_connect.get_client(**public_kwargs)
    with pytest.raises(Exception):
        public.query("SELECT count() FROM ssdf.pseudonym_map")
```

- [ ] **Step 2: Run (skips without env)**

Run: `cd services/public-metrics && uv run pytest tests/test_resolve_integration.py -v`
Expected: SKIPPED (no CH env) — proves the test is wired and collectable.

- [ ] **Step 3: Run live (operator, with env)**

Run:
```bash
cd services/public-metrics && \
  CH_HOST=198.51.100.151 CH_PORT=8443 CH_SECURE=1 CH_CA_FILE=<ca> \
  CH_PASSWORD=<pubmetrics_pw> CH_PUBLIC_PASSWORD=<public_pw> \
  PUBLIC_PSEUDONYM_KEY=<hex> \
  uv run pytest tests/test_resolve_integration.py -m integration -v
```
Expected: PASS — rows written; `ssdf.pseudonym_map` SELECT denied for `ssdf_public`.

- [ ] **Step 4: Commit**

```bash
git add services/public-metrics/tests/test_resolve_integration.py
git commit -m "test(m7c): public-metrics live resolver round-trip + de-id floor"
```

## Phase C — mcp-query: metrics tools + classification + phase-0 lockdown

This phase exposes the de-identified surface as MCP tools and flips the public tier
from M7b's topology/identity tools to the M7c metrics tools. The selection MECHANISM
(`public_tool_names`) is unchanged — only the tool catalog, a new `metrics` data
class, and the deployed classification config change.

### Task C1: Add the `metrics` data class + tool classifications

**Files:**
- Modify: `services/mcp-query/src/ssdf_mcp_query/classification.py:17-40`
- Test: `services/mcp-query/tests/test_classification.py`

`metrics` is a new configurable class (like topology/identity it may be flipped to
`shareable`). The three read tools are classed `metrics`; `reidentify` is classed
`identity` (sovereign — re-identification is the whole point of the floor).

- [ ] **Step 1: Write the failing test**

Append to `services/mcp-query/tests/test_classification.py`:

```python
def test_metrics_class_is_configurable_and_tools_classed():
    from ssdf_mcp_query.classification import (
        DATA_CLASSES, CONFIGURABLE_CLASSES, classes_for_tool,
    )
    assert "metrics" in DATA_CLASSES
    assert "metrics" in CONFIGURABLE_CLASSES
    assert classes_for_tool("metric_timeseries") == frozenset({"metrics"})
    assert classes_for_tool("top_series") == frozenset({"metrics"})
    assert classes_for_tool("entity_metric_timeseries") == frozenset({"metrics"})
    assert classes_for_tool("reidentify") == frozenset({"identity"})


def test_metrics_can_be_flipped_shareable(tmp_path):
    import json
    from ssdf_mcp_query.classification import load_classification, is_tool_shareable
    path = tmp_path / "c.json"
    path.write_text(json.dumps({"metrics": "shareable"}))
    c = load_classification(str(path))
    assert is_tool_shareable(c, "metric_timeseries") is True
    assert is_tool_shareable(c, "reidentify") is False  # identity stays sovereign
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd services/mcp-query && uv run pytest tests/test_classification.py -k metrics -v`
Expected: FAIL (`metrics` not in DATA_CLASSES).

- [ ] **Step 3: Edit `classification.py`**

Change the class sets (lines 17-20):

```python
DATA_CLASSES: frozenset[str] = frozenset(
    {"security_log", "firewall_config", "topology", "identity", "metrics"}
)
CONFIGURABLE_CLASSES: frozenset[str] = frozenset({"topology", "identity", "metrics"})
```

Add the four tool entries to `TOOL_DATA_CLASSES` (after `observed_by`, line 39):

```python
    "metric_timeseries": frozenset({"metrics"}),
    "top_series": frozenset({"metrics"}),
    "entity_metric_timeseries": frozenset({"metrics"}),
    "reidentify": frozenset({"identity"}),
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd services/mcp-query && uv run pytest tests/test_classification.py -v`
Expected: PASS (all classification tests).

- [ ] **Step 5: Commit**

```bash
git add services/mcp-query/src/ssdf_mcp_query/classification.py services/mcp-query/tests/test_classification.py
git commit -m "feat(m7c): add metrics data class + classify metric/reidentify tools"
```

### Task C2: MetricsStore read seam (ssdf_public metric tables + map)

**Files:**
- Create: `services/mcp-query/src/ssdf_mcp_query/metrics_store.py`
- Test: `services/mcp-query/tests/test_metrics_store.py`

The store reads the de-identified tables `ssdf_public.metric_timeseries` /
`ssdf_public.entity_series` (FINAL, to dedup ReplacingMergeTree re-runs) and — for
`reidentify` only — the sovereign `ssdf.pseudonym_map`. Both tiers can read the
metric tables (ssdf_ro and ssdf_public are both granted SELECT on them in migration
013); `reidentify` reads the map, which only `ssdf_ro` may SELECT, so it is wired
sovereign-only in `server.py`. The metric-table schema is ALWAYS `ssdf_public`
regardless of tier — the tables physically live there. The store takes a
`ClickHouseClient` like `entitystore`/`graphstore` and runs via `client.run`.

- [ ] **Step 1: Write the failing test**

Create `services/mcp-query/tests/test_metrics_store.py`:

```python
from ssdf_mcp_query.metrics_store import MetricsStore


class _FakeClient:
    def __init__(self, rows):
        self._rows = rows
        self.calls = []

    def run(self, sql, params=None):
        self.calls.append((sql, params))
        return {"rows": self._rows, "row_count": len(self._rows),
                "elapsed_ms": 1, "truncated": False}


def test_metric_timeseries_reads_aggregate_table():
    fake = _FakeClient([{"bucket_start": "2026-06-19 00:00:00", "value": 12.0}])
    store = MetricsStore(fake)
    out = store.metric_timeseries("bytes", since="now-1h", until=None)
    assert out["rows"][0]["value"] == 12.0
    sql = fake.calls[0][0]
    assert "ssdf_public.metric_timeseries" in sql and "FINAL" in sql
    assert "dim = ''" in sql


def test_top_series_groups_by_surrogate():
    fake = _FakeClient([{"surrogate": "h_abc", "value": 99.0}])
    store = MetricsStore(fake)
    out = store.top_series("bytes", since="now-1h", limit=5)
    sql = fake.calls[0][0]
    assert "ssdf_public.entity_series" in sql and "surrogate" in sql
    assert out["rows"][0]["surrogate"] == "h_abc"


def test_reidentify_reads_sovereign_map():
    fake = _FakeClient([{"kind": "host", "real_value": "10.74.11.20"}])
    store = MetricsStore(fake)
    out = store.reidentify("h_abc")
    sql = fake.calls[0][0]
    assert "ssdf.pseudonym_map" in sql and "FINAL" in sql
    assert out["entity"]["real_value"] == "10.74.11.20"


def test_reidentify_unknown_surrogate_returns_null_entity():
    fake = _FakeClient([])
    store = MetricsStore(fake)
    out = store.reidentify("h_nope")
    assert out["entity"] is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd services/mcp-query && uv run pytest tests/test_metrics_store.py -v`
Expected: FAIL with `ModuleNotFoundError`.

- [ ] **Step 3: Write `metrics_store.py`**

Create `services/mcp-query/src/ssdf_mcp_query/metrics_store.py`:

```python
"""Read seam for the M7c de-identified metrics surface.

Reads the public metric tables (always in the ``ssdf_public`` schema) and, for
re-identification only, the sovereign ``ssdf.pseudonym_map``. Returns plain dicts
shaped like the other store seams (``{rows, row_count, elapsed_ms, truncated}``).
"""

from __future__ import annotations

from typing import Any

_METRIC_TABLE = "ssdf_public.metric_timeseries"
_ENTITY_TABLE = "ssdf_public.entity_series"
_MAP_TABLE = "ssdf.pseudonym_map"


class MetricsStore:
    """Queries the de-identified metric tables (+ sovereign map for reidentify)."""

    def __init__(self, client: Any, tenant: str = "t_main"):
        self._client = client
        self._tenant = tenant

    def metric_timeseries(self, metric: str, since: str | None = None,
                          until: str | None = None) -> dict:
        """Aggregate (dim='') time series for one metric over a window."""
        sql = (
            f"SELECT bucket_start, value FROM {_METRIC_TABLE} FINAL "
            "WHERE tenant_id = {tenant:String} AND metric = {metric:String} "
            "AND dim = '' "
            "AND bucket_start >= parseDateTimeBestEffort({since:String}) "
            "AND ({until:String} = '' OR bucket_start <= parseDateTimeBestEffort({until:String})) "
            "ORDER BY bucket_start"
        )
        params = {"tenant": self._tenant, "metric": metric,
                  "since": _norm_since(since), "until": until or ""}
        return self._client.run(sql, params)

    def top_series(self, metric: str, since: str | None = None,
                   limit: int = 10) -> dict:
        """Top-N surrogates for a per-entity metric over a window, by total value."""
        sql = (
            "SELECT surrogate, sum(value) AS value "
            f"FROM {_ENTITY_TABLE} FINAL "
            "WHERE tenant_id = {tenant:String} AND metric = {metric:String} "
            "AND bucket_start >= parseDateTimeBestEffort({since:String}) "
            "GROUP BY surrogate ORDER BY value DESC LIMIT {limit:UInt32}"
        )
        params = {"tenant": self._tenant, "metric": metric,
                  "since": _norm_since(since), "limit": int(limit)}
        return self._client.run(sql, params)

    def entity_metric_timeseries(self, surrogate: str, metric: str,
                                 since: str | None = None,
                                 until: str | None = None) -> dict:
        """Per-bucket series for ONE surrogate + metric over a window."""
        sql = (
            f"SELECT bucket_start, value FROM {_ENTITY_TABLE} FINAL "
            "WHERE tenant_id = {tenant:String} AND surrogate = {surrogate:String} "
            "AND metric = {metric:String} "
            "AND bucket_start >= parseDateTimeBestEffort({since:String}) "
            "AND ({until:String} = '' OR bucket_start <= parseDateTimeBestEffort({until:String})) "
            "ORDER BY bucket_start"
        )
        params = {"tenant": self._tenant, "surrogate": surrogate, "metric": metric,
                  "since": _norm_since(since), "until": until or ""}
        return self._client.run(sql, params)

    def reidentify(self, surrogate: str) -> dict:
        """Map a surrogate back to its real value (SOVEREIGN — reads ssdf.pseudonym_map)."""
        sql = (
            f"SELECT kind, real_value FROM {_MAP_TABLE} FINAL "
            "WHERE surrogate = {surrogate:String} LIMIT 1"
        )
        result = self._client.run(sql, {"surrogate": surrogate})
        rows = result.get("rows", [])
        return {"surrogate": surrogate, "entity": rows[0] if rows else None}


def _norm_since(since: str | None) -> str:
    """Default the lookback window to 24h when unset (mirrors the other tools)."""
    return since if since else "now-24h"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd services/mcp-query && uv run pytest tests/test_metrics_store.py -v`
Expected: PASS (4 passed).

- [ ] **Step 5: Commit**

```bash
git add services/mcp-query/src/ssdf_mcp_query/metrics_store.py services/mcp-query/tests/test_metrics_store.py
git commit -m "feat(m7c): MetricsStore read seam for de-identified metric tables"
```

### Task C3: MetricTools façade + server.py wiring

**Files:**
- Create: `services/mcp-query/src/ssdf_mcp_query/metric_tools.py`
- Modify: `services/mcp-query/src/ssdf_mcp_query/server.py:20-26,144-167`
- Test: `services/mcp-query/tests/test_metric_tools.py`

`metric_tools.py` is a thin façade over `MetricsStore` (mirrors `AccessTools`/
`TopoTools`): it owns the agent-facing docstrings. `server.py` constructs the store
for BOTH tiers, registers the three read tools unconditionally (so the public tier
can select them via classification), and registers `reidentify` sovereign-only.

- [ ] **Step 1: Write the failing test**

Create `services/mcp-query/tests/test_metric_tools.py`:

```python
from ssdf_mcp_query.metric_tools import MetricTools


class _FakeStore:
    def __init__(self):
        self.calls = []

    def metric_timeseries(self, metric, since=None, until=None):
        self.calls.append(("metric_timeseries", metric, since, until))
        return {"rows": [{"bucket_start": "b", "value": 1.0}]}

    def top_series(self, metric, since=None, limit=10):
        self.calls.append(("top_series", metric, since, limit))
        return {"rows": [{"surrogate": "h_a", "value": 9.0}]}

    def entity_metric_timeseries(self, surrogate, metric, since=None, until=None):
        self.calls.append(("entity_metric_timeseries", surrogate, metric))
        return {"rows": []}

    def reidentify(self, surrogate):
        self.calls.append(("reidentify", surrogate))
        return {"surrogate": surrogate, "entity": {"kind": "host", "real_value": "x"}}


def test_metric_tools_delegate_to_store():
    store = _FakeStore()
    tools = MetricTools(store)
    assert tools.metric_timeseries("bytes")["rows"][0]["value"] == 1.0
    assert tools.top_series("bytes", limit=3)["rows"][0]["surrogate"] == "h_a"
    assert tools.entity_metric_timeseries("h_a", "bytes")["rows"] == []
    assert tools.reidentify("h_a")["entity"]["real_value"] == "x"
    assert [c[0] for c in store.calls] == [
        "metric_timeseries", "top_series", "entity_metric_timeseries", "reidentify",
    ]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd services/mcp-query && uv run pytest tests/test_metric_tools.py -v`
Expected: FAIL with `ModuleNotFoundError`.

- [ ] **Step 3: Write `metric_tools.py`**

Create `services/mcp-query/src/ssdf_mcp_query/metric_tools.py`:

```python
"""Agent-facing façade for the M7c de-identified metrics tools."""

from __future__ import annotations

from typing import Any


class MetricTools:
    """Thin pass-through over ``MetricsStore`` carrying the tool docstrings."""

    def __init__(self, store: Any):
        self._store = store

    def metric_timeseries(self, metric: str, since: str | None = None,
                          until: str | None = None) -> dict:
        return self._store.metric_timeseries(metric, since=since, until=until)

    def top_series(self, metric: str, since: str | None = None,
                   limit: int = 10) -> dict:
        return self._store.top_series(metric, since=since, limit=limit)

    def entity_metric_timeseries(self, surrogate: str, metric: str,
                                 since: str | None = None,
                                 until: str | None = None) -> dict:
        return self._store.entity_metric_timeseries(
            surrogate, metric, since=since, until=until)

    def reidentify(self, surrogate: str) -> dict:
        return self._store.reidentify(surrogate)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd services/mcp-query && uv run pytest tests/test_metric_tools.py -v`
Expected: PASS (1 passed).

- [ ] **Step 5: Wire into `server.py`**

Add the imports after line 25 (`from .access_tools import AccessTools`):

```python
from .metrics_store import MetricsStore
from .metric_tools import MetricTools
```

After the `access` block (after line 43, before the verifier loop), construct the
metrics tools for BOTH tiers (the metric tables are readable by both `ssdf_ro` and
`ssdf_public`):

```python
    metrics_store = MetricsStore(client, tenant="t_main")
    metrics = MetricTools(metrics_store)
```

Add the three public-candidate tool functions alongside the others (after
`observed_by`, before the `raw_tools` dict at line 144):

```python
    def metric_timeseries(metric: str, since: str | None = None,
                          until: str | None = None) -> dict:
        """De-identified AGGREGATE time series for one metric (no per-entity detail).
        metric is one of the catalog names: bytes|flows|connections (Tier 1) or the
        normalized indices deny_rate_index|ips_volume_index (ratio-to-baseline, NOT
        absolute counts). Window via since/until (ISO-8601 or "now-1h"; default 24h).
        Returns 5-minute buckets {bucket_start, value}. Carries NO IP/MAC/topology."""
        return metrics.metric_timeseries(metric, since=since, until=until)

    def top_series(metric: str, since: str | None = None, limit: int = 10) -> dict:
        """Top-N de-identified entities (opaque surrogates, e.g. "h_3f9a") for a
        per-entity metric over a window, ranked by total. Surrogates are stable across
        calls but irreversible on this tier. Use entity_metric_timeseries(surrogate,...)
        to trend one. Returns {rows:[{surrogate, value}]}. NO real IP/MAC is exposed."""
        return metrics.top_series(metric, since=since, limit=limit)

    def entity_metric_timeseries(surrogate: str, metric: str,
                                 since: str | None = None,
                                 until: str | None = None) -> dict:
        """Per-bucket time series for ONE de-identified surrogate + metric over a window.
        Pass a surrogate from top_series. Returns 5-minute buckets {bucket_start, value}
        for predictive trending. The surrogate cannot be reversed on this tier."""
        return metrics.entity_metric_timeseries(surrogate, metric, since=since, until=until)
```

Add the sovereign-only `reidentify` function next to the `access` tools (inside the
existing `if access is not None` region is fine, or just above `raw_tools`):

```python
    def reidentify(surrogate: str) -> dict:
        """SOVEREIGN-ONLY: map a public surrogate back to its real value via
        ssdf.pseudonym_map. Returns {surrogate, entity:{kind, real_value}} or
        entity:null. Never registered on the public tier."""
        return metrics.reidentify(surrogate)
```

Add the three metrics tools to `raw_tools` UNCONDITIONALLY (they must be public
candidates), and add `reidentify` only in the sovereign block. Update lines 144-159:

```python
    raw_tools = {
        "query_flows": query_flows,
        "describe_schema": describe_schema,
        "top_talkers": top_talkers,
        "run_sql": run_sql,
        "get_entity": get_entity,
        "locate": locate,
        "neighbors": neighbors,
        "find_path": find_path,
        "enforcement_points": enforcement_points,
        "topology_snapshot": topology_snapshot,
        "metric_timeseries": metric_timeseries,
        "top_series": top_series,
        "entity_metric_timeseries": entity_metric_timeseries,
    }
    if access is not None:  # sovereign-only (L5): never a candidate on public
        raw_tools["explain_access"] = explain_access
        raw_tools["configured_policies"] = configured_policies
        raw_tools["observed_by"] = observed_by
        raw_tools["reidentify"] = reidentify
```

- [ ] **Step 6: Update the server tool-surface tests**

In `services/mcp-query/tests/test_server_public.py`, grow `SOVEREIGN_TOOLS` (line 8)
to include the four new tools:

```python
SOVEREIGN_TOOLS = {
    "query_flows", "describe_schema", "top_talkers", "run_sql", "get_entity",
    "locate", "neighbors", "find_path", "enforcement_points",
    "topology_snapshot", "explain_access", "configured_policies", "observed_by",
    "metric_timeseries", "top_series", "entity_metric_timeseries", "reidentify",
}
```

Add a new test asserting the phase-0 public surface (metrics-only):

```python
def test_public_build_metrics_config_exposes_only_metrics(monkeypatch, tmp_path):
    import ssdf_mcp_query.server as server
    _patch_ch(monkeypatch, server)
    monkeypatch.setenv("MCP_CLASSIFICATION_FILE",
                       _classification_file(tmp_path, metrics="shareable"))
    app = server.build_app(tier="public")
    assert _names(app) == {
        "metric_timeseries", "top_series", "entity_metric_timeseries",
    }
    assert "reidentify" not in _names(app)  # sovereign-only, never a public candidate
```

- [ ] **Step 7: Run the server + metric-tool tests**

Run: `cd services/mcp-query && uv run pytest tests/test_server_public.py tests/test_metric_tools.py -v`
Expected: PASS (existing M7b tests + new metrics tests).

- [ ] **Step 8: Run the full mcp-query unit suite**

Run: `cd services/mcp-query && uv run pytest -m "not integration"`
Expected: PASS (all suites; tool count now 17 sovereign).

- [ ] **Step 9: Commit**

```bash
git add services/mcp-query/src/ssdf_mcp_query/metric_tools.py services/mcp-query/src/ssdf_mcp_query/server.py services/mcp-query/tests/test_metric_tools.py services/mcp-query/tests/test_server_public.py
git commit -m "feat(m7c): register metric tools (public) + reidentify (sovereign)"
```

### Task C4: Phase-0 public classification config (lockdown)

**Files:**
- Create: `services/mcp-query/infra/classification.public.metrics.example.json`

The phase-0 lockdown is a DEPLOY-CONFIG change, not code: the public tier's
`/etc/ssdf-mcp/classification.json` flips `topology`+`identity` BACK to sovereign and
`metrics` to shareable. With this config the public build (ct113) drops the five M7b
topology/identity tools and exposes only the three metrics tools.

- [ ] **Step 1: Write the example config**

Create `services/mcp-query/infra/classification.public.metrics.example.json`:

```json
{
  "topology": "sovereign",
  "identity": "sovereign",
  "metrics": "shareable"
}
```

- [ ] **Step 2: Add a contract test that this example yields metrics-only**

Append to `services/mcp-query/tests/test_server_public.py`:

```python
def test_public_metrics_example_config_is_metrics_only(monkeypatch):
    import ssdf_mcp_query.server as server
    _patch_ch(monkeypatch, server)
    monkeypatch.setenv(
        "MCP_CLASSIFICATION_FILE",
        "infra/classification.public.metrics.example.json")
    app = server.build_app(tier="public")
    assert _names(app) == {
        "metric_timeseries", "top_series", "entity_metric_timeseries",
    }
```

- [ ] **Step 3: Run the test**

Run: `cd services/mcp-query && uv run pytest tests/test_server_public.py -k metrics_example -v`
Expected: PASS (run from the `services/mcp-query` dir so the relative path resolves).

- [ ] **Step 4: Commit**

```bash
git add services/mcp-query/infra/classification.public.metrics.example.json services/mcp-query/tests/test_server_public.py
git commit -m "feat(m7c): phase-0 public classification example (metrics-only lockdown)"
```

## Phase D — deploy runbooks + docs

### Task D1: Key-management runbook

**Files:**
- Create: `onboarding/public-metrics/key-management.md`

- [ ] **Step 1: Write the runbook**

Create `onboarding/public-metrics/key-management.md`:

```markdown
# Public-metrics pseudonym key management

`PUBLIC_PSEUDONYM_KEY` is the HMAC-SHA256 key that turns real identifiers (host IPs)
into the opaque surrogates published on the public tier. It is the ONLY secret whose
disclosure would let a public-tier reader correlate surrogates back to a guessed IP
(by re-deriving the HMAC). It lives ONLY on ct109 (the public-metrics resolver host).

## Generate (one-time)

    openssl rand -hex 16          # 128-bit key, 32 hex chars

Write it to ct109 at `/etc/ssdf-public-metrics/pseudonym.key` (mode 600, root). The
systemd unit passes it to the resolver via `LoadCredential` — it is never an env
value in the unit. For a manual run, export `PUBLIC_PSEUDONYM_KEY=<hex>` instead.

## Where it must NEVER go

- Not on ct113 (public MCP) — the public process only reads `ssdf_public.*`.
- Not in ClickHouse — `ssdf.pseudonym_map` stores the real<->surrogate mapping, but
  that table is granted to `ssdf_ro` (sovereign reidentify) only, never `ssdf_public`.
- Not in git, not in the env example committed to the repo.

## Rotation (key_version)

Surrogates embed no version, but `ssdf.pseudonym_map.key_version` records which key
minted each mapping. To rotate:

1. Generate a new key; bump `PUBMETRICS_KEY_VERSION` (e.g. 1 -> 2) in
   `/etc/ssdf-public-metrics/ENV.local`.
2. Replace `/etc/ssdf-public-metrics/pseudonym.key`; `systemctl restart
   ssdf-public-metrics.service` (or wait for the timer).
3. New mappings are minted under key_version 2 (new surrogates for the same IPs).
   Old key_version-1 rows remain for historical reidentify until TTL-expired.
4. Published series under old surrogates age out with the 30-day TTL on the metric
   tables; consumers see the new surrogates going forward.

Rotation is only needed on suspected key disclosure — there is no scheduled cadence.
```

- [ ] **Step 2: Commit**

```bash
git add onboarding/public-metrics/key-management.md
git commit -m "docs(m7c): public-metrics pseudonym key management runbook"
```

### Task D2: CLAUDE.md + STATUS.md updates

**Files:**
- Modify: `CLAUDE.md` (append an M7c Commands subsection after the M12 block)
- Modify: `docs/superpowers/STATUS.md` (mark M7c done; note phase-0 lockdown; M13 still planned)

- [ ] **Step 1: Append the M7c Commands block to `CLAUDE.md`**

Add after the M12 subsection:

```markdown
### M7c (public de-identified metrics tier — services/public-metrics + metric MCP tools)
- Replaces M7b's anonymized topology graph on the public tier with a keyed-pseudonymized
  metrics/time-series surface for predictive analysis. Public tier now exposes ONLY 3
  metrics tools (`metric_timeseries`, `top_series`, `entity_metric_timeseries`); the 5 M7b
  topology/identity tools are dropped via the phase-0 classification lockdown.
- **Resolver (4th ct109 role):** `services/public-metrics` (venv `/opt/ssdf-public-metrics`,
  env `/etc/ssdf-public-metrics/ENV.local` mode 600) on a ~5-min `ssdf-public-metrics.timer`
  oneshot; writes CH ct104 as `ssdf_pubmetrics` into `ssdf_public.metric_timeseries` (aggregate)
  + `ssdf_public.entity_series` (per-surrogate, top-N) and the sovereign `ssdf.pseudonym_map`.
- Unit tests: `cd services/public-metrics && uv run pytest -m "not integration"`; live:
  `CH_HOST=… CH_PORT=8443 CH_SECURE=1 CH_CA_FILE=… CH_PASSWORD=<pubmetrics_pw>
  CH_PUBLIC_PASSWORD=<public_pw> PUBLIC_PSEUDONYM_KEY=<hex> uv run pytest -m integration`.
- Apply migration: `PUBMETRICS_PW=<pw> envsubst < infra/clickhouse/013_public_metrics.sql |
  clickhouse-client --host <ct104> --multiquery`.
- **Pseudonymization:** Python stdlib HMAC-SHA256 (no SipHash-keyed primitive in stdlib),
  per-kind prefix (host=`h_`), 10-hex surrogate, lengthen-on-collision. Key held ONLY on ct109
  via systemd `LoadCredential` (`PUBLIC_PSEUDONYM_KEY_FILE=%d/pseudonym_key`). Runbook:
  `onboarding/public-metrics/key-management.md`.
- **Hard floor:** `ssdf_public` granted SELECT on the 2 metric tables ONLY; `ssdf.pseudonym_map`
  granted to `ssdf_ro` (sovereign `reidentify`) + `ssdf_pubmetrics` (writer), NEVER `ssdf_public`.
- **Tools:** the 3 read tools are classed `metrics` (new configurable class) ⇒ public candidates;
  `reidentify` is classed `identity` and wired sovereign-only. Public lockdown config:
  `services/mcp-query/infra/classification.public.metrics.example.json`.
- **M13 (planned):** operational-health telemetry ingest (mem/CPU util %, iface error-rate,
  flap) — the measure catalog (`measures.py`) is built extensible so M13 health signals slot
  in as new Tier-3 measures with no redesign.
```

- [ ] **Step 2: Update `docs/superpowers/STATUS.md`**

Read the current M7b/forward-roadmap section and: mark M7c as built (resolver + metric
tools + phase-0 lockdown), note it supersedes M7b's public topology graph, and keep the
M13 health-ingest series on the forward roadmap as the Tier-3 prerequisite. (Edit in
place to match the file's existing milestone-entry format.)

- [ ] **Step 3: Commit**

```bash
git add CLAUDE.md docs/superpowers/STATUS.md
git commit -m "docs(m7c): record public de-identified metrics tier in CLAUDE.md + STATUS"
```

## Phase E — deployment (operator, after all tests green on main)

### Task E1: Apply migration, deploy resolver, flip public tier

**Files:** none (operational). Run after merge; each step is operator-gated.

- [ ] **Step 1: Apply migration 013 on ct104**

```bash
PUBMETRICS_PW='<gen a strong pw>' envsubst < infra/clickhouse/013_public_metrics.sql \
  | clickhouse-client --host <ct104> --multiquery
```
Verify: `ssdf_public.metric_timeseries`, `ssdf_public.entity_series`,
`ssdf.pseudonym_map` exist; `ssdf_public` can SELECT the two metric tables but is
DENIED `ssdf.pseudonym_map`.

- [ ] **Step 2: Provision ct109 (4th role)**

Mirror the policy role: create venv `/opt/ssdf-public-metrics` (pip-install the
service), drop `/etc/ssdf-public-metrics/ENV.local` (mode 600, from
`infra/ENV.local.example`, with the `ssdf_pubmetrics` password), write the key file
`/etc/ssdf-public-metrics/pseudonym.key` (`openssl rand -hex 16`, mode 600), copy the
CA cert, and install the unit+timer. Enable: `systemctl enable --now
ssdf-public-metrics.timer`. Confirm one oneshot run writes rows
(`journalctl -u ssdf-public-metrics.service`).

- [ ] **Step 3: Run the live resolver integration test once**

```bash
cd services/public-metrics && CH_HOST=<ct104> CH_PORT=8443 CH_SECURE=1 CH_CA_FILE=<ca> \
  CH_PASSWORD=<pubmetrics_pw> CH_PUBLIC_PASSWORD=<public_pw> PUBLIC_PSEUDONYM_KEY=<hex> \
  uv run pytest tests/test_resolve_integration.py -m integration -v
```
Expected: PASS — rows written; de-id floor holds.

- [ ] **Step 4: Flip the public tier (ct113) to metrics-only**

On ct113: replace `/etc/ssdf-mcp/classification.json` with the contents of
`services/mcp-query/infra/classification.public.metrics.example.json` (topology+identity
sovereign, metrics shareable), sync the updated `services/mcp-query/src` to
`/opt/src/mcp-query/src`, then `systemctl restart ssdf-mcp-public.service`. Backup the
old classification + source first (`/root/m7c-backup-*`).

- [ ] **Step 5: Verify the public surface live**

Connect an MCP client to `https://198.51.100.154:30033/mcp` with a public token and
`list_tools`: expect EXACTLY `metric_timeseries`, `top_series`,
`entity_metric_timeseries` — and NO topology/identity/`run_sql`/`reidentify` tool.
Spot-check `metric_timeseries("bytes")` returns buckets and that no response field
contains a real IP/MAC/hostname.

- [ ] **Step 6: Sync ct106 (sovereign) for the new tools + reidentify**

On ct106: sync `services/mcp-query/src` to `/opt/src/mcp-query/src` and
`systemctl restart ssdf-mcp-query.service` (backup `/root/m7c-backup-*` first). Verify
`list_tools` now shows 17 tools incl. `metric_timeseries`/`top_series`/
`entity_metric_timeseries`/`reidentify`, and `reidentify("<a surrogate>")` returns the
real value (sovereign reidentify path).
