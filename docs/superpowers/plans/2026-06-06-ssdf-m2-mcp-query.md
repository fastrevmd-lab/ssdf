# SSDF M2 — MCP Query Layer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `ssdf-mcp-query` — a read-only Python/FastMCP streamable-HTTP MCP server on a dedicated Proxmox LXC that exposes `ssdf.events` (ClickHouse ct104) to LLM agents via four tools: `query_flows`, `describe_schema`, `top_talkers`, and a `sqlglot`-guarded `run_sql`.

**Architecture:** FastMCP HTTP server, bearer-token auth (`StaticTokenVerifier`), querying ClickHouse through `clickhouse-connect` as a dedicated **read-only** user. All SQL is parameterized; the one free-text path (`run_sql`) is parsed and allowlisted before execution. Storage access is isolated behind `clickhouse.py` (the swappable-backend seam).

**Tech Stack:** Python 3.11+, `uv`, `fastmcp`, `clickhouse-connect`, `sqlglot`, `pytest`. Deployed as a systemd service on Proxmox LXC (no Docker).

**Design spec:** `docs/superpowers/specs/2026-06-06-ssdf-m2-mcp-query-design.md`

**Reference — live `ssdf.events` schema (22 cols, ct104 `198.51.100.151:8123`):**
```
timestamp DateTime64(3,'UTC'), event_id String, tenant_id LowCardinality(String) DEFAULT 't_main',
event_kind LowCardinality(String), event_category Array(LowCardinality(String)),
event_action LowCardinality(String), event_outcome LowCardinality(String),
event_provider LowCardinality(String), source_ip Nullable(IPv4), source_port Nullable(UInt16),
source_bytes Nullable(UInt64), destination_ip Nullable(IPv4), destination_port Nullable(UInt16),
destination_bytes Nullable(UInt64), network_transport LowCardinality(String),
network_bytes Nullable(UInt64), rule_name String, observer_ingress_zone LowCardinality(String),
observer_egress_zone LowCardinality(String), user_name String, ext Map(String,String), raw String
```

## File Structure

```
services/mcp-query/
  pyproject.toml                       # uv project; deps + pytest config
  README.md                            # run/deploy notes
  .env.example                         # config template (committed)
  src/ssdf_mcp_query/
    __init__.py
    config.py        # Settings loaded from env + token file
    timeparse.py     # "now-1h" / ISO-8601 -> datetime (UTC)
    sql_guard.py     # run_sql parse / allowlist / limit guard (GuardError)
    clickhouse.py    # read-only ClickHouse client wrapper (storage seam)
    builders.py      # build_query_flows / build_top_talkers / describe queries (pure SQL+params)
    tools.py         # tool functions returning result dicts (wraps builders + client)
    server.py        # FastMCP app, auth, tool registration, __main__ entrypoint
  tests/
    test_timeparse.py
    test_sql_guard.py        # allow/deny table — highest value
    test_builders.py         # param->SQL builder unit tests
    test_integration.py      # four tools vs live ct104 (read-only); skipped if no CH
  infra/ssdf-mcp-query.service       # systemd unit template
```

Boundaries: `builders.py` is pure (string+dict, no I/O) so it is fully unit-testable; `clickhouse.py` is the only module that imports `clickhouse_connect`; `sql_guard.py` is the isolated safety unit; `server.py` is the only MCP/transport-aware module.

---

## Task 1: Scaffold the Python project

**Files:**
- Create: `services/mcp-query/pyproject.toml`
- Create: `services/mcp-query/src/ssdf_mcp_query/__init__.py`
- Create: `services/mcp-query/.env.example`
- Create: `services/mcp-query/README.md`

- [ ] **Step 1: Create `pyproject.toml`**

```toml
[project]
name = "ssdf-mcp-query"
version = "0.1.0"
description = "SSDF M2 read-only MCP query layer over ssdf.events (ClickHouse)"
requires-python = ">=3.11"
dependencies = [
    "fastmcp>=2.0",
    "clickhouse-connect>=0.8",
    "sqlglot>=25.0",
]

[project.optional-dependencies]
dev = ["pytest>=8.0"]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/ssdf_mcp_query"]

[tool.pytest.ini_options]
testpaths = ["tests"]
markers = ["integration: requires a live ClickHouse (deselect with -m 'not integration')"]
```

- [ ] **Step 2: Create `src/ssdf_mcp_query/__init__.py`**

```python
"""SSDF M2 — read-only MCP query layer over ssdf.events."""

__version__ = "0.1.0"
```

- [ ] **Step 3: Create `.env.example`**

```bash
# SSDF M2 MCP query server config (copy to .env / inject via systemd; secrets gitignored)
CH_HOST=198.51.100.151
CH_PORT=8123
CH_USER=ssdf_ro
CH_PASSWORD=changeme
CH_DATABASE=ssdf
MCP_BIND=0.0.0.0
MCP_PORT=30032
# Bearer token: read from MCP_AUTH_TOKEN or the file at MCP_TOKEN_FILE
MCP_TOKEN_FILE=/etc/ssdf-mcp/token
```

- [ ] **Step 4: Create `README.md`**

```markdown
# ssdf-mcp-query (SSDF M2)

Read-only MCP server exposing `ssdf.events` to LLM agents.

## Develop
- Install: `uv sync --extra dev`
- Unit tests: `uv run pytest -m "not integration"`
- All tests (needs live ClickHouse): `uv run pytest`
- Run locally: `uv run python -m ssdf_mcp_query.server`

## Tools
`query_flows`, `describe_schema`, `top_talkers`, `run_sql` (guarded SELECT-only).

Config via env (see `.env.example`). Deployed as a systemd service on a Proxmox LXC.
```

- [ ] **Step 5: Verify the project resolves**

Run: `cd services/mcp-query && uv sync --extra dev`
Expected: a virtualenv is created and `fastmcp`, `clickhouse-connect`, `sqlglot`, `pytest` install without error.

- [ ] **Step 6: Commit**

```bash
git add services/mcp-query/pyproject.toml services/mcp-query/src/ssdf_mcp_query/__init__.py services/mcp-query/.env.example services/mcp-query/README.md
git commit -m "chore(m2): scaffold ssdf-mcp-query Python project"
```

---

## Task 2: Time parsing (`timeparse.py`)

Supports ISO-8601 timestamps and relative expressions `now`, `now-<N><unit>` where unit ∈ `s,m,h,d`. Returns timezone-aware UTC `datetime`. Used by `query_flows`/`top_talkers` to compute the time window.

**Files:**
- Create: `services/mcp-query/src/ssdf_mcp_query/timeparse.py`
- Test: `services/mcp-query/tests/test_timeparse.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_timeparse.py
from datetime import datetime, timezone, timedelta
import pytest
from ssdf_mcp_query.timeparse import parse_time, TimeParseError

def test_iso_8601_parsed_as_utc():
    dt = parse_time("2026-06-06T12:00:00Z")
    assert dt == datetime(2026, 6, 6, 12, 0, 0, tzinfo=timezone.utc)

def test_now_returns_utc(monkeypatch):
    fixed = datetime(2026, 6, 6, 12, 0, 0, tzinfo=timezone.utc)
    monkeypatch.setattr("ssdf_mcp_query.timeparse._utcnow", lambda: fixed)
    assert parse_time("now") == fixed

def test_relative_hours(monkeypatch):
    fixed = datetime(2026, 6, 6, 12, 0, 0, tzinfo=timezone.utc)
    monkeypatch.setattr("ssdf_mcp_query.timeparse._utcnow", lambda: fixed)
    assert parse_time("now-1h") == fixed - timedelta(hours=1)

def test_relative_days_and_minutes(monkeypatch):
    fixed = datetime(2026, 6, 6, 12, 0, 0, tzinfo=timezone.utc)
    monkeypatch.setattr("ssdf_mcp_query.timeparse._utcnow", lambda: fixed)
    assert parse_time("now-2d") == fixed - timedelta(days=2)
    assert parse_time("now-30m") == fixed - timedelta(minutes=30)

def test_invalid_raises():
    with pytest.raises(TimeParseError):
        parse_time("yesterday")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd services/mcp-query && uv run pytest tests/test_timeparse.py -v`
Expected: FAIL with `ModuleNotFoundError`/`ImportError` for `ssdf_mcp_query.timeparse`.

- [ ] **Step 3: Write the implementation**

```python
# src/ssdf_mcp_query/timeparse.py
"""Parse absolute (ISO-8601) and relative ("now-1h") time expressions to UTC datetimes."""

from __future__ import annotations

import re
from datetime import datetime, timezone, timedelta

_REL_RE = re.compile(r"^now(?:-(\d+)([smhd]))?$")
_UNIT_TO_KW = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}


class TimeParseError(ValueError):
    """Raised when a time expression cannot be parsed."""


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def parse_time(value: str) -> datetime:
    """Return a timezone-aware UTC datetime for an ISO-8601 or relative expression."""
    text = value.strip()
    match = _REL_RE.match(text)
    if match:
        now = _utcnow()
        amount, unit = match.group(1), match.group(2)
        if amount is None:
            return now
        return now - timedelta(**{_UNIT_TO_KW[unit]: int(amount)})
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise TimeParseError(f"unrecognized time expression: {value!r}") from exc
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_timeparse.py -v`
Expected: PASS (5 passed).

- [ ] **Step 5: Commit**

```bash
git add services/mcp-query/src/ssdf_mcp_query/timeparse.py services/mcp-query/tests/test_timeparse.py
git commit -m "feat(m2): time expression parser (ISO-8601 + relative)"
```

---

## Task 3: SQL guard (`sql_guard.py`) — the critical safety unit

Parses a candidate `run_sql` query with `sqlglot`, enforces: exactly one statement, `SELECT` only, no `SETTINGS` clause, every table in the `ssdf` database, no table functions, and an enforced/clamped `LIMIT`. Returns rewritten safe SQL or raises `GuardError`.

**Files:**
- Create: `services/mcp-query/src/ssdf_mcp_query/sql_guard.py`
- Test: `services/mcp-query/tests/test_sql_guard.py`

- [ ] **Step 1: Write the failing test (allow/deny table)**

```python
# tests/test_sql_guard.py
import pytest
from ssdf_mcp_query.sql_guard import guard_sql, GuardError

ALLOWED = [
    "SELECT * FROM ssdf.events LIMIT 10",
    "SELECT event_action, count() FROM ssdf.events GROUP BY event_action",
    "SELECT * FROM ssdf.events WHERE event_outcome = 'failure' ORDER BY timestamp DESC",
    "SELECT s.source_ip FROM ssdf.events AS s WHERE s.destination_port = 443",
]

DENIED = [
    "INSERT INTO ssdf.events VALUES (1)",
    "ALTER TABLE ssdf.events DELETE WHERE 1=1",
    "DROP TABLE ssdf.events",
    "SELECT * FROM ssdf.events; DELETE FROM ssdf.events",
    "SELECT * FROM system.tables",
    "SELECT * FROM url('http://evil/x', CSV, 'a String')",
    "SELECT * FROM ssdf.events SETTINGS readonly=0",
    "SELECT * FROM events",                    # unqualified / non-ssdf db
    "SELECT * FROM other.secrets",
    "TRUNCATE TABLE ssdf.events",
]

@pytest.mark.parametrize("query", ALLOWED)
def test_allowed_queries_pass(query):
    out = guard_sql(query, max_limit=1000)
    assert "ssdf" in out.lower()
    assert "limit" in out.lower()           # a LIMIT is always present after guarding

@pytest.mark.parametrize("query", DENIED)
def test_denied_queries_rejected(query):
    with pytest.raises(GuardError):
        guard_sql(query, max_limit=1000)

def test_missing_limit_is_injected():
    out = guard_sql("SELECT * FROM ssdf.events", max_limit=500)
    assert out.lower().rstrip().endswith("limit 500")

def test_oversized_limit_is_clamped():
    out = guard_sql("SELECT * FROM ssdf.events LIMIT 999999", max_limit=1000)
    assert "1000" in out
    assert "999999" not in out
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_sql_guard.py -v`
Expected: FAIL with import error for `guard_sql`.

- [ ] **Step 3: Write the implementation**

```python
# src/ssdf_mcp_query/sql_guard.py
"""Validate and rewrite LLM-supplied SQL for the guarded run_sql tool.

Layered defenses: single statement, SELECT-only, no SETTINGS clause, ssdf-only
tables, no table functions, enforced/clamped LIMIT. Returns safe SQL or raises.
"""

from __future__ import annotations

import sqlglot
from sqlglot import exp

ALLOWED_DB = "ssdf"
_DIALECT = "clickhouse"
# ClickHouse table functions that must never appear (data exfiltration / escape).
_TABLE_FUNCTIONS = {
    "url", "file", "remote", "remotesecure", "s3", "s3cluster", "mysql",
    "postgresql", "jdbc", "odbc", "hdfs", "cluster", "merge", "input", "numbers",
    "generaterandom", "view", "dictionary",
}


class GuardError(ValueError):
    """Raised when a query is rejected by the guard."""


def guard_sql(query: str, max_limit: int = 1000) -> str:
    """Return rewritten safe SQL for a single read-only SELECT, or raise GuardError."""
    try:
        statements = sqlglot.parse(query, read=_DIALECT)
    except Exception as exc:  # sqlglot.errors.ParseError and friends
        raise GuardError(f"could not parse query: {exc}") from exc

    statements = [s for s in statements if s is not None]
    if len(statements) != 1:
        raise GuardError("exactly one statement is allowed")

    stmt = statements[0]
    if not isinstance(stmt, exp.Select):
        raise GuardError("only SELECT statements are allowed")

    if stmt.args.get("settings"):
        raise GuardError("SETTINGS clause is not allowed")

    # Reject table functions (they appear as anonymous functions in FROM).
    for func in stmt.find_all(exp.Anonymous, exp.Func):
        name = (func.name or "").lower()
        if name in _TABLE_FUNCTIONS:
            raise GuardError(f"table function not allowed: {name}")

    tables = list(stmt.find_all(exp.Table))
    if not tables:
        raise GuardError("query must read from an ssdf table")
    for table in tables:
        db = (table.db or "").lower()
        if db != ALLOWED_DB:
            raise GuardError(
                f"only the '{ALLOWED_DB}' database is allowed (got {table.db or 'unqualified'}.{table.name})"
            )

    # Enforce / clamp LIMIT.
    limit = stmt.args.get("limit")
    if limit is None:
        stmt = stmt.limit(max_limit)
    else:
        expr = limit.expression
        if isinstance(expr, exp.Literal) and expr.is_int:
            if int(expr.name) > max_limit:
                stmt.set("limit", exp.Limit(expression=exp.Literal.number(max_limit)))
        else:
            stmt.set("limit", exp.Limit(expression=exp.Literal.number(max_limit)))

    return stmt.sql(dialect=_DIALECT)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_sql_guard.py -v`
Expected: PASS. If a specific deny case slips through (e.g. `find_all(exp.Func)` does not catch a table function in your sqlglot version), inspect with `python -c "import sqlglot; print(repr(sqlglot.parse_one(\"SELECT * FROM url('x')\", read='clickhouse')))"` and adjust the traversal until all ALLOWED pass and all DENIED raise. Do not weaken the deny set.

- [ ] **Step 5: Commit**

```bash
git add services/mcp-query/src/ssdf_mcp_query/sql_guard.py services/mcp-query/tests/test_sql_guard.py
git commit -m "feat(m2): sqlglot-based read-only SQL guard for run_sql"
```

---

## Task 4: SQL builders (`builders.py`) — pure, parameterized

Pure functions that return `(sql, params)` for `query_flows`/`top_talkers` and the schema-introspection queries. No I/O — fully unit-testable. User-supplied scalars are bound via ClickHouse `{name:Type}` params; only the integer `limit` (validated/clamped) is inlined.

**Files:**
- Create: `services/mcp-query/src/ssdf_mcp_query/builders.py`
- Test: `services/mcp-query/tests/test_builders.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_builders.py
import pytest
from ssdf_mcp_query.builders import (
    build_query_flows, build_top_talkers, FLOW_COLUMNS, BuilderError,
)

def test_query_flows_no_filters_has_window_and_limit():
    sql, params = build_query_flows(limit=100)
    assert "FROM ssdf.events" in sql
    assert "ORDER BY timestamp DESC" in sql
    assert "LIMIT 100" in sql
    assert "since" in params and "until" in params  # default window bound

def test_query_flows_filters_bind_params_not_interpolated():
    sql, params = build_query_flows(src_ip="10.64.0.1", action="flow_session_deny", dst_port=443)
    assert "10.64.0.1" not in sql            # value is bound, never inlined
    assert params["src_ip"] == "10.64.0.1"
    assert params["action"] == "flow_session_deny"
    assert params["dst_port"] == 443
    assert "{src_ip:String}" in sql
    assert "{dst_port:UInt16}" in sql

def test_query_flows_zone_matches_either_side():
    sql, _ = build_query_flows(zone="trust")
    assert "observer_ingress_zone" in sql and "observer_egress_zone" in sql

def test_query_flows_limit_clamped():
    sql, _ = build_query_flows(limit=10_000)
    assert "LIMIT 1000" in sql

def test_query_flows_selects_expected_columns():
    sql, _ = build_query_flows()
    for col in FLOW_COLUMNS:
        assert col in sql

def test_top_talkers_by_bytes_src():
    sql, params = build_top_talkers(by="bytes", side="src", limit=5)
    assert "source_ip" in sql
    assert "sum(network_bytes)" in sql
    assert "LIMIT 5" in sql

def test_top_talkers_by_flows_dst():
    sql, _ = build_top_talkers(by="flows", side="dst")
    assert "destination_ip" in sql
    assert "count()" in sql

def test_top_talkers_invalid_args_raise():
    with pytest.raises(BuilderError):
        build_top_talkers(by="nope", side="src")
    with pytest.raises(BuilderError):
        build_top_talkers(by="bytes", side="nope")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_builders.py -v`
Expected: FAIL with import error for `build_query_flows`.

- [ ] **Step 3: Write the implementation**

```python
# src/ssdf_mcp_query/builders.py
"""Pure SQL builders for the purpose-built tools. Return (sql, params); no I/O."""

from __future__ import annotations

from .timeparse import parse_time

MAX_LIMIT = 1000
TOP_MAX_LIMIT = 100

FLOW_COLUMNS = [
    "timestamp", "event_action", "event_outcome", "event_provider",
    "source_ip", "source_port", "destination_ip", "destination_port",
    "network_transport", "network_bytes", "rule_name",
    "observer_ingress_zone", "observer_egress_zone", "user_name",
]


class BuilderError(ValueError):
    """Raised on invalid builder arguments."""


def _clamp(value: int, lo: int, hi: int) -> int:
    return max(lo, min(int(value), hi))


def _window(since, until, params):
    """Bind the time window (defaults: now-24h .. now) into params and return conditions."""
    since_dt = parse_time(since) if since else parse_time("now-24h")
    until_dt = parse_time(until) if until else parse_time("now")
    params["since"] = since_dt.isoformat()
    params["until"] = until_dt.isoformat()
    return [
        "timestamp >= parseDateTimeBestEffort({since:String})",
        "timestamp <= parseDateTimeBestEffort({until:String})",
    ]


def build_query_flows(
    src_ip=None, dst_ip=None, dst_port=None, action=None, outcome=None,
    provider=None, zone=None, since=None, until=None, limit=100,
):
    params: dict = {}
    conditions = _window(since, until, params)

    if src_ip is not None:
        params["src_ip"] = src_ip
        conditions.append("source_ip = toIPv4({src_ip:String})")
    if dst_ip is not None:
        params["dst_ip"] = dst_ip
        conditions.append("destination_ip = toIPv4({dst_ip:String})")
    if dst_port is not None:
        params["dst_port"] = int(dst_port)
        conditions.append("destination_port = {dst_port:UInt16}")
    if action is not None:
        params["action"] = action
        conditions.append("event_action = {action:String}")
    if outcome is not None:
        params["outcome"] = outcome
        conditions.append("event_outcome = {outcome:String}")
    if provider is not None:
        params["provider"] = provider
        conditions.append("event_provider = {provider:String}")
    if zone is not None:
        params["zone"] = zone
        conditions.append(
            "(observer_ingress_zone = {zone:String} OR observer_egress_zone = {zone:String})"
        )

    where = " AND ".join(conditions)
    cols = ", ".join(FLOW_COLUMNS)
    limit = _clamp(limit, 1, MAX_LIMIT)
    sql = (
        f"SELECT {cols} FROM ssdf.events WHERE {where} "
        f"ORDER BY timestamp DESC LIMIT {limit}"
    )
    return sql, params


def build_top_talkers(by="bytes", side="src", since=None, until=None, limit=10):
    if by not in ("bytes", "flows"):
        raise BuilderError("by must be 'bytes' or 'flows'")
    if side not in ("src", "dst"):
        raise BuilderError("side must be 'src' or 'dst'")

    ip_col = "source_ip" if side == "src" else "destination_ip"
    order_expr = "sum(network_bytes)" if by == "bytes" else "count()"
    params: dict = {}
    conditions = _window(since, until, params)
    conditions.append(f"{ip_col} IS NOT NULL")
    where = " AND ".join(conditions)
    limit = _clamp(limit, 1, TOP_MAX_LIMIT)
    sql = (
        f"SELECT {ip_col} AS ip, sum(network_bytes) AS bytes, count() AS flows "
        f"FROM ssdf.events WHERE {where} "
        f"GROUP BY ip ORDER BY {order_expr} DESC LIMIT {limit}"
    )
    return sql, params
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_builders.py -v`
Expected: PASS (8 passed).

- [ ] **Step 5: Commit**

```bash
git add services/mcp-query/src/ssdf_mcp_query/builders.py services/mcp-query/tests/test_builders.py
git commit -m "feat(m2): parameterized SQL builders for query_flows/top_talkers"
```

---

## Task 5: Config (`config.py`)

Loads settings from environment, with the bearer token read from `MCP_AUTH_TOKEN` or the file at `MCP_TOKEN_FILE`.

**Files:**
- Create: `services/mcp-query/src/ssdf_mcp_query/config.py`
- Test: `services/mcp-query/tests/test_config.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_config.py
import pytest
from ssdf_mcp_query.config import load_config, ConfigError

def test_load_config_from_env(monkeypatch, tmp_path):
    token_file = tmp_path / "token"
    token_file.write_text("secret-token\n")
    monkeypatch.setenv("CH_HOST", "10.64.0.9")
    monkeypatch.setenv("CH_USER", "ssdf_ro")
    monkeypatch.setenv("CH_PASSWORD", "pw")
    monkeypatch.setenv("MCP_TOKEN_FILE", str(token_file))
    monkeypatch.delenv("MCP_AUTH_TOKEN", raising=False)
    cfg = load_config()
    assert cfg.ch_host == "10.64.0.9"
    assert cfg.ch_port == 8123           # default
    assert cfg.ch_user == "ssdf_ro"
    assert cfg.mcp_port == 30032         # default
    assert cfg.auth_token == "secret-token"   # trimmed from file

def test_inline_token_env_wins(monkeypatch):
    monkeypatch.setenv("CH_PASSWORD", "pw")
    monkeypatch.setenv("MCP_AUTH_TOKEN", "inline")
    monkeypatch.delenv("MCP_TOKEN_FILE", raising=False)
    assert load_config().auth_token == "inline"

def test_missing_token_raises(monkeypatch):
    monkeypatch.setenv("CH_PASSWORD", "pw")
    monkeypatch.delenv("MCP_AUTH_TOKEN", raising=False)
    monkeypatch.delenv("MCP_TOKEN_FILE", raising=False)
    with pytest.raises(ConfigError):
        load_config()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_config.py -v`
Expected: FAIL with import error.

- [ ] **Step 3: Write the implementation**

```python
# src/ssdf_mcp_query/config.py
"""Runtime configuration loaded from environment + token file."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


class ConfigError(RuntimeError):
    """Raised when required configuration is missing."""


@dataclass(frozen=True)
class Config:
    ch_host: str
    ch_port: int
    ch_user: str
    ch_password: str
    ch_database: str
    mcp_bind: str
    mcp_port: int
    auth_token: str
    max_execution_time: int = 10


def _read_token() -> str:
    inline = os.environ.get("MCP_AUTH_TOKEN")
    if inline:
        return inline.strip()
    token_file = os.environ.get("MCP_TOKEN_FILE")
    if token_file and Path(token_file).is_file():
        return Path(token_file).read_text(encoding="utf-8").strip()
    raise ConfigError("no bearer token: set MCP_AUTH_TOKEN or MCP_TOKEN_FILE")


def load_config() -> Config:
    password = os.environ.get("CH_PASSWORD")
    if password is None:
        raise ConfigError("CH_PASSWORD is required")
    return Config(
        ch_host=os.environ.get("CH_HOST", "127.0.0.1"),
        ch_port=int(os.environ.get("CH_PORT", "8123")),
        ch_user=os.environ.get("CH_USER", "ssdf_ro"),
        ch_password=password,
        ch_database=os.environ.get("CH_DATABASE", "ssdf"),
        mcp_bind=os.environ.get("MCP_BIND", "0.0.0.0"),
        mcp_port=int(os.environ.get("MCP_PORT", "30032")),
        auth_token=_read_token(),
        max_execution_time=int(os.environ.get("MCP_MAX_EXEC_SECS", "10")),
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_config.py -v`
Expected: PASS (3 passed).

- [ ] **Step 5: Commit**

```bash
git add services/mcp-query/src/ssdf_mcp_query/config.py services/mcp-query/tests/test_config.py
git commit -m "feat(m2): config loader (env + token file)"
```

---

## Task 6: ClickHouse wrapper (`clickhouse.py`) — the storage seam

The only module importing `clickhouse_connect`. Provides a thin read-only client with a `run(sql, params)` returning `(columns, rows-as-dicts, row_count)` with values JSON-serializable (datetimes → ISO strings, IPv4 → str).

**Files:**
- Create: `services/mcp-query/src/ssdf_mcp_query/clickhouse.py`
- Test: `services/mcp-query/tests/test_clickhouse.py`

- [ ] **Step 1: Write the failing test (serialization is pure-testable)**

```python
# tests/test_clickhouse.py
import datetime as dt
import ipaddress
from ssdf_mcp_query.clickhouse import jsonify

def test_jsonify_datetime_to_iso():
    value = dt.datetime(2026, 6, 6, 12, 0, 0, tzinfo=dt.timezone.utc)
    assert jsonify(value) == "2026-06-06T12:00:00+00:00"

def test_jsonify_ipv4_to_str():
    assert jsonify(ipaddress.IPv4Address("10.65.1.10")) == "10.65.1.10"

def test_jsonify_passthrough_and_none():
    assert jsonify(None) is None
    assert jsonify(443) == 443
    assert jsonify("x") == "x"

def test_jsonify_nested_collections():
    assert jsonify({"a": ipaddress.IPv4Address("1.2.3.4")}) == {"a": "1.2.3.4"}
    assert jsonify([dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)]) == ["2026-01-01T00:00:00+00:00"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_clickhouse.py -v`
Expected: FAIL with import error for `jsonify`.

- [ ] **Step 3: Write the implementation**

```python
# src/ssdf_mcp_query/clickhouse.py
"""Read-only ClickHouse access (the swappable storage seam)."""

from __future__ import annotations

import datetime as _dt
import ipaddress as _ip
from typing import Any

import clickhouse_connect

from .config import Config


def jsonify(value: Any) -> Any:
    """Convert ClickHouse-returned values into JSON-serializable Python primitives."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, _dt.datetime):
        return value.isoformat()
    if isinstance(value, (_ip.IPv4Address, _ip.IPv6Address)):
        return str(value)
    if isinstance(value, dict):
        return {k: jsonify(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [jsonify(v) for v in value]
    return str(value)


class ClickHouseClient:
    """Thin read-only client. All queries run as the configured (read-only) CH user."""

    def __init__(self, config: Config):
        self._config = config
        self._client = clickhouse_connect.get_client(
            host=config.ch_host,
            port=config.ch_port,
            username=config.ch_user,
            password=config.ch_password,
            database=config.ch_database,
        )

    def run(self, sql: str, params: dict | None = None) -> dict:
        """Execute a read query; return {columns, rows, row_count}. Rows are dicts."""
        result = self._client.query(sql, parameters=params or {})
        columns = list(result.column_names)
        rows = [
            {col: jsonify(val) for col, val in zip(columns, row)}
            for row in result.result_rows
        ]
        return {"columns": columns, "rows": rows, "row_count": len(rows)}
```

> **Deployment note (no per-query settings):** the read-only `ssdf_ro` user is created with `readonly = 1` plus `max_execution_time`/`max_result_rows` baked into its SETTINGS (Task 8). Under `readonly = 1` the client must NOT send conflicting settings, so `run()` deliberately passes none — the ceilings are enforced server-side by the user profile.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_clickhouse.py -v`
Expected: PASS (4 passed).

- [ ] **Step 5: Commit**

```bash
git add services/mcp-query/src/ssdf_mcp_query/clickhouse.py services/mcp-query/tests/test_clickhouse.py
git commit -m "feat(m2): read-only ClickHouse client wrapper + value serialization"
```

---

## Task 7: Tool functions (`tools.py`)

Wraps builders + guard + client into the four tool implementations, each returning a result dict (`{rows, row_count, truncated, elapsed_ms}` or `{error, detail}`). These are plain functions (decoupled from FastMCP) so they can be tested without a server.

**Files:**
- Create: `services/mcp-query/src/ssdf_mcp_query/tools.py`
- Test: `services/mcp-query/tests/test_tools.py`

- [ ] **Step 1: Write the failing test (with a fake client — no live DB)**

```python
# tests/test_tools.py
import pytest
from ssdf_mcp_query.tools import Tools

class FakeClient:
    def __init__(self, rows=None, columns=None, raise_exc=None):
        self._rows = rows or []
        self._columns = columns or []
        self._raise = raise_exc
        self.last_sql = None
        self.last_params = None

    def run(self, sql, params=None):
        self.last_sql = sql
        self.last_params = params
        if self._raise:
            raise self._raise
        return {"columns": self._columns, "rows": self._rows, "row_count": len(self._rows)}

def test_query_flows_returns_rows_and_metadata():
    fake = FakeClient(rows=[{"source_ip": "10.64.0.1"}], columns=["source_ip"])
    tools = Tools(fake, max_rows=1000)
    out = tools.query_flows(action="flow_session_deny", since="now-1h")
    assert out["row_count"] == 1
    assert out["rows"][0]["source_ip"] == "10.64.0.1"
    assert out["truncated"] is False
    assert "elapsed_ms" in out
    assert fake.last_params["action"] == "flow_session_deny"

def test_query_flows_truncated_flag():
    rows = [{"x": i} for i in range(1000)]
    tools = Tools(FakeClient(rows=rows, columns=["x"]), max_rows=1000)
    out = tools.query_flows(limit=1000)
    assert out["truncated"] is True          # hit the cap

def test_run_sql_rejected_returns_validation_error():
    tools = Tools(FakeClient(), max_rows=1000)
    out = tools.run_sql("DROP TABLE ssdf.events")
    assert out["error"] == "validation"

def test_run_sql_allowed_executes_guarded_sql():
    fake = FakeClient(rows=[{"n": 1}], columns=["n"])
    tools = Tools(fake, max_rows=1000)
    out = tools.run_sql("SELECT count() AS n FROM ssdf.events")
    assert out["row_count"] == 1
    assert "limit" in fake.last_sql.lower()   # guard injected a LIMIT

def test_upstream_error_is_caught():
    tools = Tools(FakeClient(raise_exc=RuntimeError("ch down")), max_rows=1000)
    out = tools.query_flows()
    assert out["error"] == "upstream"

def test_top_talkers_invalid_arg_is_validation_error():
    tools = Tools(FakeClient(), max_rows=1000)
    out = tools.top_talkers(by="bogus")
    assert out["error"] == "validation"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_tools.py -v`
Expected: FAIL with import error for `Tools`.

- [ ] **Step 3: Write the implementation**

```python
# src/ssdf_mcp_query/tools.py
"""Tool implementations: builders + guard + client -> result dicts."""

from __future__ import annotations

import time
from typing import Any

from .builders import build_query_flows, build_top_talkers, BuilderError, MAX_LIMIT
from .sql_guard import guard_sql, GuardError
from .timeparse import TimeParseError


def _ok(result: dict, requested_limit: int) -> dict:
    rows = result["rows"]
    return {
        "rows": rows,
        "columns": result["columns"],
        "row_count": result["row_count"],
        "truncated": result["row_count"] >= requested_limit,
        "elapsed_ms": result.pop("_elapsed_ms", 0),
    }


class Tools:
    """Stateless tool surface bound to a ClickHouse client."""

    def __init__(self, client, max_rows: int = MAX_LIMIT):
        self._client = client
        self._max_rows = max_rows

    def _execute(self, sql: str, params: dict, requested_limit: int) -> dict:
        start = time.monotonic()
        result = self._client.run(sql, params)
        result["_elapsed_ms"] = int((time.monotonic() - start) * 1000)
        return _ok(result, requested_limit)

    def query_flows(self, src_ip=None, dst_ip=None, dst_port=None, action=None,
                    outcome=None, provider=None, zone=None, since=None,
                    until=None, limit=100) -> dict:
        try:
            sql, params = build_query_flows(
                src_ip=src_ip, dst_ip=dst_ip, dst_port=dst_port, action=action,
                outcome=outcome, provider=provider, zone=zone, since=since,
                until=until, limit=limit,
            )
        except (BuilderError, TimeParseError, ValueError) as exc:
            return {"error": "validation", "detail": str(exc)}
        return self._safe_execute(sql, params, min(int(limit), self._max_rows))

    def top_talkers(self, by="bytes", side="src", since=None, until=None, limit=10) -> dict:
        try:
            sql, params = build_top_talkers(by=by, side=side, since=since,
                                            until=until, limit=limit)
        except (BuilderError, TimeParseError, ValueError) as exc:
            return {"error": "validation", "detail": str(exc)}
        return self._safe_execute(sql, params, int(limit))

    def describe_schema(self) -> dict:
        try:
            cols = self._client.run("DESCRIBE ssdf.events")
            columns = [{"name": r["name"], "type": r["type"]} for r in cols["rows"]]
            enums: dict[str, Any] = {}
            for key, col in (("event_actions", "event_action"),
                             ("event_outcomes", "event_outcome"),
                             ("event_providers", "event_provider")):
                res = self._client.run(
                    f"SELECT DISTINCT {col} AS v FROM ssdf.events LIMIT 100"
                )
                enums[key] = [r["v"] for r in res["rows"]]
            zones = self._client.run(
                "SELECT DISTINCT observer_ingress_zone AS v FROM ssdf.events "
                "WHERE v != '' LIMIT 100"
            )
            stats = self._client.run(
                "SELECT count() AS c, min(timestamp) AS mn, max(timestamp) AS mx "
                "FROM ssdf.events"
            )
            stat_row = stats["rows"][0] if stats["rows"] else {"c": 0, "mn": None, "mx": None}
            return {
                "columns": columns,
                "zones": [r["v"] for r in zones["rows"]],
                "row_count": stat_row["c"],
                "time_range": {"min": stat_row["mn"], "max": stat_row["mx"]},
                **enums,
            }
        except Exception as exc:  # noqa: BLE001 - surface as structured upstream error
            return {"error": "upstream", "detail": str(exc)}

    def run_sql(self, query: str) -> dict:
        try:
            safe_sql = guard_sql(query, max_limit=self._max_rows)
        except GuardError as exc:
            return {"error": "validation", "detail": str(exc)}
        return self._safe_execute(safe_sql, {}, self._max_rows)

    def _safe_execute(self, sql: str, params: dict, requested_limit: int) -> dict:
        try:
            return self._execute(sql, params, requested_limit)
        except Exception as exc:  # noqa: BLE001 - upstream/CH failures
            return {"error": "upstream", "detail": str(exc)}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_tools.py -v`
Expected: PASS (6 passed).

- [ ] **Step 5: Run the full unit suite (no live DB)**

Run: `uv run pytest -m "not integration" -v`
Expected: PASS — all of timeparse/sql_guard/builders/config/clickhouse/tools tests green.

- [ ] **Step 6: Commit**

```bash
git add services/mcp-query/src/ssdf_mcp_query/tools.py services/mcp-query/tests/test_tools.py
git commit -m "feat(m2): tool functions with structured results + error handling"
```

---

## Task 8: Provision LXC + read-only CH user + deploy [LIVE checkpoint]

> **LIVE checkpoint — pause for operator confirmation before creating infrastructure.** Present the chosen VMID and IP and get a "go" before running `pct create` / creating the CH user.

**Files:**
- Create: `services/mcp-query/infra/ssdf-mcp-query.service`

- [ ] **Step 1: Pick the next free 100-range VMID and an unused IP**

```bash
ssh root@pve3.example.com "pct list && qm list" 2>&1   # find free VMID (102/104 used by M1)
# Confirm an unused IP on the lab subnet (ping-check a candidate, e.g. 198.51.100.152)
ssh root@pve3.example.com "ping -c1 -W1 198.51.100.152" 2>&1 || echo "candidate free"
```
Record the chosen VMID (expected next free, e.g. **105**) and IP. **Do not reuse the protected VMIDs** listed in `~/.claude/CLAUDE.md` (500, 600, 601-604, 100/301, 900, and the M1 102/104).

- [ ] **Step 2: Create and start the LXC (Debian, like M1)**

```bash
ssh root@pve3.example.com "pct create <VMID> <template> \
  --hostname ssdf-mcp-query --cores 1 --memory 512 --swap 256 \
  --net0 name=eth0,bridge=vmbr0,ip=<IP>/24,gw=198.51.100.1 \
  --rootfs local-lvm:4 --unprivileged 1 --start 1"
```
Use the same Debian template M1 used (discover with `pct config 104` / `pveam list local`). Expected: container starts; `pct exec <VMID> -- ip a` shows `<IP>`.

- [ ] **Step 3: Create the read-only ClickHouse user on ct104**

```bash
ssh root@pve3.example.com "pct exec 104 -- clickhouse-client --query \"
CREATE USER IF NOT EXISTS ssdf_ro IDENTIFIED BY '<CH_RO_PASSWORD>'
  SETTINGS max_execution_time = 10, max_result_rows = 100000, readonly = 1;
GRANT SELECT ON ssdf.* TO ssdf_ro;\""
# Verify read-only + scoped:
ssh root@pve3.example.com "pct exec 104 -- clickhouse-client --user ssdf_ro --password '<CH_RO_PASSWORD>' \
  --query 'SELECT count() FROM ssdf.events'"            # expect a number
ssh root@pve3.example.com "pct exec 104 -- clickhouse-client --user ssdf_ro --password '<CH_RO_PASSWORD>' \
  --query 'INSERT INTO ssdf.events(event_id) VALUES (1)'" 2>&1 | grep -qi 'readonly\|not allowed' && echo "write blocked OK"
```
Expected: SELECT returns a count; INSERT is rejected (readonly). Record `<CH_RO_PASSWORD>` into the gitignored `infra/ENV.local` (do NOT commit).

- [ ] **Step 4: Install Python + the service into the LXC**

```bash
ssh root@pve3.example.com "pct exec <VMID> -- bash -lc 'apt-get update && apt-get install -y python3 python3-venv python3-pip rsync'"
# Push the package source
rsync -a -e "ssh root@pve3.example.com 'pct exec <VMID> --'" 2>/dev/null || true
# (If rsync-through-pct is awkward, tar the dir, scp to the host, and `pct push` then extract.)
ssh root@pve3.example.com "pct exec <VMID> -- bash -lc 'cd /opt && python3 -m venv ssdf-mcp && /opt/ssdf-mcp/bin/pip install fastmcp clickhouse-connect sqlglot && /opt/ssdf-mcp/bin/pip install /opt/ssdf-mcp-query'"
```
Expected: dependencies install; `python -c "import ssdf_mcp_query"` succeeds inside the venv. (Exact copy mechanism mirrors how M1 pushed `vector.toml` — tar + `pct push` is reliable.)

- [ ] **Step 5: Create the bearer token and the systemd unit**

```bash
ssh root@pve3.example.com "pct exec <VMID> -- bash -lc 'mkdir -p /etc/ssdf-mcp && head -c32 /dev/urandom | base64 > /etc/ssdf-mcp/token && chmod 600 /etc/ssdf-mcp/token'"
```

`services/mcp-query/infra/ssdf-mcp-query.service`:
```ini
[Unit]
Description=SSDF M2 MCP query server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=CH_HOST=198.51.100.151
Environment=CH_PORT=8123
Environment=CH_USER=ssdf_ro
Environment=CH_DATABASE=ssdf
Environment=MCP_BIND=0.0.0.0
Environment=MCP_PORT=30032
Environment=MCP_TOKEN_FILE=/etc/ssdf-mcp/token
EnvironmentFile=/etc/ssdf-mcp/secrets.env
ExecStart=/opt/ssdf-mcp/bin/python -m ssdf_mcp_query.server
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
```
Put `CH_PASSWORD=<CH_RO_PASSWORD>` into `/etc/ssdf-mcp/secrets.env` (chmod 600, NOT committed). Install the unit, then:
```bash
ssh root@pve3.example.com "pct exec <VMID> -- bash -lc 'systemctl daemon-reload && systemctl enable --now ssdf-mcp-query && sleep 2 && systemctl is-active ssdf-mcp-query'"
```
Expected: `active`.

- [ ] **Step 6: Record as-built coordinates in `infra/ENV.local` (gitignored)**

Append the VMID/IP/port and `CH_RO_PASSWORD` to `infra/ENV.local`. Commit only the systemd unit template.

```bash
git add services/mcp-query/infra/ssdf-mcp-query.service
git commit -m "feat(m2): systemd unit + read-only LXC deployment for ssdf-mcp-query"
```

---

## Task 9: FastMCP server (`server.py`) + live integration [LIVE checkpoint]

Wires the tools into a FastMCP app with bearer-token auth and HTTP transport, then verifies end-to-end against the running service.

**Files:**
- Create: `services/mcp-query/src/ssdf_mcp_query/server.py`
- Test: `services/mcp-query/tests/test_integration.py`

- [ ] **Step 1: Write the implementation (`server.py`)**

```python
# src/ssdf_mcp_query/server.py
"""FastMCP streamable-HTTP server exposing the read-only query tools."""

from __future__ import annotations

from fastmcp import FastMCP
from fastmcp.server.auth import StaticTokenVerifier

from .config import load_config
from .clickhouse import ClickHouseClient
from .tools import Tools


def build_app() -> FastMCP:
    config = load_config()
    client = ClickHouseClient(config)
    tools = Tools(client)
    auth = StaticTokenVerifier(
        tokens={config.auth_token: {"sub": "agent", "client_id": "ssdf"}}
    )
    mcp = FastMCP("ssdf-mcp-query", auth=auth)

    @mcp.tool
    def query_flows(src_ip: str | None = None, dst_ip: str | None = None,
                    dst_port: int | None = None, action: str | None = None,
                    outcome: str | None = None, provider: str | None = None,
                    zone: str | None = None, since: str | None = None,
                    until: str | None = None, limit: int = 100) -> dict:
        """Query normalized security flow events with optional filters and a time window.

        Times accept ISO-8601 or relative ("now-1h"). Default window is the last 24h.
        Returns rows plus {row_count, truncated, elapsed_ms} or {error, detail}.
        """
        return tools.query_flows(src_ip=src_ip, dst_ip=dst_ip, dst_port=dst_port,
                                 action=action, outcome=outcome, provider=provider,
                                 zone=zone, since=since, until=until, limit=limit)

    @mcp.tool
    def describe_schema() -> dict:
        """Return ssdf.events columns/types, distinct enum values, row count and time range."""
        return tools.describe_schema()

    @mcp.tool
    def top_talkers(by: str = "bytes", side: str = "src", since: str | None = None,
                    until: str | None = None, limit: int = 10) -> dict:
        """Top source/destination IPs by bytes or flow count over a time window."""
        return tools.top_talkers(by=by, side=side, since=since, until=until, limit=limit)

    @mcp.tool
    def run_sql(query: str) -> dict:
        """Run a guarded read-only SELECT against ssdf.* (single statement, enforced LIMIT)."""
        return tools.run_sql(query)

    return mcp


def main() -> None:
    config = load_config()
    app = build_app()
    app.run(transport="http", host=config.mcp_bind, port=config.mcp_port)


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Write the integration test**

```python
# tests/test_integration.py
"""Integration tests against a live ClickHouse. Run with CH_* env set; skipped otherwise."""

import os
import pytest

pytestmark = pytest.mark.integration

@pytest.fixture(scope="module")
def tools():
    if not os.environ.get("CH_PASSWORD"):
        pytest.skip("no live ClickHouse configured (set CH_HOST/CH_USER/CH_PASSWORD)")
    from ssdf_mcp_query.config import load_config
    from ssdf_mcp_query.clickhouse import ClickHouseClient
    from ssdf_mcp_query.tools import Tools
    os.environ.setdefault("MCP_AUTH_TOKEN", "test")   # config needs a token to load
    return Tools(ClickHouseClient(load_config()))

def test_describe_schema_live(tools):
    out = tools.describe_schema()
    assert "error" not in out
    names = {c["name"] for c in out["columns"]}
    assert {"timestamp", "event_action", "source_ip"} <= names
    assert out["row_count"] >= 0

def test_query_flows_live_returns_typed_rows(tools):
    out = tools.query_flows(since="now-7d", limit=5)
    assert "error" not in out
    assert isinstance(out["rows"], list)
    assert out["row_count"] <= 5

def test_query_flows_deny_acceptance(tools):
    # M1 acceptance question, now answered through MCP
    out = tools.query_flows(action="flow_session_deny", since="now-30d", limit=50)
    assert "error" not in out

def test_run_sql_guarded_live(tools):
    out = tools.run_sql("SELECT event_action, count() AS c FROM ssdf.events GROUP BY event_action")
    assert "error" not in out
    assert out["row_count"] >= 0

def test_run_sql_write_blocked_live(tools):
    out = tools.run_sql("INSERT INTO ssdf.events(event_id) VALUES ('x')")
    assert out["error"] == "validation"
```

- [ ] **Step 3: Run integration tests against ct104**

Run (from the LXC, or anywhere that can reach ct104 with the read-only creds):
```bash
cd services/mcp-query && \
  CH_HOST=198.51.100.151 CH_USER=ssdf_ro CH_PASSWORD=<CH_RO_PASSWORD> CH_DATABASE=ssdf \
  uv run pytest -m integration -v
```
Expected: PASS (5 passed) — real `ssdf.events` rows returned, write blocked.

- [ ] **Step 4: Verify the live MCP service answers an authenticated tool call**

```bash
# From the operator workstation: add the server and call a tool.
# .mcp.json entry:
#   {"mcpServers":{"ssdf-query":{"type":"http","url":"http://<IP>:30032/mcp",
#     "headers":{"Authorization":"Bearer <token from /etc/ssdf-mcp/token>"}}}}
curl -s -H "Authorization: Bearer <token>" http://<IP>:30032/mcp -X POST \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | head
```
Expected: a JSON-RPC response listing the four tools. An unauthenticated request is rejected (401).

- [ ] **Step 5: Commit**

```bash
git add services/mcp-query/src/ssdf_mcp_query/server.py services/mcp-query/tests/test_integration.py
git commit -m "feat(m2): FastMCP server with bearer auth + live integration tests"
```

---

## Task 10: Acceptance + docs

**Files:**
- Modify: `CLAUDE.md` (Commands section — add M2)

- [ ] **Step 1: M2 acceptance via an agent**

Add the server to this Claude Code session's `.mcp.json` (Task 9 Step 4) and confirm the tools are callable and return the M1 acceptance answer through MCP:
- `query_flows(action="flow_session_deny", since="now-1h")` → returns without error.
- `query_flows(action="flow_session_close", since="now-30d", limit=10)` → returns real SRX rows.
- `describe_schema()` → lists 22 columns and the live `event_action`/`event_provider` values.

M2 is **done** when an LLM agent can retrieve real `ssdf.events` data through these MCP tools, authenticated, with writes impossible.

- [ ] **Step 2: Record M2 commands in `CLAUDE.md`**

Under `## Commands`, add:
```markdown
### M2 (MCP query layer — ssdf-mcp-query)
- Unit tests: `cd services/mcp-query && uv run pytest -m "not integration"`
- Integration tests (live CH): `CH_HOST=<ip> CH_USER=ssdf_ro CH_PASSWORD=<pw> uv run pytest -m integration`
- Run locally: `uv run python -m ssdf_mcp_query.server`
- Deployed: streamable-HTTP MCP on its own Proxmox LXC (no Docker), bearer-token auth,
  reading ClickHouse ct104 as the read-only `ssdf_ro` user.
- Add to an agent via `.mcp.json`: `{"type":"http","url":"http://<ip>:30032/mcp",
  "headers":{"Authorization":"Bearer <token>"}}`.
```

- [ ] **Step 3: Commit**

```bash
git add CLAUDE.md
git commit -m "docs(m2): record MCP query layer commands; mark M2 done"
```

---

## Done criteria (M2)

- `uv run pytest -m "not integration"` passes (timeparse, sql_guard allow/deny table, builders, config, clickhouse serialization, tools).
- `run_sql` guard rejects every entry in the deny table (DDL/DML, multi-statement, `system.*`, table functions, non-`ssdf` tables, `SETTINGS` overrides) and accepts valid SELECTs with an enforced LIMIT.
- A dedicated read-only `ssdf_ro` ClickHouse user exists; writes are rejected.
- The FastMCP server runs as a systemd service on its own Proxmox LXC (no Docker), bearer-auth enforced.
- An LLM agent (via `.mcp.json`) calls `query_flows`/`describe_schema`/`top_talkers`/`run_sql` and gets real, correctly-typed `ssdf.events` data — including the M1 denied/allowed-flow acceptance question.
- Storage access stays isolated in `clickhouse.py`; no write/management tools, no non-ClickHouse backend, no agent/LLM orchestration introduced (parked per the spec).
```
