# SSDF M7a — Data Classification, Multi-Principal Auth & Audit — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden the existing read-only MCP server (`ssdf-mcp-query`, ct106) with a secure-by-default data-classification taxonomy, multi-principal token auth (optionally tool-scoped), and an append-only `ssdf.audit` log of every tool call.

**Architecture:** Three new pure Python modules (`classification.py`, `auth.py`, `audit.py`) plus a per-tool wrapper wired into `server.py`. The wrapper resolves the caller principal from the FastMCP access-token claims, enforces per-tool authorization, runs the unchanged tool, and best-effort records one audit row via a dedicated INSERT-only ClickHouse user (`ssdf_audit`) on a connection separate from the `ssdf_ro` query path. M7a only *labels* data and *records* calls — it never withholds data (that is M7b).

**Tech Stack:** Python 3.11, FastMCP (`StaticTokenVerifier`, middleware-free per-tool wrapper), `clickhouse_connect`, `uv`/`pytest`, ClickHouse (MergeTree).

**Spec:** `docs/superpowers/specs/2026-06-08-ssdf-m7a-classification-auth-audit-design.md`

**Key facts grounding this plan (verified against the live tree):**
- `StaticTokenVerifier(tokens={...})` stores the *entire* per-token dict as `AccessToken.claims` (verified in `fastmcp/server/auth/providers/jwt.py:649-654`). Each token dict MUST include a `client_id` key (`token_data["client_id"]` is read unconditionally).
- `get_access_token()` is exported from `fastmcp.server.dependencies` (`__all__` line 65) and returns an `AccessToken` with `.claims`.
- FastMCP builds a tool's schema via `get_type_hints(fn)` + `inspect.signature(fn)` (`fastmcp/utilities/types.py:167,172`). `functools.wraps` copies `__annotations__`, `__doc__`, `__name__`, and sets `__wrapped__`, so a `def wrapped(*args, **kwargs)` wrapped with `functools.wraps(fn)` presents `fn`'s real signature/docstring to FastMCP. **The per-tool wrapper approach is therefore safe — no `*args/**kwargs` leaks into the tool schema.**
- The server currently registers **11** tools (the spec prose says "10"; the spec table and `server.py` both list 11: `query_flows, describe_schema, top_talkers, run_sql, get_entity, locate, neighbors, find_path, enforcement_points, topology_snapshot, explain_access`). Use 11.
- `auth_token` is referenced only in `config.py:23,55`, `server.py:27`, and `tests/test_config.py:17,23` — all updated by this plan.
- SQL user files inject the password via `envsubst` before applying (pattern from `infra/clickhouse/005_entity_user.sql`).

**Working directory for all `uv`/`pytest` commands:** `services/mcp-query`.

---

## File Structure

**New files:**
- `services/mcp-query/src/ssdf_mcp_query/classification.py` — data-class registry, tool→class map, config loader.
- `services/mcp-query/src/ssdf_mcp_query/auth.py` — runtime reader of the caller principal from the access-token claims.
- `services/mcp-query/src/ssdf_mcp_query/audit.py` — audit row builder + best-effort `Auditor` + CH-backed factory.
- `services/mcp-query/src/ssdf_mcp_query/wrapper.py` — per-tool authz+audit wrapper.
- `services/mcp-query/tests/test_classification.py`
- `services/mcp-query/tests/test_auth.py`
- `services/mcp-query/tests/test_audit.py`
- `services/mcp-query/tests/test_wrapper.py`
- `services/mcp-query/tests/test_server_audit.py`
- `infra/clickhouse/007_audit.sql` — `ssdf.audit` table + INSERT-only `ssdf_audit` user.
- `services/mcp-query/infra/tokens.example.json` — token-map example.
- `services/mcp-query/infra/classification.example.json` — classification override example.

**Modified files:**
- `services/mcp-query/src/ssdf_mcp_query/config.py` — `TokenPrincipal`, token-map loader, audit-conn fields; `Config.tokens` replaces `auth_token`.
- `services/mcp-query/src/ssdf_mcp_query/server.py` — build classification/auditor, multi-principal verifier, register tools through the wrapper.
- `services/mcp-query/tests/test_config.py` — assert against `Config.tokens`.
- `CLAUDE.md` — add an `### M7a` Commands subsection.
- `docs/superpowers/STATUS.md` — record M7a as built.

---

## Task 1: Classification module

**Files:**
- Create: `services/mcp-query/src/ssdf_mcp_query/classification.py`
- Test: `services/mcp-query/tests/test_classification.py`

- [ ] **Step 1: Write the failing test**

Create `services/mcp-query/tests/test_classification.py`:

```python
import json
import pytest
from ssdf_mcp_query.classification import (
    classes_for_tool,
    load_classification,
    TOOL_DATA_CLASSES,
)
from ssdf_mcp_query.config import ConfigError

EXPECTED = {
    "query_flows": {"security_log"},
    "describe_schema": {"security_log"},
    "top_talkers": {"security_log"},
    "run_sql": {"security_log"},
    "get_entity": {"identity"},
    "locate": {"topology"},
    "neighbors": {"topology"},
    "find_path": {"topology"},
    "enforcement_points": {"topology", "firewall_config"},
    "topology_snapshot": {"topology"},
    "explain_access": {"security_log", "topology", "identity", "firewall_config"},
}


def test_tool_class_map_matches_spec():
    assert set(TOOL_DATA_CLASSES) == set(EXPECTED)
    for tool, classes in EXPECTED.items():
        assert set(classes_for_tool(tool)) == classes


def test_unknown_tool_returns_empty():
    assert classes_for_tool("does_not_exist") == frozenset()


def test_defaults_all_sovereign():
    c = load_classification(None)
    for cls in ("security_log", "firewall_config", "topology", "identity"):
        assert c.label_for_class(cls) == "sovereign"


def test_override_topology_shareable(tmp_path):
    f = tmp_path / "cls.json"
    f.write_text(json.dumps({"topology": "shareable"}))
    c = load_classification(str(f))
    assert c.label_for_class("topology") == "shareable"
    assert c.label_for_class("identity") == "sovereign"


def test_override_identity_sovereign_is_noop(tmp_path):
    f = tmp_path / "cls.json"
    f.write_text(json.dumps({"identity": "sovereign"}))
    assert load_classification(str(f)).label_for_class("identity") == "sovereign"


@pytest.mark.parametrize("cls", ["security_log", "firewall_config"])
def test_reject_non_configurable_override(tmp_path, cls):
    f = tmp_path / "cls.json"
    f.write_text(json.dumps({cls: "shareable"}))
    with pytest.raises(ConfigError):
        load_classification(str(f))


def test_reject_unknown_class(tmp_path):
    f = tmp_path / "cls.json"
    f.write_text(json.dumps({"bogus": "shareable"}))
    with pytest.raises(ConfigError):
        load_classification(str(f))


def test_reject_bad_value(tmp_path):
    f = tmp_path / "cls.json"
    f.write_text(json.dumps({"topology": "public"}))
    with pytest.raises(ConfigError):
        load_classification(str(f))


def test_reject_non_object_json(tmp_path):
    f = tmp_path / "cls.json"
    f.write_text(json.dumps(["topology"]))
    with pytest.raises(ConfigError):
        load_classification(str(f))


def test_label_for_unknown_class_raises():
    with pytest.raises(ConfigError):
        load_classification(None).label_for_class("bogus")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd services/mcp-query && uv run pytest tests/test_classification.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'ssdf_mcp_query.classification'`.

- [ ] **Step 3: Write minimal implementation**

Create `services/mcp-query/src/ssdf_mcp_query/classification.py`:

```python
"""Data-classification taxonomy (M7a).

Pure module, secure-by-default: every class defaults to ``sovereign``; only the
two configurable classes (``topology``, ``identity``) may be flipped to
``shareable`` via the optional JSON config. M7a only *labels* — it never gates.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from .config import ConfigError

DATA_CLASSES: frozenset[str] = frozenset(
    {"security_log", "firewall_config", "topology", "identity"}
)
CONFIGURABLE_CLASSES: frozenset[str] = frozenset({"topology", "identity"})
LABELS: frozenset[str] = frozenset({"sovereign", "shareable"})

# Single source of truth: the data classes each tool's output can contain.
TOOL_DATA_CLASSES: dict[str, frozenset[str]] = {
    "query_flows": frozenset({"security_log"}),
    "describe_schema": frozenset({"security_log"}),
    "top_talkers": frozenset({"security_log"}),
    "run_sql": frozenset({"security_log"}),
    "get_entity": frozenset({"identity"}),
    "locate": frozenset({"topology"}),
    "neighbors": frozenset({"topology"}),
    "find_path": frozenset({"topology"}),
    "enforcement_points": frozenset({"topology", "firewall_config"}),
    "topology_snapshot": frozenset({"topology"}),
    "explain_access": frozenset(
        {"security_log", "topology", "identity", "firewall_config"}
    ),
}


@dataclass(frozen=True)
class Classification:
    """Resolved per-class sovereignty labels (class -> 'sovereign'|'shareable')."""

    labels: dict[str, str]

    def label_for_class(self, data_class: str) -> str:
        """Return the sovereignty label for a known data class."""
        if data_class not in DATA_CLASSES:
            raise ConfigError(f"unknown data class: {data_class}")
        return self.labels[data_class]


def classes_for_tool(tool_name: str) -> frozenset[str]:
    """Return the set of data classes a tool's output can contain (empty if unknown)."""
    return TOOL_DATA_CLASSES.get(tool_name, frozenset())


def load_classification(path: str | None = None) -> Classification:
    """Load classification overrides from an optional JSON file (secure-by-default).

    ``path`` falls back to env ``MCP_CLASSIFICATION_FILE`` when ``None``. Missing
    keys default to ``sovereign``. Raises ``ConfigError`` on any invalid override.
    """
    labels = {data_class: "sovereign" for data_class in DATA_CLASSES}
    resolved = path if path is not None else os.environ.get("MCP_CLASSIFICATION_FILE")
    if not resolved:
        return Classification(labels=labels)
    try:
        overrides = json.loads(Path(resolved).read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigError(f"invalid classification JSON: {exc}") from exc
    if not isinstance(overrides, dict):
        raise ConfigError("classification config must be a JSON object")
    for data_class, value in overrides.items():
        if data_class not in DATA_CLASSES:
            raise ConfigError(f"unknown data class: {data_class}")
        if data_class not in CONFIGURABLE_CLASSES:
            raise ConfigError(f"class '{data_class}' is not configurable (always sovereign)")
        if value not in LABELS:
            raise ConfigError(f"invalid label '{value}' for class '{data_class}'")
        labels[data_class] = value
    return Classification(labels=labels)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd services/mcp-query && uv run pytest tests/test_classification.py -q`
Expected: PASS (all tests green).

- [ ] **Step 5: Commit**

```bash
git add services/mcp-query/src/ssdf_mcp_query/classification.py services/mcp-query/tests/test_classification.py
git commit -m "feat(m7a): data-classification taxonomy + tool->class map"
```

---

## Task 2: Multi-principal token map in config

**Files:**
- Modify: `services/mcp-query/src/ssdf_mcp_query/config.py`
- Test: `services/mcp-query/tests/test_config.py`

- [ ] **Step 1: Write the failing test**

Replace the contents of `services/mcp-query/tests/test_config.py` with:

```python
import json
import pytest
from ssdf_mcp_query.config import load_config, load_token_map, ConfigError


def test_single_token_fallback_from_file(monkeypatch, tmp_path):
    token_file = tmp_path / "token"
    token_file.write_text("secret-token\n")
    monkeypatch.setenv("CH_HOST", "10.64.0.9")
    monkeypatch.setenv("CH_USER", "ssdf_ro")
    monkeypatch.setenv("CH_PASSWORD", "pw")
    monkeypatch.setenv("MCP_TOKEN_FILE", str(token_file))
    monkeypatch.delenv("MCP_AUTH_TOKEN", raising=False)
    monkeypatch.delenv("MCP_TOKENS_FILE", raising=False)
    cfg = load_config()
    assert cfg.ch_host == "10.64.0.9"
    assert cfg.mcp_port == 30032
    assert set(cfg.tokens) == {"secret-token"}
    principal = cfg.tokens["secret-token"]
    assert principal.principal == "agent"
    assert principal.allowed_tools is None


def test_inline_token_env_wins(monkeypatch):
    monkeypatch.setenv("CH_PASSWORD", "pw")
    monkeypatch.setenv("MCP_AUTH_TOKEN", "inline")
    monkeypatch.delenv("MCP_TOKEN_FILE", raising=False)
    monkeypatch.delenv("MCP_TOKENS_FILE", raising=False)
    cfg = load_config()
    assert set(cfg.tokens) == {"inline"}
    assert cfg.tokens["inline"].principal == "agent"


def test_missing_token_raises(monkeypatch):
    monkeypatch.setenv("CH_PASSWORD", "pw")
    monkeypatch.delenv("MCP_AUTH_TOKEN", raising=False)
    monkeypatch.delenv("MCP_TOKEN_FILE", raising=False)
    monkeypatch.delenv("MCP_TOKENS_FILE", raising=False)
    with pytest.raises(ConfigError):
        load_config()


def test_token_map_multi_principal(monkeypatch, tmp_path):
    f = tmp_path / "tokens.json"
    f.write_text(json.dumps({
        "tok-triage": {"principal": "triage-agent",
                       "allowed_tools": ["query_flows", "top_talkers"]},
        "tok-admin": {"principal": "admin-agent"},
    }))
    monkeypatch.setenv("MCP_TOKENS_FILE", str(f))
    tokens = load_token_map()
    assert tokens["tok-triage"].principal == "triage-agent"
    assert tokens["tok-triage"].allowed_tools == frozenset({"query_flows", "top_talkers"})
    assert tokens["tok-admin"].allowed_tools is None


def test_token_map_empty_object_raises(monkeypatch, tmp_path):
    f = tmp_path / "tokens.json"
    f.write_text("{}")
    monkeypatch.setenv("MCP_TOKENS_FILE", str(f))
    with pytest.raises(ConfigError):
        load_token_map()


def test_token_map_entry_missing_principal_raises(monkeypatch, tmp_path):
    f = tmp_path / "tokens.json"
    f.write_text(json.dumps({"tok": {"allowed_tools": ["query_flows"]}}))
    monkeypatch.setenv("MCP_TOKENS_FILE", str(f))
    with pytest.raises(ConfigError):
        load_token_map()


def test_audit_conn_fields(monkeypatch):
    monkeypatch.setenv("CH_PASSWORD", "pw")
    monkeypatch.setenv("MCP_AUTH_TOKEN", "inline")
    monkeypatch.setenv("CH_AUDIT_PASSWORD", "apw")
    monkeypatch.delenv("MCP_TOKENS_FILE", raising=False)
    monkeypatch.delenv("MCP_TOKEN_FILE", raising=False)
    cfg = load_config()
    assert cfg.ch_audit_user == "ssdf_audit"
    assert cfg.ch_audit_password == "apw"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd services/mcp-query && uv run pytest tests/test_config.py -q`
Expected: FAIL — `ImportError: cannot import name 'load_token_map'` (and `cfg.tokens` attribute errors).

- [ ] **Step 3: Write minimal implementation**

Edit `services/mcp-query/src/ssdf_mcp_query/config.py`. Add `import json` at the top (after `import os`), and add the `TokenPrincipal` dataclass + `load_token_map` after the existing `_read_token` function. Replace the `Config` dataclass `auth_token: str` field and the `load_config` body as shown.

New imports block (top of file, after `from pathlib import Path`):

```python
import json
```

Add after the `ConfigError` class:

```python
@dataclass(frozen=True)
class TokenPrincipal:
    """A bearer token's identity. ``allowed_tools=None`` means all tools allowed."""

    principal: str
    allowed_tools: frozenset[str] | None
```

Replace the `Config` dataclass with (note `tokens` replaces `auth_token`, plus audit-conn fields):

```python
@dataclass(frozen=True)
class Config:
    ch_host: str
    ch_port: int
    ch_user: str
    ch_password: str
    ch_database: str
    mcp_bind: str
    mcp_port: int
    tokens: dict[str, "TokenPrincipal"]
    ch_audit_user: str = "ssdf_audit"
    ch_audit_password: str | None = None
    max_execution_time: int = 10
```

Add `load_token_map` after `_read_token`:

```python
def load_token_map() -> dict[str, TokenPrincipal]:
    """Load the multi-principal token map (env ``MCP_TOKENS_FILE``).

    Falls back to the single-token path (``MCP_AUTH_TOKEN``/``MCP_TOKEN_FILE``)
    mapped to principal ``agent`` with all tools allowed, preserving the existing
    deploy. Raises ``ConfigError`` if neither is configured (fail closed).
    """
    tokens_file = os.environ.get("MCP_TOKENS_FILE")
    if not tokens_file:
        single = _read_token()
        return {single: TokenPrincipal(principal="agent", allowed_tools=None)}
    path = Path(tokens_file)
    if not path.is_file():
        raise ConfigError(f"MCP_TOKENS_FILE not found: {tokens_file}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigError(f"invalid token map JSON: {exc}") from exc
    if not isinstance(data, dict) or not data:
        raise ConfigError("token map must be a non-empty JSON object")
    tokens: dict[str, TokenPrincipal] = {}
    for token, meta in data.items():
        if not token or not isinstance(meta, dict):
            raise ConfigError("each token must map to an object with a 'principal'")
        principal = meta.get("principal")
        if not principal:
            raise ConfigError("token entry missing 'principal'")
        allowed = meta.get("allowed_tools")
        allowed_set = None if allowed is None else frozenset(allowed)
        tokens[token] = TokenPrincipal(principal=principal, allowed_tools=allowed_set)
    return tokens
```

Replace the `load_config` `return Config(...)` so it uses `tokens=` and audit fields:

```python
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
        tokens=load_token_map(),
        ch_audit_user=os.environ.get("CH_AUDIT_USER", "ssdf_audit"),
        ch_audit_password=os.environ.get("CH_AUDIT_PASSWORD"),
        max_execution_time=int(os.environ.get("MCP_MAX_EXEC_SECS", "10")),
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd services/mcp-query && uv run pytest tests/test_config.py -q`
Expected: PASS. (Other suites still reference `auth_token` via `server.py`; that is fixed in Task 6 — do not run the full suite yet.)

- [ ] **Step 5: Commit**

```bash
git add services/mcp-query/src/ssdf_mcp_query/config.py services/mcp-query/tests/test_config.py
git commit -m "feat(m7a): multi-principal token map + audit-conn config"
```

---

## Task 3: Runtime auth-context reader

**Files:**
- Create: `services/mcp-query/src/ssdf_mcp_query/auth.py`
- Test: `services/mcp-query/tests/test_auth.py`

- [ ] **Step 1: Write the failing test**

Create `services/mcp-query/tests/test_auth.py`:

```python
from types import SimpleNamespace
import ssdf_mcp_query.auth as auth


def _fake_token(claims):
    return SimpleNamespace(claims=claims)


def test_principal_and_allowed_tools(monkeypatch):
    monkeypatch.setattr(auth, "get_access_token", lambda: _fake_token(
        {"principal": "triage-agent", "allowed_tools": ["query_flows"]}))
    principal, allowed = auth.current_caller()
    assert principal == "triage-agent"
    assert allowed == frozenset({"query_flows"})


def test_allowed_tools_absent_means_none(monkeypatch):
    monkeypatch.setattr(auth, "get_access_token", lambda: _fake_token(
        {"principal": "admin-agent"}))
    principal, allowed = auth.current_caller()
    assert principal == "admin-agent"
    assert allowed is None


def test_falls_back_to_sub(monkeypatch):
    monkeypatch.setattr(auth, "get_access_token", lambda: _fake_token({"sub": "agent"}))
    assert auth.current_caller() == ("agent", None)


def test_no_token_returns_unknown(monkeypatch):
    monkeypatch.setattr(auth, "get_access_token", lambda: None)
    assert auth.current_caller() == ("unknown", None)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd services/mcp-query && uv run pytest tests/test_auth.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'ssdf_mcp_query.auth'`.

- [ ] **Step 3: Write minimal implementation**

Create `services/mcp-query/src/ssdf_mcp_query/auth.py`:

```python
"""Runtime reader of the caller principal from the FastMCP access-token claims (M7a)."""

from __future__ import annotations

from fastmcp.server.dependencies import get_access_token


def current_caller() -> tuple[str, frozenset[str] | None]:
    """Return ``(principal, allowed_tools)`` for the in-flight request.

    ``allowed_tools`` is ``None`` when the token grants all tools. Falls back to
    ``sub`` then ``"unknown"`` when ``principal`` is absent.
    """
    token = get_access_token()
    claims = token.claims if token is not None and token.claims else {}
    principal = claims.get("principal") or claims.get("sub") or "unknown"
    allowed = claims.get("allowed_tools")
    allowed_set = None if allowed is None else frozenset(allowed)
    return principal, allowed_set
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd services/mcp-query && uv run pytest tests/test_auth.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add services/mcp-query/src/ssdf_mcp_query/auth.py services/mcp-query/tests/test_auth.py
git commit -m "feat(m7a): runtime caller-principal reader from access-token claims"
```

---

## Task 4: Audit row builder + best-effort Auditor

**Files:**
- Create: `services/mcp-query/src/ssdf_mcp_query/audit.py`
- Test: `services/mcp-query/tests/test_audit.py`

- [ ] **Step 1: Write the failing test**

Create `services/mcp-query/tests/test_audit.py`:

```python
import datetime as dt
import json
from ssdf_mcp_query.audit import build_audit_row, Auditor, AUDIT_COLUMNS


def test_build_audit_row_shapes_all_columns():
    row = build_audit_row(
        principal="triage-agent", tier="sovereign", tool="query_flows",
        args={"dst_port": 443}, data_classes=["security_log"],
        decision="allow", row_count=7, error="",
    )
    assert set(row) == set(AUDIT_COLUMNS)
    assert row["principal"] == "triage-agent"
    assert row["tier"] == "sovereign"
    assert row["tool"] == "query_flows"
    assert json.loads(row["args"]) == {"dst_port": 443}
    assert row["data_classes"] == ["security_log"]
    assert row["decision"] == "allow"
    assert row["row_count"] == 7
    assert row["error"] == ""
    assert isinstance(row["ts"], dt.datetime)


def test_build_audit_row_serializes_non_json_args():
    row = build_audit_row(
        principal="p", tier="sovereign", tool="run_sql",
        args={"since": dt.datetime(2026, 6, 9)}, data_classes=["security_log"],
        decision="allow", row_count=0, error=None,
    )
    assert "2026-06-09" in row["args"]
    assert row["error"] == ""


def test_auditor_record_calls_insert():
    captured = []
    Auditor(captured.append).record(
        principal="p", tier="sovereign", tool="locate", args={"identifier": "x"},
        data_classes=["topology"], decision="allow", row_count=1, error="",
    )
    assert len(captured) == 1
    assert captured[0]["tool"] == "locate"


def test_auditor_swallows_insert_failure(capsys):
    def boom(_row):
        raise RuntimeError("ch down")

    Auditor(boom).record(
        principal="p", tier="sovereign", tool="locate", args={},
        data_classes=["topology"], decision="allow", row_count=0, error="",
    )  # must NOT raise
    assert "audit" in capsys.readouterr().err.lower()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd services/mcp-query && uv run pytest tests/test_audit.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'ssdf_mcp_query.audit'`.

- [ ] **Step 3: Write minimal implementation**

Create `services/mcp-query/src/ssdf_mcp_query/audit.py`:

```python
"""Append-only audit of MCP tool calls (M7a).

Best-effort by design: an audit write failure is logged to stderr but must never
fail the tool call. Rows are inserted by a dedicated INSERT-only ``ssdf_audit``
CH user on a connection separate from the ``ssdf_ro`` query path.
"""

from __future__ import annotations

import datetime as _dt
import json
import sys
from typing import Any, Callable, Iterable

# Column order MUST match infra/clickhouse/007_audit.sql.
AUDIT_COLUMNS: list[str] = [
    "ts", "principal", "tier", "tool", "args",
    "data_classes", "decision", "row_count", "error",
]


def build_audit_row(
    *,
    principal: str,
    tier: str,
    tool: str,
    args: Any,
    data_classes: Iterable[str],
    decision: str,
    row_count: int,
    error: Any,
    ts: _dt.datetime | None = None,
) -> dict:
    """Build a fully-shaped audit row dict (pure; no I/O)."""
    return {
        "ts": ts or _dt.datetime.now(_dt.timezone.utc),
        "principal": principal,
        "tier": tier,
        "tool": tool,
        "args": json.dumps(args, default=str, sort_keys=True),
        "data_classes": list(data_classes),
        "decision": decision,
        "row_count": int(row_count),
        "error": str(error or ""),
    }


class Auditor:
    """Wraps a row-insert callable, swallowing (and logging) insert failures."""

    def __init__(self, insert: Callable[[dict], None]):
        self._insert = insert

    def record(self, **fields: Any) -> None:
        """Build and insert one audit row; never raises."""
        row = build_audit_row(**fields)
        try:
            self._insert(row)
        except Exception as exc:  # best-effort: audit must not block a tool call
            print(f"[audit] insert failed: {exc}", file=sys.stderr)


def _noop_insert(_row: dict) -> None:
    return None


def make_ch_auditor(config) -> Auditor:
    """Build a CH-backed Auditor, or a no-op one when no audit password is set."""
    if not config.ch_audit_password:
        print("[audit] CH_AUDIT_PASSWORD unset; audit disabled (no-op)", file=sys.stderr)
        return Auditor(_noop_insert)
    import clickhouse_connect

    client = clickhouse_connect.get_client(
        host=config.ch_host,
        port=config.ch_port,
        username=config.ch_audit_user,
        password=config.ch_audit_password,
        database=config.ch_database,
    )

    def insert(row: dict) -> None:
        client.insert(
            "ssdf.audit",
            [[row[col] for col in AUDIT_COLUMNS]],
            column_names=AUDIT_COLUMNS,
        )

    return Auditor(insert)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd services/mcp-query && uv run pytest tests/test_audit.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add services/mcp-query/src/ssdf_mcp_query/audit.py services/mcp-query/tests/test_audit.py
git commit -m "feat(m7a): audit row builder + best-effort CH auditor"
```

---

## Task 5: ClickHouse audit schema + INSERT-only user

**Files:**
- Create: `infra/clickhouse/007_audit.sql`

- [ ] **Step 1: Write the schema file**

Create `infra/clickhouse/007_audit.sql`:

```sql
-- infra/clickhouse/007_audit.sql
-- M7a append-only audit of MCP tool calls + INSERT-only ssdf_audit user.
-- ClickHouse does NOT expand {name:Type} params inside CREATE USER ... BY '...',
-- so inject the password before applying (never commit the real value):
--   AUDIT_PW="$CH_AUDIT_PASSWORD" envsubst < 007_audit.sql \
--     | clickhouse-client --host <ct104> --multiquery
--
-- Schema reserves room for future hash-chained tamper-evidence (prev_hash/row_hash)
-- to be added without migrating existing rows (M7a does NOT build that).
CREATE TABLE IF NOT EXISTS ssdf.audit
(
    ts           DateTime64(3, 'UTC'),
    principal    LowCardinality(String),
    tier         LowCardinality(String),
    tool         LowCardinality(String),
    args         String,
    data_classes Array(LowCardinality(String)),
    decision     LowCardinality(String),
    row_count    UInt32,
    error        String
)
ENGINE = MergeTree
ORDER BY (ts, principal)
TTL toDateTime(ts) + INTERVAL 90 DAY;

-- INSERT-only writer. Deliberately no SELECT grant: the query identity (ssdf_ro)
-- cannot read or edit the trail, and ssdf_audit cannot read what it wrote.
CREATE USER IF NOT EXISTS ssdf_audit IDENTIFIED WITH sha256_password BY '${AUDIT_PW}';
GRANT INSERT ON ssdf.audit TO ssdf_audit;
```

- [ ] **Step 2: Validate the SQL parses (dry, no live CH)**

Run: `cd services/mcp-query && AUDIT_PW=dummy envsubst < ../../infra/clickhouse/007_audit.sql | head -40`
Expected: the rendered SQL prints with `${AUDIT_PW}` replaced by `dummy` and no `envsubst` error. (No live apply here — that is the integration task / deploy.)

- [ ] **Step 3: Commit**

```bash
git add infra/clickhouse/007_audit.sql
git commit -m "feat(m7a): ssdf.audit table + INSERT-only ssdf_audit user"
```

---

## Task 6: Per-tool wrapper + server wiring

**Files:**
- Create: `services/mcp-query/src/ssdf_mcp_query/wrapper.py`
- Modify: `services/mcp-query/src/ssdf_mcp_query/server.py`
- Test: `services/mcp-query/tests/test_wrapper.py`, `services/mcp-query/tests/test_server_audit.py`

- [ ] **Step 1: Write the failing wrapper test**

Create `services/mcp-query/tests/test_wrapper.py`:

```python
from ssdf_mcp_query.wrapper import audited_tool, row_count_of
from ssdf_mcp_query.audit import Auditor


class _Recorder:
    def __init__(self):
        self.calls = []

    def record(self, **fields):
        self.calls.append(fields)


def test_row_count_from_row_count_field():
    assert row_count_of({"row_count": 5, "rows": [1, 2]}) == 5


def test_row_count_from_rows_len():
    assert row_count_of({"rows": [1, 2, 3]}) == 3


def test_row_count_default_zero():
    assert row_count_of({"error": "x"}) == 0
    assert row_count_of("not-a-dict") == 0


def test_allowed_tool_runs_and_audits_allow():
    rec = _Recorder()
    fn = lambda dst_port=None: {"rows": [1, 2], "row_count": 2}
    wrapped = audited_tool("query_flows", fn, rec, caller=lambda: ("p", None))
    assert wrapped(dst_port=443) == {"rows": [1, 2], "row_count": 2}
    assert len(rec.calls) == 1
    call = rec.calls[0]
    assert call["decision"] == "allow"
    assert call["tool"] == "query_flows"
    assert call["principal"] == "p"
    assert call["data_classes"] == ["security_log"]
    assert call["row_count"] == 2
    assert call["args"] == {"dst_port": 443}


def test_disallowed_tool_denied_and_not_invoked():
    rec = _Recorder()
    invoked = {"hit": False}

    def fn(**kwargs):
        invoked["hit"] = True
        return {"rows": []}

    wrapped = audited_tool(
        "run_sql", fn, rec, caller=lambda: ("p", frozenset({"query_flows"})))
    result = wrapped(query="SELECT 1")
    assert result["error"] == "forbidden"
    assert invoked["hit"] is False
    assert rec.calls[0]["decision"] == "deny"
    assert rec.calls[0]["row_count"] == 0


def test_tool_error_result_audits_allow_with_error():
    rec = _Recorder()
    fn = lambda query=None: {"error": "bad_sql", "detail": "nope"}
    wrapped = audited_tool("run_sql", fn, rec, caller=lambda: ("p", None))
    result = wrapped(query="DROP")
    assert result["error"] == "bad_sql"
    assert rec.calls[0]["decision"] == "allow"
    assert rec.calls[0]["error"] == "bad_sql"
    assert rec.calls[0]["row_count"] == 0


def test_audit_write_failure_does_not_break_tool():
    def boom(_row):
        raise RuntimeError("ch down")

    fn = lambda: {"rows": [1]}
    wrapped = audited_tool("describe_schema", fn, Auditor(boom),
                           caller=lambda: ("p", None))
    assert wrapped() == {"rows": [1]}  # tool result still returned


def test_wrapped_preserves_signature_and_doc():
    import inspect

    def query_flows(dst_port: int | None = None) -> dict:
        """Real docstring."""
        return {"rows": []}

    wrapped = audited_tool("query_flows", query_flows, _Recorder(),
                           caller=lambda: ("p", None))
    assert wrapped.__doc__ == "Real docstring."
    assert list(inspect.signature(wrapped).parameters) == ["dst_port"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd services/mcp-query && uv run pytest tests/test_wrapper.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'ssdf_mcp_query.wrapper'`.

- [ ] **Step 3: Write the wrapper implementation**

Create `services/mcp-query/src/ssdf_mcp_query/wrapper.py`:

```python
"""Per-tool authz + audit wrapper (M7a).

Wraps each registered tool so that, per call: (1) the caller principal +
allowed_tools are resolved, (2) per-tool authorization is enforced (deny ->
structured ``{"error": "forbidden"}``, audited), (3) the underlying tool runs
unchanged, (4) one audit row is recorded. ``functools.wraps`` preserves the
tool's signature + docstring so FastMCP builds the correct schema.
"""

from __future__ import annotations

import functools
from typing import Any, Callable

from .auth import current_caller
from .classification import classes_for_tool


def row_count_of(result: Any) -> int:
    """Best-effort row count: explicit ``row_count``, else ``len(rows)``, else 0."""
    if isinstance(result, dict):
        explicit = result.get("row_count")
        if isinstance(explicit, int):
            return explicit
        rows = result.get("rows")
        if isinstance(rows, list):
            return len(rows)
    return 0


def audited_tool(
    tool_name: str,
    fn: Callable[..., Any],
    auditor: Any,
    *,
    tier: str = "sovereign",
    caller: Callable[[], tuple[str, frozenset[str] | None]] = current_caller,
) -> Callable[..., Any]:
    """Return ``fn`` wrapped with per-call authz + audit for ``tool_name``."""
    data_classes = sorted(classes_for_tool(tool_name))

    @functools.wraps(fn)
    def wrapped(*args: Any, **kwargs: Any) -> Any:
        principal, allowed = caller()
        if allowed is not None and tool_name not in allowed:
            auditor.record(
                principal=principal, tier=tier, tool=tool_name, args=kwargs,
                data_classes=data_classes, decision="deny", row_count=0,
                error="forbidden",
            )
            return {
                "error": "forbidden",
                "detail": f"tool '{tool_name}' not permitted for principal '{principal}'",
            }
        result = fn(*args, **kwargs)
        error = result.get("error", "") if isinstance(result, dict) else ""
        auditor.record(
            principal=principal, tier=tier, tool=tool_name, args=kwargs,
            data_classes=data_classes, decision="allow",
            row_count=row_count_of(result), error=error,
        )
        return result

    return wrapped
```

- [ ] **Step 4: Run wrapper test to verify it passes**

Run: `cd services/mcp-query && uv run pytest tests/test_wrapper.py -q`
Expected: PASS.

- [ ] **Step 5: Write the failing server test**

Create `services/mcp-query/tests/test_server_audit.py`:

```python
import asyncio
import json
import os

os.environ.setdefault("CH_PASSWORD", "x")
os.environ.setdefault("MCP_AUTH_TOKEN", "t")

EXPECTED_TOOLS = {
    "query_flows", "describe_schema", "top_talkers", "run_sql", "get_entity",
    "locate", "neighbors", "find_path", "enforcement_points",
    "topology_snapshot", "explain_access",
}


def _names(app):
    return {t.name for t in asyncio.run(app.list_tools())}


def _patch_ch(monkeypatch, server):
    class _Dummy:
        def __init__(self, *a, **k):
            pass

    monkeypatch.setattr(server, "ClickHouseClient", _Dummy)
    monkeypatch.setattr(server, "make_ch_auditor",
                        lambda config: server.Auditor(lambda row: None))


def test_all_tools_registered_single_token(monkeypatch):
    import ssdf_mcp_query.server as server
    _patch_ch(monkeypatch, server)
    app = server.build_app()
    assert _names(app) == EXPECTED_TOOLS


def test_multi_principal_tokens_register(monkeypatch, tmp_path):
    import ssdf_mcp_query.server as server
    f = tmp_path / "tokens.json"
    f.write_text(json.dumps({
        "tok-a": {"principal": "triage-agent", "allowed_tools": ["query_flows"]},
        "tok-b": {"principal": "admin-agent"},
    }))
    monkeypatch.setenv("MCP_TOKENS_FILE", str(f))
    _patch_ch(monkeypatch, server)
    app = server.build_app()
    assert _names(app) == EXPECTED_TOOLS
```

- [ ] **Step 6: Run server test to verify it fails**

Run: `cd services/mcp-query && uv run pytest tests/test_server_audit.py -q`
Expected: FAIL — `AttributeError: module 'ssdf_mcp_query.server' has no attribute 'make_ch_auditor'` (and `Auditor`), because `server.py` does not yet import them.

- [ ] **Step 7: Rewrite `server.py` to wire classification, auditor, multi-principal auth, and the wrapper**

Replace the entire contents of `services/mcp-query/src/ssdf_mcp_query/server.py` with:

```python
# src/ssdf_mcp_query/server.py
"""FastMCP streamable-HTTP server exposing the read-only query tools.

M7a: every tool is registered through ``audited_tool`` so each call is
authorized (per-principal ``allowed_tools``) and recorded to ``ssdf.audit``.
"""

from __future__ import annotations

from fastmcp import FastMCP
from fastmcp.server.auth import StaticTokenVerifier

from .config import load_config
from .classification import load_classification
from .audit import Auditor, make_ch_auditor
from .wrapper import audited_tool
from .clickhouse import ClickHouseClient
from .tools import Tools
from .graphstore import ClickHouseGraphStore
from .topo_tools import TopoTools
from .entitystore import ClickHouseEntityStore
from .access_tools import AccessTools


def build_app() -> FastMCP:
    config = load_config()
    load_classification()  # fail closed on invalid classification config
    auditor = make_ch_auditor(config)

    client = ClickHouseClient(config)
    tools = Tools(client)
    graph_store = ClickHouseGraphStore(client, tenant="t_main")
    topo = TopoTools(graph_store)
    entity_store = ClickHouseEntityStore(client, tenant="t_main")
    access = AccessTools(entity_store, topo)

    verifier_tokens: dict[str, dict] = {}
    for token, tp in config.tokens.items():
        payload = {
            "sub": tp.principal,
            "client_id": "ssdf",
            "tier": "sovereign",
            "principal": tp.principal,
        }
        if tp.allowed_tools is not None:
            payload["allowed_tools"] = sorted(tp.allowed_tools)
        verifier_tokens[token] = payload
    auth = StaticTokenVerifier(tokens=verifier_tokens)
    mcp = FastMCP("ssdf-mcp-query", auth=auth)

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

    def describe_schema() -> dict:
        """Return ssdf.events columns/types, distinct enum values, row count and time range."""
        return tools.describe_schema()

    def top_talkers(by: str = "bytes", side: str = "src", since: str | None = None,
                    until: str | None = None, limit: int = 10) -> dict:
        """Top source/destination IPs by bytes or flow count over a time window."""
        return tools.top_talkers(by=by, side=side, since=since, until=until, limit=limit)

    def run_sql(query: str) -> dict:
        """Run a guarded read-only SELECT against ssdf.* (single statement, enforced LIMIT)."""
        return tools.run_sql(query)

    def get_entity(identifier: str) -> dict:
        """Resolve a canonical entity (host/device/identity) from any alias: ip, mac, hostname, or name."""
        return topo.get_entity(identifier)

    def locate(identifier: str) -> dict:
        """Where does an entity attach? Returns switch/AP (or hypervisor bridge), port, and VLAN."""
        return topo.locate(identifier)

    def neighbors(identifier: str, layer: str | None = None, depth: int = 1,
                  since_hours: int | None = None) -> dict:
        """Adjacent nodes/edges around an entity, optionally filtered by layer (l2|l3|flow|virt)."""
        return topo.neighbors(identifier, layer=layer, depth=depth, since_hours=since_hours)

    def find_path(src: str, dst: str, layer: str = "any") -> dict:
        """Shortest path between two entities. layer: 'physical' (l1/l2), 'flow' (l3/flow), or 'any'."""
        return topo.find_path(src, dst, layer=layer)

    def enforcement_points(src: str, dst: str) -> dict:
        """Read-only: firewall device(s), zone(s), and rule(s) governing traffic between two entities."""
        return topo.enforcement_points(src, dst)

    def topology_snapshot(layer: str | None = None, since_hours: int | None = None) -> dict:
        """Bounded nodes+edges subgraph for visualization/LLM context; reports truncation."""
        return topo.topology_snapshot(layer=layer, since_hours=since_hours)

    def explain_access(client: str, server: str, since_hours: int | None = None) -> dict:
        """End-to-end view: observed flows + observed controls + CONFIGURED rules (from each
        firewall's ruleset) + topology path between a client and a server. Accepts ip/mac/name.
        `configured_controls` lists rules on the path firewalls (no match-scoring); `coverage`
        reports observed (bool) and configured (rule count). Firewall attribution is from
        topology; `configured_basis` flags no_path_firewall / firewall_name_unmatched."""
        return access.explain_access(client, server, since_hours=since_hours)

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
        "explain_access": explain_access,
    }
    for name, fn in raw_tools.items():
        mcp.tool(name=name)(audited_tool(name, fn, auditor))

    return mcp


def main() -> None:
    config = load_config()
    app = build_app()
    app.run(transport="http", host=config.mcp_bind, port=config.mcp_port)


if __name__ == "__main__":
    main()
```

- [ ] **Step 8: Run the server tests to verify they pass**

Run: `cd services/mcp-query && uv run pytest tests/test_server_audit.py tests/test_server_entity.py tests/test_server_topo.py -q`
Expected: PASS. (The pre-existing `test_server_entity.py`/`test_server_topo.py` register tools through the new wrapper but the tool names are unchanged, so they still pass.)

- [ ] **Step 9: Run the full unit suite to verify no regressions**

Run: `cd services/mcp-query && uv run pytest -m "not integration" -q`
Expected: PASS — all prior tests plus the new ones. If `test_server_entity.py`/`test_server_topo.py` fail because they don't stub `make_ch_auditor`, add the same `monkeypatch.setattr(server, "make_ch_auditor", lambda config: ...)` they need — but they pass `CH_PASSWORD`/`MCP_AUTH_TOKEN` and stub only `ClickHouseClient`; `make_ch_auditor` returns a no-op Auditor when `CH_AUDIT_PASSWORD` is unset, so no CH connection is attempted. Confirm green.

- [ ] **Step 10: Commit**

```bash
git add services/mcp-query/src/ssdf_mcp_query/wrapper.py services/mcp-query/src/ssdf_mcp_query/server.py services/mcp-query/tests/test_wrapper.py services/mcp-query/tests/test_server_audit.py
git commit -m "feat(m7a): per-tool authz+audit wrapper + multi-principal server wiring"
```

---

## Task 7: Example config files

**Files:**
- Create: `services/mcp-query/infra/tokens.example.json`
- Create: `services/mcp-query/infra/classification.example.json`

- [ ] **Step 1: Create the token-map example**

Create `services/mcp-query/infra/tokens.example.json`:

```json
{
  "REPLACE_WITH_TRIAGE_TOKEN": {
    "principal": "triage-agent",
    "allowed_tools": ["query_flows", "top_talkers", "explain_access"]
  },
  "REPLACE_WITH_ADMIN_TOKEN": {
    "principal": "admin-agent"
  }
}
```

- [ ] **Step 2: Create the classification example**

Create `services/mcp-query/infra/classification.example.json`:

```json
{
  "topology": "shareable",
  "identity": "sovereign"
}
```

- [ ] **Step 3: Verify the examples are valid JSON**

Run: `cd services/mcp-query && python -c "import json,sys; [json.load(open(p)) for p in ['infra/tokens.example.json','infra/classification.example.json']]; print('ok')"`
Expected: prints `ok`.

- [ ] **Step 4: Commit**

```bash
git add services/mcp-query/infra/tokens.example.json services/mcp-query/infra/classification.example.json
git commit -m "docs(m7a): example token-map + classification config"
```

---

## Task 8: Live integration test (marked `integration`)

**Files:**
- Create: `services/mcp-query/tests/test_audit_integration.py`

> This test needs a live ClickHouse with `007_audit.sql` applied and the
> `ssdf_audit` password available. It is excluded from the default unit run by
> the `integration` marker (existing project convention).

- [ ] **Step 1: Write the integration test**

Create `services/mcp-query/tests/test_audit_integration.py`:

```python
import os
import time
import uuid
import pytest
import clickhouse_connect

pytestmark = pytest.mark.integration

CH_HOST = os.environ.get("CH_HOST")
AUDIT_PW = os.environ.get("CH_AUDIT_PASSWORD")
RO_PW = os.environ.get("CH_PASSWORD")


def _audit_client():
    return clickhouse_connect.get_client(
        host=CH_HOST, port=int(os.environ.get("CH_PORT", "8123")),
        username=os.environ.get("CH_AUDIT_USER", "ssdf_audit"),
        password=AUDIT_PW, database="ssdf",
    )


@pytest.mark.skipif(not (CH_HOST and AUDIT_PW), reason="needs live CH + ssdf_audit pw")
def test_audit_row_inserts_and_round_trips():
    from ssdf_mcp_query.audit import make_ch_auditor
    from ssdf_mcp_query.config import load_config

    principal = f"itest-{uuid.uuid4().hex[:8]}"
    auditor = make_ch_auditor(load_config())
    auditor.record(
        principal=principal, tier="sovereign", tool="query_flows",
        args={"dst_port": 443}, data_classes=["security_log"],
        decision="allow", row_count=3, error="",
    )
    time.sleep(0.5)
    # Read back as an admin/ro path that CAN select (ssdf_ro has no audit grant,
    # so use a privileged client via CH_ADMIN_* if provided; else skip read-back).
    admin_pw = os.environ.get("CH_ADMIN_PASSWORD")
    if not admin_pw:
        pytest.skip("set CH_ADMIN_PASSWORD to verify read-back")
    admin = clickhouse_connect.get_client(
        host=CH_HOST, port=int(os.environ.get("CH_PORT", "8123")),
        username=os.environ.get("CH_ADMIN_USER", "default"),
        password=admin_pw, database="ssdf",
    )
    rows = admin.query(
        "SELECT tool, decision, row_count, data_classes FROM ssdf.audit "
        "WHERE principal = {p:String} ORDER BY ts DESC LIMIT 1",
        parameters={"p": principal},
    ).result_rows
    assert rows, "audit row not found"
    tool, decision, row_count, data_classes = rows[0]
    assert tool == "query_flows"
    assert decision == "allow"
    assert row_count == 3
    assert list(data_classes) == ["security_log"]


@pytest.mark.skipif(not (CH_HOST and AUDIT_PW), reason="needs live CH + ssdf_audit pw")
def test_ssdf_audit_cannot_select():
    from clickhouse_connect.driver.exceptions import DatabaseError

    client = _audit_client()
    with pytest.raises(DatabaseError):
        client.query("SELECT count() FROM ssdf.audit")
```

- [ ] **Step 2: Verify the test is collected but deselected in the default run**

Run: `cd services/mcp-query && uv run pytest -m "not integration" -q tests/test_audit_integration.py`
Expected: `no tests ran` / deselected (the `integration` marker excludes it).

- [ ] **Step 3: Commit**

```bash
git add services/mcp-query/tests/test_audit_integration.py
git commit -m "test(m7a): live audit insert + ssdf_audit SELECT-denial integration"
```

---

## Task 9: Documentation

**Files:**
- Modify: `CLAUDE.md`
- Modify: `docs/superpowers/STATUS.md`

- [ ] **Step 1: Add the M7a Commands subsection to `CLAUDE.md`**

In `CLAUDE.md`, immediately after the `### M6c scope B (...)` block (the last sub-section before the `Future Rust/Python components...` line), insert:

```markdown
### M7a (classification + multi-principal auth + audit — ssdf-mcp-query hardening)
- Unit tests: `cd services/mcp-query && uv run pytest -m "not integration"` (adds classification/auth/audit/wrapper/server-audit suites).
- Live audit integration: `cd services/mcp-query && CH_HOST=<ip> CH_PASSWORD=<ro_pw> CH_AUDIT_PASSWORD=<audit_pw> [CH_ADMIN_PASSWORD=<pw>] uv run pytest -m integration`.
- Apply audit schema + user: `AUDIT_PW="$CH_AUDIT_PASSWORD" envsubst < infra/clickhouse/007_audit.sql | clickhouse-client --host <ct104> --multiquery` (creates `ssdf.audit` + INSERT-only `ssdf_audit`; pattern mirrors `005_entity_user.sql`).
- **Multi-principal auth:** set `MCP_TOKENS_FILE` (JSON `{ "<token>": {"principal": "...", "allowed_tools": [...]} }`; omit `allowed_tools` ⇒ all tools). Leaving it unset keeps the single-token path (`MCP_AUTH_TOKEN`/`MCP_TOKEN_FILE`) mapped to principal `agent`/all-tools — existing ct106 deploy works unchanged. Example: `services/mcp-query/infra/tokens.example.json`.
- **Classification:** secure-by-default; only `topology`/`identity` are configurable to `shareable` via `MCP_CLASSIFICATION_FILE`. Overriding `security_log`/`firewall_config`, an unknown class, or a bad value ⇒ `ConfigError` at startup (fail closed). M7a only *labels*+*audits* — it never withholds data (that is M7b). Example: `services/mcp-query/infra/classification.example.json`.
- **Audit path:** every tool call writes one `ssdf.audit` row (ts, principal, tier=`sovereign`, tool, args-JSON, data_classes, decision allow|deny, row_count, error) as the `ssdf_audit` user on a connection SEPARATE from the `ssdf_ro` query path. Audit is best-effort — an insert failure is logged to stderr but never fails the tool call. A disallowed tool returns `{"error":"forbidden"}` (HTTP 200) and audits `decision="deny"` without invoking the tool. `CH_AUDIT_PASSWORD` unset ⇒ no-op auditor (server still runs).
- **Per-tool wrapper:** `wrapper.audited_tool` wraps each tool with `functools.wraps`, so FastMCP's schema (built via `get_type_hints`+`inspect.signature`) still sees the real tool signature/docstring. Tool return shapes are unchanged (agents already bind to them).
- ct106 is an editable install at `/opt/src/mcp-query/src` — sync source + `systemctl restart ssdf-mcp-query.service`; add `MCP_TOKENS_FILE`/`MCP_CLASSIFICATION_FILE`/`CH_AUDIT_USER`/`CH_AUDIT_PASSWORD` to `/etc/ssdf-mcp/…` (mode 600).
- **Hands to M7b:** `classification.py` (taxonomy+map), `audit.py`+`ssdf.audit` (public process writes `tier="public"`), and the token-map auth pattern. Classes flagged `shareable` drive M7b's shareable views + `ssdf_public` grants.
```

- [ ] **Step 2: Record M7a in `docs/superpowers/STATUS.md`**

Read `docs/superpowers/STATUS.md` first to match its existing format, then add an M7a entry consistent with the M6c entries: built modules (`classification.py`, `auth.py`, `audit.py`, `wrapper.py`), the `ssdf.audit` table + `ssdf_audit` user, multi-principal token map with single-token backward-compat, secure-by-default classification (fail-closed), and best-effort audit. Mark deploy/live-proof as pending the ct106 sync + `007_audit.sql` apply (this plan does not deploy).

- [ ] **Step 3: Commit**

```bash
git add CLAUDE.md docs/superpowers/STATUS.md
git commit -m "docs(m7a): commands + status for classification/auth/audit"
```

---

## Final verification

- [ ] **Run the full unit suite once more**

Run: `cd services/mcp-query && uv run pytest -m "not integration" -q`
Expected: all green (81 pre-existing + new classification/auth/audit/wrapper/server-audit tests).

- [ ] **Confirm no stray `auth_token` references remain**

Run: `cd services/mcp-query && grep -rn "auth_token" src tests | grep -v __pycache__ || echo "clean"`
Expected: `clean`.

---

## Self-Review notes (author)

- **Spec coverage:** classification taxonomy + loader (Task 1), tool→class map (Task 1), multi-principal token map + single-token fallback (Task 2), per-tool authz + structured `forbidden` (Task 6), `ssdf.audit` schema + INSERT-only user + no SELECT for `ssdf_ro`/`ssdf_audit` (Task 5), best-effort auditor (Task 4), per-tool wrapper with unchanged return shapes (Task 6), fail-closed startup on bad classification/missing tokens (Tasks 1,2,6), args-verbatim recording (Task 4), live integration proof (Task 8), deploy mechanics in docs (Task 9). Non-goals (M7b public process, shareable views, redaction, hash-chain, LLM egress) are intentionally absent.
- **Type consistency:** `Config.tokens: dict[str, TokenPrincipal]`; `TokenPrincipal.allowed_tools: frozenset|None`; `classes_for_tool -> frozenset`; `Auditor.record(**fields)` matches `build_audit_row` kwargs and `AUDIT_COLUMNS` order matches `007_audit.sql` column order. `audited_tool(tool_name, fn, auditor, *, tier, caller)` signature is identical across Task 6 impl, tests, and server wiring.
- **Placeholders:** none — every code step is complete; the only prose-only step is STATUS.md (Task 9 Step 2), which intentionally defers to the file's existing format.
