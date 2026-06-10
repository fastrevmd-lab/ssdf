# SSDF P1 In-Place Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close five Medium security findings (M1, M3, M4, M5, M6) by hardening existing SSDF services and deploy artifacts in place — no new components.

**Architecture:** Each finding is an independent commit (TDD). M1/M3/M6 touch `services/mcp-query`; M4 touches the two `services/{topo,policy}` PAN-OS collectors; M5 edits five systemd unit files. M3 adds a per-tier, in-process audit hash chain plus an offline verifier; the writer stays INSERT-only and the hot insert path stays read-free.

**Tech Stack:** Python 3.11 (`uv`/pytest, `clickhouse_connect`, `fastmcp`), ClickHouse SQL migrations, systemd unit files, `defusedxml`.

**Spec:** `docs/superpowers/specs/2026-06-10-ssdf-p1-inplace-hardening-design.md`

**Conventions (verified):**
- mcp-query tests run: `cd services/mcp-query && uv run pytest -m "not integration" -q`
- topo tests run: `cd services/topo && uv run pytest -m "not integration" -q`
- policy tests run: `cd services/policy && uv run pytest -m "not integration" -q`
- All three services use `tests/` + an `integration` pytest marker; mcp-query layout is `src/ssdf_mcp_query/`.
- Live deploys (M3 migration + service restarts, M5 unit redeploy) are **operator-gated** — do not apply to ct104/ct106/ct109/ct113 during implementation; they are noted at the end.

---

## File Structure

| File | Responsibility | Task |
|---|---|---|
| `services/mcp-query/src/ssdf_mcp_query/config.py` | + `max_result_rows`, `max_memory_usage`, `ch_audit_verify_password` fields | 1, 5 |
| `services/mcp-query/src/ssdf_mcp_query/clickhouse.py` | pass query `settings=` | 1 |
| `services/mcp-query/src/ssdf_mcp_query/tools.py` | scrub upstream error text + correlation id | 2 |
| `services/topo/src/ssdf_topo/collectors/panos.py` | parse via defusedxml | 3 |
| `services/policy/src/ssdf_policy/collectors/panos.py` | parse via defusedxml | 3 |
| `services/{topo,policy}/pyproject.toml` | + `defusedxml` dep | 3 |
| `services/mcp-query/src/ssdf_mcp_query/audit_chain.py` | **new** — pure hashing/canonical fns | 4 |
| `services/mcp-query/src/ssdf_mcp_query/audit.py` | chain advance in `Auditor`, seeded `make_ch_auditor(config, tier)` | 5 |
| `services/mcp-query/src/ssdf_mcp_query/server.py` | pass `tier` to `make_ch_auditor` | 5 |
| `infra/clickhouse/009_audit_hash_chain.sql` | **new** — add hash cols + `ssdf_audit_verify` | 6 |
| `services/mcp-query/src/ssdf_mcp_query/verify_audit.py` | **new** — offline chain verifier CLI | 7 |
| `services/mcp-query/infra/ssdf-mcp-query.service` + `ssdf-mcp-public.service` | systemd hardening | 8 |
| `services/{topo,entity,policy}/infra/ssdf-*.service` | systemd hardening | 8 |

---

## Task 1: M1 — Wire query limits

**Files:**
- Modify: `services/mcp-query/src/ssdf_mcp_query/config.py` (Config dataclass + `load_config`)
- Modify: `services/mcp-query/src/ssdf_mcp_query/clickhouse.py` (`ClickHouseClient.run`)
- Test: `services/mcp-query/tests/test_clickhouse.py`, `services/mcp-query/tests/test_config.py`

- [ ] **Step 1: Write the failing test** — append to `services/mcp-query/tests/test_clickhouse.py`:

```python
from ssdf_mcp_query.clickhouse import ClickHouseClient
from ssdf_mcp_query.config import Config


class _FakeResult:
    column_names = ["x"]
    result_rows = [[1]]


class _FakeClient:
    def __init__(self):
        self.calls = []

    def query(self, sql, parameters=None, settings=None):
        self.calls.append({"sql": sql, "parameters": parameters, "settings": settings})
        return _FakeResult()


def _config(**over):
    base = dict(
        ch_host="h", ch_port=8123, ch_user="u", ch_password="p", ch_database="ssdf",
        mcp_bind="0.0.0.0", mcp_port=30032, tokens={},
        max_execution_time=7, max_result_rows=222, max_memory_usage=333,
    )
    base.update(over)
    return Config(**base)


def test_run_passes_query_settings(monkeypatch):
    fake = _FakeClient()
    monkeypatch.setattr(
        "ssdf_mcp_query.clickhouse.clickhouse_connect.get_client",
        lambda **kw: fake,
    )
    client = ClickHouseClient(_config())
    client.run("SELECT 1")
    settings = fake.calls[0]["settings"]
    assert settings["max_execution_time"] == 7
    assert settings["max_result_rows"] == 222
    assert settings["max_memory_usage"] == 333
    assert settings["result_overflow_mode"] == "throw"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd services/mcp-query && uv run pytest tests/test_clickhouse.py::test_run_passes_query_settings -q`
Expected: FAIL — `TypeError` on `Config(... max_result_rows=...)` (unknown field) or `settings` is `None`.

- [ ] **Step 3: Add the two config fields** — in `services/mcp-query/src/ssdf_mcp_query/config.py`, in the `Config` dataclass add after `max_execution_time: int = 10`:

```python
    max_result_rows: int = 100000
    max_memory_usage: int = 1_000_000_000
```

And in `load_config()`'s `return Config(...)`, add after `max_execution_time=int(os.environ.get("MCP_MAX_EXEC_SECS", "10")),`:

```python
        max_result_rows=int(os.environ.get("MCP_MAX_RESULT_ROWS", "100000")),
        max_memory_usage=int(os.environ.get("MCP_MAX_MEMORY_BYTES", "1000000000")),
```

- [ ] **Step 4: Pass settings in the query** — in `services/mcp-query/src/ssdf_mcp_query/clickhouse.py`, replace the body of `run` (line 45):

```python
        result = self._client.query(
            sql,
            parameters=params or {},
            settings={
                "max_execution_time": self._config.max_execution_time,
                "max_result_rows": self._config.max_result_rows,
                "max_memory_usage": self._config.max_memory_usage,
                "result_overflow_mode": "throw",
            },
        )
```

- [ ] **Step 5: Add a config env test** — append to `services/mcp-query/tests/test_config.py`:

```python
def test_load_config_reads_query_limit_envs(monkeypatch):
    from ssdf_mcp_query.config import load_config
    monkeypatch.setenv("CH_PASSWORD", "x")
    monkeypatch.setenv("MCP_AUTH_TOKEN", "t")
    monkeypatch.setenv("MCP_MAX_RESULT_ROWS", "5")
    monkeypatch.setenv("MCP_MAX_MEMORY_BYTES", "9")
    cfg = load_config()
    assert cfg.max_result_rows == 5
    assert cfg.max_memory_usage == 9


def test_load_config_query_limit_defaults(monkeypatch):
    from ssdf_mcp_query.config import load_config
    monkeypatch.setenv("CH_PASSWORD", "x")
    monkeypatch.setenv("MCP_AUTH_TOKEN", "t")
    monkeypatch.delenv("MCP_MAX_RESULT_ROWS", raising=False)
    monkeypatch.delenv("MCP_MAX_MEMORY_BYTES", raising=False)
    cfg = load_config()
    assert cfg.max_result_rows == 100000
    assert cfg.max_memory_usage == 1_000_000_000
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd services/mcp-query && uv run pytest -m "not integration" -q`
Expected: PASS (all, including the new tests).

- [ ] **Step 7: Commit**

```bash
git add services/mcp-query/src/ssdf_mcp_query/config.py \
        services/mcp-query/src/ssdf_mcp_query/clickhouse.py \
        services/mcp-query/tests/test_clickhouse.py \
        services/mcp-query/tests/test_config.py
git commit -m "fix(m1): wire CH query timeout + result-row + memory caps"
```

---

## Task 2: M6 — Scrub upstream error text

**Files:**
- Modify: `services/mcp-query/src/ssdf_mcp_query/tools.py` (the two `upstream` handlers at lines 88 and 101; add a logger)
- Test: `services/mcp-query/tests/test_tools.py`

- [ ] **Step 1: Write the failing test** — append to `services/mcp-query/tests/test_tools.py`:

```python
import re
from ssdf_mcp_query.tools import Tools


class _BoomClient:
    def run(self, sql, params=None):
        raise RuntimeError("CH internal: column observer_hostname on host 198.51.100.151")


def test_safe_execute_scrubs_upstream_detail():
    out = Tools(_BoomClient()).query_flows(dst_port=443)
    assert out["error"] == "upstream"
    assert out["detail"] == "query failed"
    assert re.fullmatch(r"[0-9a-f]{32}", out["correlation_id"])
    # Internal text must not leak anywhere in the response.
    blob = str(out)
    assert "198.51.100.151" not in blob
    assert "observer_hostname" not in blob


def test_describe_schema_scrubs_upstream_detail():
    out = Tools(_BoomClient()).describe_schema()
    assert out["error"] == "upstream"
    assert out["detail"] == "query failed"
    assert re.fullmatch(r"[0-9a-f]{32}", out["correlation_id"])
    assert "198.51.100.151" not in str(out)


def test_validation_error_detail_is_preserved():
    # A bad time string is a caller-input (validation) error — must stay helpful.
    out = Tools(_BoomClient()).query_flows(since="not-a-time")
    assert out["error"] == "validation"
    assert out["detail"] != "query failed"
    assert "correlation_id" not in out
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd services/mcp-query && uv run pytest tests/test_tools.py::test_safe_execute_scrubs_upstream_detail tests/test_tools.py::test_describe_schema_scrubs_upstream_detail -q`
Expected: FAIL — current handler returns `detail=str(exc)` (leaks the internal text; no `correlation_id`).

- [ ] **Step 3: Add a logger + uuid import** — in `services/mcp-query/src/ssdf_mcp_query/tools.py`, replace the top imports block (lines 4-11) so it reads:

```python
from __future__ import annotations

import logging
import time
import uuid
from typing import Any

from .builders import build_query_flows, build_top_talkers, BuilderError, MAX_LIMIT
from .sql_guard import guard_sql, GuardError
from .timeparse import TimeParseError

logger = logging.getLogger("ssdf_mcp_query.tools")
```

- [ ] **Step 4: Scrub both upstream handlers** — in the same file, replace the `describe_schema` handler (was line 87-88):

```python
        except Exception:  # noqa: BLE001 - surface as scrubbed upstream error
            cid = uuid.uuid4().hex
            logger.exception("describe_schema upstream error correlation_id=%s", cid)
            return {"error": "upstream", "detail": "query failed", "correlation_id": cid}
```

and the `_safe_execute` handler (was line 100-101):

```python
        except Exception:  # noqa: BLE001 - upstream/CH failures, scrubbed
            cid = uuid.uuid4().hex
            logger.exception("tool upstream error correlation_id=%s", cid)
            return {"error": "upstream", "detail": "query failed", "correlation_id": cid}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd services/mcp-query && uv run pytest -m "not integration" -q`
Expected: PASS (all).

- [ ] **Step 6: Commit**

```bash
git add services/mcp-query/src/ssdf_mcp_query/tools.py \
        services/mcp-query/tests/test_tools.py
git commit -m "fix(m6): scrub raw upstream error text; log server-side w/ correlation id"
```

---

## Task 3: M4 — defusedxml for vendor XML

**Files:**
- Modify: `services/topo/pyproject.toml`, `services/policy/pyproject.toml` (+ `defusedxml` dep)
- Modify: `services/topo/src/ssdf_topo/collectors/panos.py` (parse via defusedxml; keep stdlib for `tostring`)
- Modify: `services/policy/src/ssdf_policy/collectors/panos.py` (parse via defusedxml; drop stdlib import)
- Test: `services/topo/tests/test_collector_panos.py`, `services/policy/tests/test_panos_rules.py`

- [ ] **Step 1: Add the dependency to both services** — in `services/topo/pyproject.toml` and `services/policy/pyproject.toml`, change the `dependencies` list to add `"defusedxml>=0.7"`:

```toml
dependencies = [
    "clickhouse-connect>=0.8",
    "fastmcp>=2.0",
    "defusedxml>=0.7",
]
```

Then install it into each venv: `cd services/topo && uv sync` and `cd services/policy && uv sync` (or `uv pip install defusedxml` if the project uses a bare venv).

- [ ] **Step 2: Write the failing tests** — append to `services/topo/tests/test_collector_panos.py`:

```python
from ssdf_topo.collectors.panos import parse_arp_xml

_BILLION_LAUGHS = """<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<response><result><entry><ip>&lol3;</ip><mac>00:11:22:33:44:55</mac></entry></result></response>"""


def test_parse_arp_xml_rejects_entity_expansion():
    # defusedxml must refuse entity expansion; collector degrades to [] (no hang/OOM).
    assert parse_arp_xml(_BILLION_LAUGHS, "panosvm", "2026-06-10T00:00:00Z") == []
```

And append to `services/policy/tests/test_panos_rules.py`:

```python
from ssdf_policy.collectors.panos import _root

_BILLION_LAUGHS = """<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
]>
<response><result><rules><entry name="&lol2;"/></rules></response>"""


def test_root_rejects_entity_expansion():
    # defusedxml must refuse entity expansion; _root degrades to None.
    assert _root(_BILLION_LAUGHS) is None
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd services/topo && uv run pytest tests/test_collector_panos.py::test_parse_arp_xml_rejects_entity_expansion -q`
and `cd services/policy && uv run pytest tests/test_panos_rules.py::test_root_rejects_entity_expansion -q`
Expected: FAIL — stdlib `xml.etree` either expands the entity or raises a bare `ParseError` not caught the same way; in the topo case the assertion may fail because stdlib does not raise `EntitiesForbidden`.

- [ ] **Step 4: Swap the topo parser** — in `services/topo/src/ssdf_topo/collectors/panos.py`, change the import block (lines 6-7) to:

```python
import json
import xml.etree.ElementTree as ET  # serialization only (ET.tostring)
from defusedxml.ElementTree import fromstring as _xml_fromstring, ParseError as _XmlParseError
```

Then in `_entries`, replace the parse try/except (lines 26-29) with:

```python
    try:
        root = _xml_fromstring(xml_text)
    except (_XmlParseError, Exception):  # ParseError + defused EntitiesForbidden/DTDForbidden
        return []
```

(`ET.tostring` calls at lines 63/92 are unchanged — `defusedxml` does not provide serialization.)

- [ ] **Step 5: Swap the policy parser** — in `services/policy/src/ssdf_policy/collectors/panos.py`, replace the import line `import xml.etree.ElementTree as ET` (line 7) with:

```python
from defusedxml.ElementTree import fromstring as _xml_fromstring, ParseError as _XmlParseError
import xml.etree.ElementTree as ET  # type annotations only (ET.Element)
```

Then in `_root`, replace the parse try/except (lines 27-31) with:

```python
    try:
        return _xml_fromstring(xml_text)
    except (_XmlParseError, Exception) as exc:  # ParseError + defused entity/DTD errors
        logger.warning("panos: failed to parse config XML: %s", exc)
        return None
```

(The `ET.Element` type hints elsewhere in the file still resolve via the retained stdlib import.)

- [ ] **Step 6: Run tests to verify all pass**

Run: `cd services/topo && uv run pytest -m "not integration" -q` then `cd services/policy && uv run pytest -m "not integration" -q`
Expected: PASS (new entity-expansion tests + all existing parse-success tests).

- [ ] **Step 7: Commit**

```bash
git add services/topo/pyproject.toml services/policy/pyproject.toml \
        services/topo/src/ssdf_topo/collectors/panos.py \
        services/policy/src/ssdf_policy/collectors/panos.py \
        services/topo/tests/test_collector_panos.py \
        services/policy/tests/test_panos_rules.py
git commit -m "fix(m4): parse vendor PAN-OS XML with defusedxml (entity-expansion DoS)"
```

---

## Task 4: M3a — Pure hashing module

**Files:**
- Create: `services/mcp-query/src/ssdf_mcp_query/audit_chain.py`
- Test: `services/mcp-query/tests/test_audit_chain.py`

- [ ] **Step 1: Write the failing test** — create `services/mcp-query/tests/test_audit_chain.py`:

```python
import datetime as dt
from ssdf_mcp_query.audit_chain import ts_ms_iso, canonical, compute_row_hash


def _row(**over):
    base = dict(
        ts=dt.datetime(2026, 6, 10, 12, 0, 0, 123000, tzinfo=dt.timezone.utc),
        principal="agent", tier="sovereign", tool="locate", args='{"x":1}',
        data_classes=["topology"], decision="allow", row_count=1, error="",
    )
    base.update(over)
    return base


def test_ts_ms_iso_millisecond_precision():
    # Microseconds beyond ms are truncated so the hash matches a DateTime64(3) round-trip.
    ts = dt.datetime(2026, 6, 10, 12, 0, 0, 123999, tzinfo=dt.timezone.utc)
    assert ts_ms_iso(ts) == "2026-06-10T12:00:00.123Z"


def test_ts_ms_iso_assumes_utc_when_naive():
    ts = dt.datetime(2026, 6, 10, 12, 0, 0, 0)
    assert ts_ms_iso(ts) == "2026-06-10T12:00:00.000Z"


def test_canonical_is_deterministic():
    assert canonical(_row()) == canonical(_row())


def test_row_hash_changes_when_any_field_changes():
    base = compute_row_hash("", _row())
    assert compute_row_hash("", _row(tool="run_sql")) != base
    assert compute_row_hash("", _row(row_count=2)) != base
    assert compute_row_hash("prevX", _row()) != base  # prev_hash participates


def test_row_hash_is_sha256_hex():
    h = compute_row_hash("", _row())
    assert len(h) == 64 and all(c in "0123456789abcdef" for c in h)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd services/mcp-query && uv run pytest tests/test_audit_chain.py -q`
Expected: FAIL — `ModuleNotFoundError: ssdf_mcp_query.audit_chain`.

- [ ] **Step 3: Implement the module** — create `services/mcp-query/src/ssdf_mcp_query/audit_chain.py`:

```python
"""Pure helpers for the per-tier audit hash chain (M3).

No I/O. The same functions are used by the write path (audit.py) and the offline
verifier (verify_audit.py), so a chain written by one is reproducible by the other.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json


def ts_ms_iso(ts: _dt.datetime) -> str:
    """UTC ISO-8601 truncated to milliseconds, matching a ClickHouse DateTime64(3,'UTC')
    round-trip. Naive datetimes are assumed UTC."""
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=_dt.timezone.utc)
    ts = ts.astimezone(_dt.timezone.utc)
    return ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z"


def canonical(row: dict) -> str:
    """Deterministic serialization of a row's nine non-hash fields, in fixed order."""
    return json.dumps(
        [
            ts_ms_iso(row["ts"]),
            row["principal"],
            row["tier"],
            row["tool"],
            row["args"],
            list(row["data_classes"]),
            row["decision"],
            int(row["row_count"]),
            row["error"],
        ],
        separators=(",", ":"),
        ensure_ascii=False,
    )


def compute_row_hash(prev_hash: str, row: dict) -> str:
    """row_hash = SHA-256( prev_hash + '\\n' + canonical(row) ), hex digest."""
    return hashlib.sha256(
        (prev_hash + "\n" + canonical(row)).encode("utf-8")
    ).hexdigest()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd services/mcp-query && uv run pytest tests/test_audit_chain.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add services/mcp-query/src/ssdf_mcp_query/audit_chain.py \
        services/mcp-query/tests/test_audit_chain.py
git commit -m "feat(m3): pure audit-chain hashing helpers (canonical + row_hash)"
```

---

## Task 5: M3b — Chain advance in the Auditor

**Files:**
- Modify: `services/mcp-query/src/ssdf_mcp_query/audit.py` (`AUDIT_COLUMNS`, `Auditor`, `make_ch_auditor`)
- Modify: `services/mcp-query/src/ssdf_mcp_query/config.py` (+ `ch_audit_verify_password`)
- Modify: `services/mcp-query/src/ssdf_mcp_query/server.py` (pass `tier` into `make_ch_auditor`)
- Test: `services/mcp-query/tests/test_audit.py`

- [ ] **Step 1: Write the failing tests** — append to `services/mcp-query/tests/test_audit.py`:

```python
import threading
from ssdf_mcp_query.audit import AUDIT_BASE_COLUMNS
from ssdf_mcp_query.audit_chain import compute_row_hash


def test_audit_columns_extend_base_with_hash_cols():
    assert AUDIT_COLUMNS == AUDIT_BASE_COLUMNS + ["prev_hash", "row_hash"]


def test_build_audit_row_shapes_base_columns():
    row = build_audit_row(
        principal="p", tier="sovereign", tool="locate", args={},
        data_classes=["topology"], decision="allow", row_count=0, error="",
    )
    assert set(row) == set(AUDIT_BASE_COLUMNS)


def test_record_chains_hashes_across_calls():
    captured = []
    aud = Auditor(captured.append, last_hash="")
    common = dict(principal="p", tier="sovereign", data_classes=["topology"],
                  decision="allow", row_count=0, error="")
    aud.record(tool="a", args={}, **common)
    aud.record(tool="b", args={}, **common)
    assert captured[0]["prev_hash"] == ""
    assert captured[1]["prev_hash"] == captured[0]["row_hash"]
    # Each row_hash is reproducible from its own fields + prev_hash.
    assert captured[1]["row_hash"] == compute_row_hash(captured[1]["prev_hash"], captured[1])


def test_record_does_not_advance_chain_on_insert_failure():
    captured = []
    state = {"fail_next": False}

    def insert(row):
        if state["fail_next"]:
            raise RuntimeError("ch down")
        captured.append(row)

    aud = Auditor(insert, last_hash="")
    common = dict(principal="p", tier="sovereign", data_classes=["topology"],
                  decision="allow", row_count=0, error="")
    aud.record(tool="a", args={}, **common)          # lands
    first_hash = captured[0]["row_hash"]
    state["fail_next"] = True
    aud.record(tool="b", args={}, **common)          # insert fails, must not advance
    state["fail_next"] = False
    aud.record(tool="c", args={}, **common)          # lands, chains off 'a'
    assert captured[-1]["prev_hash"] == first_hash


def test_record_concurrent_calls_form_valid_chain():
    captured = []
    lock = threading.Lock()

    def insert(row):
        with lock:
            captured.append(row)

    aud = Auditor(insert, last_hash="")
    common = dict(principal="p", tier="sovereign", data_classes=["topology"],
                  decision="allow", row_count=0, error="")

    def worker(n):
        aud.record(tool=f"t{n}", args={}, **common)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    # Reconstruct the linked list: every prev_hash (except genesis) names a real row_hash.
    by_hash = {r["row_hash"]: r for r in captured}
    genesis = [r for r in captured if r["prev_hash"] == ""]
    assert len(genesis) == 1
    for r in captured:
        if r["prev_hash"] != "":
            assert r["prev_hash"] in by_hash
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd services/mcp-query && uv run pytest tests/test_audit.py -q`
Expected: FAIL — `AUDIT_BASE_COLUMNS` does not exist; `Auditor(...)` has no `last_hash` kwarg; rows lack `prev_hash`/`row_hash`.

- [ ] **Step 3: Rework `audit.py`** — replace the whole file `services/mcp-query/src/ssdf_mcp_query/audit.py` with:

```python
"""Append-only audit of MCP tool calls (M7a) with a per-tier hash chain (M3).

Best-effort by design: an audit write failure is logged to stderr and never fails
the tool call. Rows are inserted by a dedicated INSERT-only ``ssdf_audit`` CH user
on a connection separate from the ``ssdf_ro`` query path. Each row carries
``prev_hash``/``row_hash`` linking it to the previous row of the SAME tier written
by this process, so tampering (edits, deletions, reorders) is later detectable by
``verify_audit``. The chain head is kept in-process and seeded at startup via the
read-only ``ssdf_audit_verify`` identity; the insert path itself never reads.
"""

from __future__ import annotations

import datetime as _dt
import json
import sys
import threading
from typing import Any, Callable, Iterable

from .audit_chain import compute_row_hash

# The nine stored business fields (what build_audit_row produces).
AUDIT_BASE_COLUMNS: list[str] = [
    "ts", "principal", "tier", "tool", "args",
    "data_classes", "decision", "row_count", "error",
]
# Full insert column order MUST match infra/clickhouse/007_audit.sql + 009_audit_hash_chain.sql.
AUDIT_COLUMNS: list[str] = AUDIT_BASE_COLUMNS + ["prev_hash", "row_hash"]


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
    """Build the nine business fields of an audit row (pure; no hashes, no I/O)."""
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
    """Wraps a row-insert callable; chains hashes per process and swallows failures."""

    def __init__(self, insert: Callable[[dict], None], last_hash: str = ""):
        self._insert = insert
        self._last_hash = last_hash
        self._lock = threading.Lock()

    def record(self, **fields: Any) -> None:
        """Build, hash-chain, and insert one audit row; never raises."""
        row = build_audit_row(**fields)
        with self._lock:
            prev = self._last_hash
            row_hash = compute_row_hash(prev, row)
            row["prev_hash"] = prev
            row["row_hash"] = row_hash
            try:
                self._insert(row)
            except Exception as exc:  # best-effort: audit must not block a tool call
                print(f"[audit] insert failed: {exc}", file=sys.stderr)
                return
            self._last_hash = row_hash  # advance only after a successful insert


def _noop_insert(_row: dict) -> None:
    return None


def _seed_last_hash(config, tier: str) -> str:
    """Seed the chain head from the latest row of this tier (read-only identity)."""
    if not config.ch_audit_verify_password:
        print("[audit] CH_AUDIT_VERIFY_PASSWORD unset; chain starts fresh "
              "(not seeded from history)", file=sys.stderr)
        return ""
    import clickhouse_connect

    verify_client = clickhouse_connect.get_client(
        host=config.ch_host,
        port=config.ch_port,
        username="ssdf_audit_verify",
        password=config.ch_audit_verify_password,
        database=config.ch_database,
    )
    res = verify_client.query(
        "SELECT row_hash FROM ssdf.audit WHERE tier = {tier:String} "
        "ORDER BY ts DESC LIMIT 1",
        parameters={"tier": tier},
    )
    if res.result_rows:
        return res.result_rows[0][0]
    return ""


def make_ch_auditor(config, tier: str = "sovereign") -> Auditor:
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

    last_hash = _seed_last_hash(config, tier)
    return Auditor(insert, last_hash=last_hash)
```

- [ ] **Step 4: Add the verify-password config field** — in `services/mcp-query/src/ssdf_mcp_query/config.py`, add to the `Config` dataclass after `ch_audit_password: str | None = None`:

```python
    ch_audit_verify_password: str | None = None
```

and in `load_config()`'s `return Config(...)`, after `ch_audit_password=os.environ.get("CH_AUDIT_PASSWORD"),`:

```python
        ch_audit_verify_password=os.environ.get("CH_AUDIT_VERIFY_PASSWORD"),
```

- [ ] **Step 5: Pass tier into the auditor** — in `services/mcp-query/src/ssdf_mcp_query/server.py`, change line 31 from `auditor = make_ch_auditor(config)` to:

```python
    auditor = make_ch_auditor(config, tier)
```

- [ ] **Step 6: Run the full mcp-query suite**

Run: `cd services/mcp-query && uv run pytest -m "not integration" -q`
Expected: PASS — including the updated `test_audit.py`. (The pre-existing `test_build_audit_row_shapes_all_columns` asserted `set(row) == set(AUDIT_COLUMNS)`; update that one assertion to `set(AUDIT_BASE_COLUMNS)` if it now fails, since `build_audit_row` deliberately no longer emits the hash columns.)

- [ ] **Step 7: Commit**

```bash
git add services/mcp-query/src/ssdf_mcp_query/audit.py \
        services/mcp-query/src/ssdf_mcp_query/config.py \
        services/mcp-query/src/ssdf_mcp_query/server.py \
        services/mcp-query/tests/test_audit.py
git commit -m "feat(m3): per-tier in-process audit hash chain (seeded, fail-safe advance)"
```

---

## Task 6: M3c — Schema migration

**Files:**
- Create: `infra/clickhouse/009_audit_hash_chain.sql`

- [ ] **Step 1: Create the migration** — create `infra/clickhouse/009_audit_hash_chain.sql`:

```sql
-- infra/clickhouse/009_audit_hash_chain.sql
-- M3: add per-tier hash-chain columns to ssdf.audit + a READ-ONLY verifier user.
-- The INSERT-only ssdf_audit writer (007) is unchanged. ClickHouse does NOT expand
-- {name:Type} params inside CREATE USER ... BY '...', so inject the password first:
--   AUDIT_VERIFY_PW="$CH_AUDIT_VERIFY_PASSWORD" envsubst < 009_audit_hash_chain.sql \
--     | clickhouse-client --host <ct104> --multiquery
--
-- Rows written before this migration keep prev_hash='' / row_hash='' (column DEFAULT);
-- the verifier treats the first hashed row per tier as that tier's chain start. No
-- backfill — historical rows cannot be authentically re-hashed.
ALTER TABLE ssdf.audit ADD COLUMN IF NOT EXISTS prev_hash String DEFAULT '';
ALTER TABLE ssdf.audit ADD COLUMN IF NOT EXISTS row_hash  String DEFAULT '';

-- Read-only verifier identity: used for startup chain-seeding and verify_audit.
-- Separate from ssdf_audit (which stays INSERT-only) and ssdf_ro (query path).
CREATE USER IF NOT EXISTS ssdf_audit_verify IDENTIFIED WITH sha256_password BY '${AUDIT_VERIFY_PW}';
GRANT SELECT ON ssdf.audit TO ssdf_audit_verify;
```

- [ ] **Step 2: Validate the SQL parses (offline syntax check)**

Run: `grep -c 'ADD COLUMN IF NOT EXISTS' infra/clickhouse/009_audit_hash_chain.sql`
Expected: `2` (sanity that both columns are present; full apply is operator-gated below).

- [ ] **Step 3: Commit**

```bash
git add infra/clickhouse/009_audit_hash_chain.sql
git commit -m "feat(m3): migration 009 — audit hash cols + read-only ssdf_audit_verify"
```

---

## Task 7: M3d — Offline chain verifier

**Files:**
- Create: `services/mcp-query/src/ssdf_mcp_query/verify_audit.py`
- Test: `services/mcp-query/tests/test_verify_audit.py`

- [ ] **Step 1: Write the failing test** — create `services/mcp-query/tests/test_verify_audit.py`:

```python
import datetime as dt
from ssdf_mcp_query.audit_chain import compute_row_hash
from ssdf_mcp_query.verify_audit import verify_tier


def _chain(n, tier="sovereign"):
    """Build n correctly-chained rows for one tier."""
    rows = []
    prev = ""
    for i in range(n):
        row = dict(
            ts=dt.datetime(2026, 6, 10, 12, 0, i, 0, tzinfo=dt.timezone.utc),
            principal="agent", tier=tier, tool=f"t{i}", args="{}",
            data_classes=["topology"], decision="allow", row_count=i, error="",
        )
        row["prev_hash"] = prev
        row["row_hash"] = compute_row_hash(prev, row)
        prev = row["row_hash"]
        rows.append(row)
    return rows


def test_clean_chain_has_no_issues():
    assert verify_tier(_chain(4)) == []


def test_detects_content_edit():
    rows = _chain(4)
    rows[2]["tool"] = "TAMPERED"  # stored row_hash no longer matches recomputed
    issues = verify_tier(rows)
    assert any(i["type"] == "content_edit" for i in issues)


def test_detects_deletion_of_predecessor():
    rows = _chain(4)
    del rows[1]  # row[2].prev_hash now names a missing row_hash
    issues = verify_tier(rows)
    assert any(i["type"] == "missing_predecessor" for i in issues)


def test_detects_unreachable_orphan():
    rows = _chain(3)
    orphan = dict(
        ts=dt.datetime(2026, 6, 10, 13, 0, 0, 0, tzinfo=dt.timezone.utc),
        principal="agent", tier="sovereign", tool="x", args="{}",
        data_classes=["topology"], decision="allow", row_count=0, error="",
        prev_hash="deadbeef", row_hash="feedface",
    )
    rows.append(orphan)
    issues = verify_tier(rows)
    assert any(i["type"] in ("unreachable", "missing_predecessor") for i in issues)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd services/mcp-query && uv run pytest tests/test_verify_audit.py -q`
Expected: FAIL — `ModuleNotFoundError: ssdf_mcp_query.verify_audit`.

- [ ] **Step 3: Implement the verifier** — create `services/mcp-query/src/ssdf_mcp_query/verify_audit.py`:

```python
"""Offline tamper-evidence verifier for the ssdf.audit hash chain (M3).

Reads as the read-only ``ssdf_audit_verify`` identity, groups rows by tier, and
follows each tier's prev_hash -> row_hash linkage from genesis (prev_hash == "").
Detects: content edits (recomputed hash != stored), deletions (a prev_hash naming
a missing row), and insertions/reorders (rows unreachable from genesis). Follows
the linkage, NOT ts ordering, so same-millisecond ts ties never false-positive.

Usage: python -m ssdf_mcp_query.verify_audit
Exit code 0 = all tiers clean; 1 = at least one issue (or 2 = config error).
"""

from __future__ import annotations

import sys
from collections import defaultdict

from .audit_chain import compute_row_hash
from .config import load_config

_VERIFY_COLUMNS = [
    "ts", "principal", "tier", "tool", "args", "data_classes",
    "decision", "row_count", "error", "prev_hash", "row_hash",
]


def verify_tier(rows: list[dict]) -> list[dict]:
    """Verify one tier's rows. Returns a list of issue dicts (empty == clean)."""
    issues: list[dict] = []
    by_hash = {r["row_hash"]: r for r in rows}

    # 1. Content integrity: each stored row_hash must equal H(prev_hash, fields).
    for r in rows:
        if compute_row_hash(r["prev_hash"], r) != r["row_hash"]:
            issues.append({"type": "content_edit", "row_hash": r["row_hash"]})

    # 2. Linkage: a non-genesis prev_hash must name a present row.
    for r in rows:
        if r["prev_hash"] != "" and r["prev_hash"] not in by_hash:
            issues.append({"type": "missing_predecessor", "row_hash": r["row_hash"]})

    # 3. Reachability from genesis (prev_hash == "").
    children: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        children[r["prev_hash"]].append(r)
    reachable: set[str] = set()
    stack = list(children.get("", []))
    while stack:
        r = stack.pop()
        if r["row_hash"] in reachable:
            continue
        reachable.add(r["row_hash"])
        stack.extend(children.get(r["row_hash"], []))
    for r in rows:
        if r["row_hash"] not in reachable:
            issues.append({"type": "unreachable", "row_hash": r["row_hash"]})

    return issues


def _fetch_rows(config) -> list[dict]:
    import clickhouse_connect

    client = clickhouse_connect.get_client(
        host=config.ch_host,
        port=config.ch_port,
        username="ssdf_audit_verify",
        password=config.ch_audit_verify_password,
        database=config.ch_database,
    )
    res = client.query(
        f"SELECT {', '.join(_VERIFY_COLUMNS)} FROM ssdf.audit ORDER BY ts ASC"
    )
    return [dict(zip(_VERIFY_COLUMNS, row)) for row in res.result_rows]


def main() -> int:
    config = load_config()
    if not config.ch_audit_verify_password:
        print("CH_AUDIT_VERIFY_PASSWORD is required to verify the audit chain",
              file=sys.stderr)
        return 2
    rows = _fetch_rows(config)
    by_tier: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        by_tier[r["tier"]].append(r)
    total = 0
    for tier, tier_rows in sorted(by_tier.items()):
        issues = verify_tier(tier_rows)
        total += len(issues)
        status = "OK" if not issues else f"{len(issues)} ISSUE(S)"
        print(f"tier={tier} rows={len(tier_rows)} {status}")
        for issue in issues:
            print(f"  {issue['type']}: row_hash={issue['row_hash'][:16]}…")
    return 0 if total == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd services/mcp-query && uv run pytest tests/test_verify_audit.py -q`
Expected: PASS.

- [ ] **Step 5: Run the full mcp-query suite**

Run: `cd services/mcp-query && uv run pytest -m "not integration" -q`
Expected: PASS (all).

- [ ] **Step 6: Commit**

```bash
git add services/mcp-query/src/ssdf_mcp_query/verify_audit.py \
        services/mcp-query/tests/test_verify_audit.py
git commit -m "feat(m3): offline audit-chain verifier CLI (content/deletion/reorder detection)"
```

---

## Task 8: M5 — systemd hardening

**Files:**
- Modify: `services/mcp-query/infra/ssdf-mcp-query.service`
- Modify: `services/mcp-query/infra/ssdf-mcp-public.service`
- Modify: `services/topo/infra/ssdf-topo.service`
- Modify: `services/entity/infra/ssdf-entity.service`
- Modify: `services/policy/infra/ssdf-policy.service`

No unit tests possible (these are deploy artifacts). Verification = offline `systemd-analyze verify` of the file + the operator-gated live `systemd-analyze security` check.

- [ ] **Step 1: Add the hardening block to each unit** — insert these lines into the `[Service]` section of all five files (place them immediately after the `Type=` line in each):

```ini
DynamicUser=yes
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
CapabilityBoundingSet=
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
Environment=PYTHONDONTWRITEBYTECODE=1
```

Rationale captured in the spec: `EnvironmentFile` is read by systemd (root) before dropping to the transient user, so secrets still load; services write only to the network; ports are >1024 so no capabilities are needed; `PYTHONDONTWRITEBYTECODE=1` avoids `__pycache__` writes under read-only `/opt`.

- [ ] **Step 2: Validate each unit's syntax offline**

Run (one per file):
```bash
for u in services/mcp-query/infra/ssdf-mcp-query.service \
         services/mcp-query/infra/ssdf-mcp-public.service \
         services/topo/infra/ssdf-topo.service \
         services/entity/infra/ssdf-entity.service \
         services/policy/infra/ssdf-policy.service; do
  echo "== $u =="; systemd-analyze verify "$u" 2>&1 || true
done
```
Expected: no fatal parse errors. (Benign warnings about the `ExecStart` binary path not existing on the dev host are acceptable — the binaries live on the target LXCs.)

- [ ] **Step 3: Commit**

```bash
git add services/mcp-query/infra/ssdf-mcp-query.service \
        services/mcp-query/infra/ssdf-mcp-public.service \
        services/topo/infra/ssdf-topo.service \
        services/entity/infra/ssdf-entity.service \
        services/policy/infra/ssdf-policy.service
git commit -m "fix(m5): systemd hardening (DynamicUser, ProtectSystem, drop caps) on all units"
```

---

## Operator-gated live deploy (AFTER all tasks merge — do NOT run during implementation)

These steps affect live infra and require explicit operator go-ahead (same posture as the H1 apply). Listed here so they aren't lost.

1. **M1 / M6 (ct106 + ct113):** sync `services/mcp-query/src` to each editable install (`/opt/src/mcp-query/src`), `systemctl restart ssdf-mcp-query.service` (ct106) / `ssdf-mcp-public.service` (ct113). Optionally set `MCP_MAX_RESULT_ROWS` / `MCP_MAX_MEMORY_BYTES` in `/etc/ssdf-mcp/…` (defaults are safe).
2. **M4 (ct109):** reinstall the topo + policy packages into their venvs *with* dependencies so `defusedxml` lands (`pip install` from `/opt/src/*`, not `--no-deps`); collectors pick it up on the next timer tick.
3. **M3 (ct104 then ct106 + ct113):**
   - Apply `009`: `AUDIT_VERIFY_PW="$CH_AUDIT_VERIFY_PASSWORD" envsubst < infra/clickhouse/009_audit_hash_chain.sql | clickhouse-client --host <ct104> --multiquery` (default-user local trust on ct104).
   - Add `CH_AUDIT_VERIFY_PASSWORD` to **both** ct106 and ct113 `/etc/ssdf-mcp/secrets.env` (mode 600); restart both services so each auditor seeds + chains (tier `sovereign` / `public`).
   - Validate: make a couple of tool calls, then `CH_AUDIT_VERIFY_PASSWORD=… python -m ssdf_mcp_query.verify_audit` → all tiers `OK`; `ALTER UPDATE` one field on ct104 → verifier flags `content_edit`.
4. **M5 (ct106, ct113, ct109):** copy each updated unit to its host, `systemctl daemon-reload`, restart the MCP services / let the ct109 timers fire. Confirm `systemctl is-active` and `systemd-analyze security <unit>` shows a large exposure-score drop; run one live MCP tool call + one clean ct109 collect→resolve cycle.

---

## Self-review notes

- **Spec coverage:** M1→Task 1; M6→Task 2; M4→Task 3; M3→Tasks 4-7 (pure hash, chain advance, migration, verifier); M5→Task 8. All five findings covered.
- **Type consistency:** `AUDIT_BASE_COLUMNS` (9) + `AUDIT_COLUMNS` (11) defined in Task 5 and consumed by the verifier's `_VERIFY_COLUMNS` (Task 7) in the same order; `compute_row_hash(prev_hash, row)` / `canonical(row)` / `ts_ms_iso(ts)` signatures defined in Task 4 are used unchanged in Tasks 5 and 7; `make_ch_auditor(config, tier)` (Task 5) matches the `server.py` call site updated in the same task.
- **Pre-existing test to update:** `test_audit.py::test_build_audit_row_shapes_all_columns` asserts `set(row) == set(AUDIT_COLUMNS)`; Task 5 Step 6 notes changing that one assertion to `AUDIT_BASE_COLUMNS`.
```
