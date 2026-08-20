# fabric_status Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a sovereign MCP tool `fabric_status` that reports whether every ingest source and every resolver is still producing, so the silent-failure class that caused the 2026-08-19 outage becomes a single question an agent can ask.

**Architecture:** A frozen manifest in code declares, per subject, the table/column that proves it alive and a freshness budget. One parameterised query builder turns any entry into a `max(ts)` probe. `FabricTools.fabric_status()` runs each probe, marks stale/fresh/error, and folds in a device roll-up by delegating to the existing `LivenessTools.ingest_status()`. `ingest_status` itself is not modified.

**Tech Stack:** Python 3.12, uv, FastMCP, ClickHouse via `clickhouse-connect`, pytest.

**Spec:** `docs/superpowers/specs/2026-08-19-ssdf-fabric-status-design.md`

## Global Constraints

- Service is `services/mcp-query`; run everything from that directory.
- Unit tests must be offline — no live ClickHouse. Live checks are marked `integration`.
- `ruff check` and `ruff format --check` must pass; hooks are now enabled repo-wide, so do NOT use `--no-verify`.
- Table, timestamp and filter *column* names come only from the frozen manifest, never from caller input. Filter *values* are bound as query parameters.
- `hours_since` is computed in SQL via `dateDiff`; clickhouse-connect returns tz-aware datetimes and naive Python subtraction raises (M14d finding).
- `ts_column` must be a **write-time** column, never a data-time column (spec: "Write time, not data time").
- New tool is classed `security_log` — sovereign-only, never registered on the public tier.

---

### Task 1: Manifest module

**Files:**
- Create: `services/mcp-query/src/ssdf_mcp_query/fabric_manifest.py`
- Test: `services/mcp-query/tests/test_fabric_manifest.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `Subject` (frozen dataclass with fields `name: str`, `kind: str`, `table: str`, `ts_column: str`, `filter_column: str | None`, `filter_value: str | None`, `budget_hours: float`, `note: str`); `MANIFEST: tuple[Subject, ...]`; `build_subject_sql(subject: Subject) -> tuple[str, dict]`; `signal_label(subject: Subject) -> str`.

- [ ] **Step 1: Write the failing test**

```python
# services/mcp-query/tests/test_fabric_manifest.py
from ssdf_mcp_query.fabric_manifest import (
    MANIFEST,
    Subject,
    build_subject_sql,
    signal_label,
)

EXPECTED_SOURCES = {"juniper", "paloalto", "proxmox", "unifi"}
EXPECTED_RESOLVERS = {
    "ssdf-topo",
    "ssdf-entity",
    "ssdf-policy",
    "ssdf-health",
    "ssdf-public-metrics",
}


def test_sql_binds_the_filter_value_as_a_parameter():
    """Filter values must never be interpolated into SQL text."""
    subject = Subject(
        name="juniper", kind="source", table="ssdf.events", ts_column="timestamp",
        filter_column="event_provider", filter_value="juniper",
        budget_hours=1.0, note="continuous flow/security stream",
    )
    sql, params = build_subject_sql(subject)

    assert "{fval:String}" in sql
    assert params == {"fval": "juniper"}
    assert "'juniper'" not in sql
    assert "FROM ssdf.events" in sql
    assert "max(timestamp)" in sql
    # hours_since computed in SQL: tz-aware datetimes break Python subtraction.
    assert "dateDiff" in sql
    # count() lets the caller tell "never observed" from "observed long ago".
    assert "count()" in sql


def test_sql_omits_the_where_clause_when_there_is_no_filter():
    subject = Subject(
        name="ssdf-topo", kind="resolver", table="ssdf.topo_observations",
        ts_column="observed_at", filter_column=None, filter_value=None,
        budget_hours=0.25, note="5-minute timer",
    )
    sql, params = build_subject_sql(subject)

    assert "WHERE" not in sql
    assert params == {}


def test_signal_label_is_human_readable():
    with_filter = Subject(
        name="unifi", kind="source", table="ssdf.health_metrics", ts_column="timestamp",
        filter_column="provider", filter_value="unifi", budget_hours=0.5, note="n",
    )
    without = Subject(
        name="ssdf-topo", kind="resolver", table="ssdf.topo_observations",
        ts_column="observed_at", filter_column=None, filter_value=None,
        budget_hours=0.25, note="n",
    )
    assert signal_label(with_filter) == "ssdf.health_metrics(provider=unifi)"
    assert signal_label(without) == "ssdf.topo_observations.observed_at"


def test_manifest_covers_every_source_and_resolver():
    """Tripwire: adding an ingest source or resolver without declaring it here
    fails CI. Update EXPECTED_* deliberately, never to make the test pass."""
    by_kind: dict[str, set[str]] = {"source": set(), "resolver": set()}
    for subject in MANIFEST:
        by_kind[subject.kind].add(subject.name)

    assert by_kind["source"] == EXPECTED_SOURCES
    assert by_kind["resolver"] == EXPECTED_RESOLVERS


def test_manifest_entries_are_well_formed():
    names = [s.name for s in MANIFEST]
    assert len(names) == len(set(names)), "subject names must be unique"
    for subject in MANIFEST:
        assert subject.kind in {"source", "resolver"}
        assert subject.budget_hours > 0
        # note is required, not decorative: budgets are judgement calls and an
        # undocumented one cannot be reviewed later.
        assert subject.note.strip(), f"{subject.name} has no note"
        # A filter needs both halves or neither.
        assert (subject.filter_column is None) == (subject.filter_value is None)


def test_public_metrics_uses_write_time_not_bucket_time():
    """bucket_start lags ~0.5h by design and would read stale against a 0.25h
    budget while the resolver is healthy. Measured on the live fabric."""
    subject = next(s for s in MANIFEST if s.name == "ssdf-public-metrics")
    assert subject.ts_column == "inserted_at"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd services/mcp-query && uv run pytest tests/test_fabric_manifest.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'ssdf_mcp_query.fabric_manifest'`

- [ ] **Step 3: Write minimal implementation**

```python
# services/mcp-query/src/ssdf_mcp_query/fabric_manifest.py
"""Declared liveness subjects: what proves each source and resolver is alive.

A set derived from observations cannot miss a thing that was never observed —
UniFi produced zero events for 30+ days and nothing noticed, because nothing was
present to go stale. Sources and resolvers are therefore DECLARED here rather
than derived. The device fleet stays derived; that is ``ingest_status``.

Each entry names the observable that proves liveness, which is not always
``ssdf.events``: UniFi IPS detections are rare by design, so the collector poll
is the honest signal for "is the integration alive".
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Subject:
    """One thing whose liveness is asserted, and the signal that proves it."""

    name: str
    kind: str  # "source" | "resolver"
    table: str
    ts_column: str
    filter_column: str | None
    filter_value: str | None
    budget_hours: float
    note: str


# INVARIANT: ts_column must be a WRITE-time column, never a data-time column.
# ssdf_public.metric_timeseries.bucket_start lags ~0.5h by design and would
# report a healthy resolver stale; inserted_at is the write time. Verify this
# when adding a subject — a table offering only data time is not a valid signal.
MANIFEST: tuple[Subject, ...] = (
    Subject(
        name="juniper", kind="source", table="ssdf.events", ts_column="timestamp",
        filter_column="event_provider", filter_value="juniper", budget_hours=1.0,
        note="Continuous SRX security stream; quiet for an hour means something broke.",
    ),
    Subject(
        name="paloalto", kind="source", table="ssdf.events", ts_column="timestamp",
        filter_column="event_provider", filter_value="paloalto", budget_hours=1.0,
        note="Continuous PAN-OS traffic stream.",
    ),
    Subject(
        name="proxmox", kind="source", table="ssdf.events", ts_column="timestamp",
        filter_column="event_provider", filter_value="proxmox", budget_hours=24.0,
        note="Event-driven: auth and task events only on activity. Idle overnight is correct.",
    ),
    Subject(
        name="unifi", kind="source", table="ssdf.health_metrics", ts_column="timestamp",
        filter_column="provider", filter_value="unifi", budget_hours=0.5,
        note=(
            "Checked against the 5-minute collector poll, NOT ssdf.events: IPS "
            "detections are rare by design, so event silence is not a fault while "
            "a dead integration is."
        ),
    ),
    Subject(
        name="ssdf-topo", kind="resolver", table="ssdf.topo_observations",
        ts_column="observed_at", filter_column=None, filter_value=None,
        budget_hours=0.25, note="5-minute timer; 0.25h allows three missed runs.",
    ),
    Subject(
        name="ssdf-entity", kind="resolver", table="ssdf.entity_edges",
        ts_column="last_seen", filter_column=None, filter_value=None,
        budget_hours=0.25,
        note=(
            "5-minute timer. last_seen reads event-derived but is stamped by the "
            "resolver at write time — verified live while flow events were ~0."
        ),
    ),
    Subject(
        name="ssdf-policy", kind="resolver", table="ssdf.entities",
        ts_column="last_seen", filter_column="source", filter_value="configured",
        budget_hours=2.0,
        note=(
            "Hourly timer. This is the signal that was flat for four days while the "
            "resolver ran, exited 0 and logged '0 entities upserted'."
        ),
    ),
    Subject(
        name="ssdf-health", kind="resolver", table="ssdf.health_metrics",
        ts_column="timestamp", filter_column=None, filter_value=None,
        budget_hours=0.25, note="5-minute timer.",
    ),
    Subject(
        name="ssdf-public-metrics", kind="resolver",
        table="ssdf_public.metric_timeseries", ts_column="inserted_at",
        filter_column=None, filter_value=None, budget_hours=0.25,
        note="5-minute timer. inserted_at, not bucket_start, which lags by design.",
    ),
)


def signal_label(subject: Subject) -> str:
    """Human-readable description of what is being probed."""
    if subject.filter_column is not None:
        return f"{subject.table}({subject.filter_column}={subject.filter_value})"
    return f"{subject.table}.{subject.ts_column}"


def build_subject_sql(subject: Subject) -> tuple[str, dict]:
    """Build the freshness probe for one subject.

    Table, timestamp and filter column come only from the frozen MANIFEST and are
    never caller-supplied; the filter VALUE is bound as a parameter. ``count()``
    lets the caller distinguish "never observed" from "observed long ago".
    """
    params: dict = {}
    where = ""
    if subject.filter_column is not None:
        where = f" WHERE {subject.filter_column} = {{fval:String}}"
        params["fval"] = subject.filter_value
    sql = (
        f"SELECT count() AS n, max({subject.ts_column}) AS last_seen, "
        f"dateDiff('second', max({subject.ts_column}), now()) / 3600.0 AS hours_since "
        f"FROM {subject.table}{where}"
    )
    return sql, params
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd services/mcp-query && uv run pytest tests/test_fabric_manifest.py -v`
Expected: PASS (6 tests)

- [ ] **Step 5: Lint and commit**

```bash
cd /home/mharman/Projects/SSDF
ruff check services && ruff format --check services
git add services/mcp-query/src/ssdf_mcp_query/fabric_manifest.py services/mcp-query/tests/test_fabric_manifest.py
git commit -m "feat(mcp-query): declare fabric liveness subjects and their probe SQL"
```

---

### Task 2: fabric_status tool logic

**Files:**
- Create: `services/mcp-query/src/ssdf_mcp_query/fabric_tools.py`
- Test: `services/mcp-query/tests/test_fabric_tools.py`

**Interfaces:**
- Consumes: `MANIFEST`, `Subject`, `build_subject_sql`, `signal_label` from Task 1.
- Produces: `FabricTools(ch_client, liveness=None, manifest=MANIFEST)` with method `fabric_status() -> dict` returning keys `healthy: bool`, `checked_at: str`, `subjects: list[dict]`, `devices: dict | None`, `summary: dict`.

- [ ] **Step 1: Write the failing test**

```python
# services/mcp-query/tests/test_fabric_tools.py
from ssdf_mcp_query.fabric_manifest import Subject
from ssdf_mcp_query.fabric_tools import FabricTools

FRESH = Subject(
    name="juniper", kind="source", table="ssdf.events", ts_column="timestamp",
    filter_column="event_provider", filter_value="juniper", budget_hours=1.0, note="n",
)
SLOW = Subject(
    name="ssdf-policy", kind="resolver", table="ssdf.entities", ts_column="last_seen",
    filter_column="source", filter_value="configured", budget_hours=2.0, note="n",
)


class _FakeCH:
    """Returns a canned row per table, or raises if the value is an Exception."""

    def __init__(self, by_table):
        self._by_table = by_table
        self.calls = []

    def run(self, sql, params=None):
        table = next(t for t in self._by_table if f"FROM {t}" in sql)
        self.calls.append((table, params))
        row = self._by_table[table]
        if isinstance(row, Exception):
            raise row
        return {"rows": [row]}


def test_fresh_subject_is_not_stale():
    ch = _FakeCH({"ssdf.events": {"n": 5, "last_seen": "2026-08-19T12:00:00Z",
                                  "hours_since": 0.5}})
    result = FabricTools(ch, manifest=(FRESH,)).fabric_status()

    assert result["healthy"] is True
    subject = result["subjects"][0]
    assert subject["name"] == "juniper"
    assert subject["stale"] is False
    assert subject["hours_since"] == 0.5
    assert subject["budget_hours"] == 1.0
    assert subject["signal"] == "ssdf.events(event_provider=juniper)"


def test_subject_past_its_budget_is_stale_and_makes_the_fabric_unhealthy():
    ch = _FakeCH({"ssdf.entities": {"n": 22, "last_seen": "2026-08-15T18:00:00Z",
                                    "hours_since": 97.3}})
    result = FabricTools(ch, manifest=(SLOW,)).fabric_status()

    assert result["subjects"][0]["stale"] is True
    assert result["healthy"] is False
    assert result["summary"] == {"total": 1, "stale": 1, "fresh": 0, "errored": 0}


def test_exactly_at_budget_is_not_stale():
    """Boundary: stale means strictly past budget, so a 0.25h timer checked at
    exactly 0.25h does not flap."""
    ch = _FakeCH({"ssdf.events": {"n": 1, "last_seen": "x", "hours_since": 1.0}})
    result = FabricTools(ch, manifest=(FRESH,)).fabric_status()
    assert result["subjects"][0]["stale"] is False


def test_never_observed_is_stale_not_absent():
    """UniFi went unnoticed for 30 days because nothing was there to age.
    Absence must be loud."""
    ch = _FakeCH({"ssdf.events": {"n": 0, "last_seen": None, "hours_since": None}})
    result = FabricTools(ch, manifest=(FRESH,)).fabric_status()

    subject = result["subjects"][0]
    assert subject["stale"] is True
    assert subject["last_seen"] is None
    assert subject["hours_since"] is None
    assert result["healthy"] is False


def test_a_failing_subject_is_surfaced_not_swallowed():
    """run_collectors catching errors and continuing SILENTLY is what hid every
    bug on 2026-08-19. The tool built to detect that must not repeat it."""
    ch = _FakeCH({
        "ssdf.events": {"n": 5, "last_seen": "2026-08-19T12:00:00Z", "hours_since": 0.5},
        "ssdf.entities": RuntimeError("table does not exist"),
    })
    result = FabricTools(ch, manifest=(FRESH, SLOW)).fabric_status()

    by_name = {s["name"]: s for s in result["subjects"]}
    assert "table does not exist" in by_name["ssdf-policy"]["error"]
    # the healthy subject still reported
    assert by_name["juniper"]["stale"] is False
    assert result["healthy"] is False
    assert result["summary"]["errored"] == 1


def test_subjects_sort_stale_first():
    ch = _FakeCH({
        "ssdf.events": {"n": 5, "last_seen": "x", "hours_since": 0.1},
        "ssdf.entities": {"n": 1, "last_seen": "y", "hours_since": 99.0},
    })
    result = FabricTools(ch, manifest=(FRESH, SLOW)).fabric_status()
    assert [s["name"] for s in result["subjects"]] == ["ssdf-policy", "juniper"]


def test_devices_rollup_delegates_to_ingest_status():
    class _FakeLiveness:
        def ingest_status(self):
            return {"firewalls": [{}, {}, {}],
                    "summary": {"total": 3, "stale": 1, "fresh": 2}}

    ch = _FakeCH({"ssdf.events": {"n": 5, "last_seen": "x", "hours_since": 0.1}})
    result = FabricTools(ch, liveness=_FakeLiveness(), manifest=(FRESH,)).fabric_status()

    assert result["devices"] == {"total": 3, "stale": 1, "fresh": 2}


def test_devices_is_null_when_no_liveness_store_is_wired():
    ch = _FakeCH({"ssdf.events": {"n": 5, "last_seen": "x", "hours_since": 0.1}})
    result = FabricTools(ch, manifest=(FRESH,)).fabric_status()
    assert result["devices"] is None


def test_device_rollup_failure_does_not_lose_subject_results():
    class _BrokenLiveness:
        def ingest_status(self):
            raise RuntimeError("graph unavailable")

    ch = _FakeCH({"ssdf.events": {"n": 5, "last_seen": "x", "hours_since": 0.1}})
    result = FabricTools(ch, liveness=_BrokenLiveness(), manifest=(FRESH,)).fabric_status()

    assert result["subjects"][0]["name"] == "juniper"
    assert "graph unavailable" in result["devices_error"]
    assert result["healthy"] is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd services/mcp-query && uv run pytest tests/test_fabric_tools.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'ssdf_mcp_query.fabric_tools'`

- [ ] **Step 3: Write minimal implementation**

```python
# services/mcp-query/src/ssdf_mcp_query/fabric_tools.py
"""fabric_status: is every ingest source and resolver still producing?

Answers the question nobody could ask on 2026-08-19, when three collectors had
been dead for four days, the policy resolver had produced nothing while exiting
0, and UniFi had been silent for a month — none of it visible without
hand-querying ClickHouse.
"""

from __future__ import annotations

import datetime as _dt

from .fabric_manifest import MANIFEST, build_subject_sql, signal_label


class FabricTools:
    """Runs the declared liveness probes. Stateless apart from its stores."""

    def __init__(self, ch_client, liveness=None, manifest=MANIFEST):
        self._ch = ch_client
        self._liveness = liveness
        self._manifest = manifest

    def _probe(self, subject) -> dict:
        """Probe one subject. A query failure becomes a reported error, never a
        silent omission."""
        base = {
            "name": subject.name,
            "kind": subject.kind,
            "signal": signal_label(subject),
            "budget_hours": subject.budget_hours,
            "note": subject.note,
        }
        sql, params = build_subject_sql(subject)
        try:
            rows = self._ch.run(sql, params)["rows"]
        except Exception as exc:  # surfaced in the payload, not just logged
            return {**base, "last_seen": None, "hours_since": None,
                    "stale": True, "error": str(exc)}

        row = rows[0] if rows else {}
        count = row.get("n") or 0
        hours_since = row.get("hours_since")
        if not count or hours_since is None:
            # Never observed. Absence is the signal, not a missing row.
            return {**base, "last_seen": None, "hours_since": None, "stale": True}

        last_seen = row.get("last_seen")
        return {
            **base,
            "last_seen": str(last_seen) if last_seen is not None else None,
            "hours_since": hours_since,
            "stale": hours_since > subject.budget_hours,
        }

    def fabric_status(self) -> dict:
        """Report freshness for every declared source and resolver.

        Returns {healthy, checked_at, subjects[], devices, summary}. ``healthy``
        is true only when nothing is stale and nothing errored.
        """
        subjects = [self._probe(s) for s in self._manifest]
        subjects.sort(key=lambda s: (not s["stale"], s["name"]))

        stale = sum(1 for s in subjects if s["stale"])
        errored = sum(1 for s in subjects if "error" in s)

        result = {
            "healthy": stale == 0 and errored == 0,
            "checked_at": _dt.datetime.now(_dt.timezone.utc).isoformat(
                timespec="milliseconds"
            ),
            "subjects": subjects,
            "devices": None,
            "summary": {
                "total": len(subjects),
                "stale": stale,
                "fresh": len(subjects) - stale,
                "errored": errored,
            },
        }

        if self._liveness is not None:
            try:
                result["devices"] = self._liveness.ingest_status()["summary"]
            except Exception as exc:
                result["devices_error"] = str(exc)
                result["healthy"] = False

        return result
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd services/mcp-query && uv run pytest tests/test_fabric_tools.py -v`
Expected: PASS (9 tests)

- [ ] **Step 5: Lint and commit**

```bash
cd /home/mharman/Projects/SSDF
ruff check services && ruff format --check services
git add services/mcp-query/src/ssdf_mcp_query/fabric_tools.py services/mcp-query/tests/test_fabric_tools.py
git commit -m "feat(mcp-query): fabric_status probes every declared subject, surfacing errors"
```

---

### Task 3: Register the tool, class it sovereign-only, document it

**Files:**
- Modify: `services/mcp-query/src/ssdf_mcp_query/classification.py` (the `TOOL_DATA_CLASSES` dict)
- Modify: `services/mcp-query/src/ssdf_mcp_query/server.py` (import, construction near the existing `liveness = LivenessTools(...)`, tool definition beside `ingest_status`, and the `if liveness is not None:` registration block)
- Modify: `CLAUDE.md`
- Test: `services/mcp-query/tests/test_fabric_registration.py`

**Interfaces:**
- Consumes: `FabricTools.fabric_status()` from Task 2; `LivenessTools` already constructed in `server.py`.
- Produces: MCP tool named `fabric_status`; classification entry `"fabric_status": frozenset({"security_log"})`.

- [ ] **Step 1: Write the failing test**

```python
# services/mcp-query/tests/test_fabric_registration.py
from ssdf_mcp_query.classification import TOOL_DATA_CLASSES, Classification, public_tool_names


def test_fabric_status_is_classed_security_log():
    assert TOOL_DATA_CLASSES["fabric_status"] == frozenset({"security_log"})


def test_fabric_status_can_never_be_public():
    """security_log is not a configurable class, so no config can flip it. The
    response carries device names, provider inventory and infrastructure shape."""
    # Even with every configurable class flipped shareable, fabric_status must
    # not be selected for a public build.
    classification = Classification(
        {"security_log": "sovereign", "firewall_config": "sovereign",
         "topology": "shareable", "identity": "shareable", "metrics": "shareable"}
    )
    selected = public_tool_names(classification, ["fabric_status", "locate"])
    assert "fabric_status" not in selected
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd services/mcp-query && uv run pytest tests/test_fabric_registration.py -v`
Expected: FAIL — `KeyError: 'fabric_status'`

Note: `Classification` is a frozen dataclass whose only field is `labels: dict[str, str]`, and `public_tool_names(classification, candidates)` takes the list in input order — both verified against `classification.py`, so the test above matches the real API as written.

- [ ] **Step 3: Add the classification entry**

In `services/mcp-query/src/ssdf_mcp_query/classification.py`, add to `TOOL_DATA_CLASSES` immediately after the `"ingest_status"` line:

```python
    "fabric_status": frozenset({"security_log"}),
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd services/mcp-query && uv run pytest tests/test_fabric_registration.py -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Wire the tool into the server**

In `services/mcp-query/src/ssdf_mcp_query/server.py`:

Add the import beside the existing `from .liveness_tools import LivenessTools`:

```python
from .fabric_tools import FabricTools
```

Construct it where `liveness = LivenessTools(graph_store, entity_store)` is built (around line 49), reusing the same ClickHouse client the entity store holds:

```python
        fabric = FabricTools(entity_store._ch, liveness=liveness)
```

Define the tool immediately after the existing `ingest_status` function:

```python
    def fabric_status() -> dict:
        """Is the whole data fabric still producing? Checks EVERY ingest source
        (juniper, paloalto, proxmox, unifi) and EVERY resolver (topo, entity,
        policy, health, public-metrics) against a declared freshness budget.
        Use for "is anything broken/stale", "is ingest healthy", "did a collector
        stop" questions. Returns {healthy, subjects:[{name, kind, signal,
        last_seen, hours_since, budget_hours, stale}], devices:{total,fresh,stale},
        summary}. For per-device firewall detail use ingest_status instead."""
        return fabric.fabric_status()
```

Register it in the existing sovereign-only block:

```python
    if liveness is not None:  # sovereign-only: ingest liveness
        raw_tools["ingest_status"] = ingest_status
        raw_tools["fabric_status"] = fabric_status
```

- [ ] **Step 6: Run the full mcp-query suite**

Run: `cd services/mcp-query && uv run pytest -m "not integration" -q`
Expected: PASS, count increased by 11 over the pre-task baseline.

- [ ] **Step 7: Document it in CLAUDE.md**

Add to `CLAUDE.md` under the M14d bullet that describes `ingest_status`:

```markdown
- **`fabric_status` sovereign tool:** whole-fabric liveness — every ingest source
  (juniper/paloalto/proxmox/unifi) and every resolver (topo/entity/policy/health/
  public-metrics) against a declared budget in `fabric_manifest.py`. Complements
  `ingest_status`, which stays the per-device firewall view. Two rules encode the
  2026-08-19 outage: a subject never observed is `stale`, not absent (UniFi was
  silent 30+ days and nothing noticed); and a probe that errors is reported in the
  payload, never swallowed. `ts_column` must be WRITE time — `metric_timeseries.
  bucket_start` lags ~0.5h by design and would report a healthy resolver stale.
```

- [ ] **Step 8: Lint and commit**

```bash
cd /home/mharman/Projects/SSDF
ruff check services && ruff format --check services
git add services/mcp-query CLAUDE.md
git commit -m "feat(mcp-query): register fabric_status as a sovereign-only tool"
```

---

### Task 4: Deploy and verify against the live fabric

**Files:**
- No repo changes. Deploys `services/mcp-query/src` to the sovereign MCP guest.

**Interfaces:**
- Consumes: the registered `fabric_status` tool from Task 3.
- Produces: live confirmation; a `docs/superpowers/STATUS.md` row.

- [ ] **Step 1: Back up and deploy the source**

Guest 702 (`ssdf-sovereign-mcp`, was ct106) is an editable install at `/opt/src/mcp-query/src`.

```bash
cd /home/mharman/Projects/SSDF
scp -q services/mcp-query/src/ssdf_mcp_query/fabric_manifest.py root@pve2.example.com:/tmp/
scp -q services/mcp-query/src/ssdf_mcp_query/fabric_tools.py root@pve2.example.com:/tmp/
scp -q services/mcp-query/src/ssdf_mcp_query/classification.py root@pve2.example.com:/tmp/
scp -q services/mcp-query/src/ssdf_mcp_query/server.py root@pve2.example.com:/tmp/
ssh root@pve2.example.com 'S=$(date +%Y%m%d-%H%M%S); for f in fabric_manifest.py fabric_tools.py classification.py server.py; do
  pct exec 702 -- cp -a /opt/src/mcp-query/src/ssdf_mcp_query/$f /opt/src/mcp-query/src/ssdf_mcp_query/$f.bak-$S 2>/dev/null || true
  pct push 702 /tmp/$f /opt/src/mcp-query/src/ssdf_mcp_query/$f; rm -f /tmp/$f
done; echo "deployed (backups .bak-$S)"'
```

- [ ] **Step 2: Restart and confirm the service is healthy**

```bash
ssh root@pve2.example.com 'pct exec 702 -- systemctl restart ssdf-mcp-query.service; sleep 5
  pct exec 702 -- systemctl is-active ssdf-mcp-query.service
  pct exec 702 -- journalctl -u ssdf-mcp-query.service --since "-2min" --no-pager | grep -iE "error|traceback" | tail -5 || echo "no errors"'
```

Expected: `active`, no tracebacks. If the unit fails, restore the `.bak-*` files and restart before investigating.

- [ ] **Step 3: Call the tool through the live MCP endpoint**

Use the local `.mcp.json` sovereign token (gitignored) with `NODE_EXTRA_CA_CERTS` pointing at `infra/tls-local/ssdf-ca.crt`, or call it from guest 704's venv the way the collector probes in this repo do. Confirm the response contains all 9 subjects and a `devices` roll-up.

Expected shape: `healthy` boolean, `summary.total == 9`.

- [ ] **Step 4: Verify it reports the known-good state correctly**

Every resolver is currently running on a 5-minute timer and every source except `unifi` events is producing, so the expected live result is: all 5 resolvers fresh, `juniper`/`paloalto` fresh, `proxmox` fresh-or-stale depending on recent host activity (24h budget), `unifi` fresh via the health-poll signal.

If any subject reports stale, confirm against ClickHouse directly before assuming a tool bug:

```bash
ssh root@pve2.example.com "pct exec 701 -- clickhouse-client --query \"
SELECT max(inserted_at), dateDiff('second', max(inserted_at), now())/3600.0
FROM ssdf_public.metric_timeseries\""
```

- [ ] **Step 5: Prove the tool detects a real stall**

Stop one 5-minute timer, wait past its budget, and confirm the subject flips to stale — this is the only test that proves the tool does its job.

```bash
ssh root@pve2.example.com 'pct exec 704 -- systemctl stop ssdf-health.timer'
# wait > 0.25h (15 min), call fabric_status again, expect ssdf-health stale:true
ssh root@pve2.example.com 'pct exec 704 -- systemctl start ssdf-health.timer'
```

Confirm the timer is running again afterwards: `pct exec 704 -- systemctl is-active ssdf-health.timer`.

- [ ] **Step 6: Record as-built and commit**

Add a row to `docs/superpowers/STATUS.md` describing the tool, its deployment on guest 702, and the live verification result including the stall test.

```bash
cd /home/mharman/Projects/SSDF
git add docs/superpowers/STATUS.md
git commit -m "docs(status): fabric_status deployed and live-verified"
```
