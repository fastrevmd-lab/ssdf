# M12 — MCP ergonomics & agent-routing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the routable eval misses by adding two sovereign MCP tools (`configured_policies`, `observed_by`), a role filter on `topology_snapshot`, sharper tool descriptions, and corpus fixes — no ingest/schema/resolver changes.

**Architecture:** All work lives in the existing `services/mcp-query` package (deployed on ct106 sovereign, ct113 public). The two new tools are methods on the existing `AccessTools` class (sovereign-only, already guarded by `access is not None` in `server.py`), reusing the `ClickHouseEntityStore` seam. `observed_by` reads `ssdf.events` `observer_hostname` via a new store method that mirrors the existing `alerts_for_pair` events-query pattern. `topology_snapshot` gains an additive `role`/`kind` filter. Corpus changes are data-only in `services/evals/golden/core.yaml`.

**Tech Stack:** Python 3 + FastMCP, uv, pytest; ClickHouse (clickhouse-connect) read path; networkx for topo graph.

---

## File Structure

- `services/mcp-query/src/ssdf_mcp_query/entitystore.py` — add `build_observers_for_ips_sql` + `ClickHouseEntityStore.observers_for_ips` + Protocol entry (Component E store seam).
- `services/mcp-query/src/ssdf_mcp_query/access_tools.py` — add `AccessTools.configured_policies` (Component B) and `AccessTools.observed_by` (Component E) methods.
- `services/mcp-query/src/ssdf_mcp_query/topo_tools.py` — add `role`/`kind` filter to `topology_snapshot` (Component C).
- `services/mcp-query/src/ssdf_mcp_query/classification.py` — add `configured_policies` + `observed_by` to `TOOL_DATA_CLASSES` (Components B + E).
- `services/mcp-query/src/ssdf_mcp_query/server.py` — register the two new sovereign tools; pass `role` through `topology_snapshot`; rewrite docstrings (Component A).
- `services/mcp-query/tests/test_access_tools.py` — unit tests for `configured_policies` + `observed_by`.
- `services/mcp-query/tests/test_entitystore.py` — unit test for `observers_for_ips` SQL builder.
- `services/mcp-query/tests/test_topo_tools.py` — unit test for `topology_snapshot` role filter.
- `services/mcp-query/tests/test_server_entity.py` — registration test for the two new sovereign tools + absence on public.
- `services/mcp-query/tests/test_classification.py` — assert the two new tools are NOT shareable (secure-by-default).
- `services/evals/golden/core.yaml` — corpus fixes (Component D).

Run all unit tests from `services/mcp-query` with: `uv run pytest -m "not integration"`.

---

## Task 1: Component E store seam — `observers_for_ips` SQL builder

**Files:**
- Modify: `services/mcp-query/src/ssdf_mcp_query/entitystore.py`
- Test: `services/mcp-query/tests/test_entitystore.py`

- [ ] **Step 1: Write the failing test**

Append to `services/mcp-query/tests/test_entitystore.py`:

```python
def test_build_observers_for_ips_sql():
    from ssdf_mcp_query.entitystore import build_observers_for_ips_sql

    sql, params = build_observers_for_ips_sql(
        ["10.74.11.20", "198.51.100.1"], "2026-06-18T00:00:00.000+00:00", "t_main")
    assert "observer_hostname" in sql
    assert "ssdf.events" in sql
    assert "observer_hostname != ''" in sql
    # both directions matched, parameterized (no raw IP interpolation)
    assert "toString(source_ip) IN {ips:Array(String)}" in sql
    assert "toString(destination_ip) IN {ips:Array(String)}" in sql
    assert "{since:String}" in sql
    assert params == {"tenant": "t_main", "ips": ["10.74.11.20", "198.51.100.1"],
                      "since": "2026-06-18T00:00:00.000+00:00"}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd services/mcp-query && uv run pytest tests/test_entitystore.py::test_build_observers_for_ips_sql -v`
Expected: FAIL with `ImportError: cannot import name 'build_observers_for_ips_sql'`.

- [ ] **Step 3: Write minimal implementation**

In `entitystore.py`, add this builder immediately after `build_alerts_for_pair_sql` (before the `EntityStore` Protocol class):

```python
def build_observers_for_ips_sql(ips: list[str], since_iso: str,
                                tenant: str) -> tuple[str, dict]:
    # Distinct firewall observer_hostname values that LOGGED a flow touching any of
    # the given IPs in-window (provenance: the firewall that logged a flow is on its
    # path). source_ip/destination_ip are IPv6-typed; toString yields the dotted-quad
    # for IPv4-mapped values (same pattern as build_alerts_for_pair_sql). Both flow
    # directions match (a firewall observes the IP as src OR dst).
    sql = (
        "SELECT DISTINCT observer_hostname FROM ssdf.events "
        "WHERE tenant_id = {tenant:String} AND observer_hostname != '' "
        "AND timestamp >= {since:String} AND ("
        "toString(source_ip) IN {ips:Array(String)} OR "
        "toString(destination_ip) IN {ips:Array(String)})"
    )
    return sql, {"tenant": tenant, "ips": ips, "since": since_iso}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd services/mcp-query && uv run pytest tests/test_entitystore.py::test_build_observers_for_ips_sql -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add services/mcp-query/src/ssdf_mcp_query/entitystore.py services/mcp-query/tests/test_entitystore.py
git commit -m "feat(m12): observers_for_ips SQL builder for observed_by provenance"
```

---

## Task 2: Component E store seam — `observers_for_ips` store method + Protocol

**Files:**
- Modify: `services/mcp-query/src/ssdf_mcp_query/entitystore.py`
- Test: `services/mcp-query/tests/test_entitystore.py`

- [ ] **Step 1: Write the failing test**

Append to `services/mcp-query/tests/test_entitystore.py`:

```python
def test_observers_for_ips_method_runs_builder_and_returns_rows():
    from ssdf_mcp_query.entitystore import ClickHouseEntityStore

    class _FakeCH:
        def __init__(self):
            self.calls = []

        def run(self, sql, params):
            self.calls.append((sql, params))
            return {"rows": [{"observer_hostname": "panosvm.example.com"}]}

    ch = _FakeCH()
    store = ClickHouseEntityStore(ch, tenant="t_main")
    rows = store.observers_for_ips(["10.74.11.20"], "2026-06-18T00:00:00.000+00:00")
    assert rows == [{"observer_hostname": "panosvm.example.com"}]
    assert ch.calls and ch.calls[0][1]["ips"] == ["10.74.11.20"]


def test_observers_for_ips_empty_ips_short_circuits():
    from ssdf_mcp_query.entitystore import ClickHouseEntityStore

    class _BoomCH:
        def run(self, sql, params):
            raise AssertionError("must not query CH with no IPs")

    store = ClickHouseEntityStore(_BoomCH(), tenant="t_main")
    assert store.observers_for_ips([], "2026-06-18T00:00:00.000+00:00") == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd services/mcp-query && uv run pytest tests/test_entitystore.py::test_observers_for_ips_method_runs_builder_and_returns_rows tests/test_entitystore.py::test_observers_for_ips_empty_ips_short_circuits -v`
Expected: FAIL with `AttributeError: 'ClickHouseEntityStore' object has no attribute 'observers_for_ips'`.

- [ ] **Step 3: Write minimal implementation**

In `entitystore.py`, add `observers_for_ips` to the `EntityStore` Protocol (after `alerts_for_pair`):

```python
    def observers_for_ips(self, ips: list[str], since_iso: str) -> list[dict]: ...
```

And add the method to `ClickHouseEntityStore` (after `alerts_for_pair`):

```python
    def observers_for_ips(self, ips: list[str], since_iso: str) -> list[dict]:
        if not ips:
            return []
        sql, params = build_observers_for_ips_sql(ips, since_iso, self._tenant)
        return self._ch.run(sql, params)["rows"]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd services/mcp-query && uv run pytest tests/test_entitystore.py -k observers_for_ips -v`
Expected: PASS (both tests).

- [ ] **Step 5: Commit**

```bash
git add services/mcp-query/src/ssdf_mcp_query/entitystore.py services/mcp-query/tests/test_entitystore.py
git commit -m "feat(m12): ClickHouseEntityStore.observers_for_ips store method"
```

---

## Task 3: Component E — `AccessTools.observed_by`

**Files:**
- Modify: `services/mcp-query/src/ssdf_mcp_query/access_tools.py`
- Test: `services/mcp-query/tests/test_access_tools.py`

`observed_by` resolves the identifier to an entity, gathers candidate IP strings (the
identifier itself if it is an IP, plus any IP-shaped entity identifiers), queries
`observers_for_ips`, and normalizes each `observer_hostname` to its device name via the
existing `_short_host`. Returns `{entity, firewalls}` (sorted, deduped device names).

- [ ] **Step 1: Write the failing test**

Append to `services/mcp-query/tests/test_access_tools.py`:

```python
class _StoreObservers:
    """EntityStore double for observed_by: resolves one entity, scripts observers."""

    def __init__(self, entity, observers):
        self._entity = entity
        self._observers = observers
        self.seen_ips = None

    def find_entities(self, identifier):
        return [self._entity] if self._entity else []

    def observers_for_ips(self, ips, since_iso):
        self.seen_ips = ips
        return self._observers

    # unused-by-observed_by seam methods
    def find_entity(self, identifier):
        return self._entity

    def communicated_edges(self, a, b, since):
        return []

    def communicated_edges_multi(self, a_ids, b_ids, since_iso):
        return []

    def governed_policies(self, ids):
        return []

    def configured_policies_for_firewalls(self, names):
        return []

    def alerts_for_pair(self, ips, since_iso):
        return []


def test_observed_by_normalizes_and_dedupes_firewalls():
    ent = {"entity_id": "A", "name": "ep-panos",
           "identifiers": {"ip": "10.74.11.20", "mac": "aa:bb:cc:dd:ee:ff"}}
    store = _StoreObservers(ent, [{"observer_hostname": "panosvm.example.com"},
                                  {"observer_hostname": "panosvm.example.com"},
                                  {"observer_hostname": "vSRX-Production"}])
    out = AccessTools(store, _FakeTopo([], {"found": False})).observed_by("10.74.11.20")
    assert out["entity"]["entity_id"] == "A"
    assert out["firewalls"] == ["panosvm", "vSRX-Production"]
    # the lookup arg IP is among the queried IPs; the MAC is excluded
    assert "10.74.11.20" in store.seen_ips
    assert "aa:bb:cc:dd:ee:ff" not in store.seen_ips


def test_observed_by_not_found():
    store = _StoreObservers(None, [])
    out = AccessTools(store, _FakeTopo([], {"found": False})).observed_by("nope")
    assert out["error"] == "not_found"


def test_observed_by_no_observers_returns_empty_list():
    ent = {"entity_id": "A", "name": "x", "identifiers": {"ip": "10.64.0.9"}}
    store = _StoreObservers(ent, [])
    out = AccessTools(store, _FakeTopo([], {"found": False})).observed_by("10.64.0.9")
    assert out["firewalls"] == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd services/mcp-query && uv run pytest tests/test_access_tools.py -k observed_by -v`
Expected: FAIL with `AttributeError: 'AccessTools' object has no attribute 'observed_by'`.

- [ ] **Step 3: Write minimal implementation**

In `access_tools.py`, add this method to the `AccessTools` class (after `explain_access`).
It reuses the module-level `_since`, `_short_host`, and `ipaddress` already imported:

```python
    def observed_by(self, identifier: str, since_hours: int | None = None) -> dict:
        """Firewalls that LOGGED traffic for an IP/asset (L3 provenance, multi-FW aware)."""
        cands = self._store.find_entities(identifier)
        if not cands:
            return {"error": "not_found", "detail": f"no entity matches '{identifier}'"}
        entity = cands[0]
        window = since_hours or self._window
        candidate_ips: set[str] = set()
        for value in (identifier, *entity.get("identifiers", {}).values()):
            try:
                ipaddress.ip_address(value)
                candidate_ips.add(value)
            except (ValueError, TypeError):
                continue
        rows = self._store.observers_for_ips(sorted(candidate_ips), _since(window))
        firewalls = sorted({_short_host(r["observer_hostname"]) for r in rows
                            if r.get("observer_hostname")})
        return {"entity": {"entity_id": entity["entity_id"],
                           "name": entity.get("name", "")},
                "firewalls": firewalls}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd services/mcp-query && uv run pytest tests/test_access_tools.py -k observed_by -v`
Expected: PASS (all three tests).

- [ ] **Step 5: Commit**

```bash
git add services/mcp-query/src/ssdf_mcp_query/access_tools.py services/mcp-query/tests/test_access_tools.py
git commit -m "feat(m12): AccessTools.observed_by L3-provenance firewall tool"
```

---

## Task 4: Component B — `AccessTools.configured_policies`

**Files:**
- Modify: `services/mcp-query/src/ssdf_mcp_query/access_tools.py`
- Test: `services/mcp-query/tests/test_access_tools.py`

`configured_policies` accepts one firewall name or a list, calls
`configured_policies_for_firewalls`, groups rows per firewall, deduplicates by policy
`entity_id` (fixes the ReplacingMergeTree duplicate-version count trap), and returns a
per-firewall rule list plus a deduped `count`.

- [ ] **Step 1: Write the failing test**

Append to `services/mcp-query/tests/test_access_tools.py`:

```python
def test_configured_policies_groups_dedupes_and_counts():
    # two distinct rules + one duplicate version of allow-web (same entity_id) -> count 2
    rows = [
        {"firewall": "panosvm",
         "policy": {"entity_id": "p1", "name": "allow-web",
                    "attrs": {"action": "allow", "from_zone": "trust",
                              "to_zone": "untrust", "position": "0", "enabled": "true"}}},
        {"firewall": "panosvm",
         "policy": {"entity_id": "p1", "name": "allow-web",
                    "attrs": {"action": "allow", "from_zone": "trust",
                              "to_zone": "untrust", "position": "0", "enabled": "true"}}},
        {"firewall": "panosvm",
         "policy": {"entity_id": "p2", "name": "deny-all",
                    "attrs": {"action": "deny", "from_zone": "any",
                              "to_zone": "any", "position": "1", "enabled": "false"}}},
    ]
    access = AccessTools(_StoreWithConfigured(rows), _TopoOneFw())
    out = access.configured_policies("panosvm")
    assert len(out["firewalls"]) == 1
    fw = out["firewalls"][0]
    assert fw["firewall"] == "panosvm"
    assert fw["count"] == 2
    names = sorted(r["rule"] for r in fw["rules"])
    assert names == ["allow-web", "deny-all"]
    web = next(r for r in fw["rules"] if r["rule"] == "allow-web")
    assert web["action"] == "allow" and web["enabled"] is True and web["source"] == "configured"
    deny = next(r for r in fw["rules"] if r["rule"] == "deny-all")
    assert deny["enabled"] is False


def test_configured_policies_accepts_list_and_unknown_firewall_is_empty():
    access = AccessTools(_StoreWithConfigured([]), _TopoOneFw())
    out = access.configured_policies(["nope"])
    assert out["firewalls"] == []
```

Note: `_StoreWithConfigured` already exists in this test file and returns its `configured`
rows from `configured_policies_for_firewalls`.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd services/mcp-query && uv run pytest tests/test_access_tools.py -k configured_policies -v`
Expected: FAIL with `AttributeError: 'AccessTools' object has no attribute 'configured_policies'`.

- [ ] **Step 3: Write minimal implementation**

In `access_tools.py`, add this method to `AccessTools` (after `observed_by`):

```python
    def configured_policies(self, firewall) -> dict:
        """Configured security rules on the named firewall(s), grouped + deduped per firewall."""
        names = [firewall] if isinstance(firewall, str) else list(firewall)
        by_fw: dict[str, dict] = {}
        for item in self._store.configured_policies_for_firewalls(names):
            policy = item["policy"]
            attrs = policy.get("attrs", {})
            bucket = by_fw.setdefault(item["firewall"], {})
            bucket[policy["entity_id"]] = {  # dedup by policy entity_id
                "rule": policy.get("name", ""),
                "action": attrs.get("action", ""),
                "from_zone": attrs.get("from_zone", ""),
                "to_zone": attrs.get("to_zone", ""),
                "position": attrs.get("position", ""),
                "enabled": attrs.get("enabled", "") == "true",
                "source": "configured",
            }
        firewalls = [{"firewall": name, "rules": list(rules.values()),
                      "count": len(rules)}
                     for name, rules in sorted(by_fw.items())]
        return {"firewalls": firewalls}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd services/mcp-query && uv run pytest tests/test_access_tools.py -k configured_policies -v`
Expected: PASS (both tests).

- [ ] **Step 5: Commit**

```bash
git add services/mcp-query/src/ssdf_mcp_query/access_tools.py services/mcp-query/tests/test_access_tools.py
git commit -m "feat(m12): AccessTools.configured_policies grouped deduped firewall rules"
```

---

## Task 5: Component C — `topology_snapshot` role/kind filter

**Files:**
- Modify: `services/mcp-query/src/ssdf_mcp_query/topo_tools.py:133-141`
- Test: `services/mcp-query/tests/test_topo_tools.py`

- [ ] **Step 1: Write the failing test**

Append to `services/mcp-query/tests/test_topo_tools.py`:

```python
def test_topology_snapshot_role_filters_to_firewalls():
    out = tools().topology_snapshot(role="firewall")
    names = {n["name"] for n in out["nodes"]}
    assert names == {"fw1"}              # only the role=firewall node survives
    assert out["node_count"] == 1
    # edges are pruned to those between surviving nodes
    for e in out["edges"]:
        assert e["src_id"] in {n["node_id"] for n in out["nodes"]}
        assert e["dst_id"] in {n["node_id"] for n in out["nodes"]}


def test_topology_snapshot_kind_filters_to_devices():
    out = tools().topology_snapshot(kind="device")
    kinds = {n["kind"] for n in out["nodes"]}
    assert kinds == {"device"}           # sw1 + fw1
    assert out["node_count"] == 2


def test_topology_snapshot_no_filter_unchanged():
    out = tools().topology_snapshot()
    assert out["node_count"] == len(NODES)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd services/mcp-query && uv run pytest tests/test_topo_tools.py -k topology_snapshot -v`
Expected: FAIL with `TypeError: topology_snapshot() got an unexpected keyword argument 'role'`.

- [ ] **Step 3: Write minimal implementation**

Replace the `topology_snapshot` method in `topo_tools.py` (lines 133-141) with:

```python
    def topology_snapshot(self, layer: str | None = None,
                          since_hours: int | None = None,
                          role: str | None = None,
                          kind: str | None = None) -> dict:
        nodes, edges = self._store.load_subgraph(_since(since_hours or self._window),
                                                 limit=MAX_NODES)
        if layer:
            edges = [e for e in edges if e.get("layer") == layer]
        if role is not None:
            nodes = [n for n in nodes if n.get("attrs", {}).get("role") == role]
        if kind is not None:
            nodes = [n for n in nodes if n.get("kind") == kind]
        if role is not None or kind is not None:
            keep = {n["node_id"] for n in nodes}
            edges = [e for e in edges if e["src_id"] in keep and e["dst_id"] in keep]
        truncated = len(nodes) >= MAX_NODES
        return {"nodes": nodes, "edges": edges, "node_count": len(nodes),
                "edge_count": len(edges), "truncated": truncated}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd services/mcp-query && uv run pytest tests/test_topo_tools.py -k topology_snapshot -v`
Expected: PASS (all three tests).

- [ ] **Step 5: Commit**

```bash
git add services/mcp-query/src/ssdf_mcp_query/topo_tools.py services/mcp-query/tests/test_topo_tools.py
git commit -m "feat(m12): topology_snapshot role/kind filter (additive)"
```

---

## Task 6: Components B + E classification — secure-by-default mapping

**Files:**
- Modify: `services/mcp-query/src/ssdf_mcp_query/classification.py:24-38`
- Test: `services/mcp-query/tests/test_classification.py`

- [ ] **Step 1: Write the failing test**

Append to `services/mcp-query/tests/test_classification.py`:

```python
def test_new_m12_tools_are_classified_and_never_shareable():
    from ssdf_mcp_query.classification import (
        classes_for_tool, is_tool_shareable, load_classification, Classification)

    assert classes_for_tool("configured_policies") == frozenset({"firewall_config"})
    assert classes_for_tool("observed_by") == frozenset({"security_log"})

    # even with topology+identity flipped shareable (the public config), neither
    # tool is shareable: firewall_config + security_log are not configurable.
    cls = Classification(labels={"security_log": "sovereign", "firewall_config": "sovereign",
                                 "topology": "shareable", "identity": "shareable"})
    assert is_tool_shareable(cls, "configured_policies") is False
    assert is_tool_shareable(cls, "observed_by") is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd services/mcp-query && uv run pytest tests/test_classification.py::test_new_m12_tools_are_classified_and_never_shareable -v`
Expected: FAIL — `classes_for_tool` returns empty frozenset, so the first assert fails.

- [ ] **Step 3: Write minimal implementation**

In `classification.py`, add two entries to `TOOL_DATA_CLASSES` (after the `explain_access` entry):

```python
    "configured_policies": frozenset({"firewall_config"}),
    "observed_by": frozenset({"security_log"}),
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd services/mcp-query && uv run pytest tests/test_classification.py::test_new_m12_tools_are_classified_and_never_shareable -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add services/mcp-query/src/ssdf_mcp_query/classification.py services/mcp-query/tests/test_classification.py
git commit -m "feat(m12): classify configured_policies + observed_by (secure-by-default)"
```

---

## Task 7: Register the two new sovereign tools in the server

**Files:**
- Modify: `services/mcp-query/src/ssdf_mcp_query/server.py:113-134`
- Test: `services/mcp-query/tests/test_server_entity.py`

- [ ] **Step 1: Write the failing test**

Append to `services/mcp-query/tests/test_server_entity.py`:

```python
def test_m12_sovereign_tools_registered(monkeypatch):
    import ssdf_mcp_query.server as server

    class _Dummy:
        def __init__(self, *a, **k):
            pass

    monkeypatch.setattr(server, "ClickHouseClient", _Dummy)
    names = _registered_tool_names(server.build_app())
    assert "configured_policies" in names
    assert "observed_by" in names


def test_m12_tools_absent_on_public(monkeypatch):
    import ssdf_mcp_query.server as server

    class _Dummy:
        def __init__(self, *a, **k):
            pass

    monkeypatch.setattr(server, "ClickHouseClient", _Dummy)
    names = _registered_tool_names(server.build_app(tier="public"))
    assert "configured_policies" not in names
    assert "observed_by" not in names
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd services/mcp-query && uv run pytest tests/test_server_entity.py -k m12 -v`
Expected: FAIL on `test_m12_sovereign_tools_registered` (tools not registered).

- [ ] **Step 3: Write minimal implementation**

In `server.py`, define the two wrappers inside `build_app` immediately after the
`explain_access` wrapper (after line 119):

```python
    def configured_policies(firewall) -> dict:
        """Configured security rules on the named firewall(s) (e.g. "panosvm" or a list).
        Returns {firewalls:[{firewall, rules:[{rule,action,from_zone,to_zone,position,
        enabled,source}], count}]}. `count` is the de-duplicated configured-policy count
        for that firewall — use this to answer "how many rules does firewall X have"."""
        return access.configured_policies(firewall)

    def observed_by(identifier: str, since_hours: int | None = None) -> dict:
        """Which firewall(s) actually LOGGED traffic for this IP/asset (L3 provenance).
        Accepts ip/mac/name. Returns {entity, firewalls:[<device names>]} — device names,
        not vendor strings, and multiple when several firewalls observed the flow. Use this
        for "which firewall sees/observes traffic from X", NOT locate (which is L2 attach)."""
        return access.observed_by(identifier, since_hours=since_hours)
```

Then extend the sovereign-only block (currently line 133-134) so all three register together:

```python
    if access is not None:  # sovereign-only (L5): never a candidate on public
        raw_tools["explain_access"] = explain_access
        raw_tools["configured_policies"] = configured_policies
        raw_tools["observed_by"] = observed_by
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd services/mcp-query && uv run pytest tests/test_server_entity.py -k m12 -v`
Expected: PASS (both tests).

- [ ] **Step 5: Commit**

```bash
git add services/mcp-query/src/ssdf_mcp_query/server.py services/mcp-query/tests/test_server_entity.py
git commit -m "feat(m12): register configured_policies + observed_by sovereign tools"
```

---

## Task 8: Component C wiring + Component A descriptions in the server

**Files:**
- Modify: `services/mcp-query/src/ssdf_mcp_query/server.py` (`topology_snapshot` wrapper + docstrings)
- Test: `services/mcp-query/tests/test_server_topo.py`

- [ ] **Step 1: Write the failing test**

First inspect the existing topo server test to mirror its harness:

Run: `cd services/mcp-query && sed -n '1,40p' tests/test_server_topo.py`

Then append a test that calls the registered `topology_snapshot` with `role`. If
`test_server_topo.py` builds the app and invokes tools through a fake store, follow that
pattern. If it does not exercise tool invocation, add this minimal direct-wrapper check
instead (it asserts the server passes `role` through to `TopoTools`):

```python
def test_server_topology_snapshot_passes_role(monkeypatch):
    import ssdf_mcp_query.server as server

    class _Dummy:
        def __init__(self, *a, **k):
            pass

    captured = {}

    class _FakeTopo:
        def __init__(self, *a, **k):
            pass

        def topology_snapshot(self, layer=None, since_hours=None, role=None, kind=None):
            captured["role"] = role
            return {"nodes": [], "edges": [], "node_count": 0, "edge_count": 0,
                    "truncated": False}

    monkeypatch.setattr(server, "ClickHouseClient", _Dummy)
    monkeypatch.setattr(server, "TopoTools", _FakeTopo)
    app = server.build_app()
    import asyncio
    asyncio.run(app.call_tool("topology_snapshot", {"role": "firewall"}))
    assert captured["role"] == "firewall"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd services/mcp-query && uv run pytest tests/test_server_topo.py::test_server_topology_snapshot_passes_role -v`
Expected: FAIL — the server's `topology_snapshot` wrapper does not accept/forward `role`.

- [ ] **Step 3: Write minimal implementation**

In `server.py`, replace the `topology_snapshot` wrapper (lines 109-111) with a version that
accepts and forwards the new params and documents them:

```python
    def topology_snapshot(layer: str | None = None, since_hours: int | None = None,
                          role: str | None = None, kind: str | None = None) -> dict:
        """Bounded nodes+edges subgraph for visualization/LLM context; reports truncation.
        Filter with `role` (e.g. "firewall") or `kind` (e.g. "device") to enumerate just
        those nodes — use role="firewall" to list the firewalls in the topology."""
        return topo.topology_snapshot(layer=layer, since_hours=since_hours,
                                      role=role, kind=kind)
```

Then sharpen the routing-relevant docstrings (Component A). Replace the `query_flows`,
`locate`, `neighbors`, and `explain_access` wrapper docstrings with:

`query_flows` docstring body:

```python
        """Query RAW normalized flow events (one row per event) with optional filters and a
        time window. `provider` is a VENDOR string (e.g. "paloalto"/"juniper"), NOT a
        firewall device identity — for "which firewall" questions use explain_access or
        observed_by. Times accept ISO-8601 or relative ("now-1h"); default window 24h.
        Returns rows plus {row_count, truncated, elapsed_ms} or {error, detail}."""
```

`locate` docstring body:

```python
        """Where an entity is ATTACHED at L2: switch/AP (or hypervisor bridge), port, VLAN.
        This is physical attachment, NOT firewall observation — for "which firewall sees
        this IP" use observed_by."""
```

`neighbors` docstring body:

```python
        """L2/L3-adjacent nodes/edges around an entity, optionally filtered by layer
        (l2|l3|flow|virt). Adjacency only — for firewall attribution use explain_access
        (which rule/firewall) or observed_by (which firewall logged it)."""
```

`explain_access` docstring body:

```python
        """End-to-end view for a client->server pair: observed flows + observed controls +
        CONFIGURED rules + topology path. Owns "which rule / which firewall" questions; its
        `firewalls` are DEVICE NAMES (not vendor strings). `configured_controls` lists rules
        on the path firewalls (no match-scoring); `coverage` reports observed (bool) and
        configured (rule count); `firewall_basis` is provenance|topology|no_path_firewall.
        Accepts ip/mac/name."""
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd services/mcp-query && uv run pytest tests/test_server_topo.py::test_server_topology_snapshot_passes_role -v`
Expected: PASS.

- [ ] **Step 5: Run the full unit suite to confirm no regressions**

Run: `cd services/mcp-query && uv run pytest -m "not integration"`
Expected: PASS (all tests green).

- [ ] **Step 6: Commit**

```bash
git add services/mcp-query/src/ssdf_mcp_query/server.py services/mcp-query/tests/test_server_topo.py
git commit -m "feat(m12): topology_snapshot role passthrough + routing-sharpened tool descriptions"
```

---

## Task 9: Component D — corpus fixes (golden/core.yaml)

**Files:**
- Modify: `services/evals/golden/core.yaml`
- Test (lint): `cd services/evals && uv run pytest -m "not integration"`

This task has a **live-data verification step**: the firewall-inventory expectation and the
`topo-locate-labgen` reference must reflect the real lab. Use the read-only `run_sql` MCP
tool or `clickhouse-client` against ct104 to ground the values before editing.

- [ ] **Step 1: Verify the live firewall-role node set**

Run (read-only) against the live entity graph to list device nodes with role=firewall:

```sql
SELECT DISTINCT name FROM ssdf.entities FINAL
WHERE kind = 'device' AND identifiers['role'] = 'firewall'
ORDER BY name
```

If `identifiers['role']` is not populated, fall back to the graph-node form used by
`enforcement_points` (kind=device, attrs.role=firewall) via the topology snapshot:
inspect `topology_snapshot(role="firewall")` output on the live ct106 endpoint and record
the exact `name` set. Write the observed set down — it is the new expectation.

Expected: a small set, e.g. `[panosvm, vSRX-Production, vSRX-test10]` (the Phase-2 lab adds
vSRX-Production). Use the ACTUAL observed names, not this example.

- [ ] **Step 2: Update the `topo-firewall-inventory` expectation**

In `services/evals/golden/core.yaml`, edit the `topo-firewall-inventory` question's
`predicate.expected.firewalls` list to the set recorded in Step 1. Example diff (replace
with the real set):

```yaml
  predicate:
    type: expected_json
    expected: {firewalls: [panosvm, vSRX-Production, vSRX-test10]}
```

- [ ] **Step 3: Make the `topo-locate-labgen` reference emit short device labels**

The reference SQL currently returns the full `observer_hostname` (FQDN), which cannot
overlap the short device names `observed_by` returns. Align it to the project's short-label
contract (matching `reach-firewall-attribution`'s `splitByChar`). Edit the
`topo-locate-labgen` predicate SQL to:

```yaml
  predicate:
    type: reference_sql
    sql: >-
      SELECT DISTINCT splitByChar('.', observer_hostname)[1] FROM ssdf.events
      WHERE source_ip = toIPv6('10.74.11.20') AND observer_hostname != ''
    match: set_overlap
    answer_key: firewalls
    params: {min_overlap: 1}
```

- [ ] **Step 4: Re-point `topo-locate-labgen` required_tools to the new owner**

The question "which firewall(s) observe traffic from IP X" is now owned by `observed_by`
(L3 provenance), not `locate` (L2 attach). Update its `required_tools`:

```yaml
  required_tools: [observed_by]
```

Leave all other questions' `required_tools` unchanged (strict mandates stay strict).

- [ ] **Step 5: Run the corpus lint**

Run: `cd services/evals && uv run pytest -m "not integration"`
Expected: PASS — unique ids, SELECT-only SQL, public-tool restriction all still hold.
(`observed_by` is sovereign-tier; `topo-locate-labgen` is tier `both` — confirm the lint's
public-tool restriction does not flag it. If the lint requires every `both`/`public`
question's `required_tools` to be public-exposable, change `topo-locate-labgen`'s `tier` to
`sovereign`, since L3 provenance is sovereign-only, and note it in the commit.)

- [ ] **Step 6: Commit**

```bash
git add services/evals/golden/core.yaml
git commit -m "test(m12): refresh firewall-inventory expectation + route locate-labgen to observed_by"
```

---

## Task 10: Full suite, deploy, and live re-eval

**Files:** none (validation + deploy)

- [ ] **Step 1: Run both unit suites**

Run:
```bash
cd services/mcp-query && uv run pytest -m "not integration"
cd ../evals && uv run pytest -m "not integration"
```
Expected: all PASS.

- [ ] **Step 2: Scan for vulnerabilities in the changed surface**

Confirm no new raw SQL interpolation (all new SQL is parameterized — `observers_for_ips`
uses `{ips:Array(String)}`/`{since:String}`) and that the two new tools are sovereign-only
(absent on public, proven by `test_m12_tools_absent_on_public`). Confirm no secret/PII is
logged by the new code paths.

- [ ] **Step 3: Deploy to ct106 (sovereign)**

ct106 is an editable install at `/opt/src/mcp-query/src`. Sync the changed source and
restart:

```bash
# from the dev host, push the updated package source to ct106, then:
ssh root@pve3.example.com "pct exec 106 -- systemctl restart ssdf-mcp-query.service"
ssh root@pve3.example.com "pct exec 106 -- systemctl is-active ssdf-mcp-query.service"
```
Expected: `active`. Public ct113 is unchanged (no redeploy — the new tools never register there).

- [ ] **Step 4: Live smoke-test the three new behaviors**

Against the live sovereign MCP endpoint (or via `clickhouse-client` to cross-check):
- `configured_policies("panosvm")` → one firewall bucket with `count == 7`.
- `topology_snapshot(role="firewall")` → exactly the firewall set recorded in Task 9 Step 1.
- `observed_by("10.74.11.20")` → `firewalls` includes `panosvm`.

- [ ] **Step 5: Re-run the claude sovereign eval and commit the scorecard**

Run the external runner (sibling repo `~/ssdf-eval-runner/`) sovereign tier against the live
endpoint with the `eval-claude` principal, then score:

```bash
cd services/evals && uv run python -m ssdf_evals.score <new-manifest.json>
```
Expected: `reach-configured-policy-count-panosvm` (#3), `topo-firewall-inventory` (#6), and
`topo-locate-labgen` (#5) flip to PASS deterministically; `reach-rule-trust-untrust` (#1) and
`reach-firewall-attribution` (#2) remain probabilistic (description nudge only). Commit the
new scorecard under `services/evals/results/` (git history is the eval database).

- [ ] **Step 6: Run the regression gate**

Run: `cd services/evals && uv run python -m ssdf_evals.regress results/<new-scorecard>.json`
Expected: exit 0 (no regressions vs the prior committed sovereign scorecard).

- [ ] **Step 7: Update STATUS.md + CLAUDE.md M12 section**

Add an M12 entry to `docs/superpowers/STATUS.md` (milestone ledger) and a `### M12` commands
block to `CLAUDE.md` documenting the two new tools, the `topology_snapshot` role filter, and
the corpus fixes. Commit.

```bash
git add docs/superpowers/STATUS.md CLAUDE.md
git commit -m "docs(m12): record MCP ergonomics tools + corpus fixes as-built"
```

---

## Self-Review Notes

- **Spec coverage:** A (Task 8 docstrings) · B (`configured_policies`: Tasks 4, 6, 7) ·
  C (`topology_snapshot` filter: Tasks 5, 8) · D (corpus: Task 9) · E (`observed_by`:
  Tasks 1, 2, 3, 6, 7). Testing + deploy + re-eval: Task 10. All five components covered.
- **Determinism:** #3/#5/#6 fixed by B/E + C/D (deterministic); #1/#2 only nudged by A
  (probabilistic) — matches the spec's risk note.
- **Type consistency:** `observers_for_ips(ips, since_iso)` signature identical in builder
  test (Task 1), Protocol + method (Task 2), and `observed_by` call site (Task 3).
  `configured_policies(firewall)` returns `{firewalls:[{firewall,rules,count}]}` consistently
  in Task 4 impl/test and Task 7 server wrapper. `topology_snapshot(..., role, kind)`
  signature matches across Tasks 5 and 8.
- **Secure-by-default:** both new tools classed in Task 6 (`firewall_config`/`security_log`,
  non-configurable) AND constructed only under `access is not None` (Task 7) — two
  independent guarantees they never reach public.
