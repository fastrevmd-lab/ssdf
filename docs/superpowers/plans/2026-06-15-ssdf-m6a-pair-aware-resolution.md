# M6a Pair-Aware Resolution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `explain_access(client, server)` surface the correct firewall provenance when an identifier has multiple entity twins, by resolving each side to all candidates and selecting the pair that actually has `communicated_with` edges.

**Architecture:** Read-path-only change in `services/mcp-query`. Add two SQL builders + two store methods that return *all* candidate twins / multi-id edges (existing single-pick methods stay untouched). Rewrite `explain_access` resolution to pick the edge-bearing `(client, server)` pair via a pure `_select_pair` helper, falling back to today's confidence-first single pick (`sessions:0`) when no pair has edges. No schema, resolver, or data-migration changes.

**Tech Stack:** Python 3, FastMCP, ClickHouse (clickhouse-connect), pytest, uv.

Spec: `docs/superpowers/specs/2026-06-15-ssdf-m6a-pair-aware-resolution-design.md`

---

## File Structure

- `services/mcp-query/src/ssdf_mcp_query/entitystore.py` — add `build_entities_match_sql`, `build_comm_edges_multi_sql`, `ClickHouseEntityStore.find_entities`, `ClickHouseEntityStore.communicated_edges_multi`, and two `EntityStore` Protocol methods. Existing builders/methods unchanged.
- `services/mcp-query/src/ssdf_mcp_query/access_tools.py` — add module-level `_select_pair` helper; rewrite the resolution head of `explain_access` to be pair-aware. Everything after edge selection is unchanged.
- `services/mcp-query/tests/test_entitystore.py` — unit tests for the two new builders + two new store methods.
- `services/mcp-query/tests/test_access_tools.py` — extend the existing fakes with the two new methods; add pair-selection unit tests + `_select_pair` direct tests.

All `cd` paths below are relative to `services/mcp-query` unless absolute.

---

### Task 1: entitystore SQL builders (`build_entities_match_sql`, `build_comm_edges_multi_sql`)

**Files:**
- Modify: `services/mcp-query/src/ssdf_mcp_query/entitystore.py` (add after `build_entity_match_sql` and `build_comm_edges_sql`)
- Test: `services/mcp-query/tests/test_entitystore.py`

- [ ] **Step 1: Write the failing tests**

Add to `services/mcp-query/tests/test_entitystore.py`. First extend the import block at the top of the file (lines 1-5) to include the two new builders:

```python
from ssdf_mcp_query.entitystore import (
    build_entity_match_sql, build_comm_edges_sql, build_governed_by_sql,
    build_entities_by_id_sql, ClickHouseEntityStore,
    build_entities_match_sql, build_comm_edges_multi_sql,
)
from ssdf_mcp_query.entitystore import build_alerts_for_pair_sql
```

Then append these tests to the file:

```python
def test_build_entities_match_sql_omits_limit_keeps_order():
    # Same match as build_entity_match_sql but returns ALL twins (no LIMIT 1),
    # keeping confidence-first order so row 0 == what find_entity returns today.
    sql, params = build_entities_match_sql("198.51.100.150", tenant="t_main")
    assert "ssdf.entities FINAL" in sql
    assert "LIMIT 1" not in sql
    assert "ORDER BY confidence DESC, entities.last_seen DESC" in sql
    assert "has(mapValues(identifiers), {val:String})" in sql
    assert params["val"] == "198.51.100.150"
    assert params["tenant"] == "t_main"


def test_build_entities_match_sql_lowercases_mac():
    _, params = build_entities_match_sql("AA:BB:CC:DD:EE:FF", tenant="t_main")
    assert params["val"] == "aa:bb:cc:dd:ee:ff"


def test_build_comm_edges_multi_sql_in_lists_both_directions():
    sql, params = build_comm_edges_multi_sql(
        ["A1", "A2"], ["B1"], "2026-06-15T00:00:00.000", tenant="t_main")
    assert "edge_type = 'communicated_with'" in sql
    # qualified column so the toString(last_seen) alias doesn't lexically drop rows
    assert "entity_edges.last_seen >= {since:String}" in sql
    assert "src_id IN {a:Array(String)} AND dst_id IN {b:Array(String)}" in sql
    assert "src_id IN {b:Array(String)} AND dst_id IN {a:Array(String)}" in sql
    assert params["a"] == ["A1", "A2"]
    assert params["b"] == ["B1"]
    assert params["since"] == "2026-06-15T00:00:00.000"
    assert params["tenant"] == "t_main"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd services/mcp-query && uv run pytest tests/test_entitystore.py -k "entities_match_sql or comm_edges_multi_sql" -v`
Expected: FAIL with `ImportError: cannot import name 'build_entities_match_sql'`

- [ ] **Step 3: Write the builders**

In `services/mcp-query/src/ssdf_mcp_query/entitystore.py`, insert `build_entities_match_sql` immediately after `build_entity_match_sql` (after line 31), and `build_comm_edges_multi_sql` immediately after `build_comm_edges_sql` (after line 46):

```python
def build_entities_match_sql(value: str, tenant: str) -> tuple[str, dict]:
    # Identical match to build_entity_match_sql WITHOUT LIMIT 1: returns every
    # candidate twin for the identifier. Order is preserved (confidence DESC,
    # last_seen DESC) so row 0 is the same entity find_entity returns today.
    sql = (
        f"SELECT {_ENTITY_COLS} FROM ssdf.entities FINAL "
        "WHERE tenant_id = {tenant:String} AND ("
        "entity_id = {val:String} OR has(mapValues(identifiers), {val:String})) "
        "ORDER BY confidence DESC, entities.last_seen DESC"
    )
    return sql, {"tenant": tenant, "val": _normalize_identifier(value)}
```

```python
def build_comm_edges_multi_sql(a_ids: list[str], b_ids: list[str], since_iso: str,
                               tenant: str) -> tuple[str, dict]:
    # Same shape as build_comm_edges_sql but with IN-lists on both directions, so
    # candidate twin sets on each side are matched in one query. `entity_edges.last_seen`
    # is qualified per the alias-shadowing note above (unqualified binds the String alias).
    sql = (
        f"SELECT {_EDGE_COLS} FROM ssdf.entity_edges FINAL "
        "WHERE tenant_id = {tenant:String} AND edge_type = 'communicated_with' "
        "AND entity_edges.last_seen >= {since:String} AND ("
        "(src_id IN {a:Array(String)} AND dst_id IN {b:Array(String)}) OR "
        "(src_id IN {b:Array(String)} AND dst_id IN {a:Array(String)}))"
    )
    return sql, {"tenant": tenant, "a": a_ids, "b": b_ids, "since": since_iso}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd services/mcp-query && uv run pytest tests/test_entitystore.py -k "entities_match_sql or comm_edges_multi_sql" -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add services/mcp-query/src/ssdf_mcp_query/entitystore.py services/mcp-query/tests/test_entitystore.py
git commit -m "feat(m6a): entitystore builders for all-twins match + multi-id comm edges"
```

---

### Task 2: entitystore store methods (`find_entities`, `communicated_edges_multi`) + Protocol

**Files:**
- Modify: `services/mcp-query/src/ssdf_mcp_query/entitystore.py` (Protocol lines 109-114; `ClickHouseEntityStore` methods after line 131)
- Test: `services/mcp-query/tests/test_entitystore.py`

- [ ] **Step 1: Write the failing tests**

Append to `services/mcp-query/tests/test_entitystore.py` (the file already defines `_FakeCH` at line 67, whose `run()` pops one row-batch per call and raises `IndexError` if called with no batches queued — use that to assert "no query"):

```python
def test_store_find_entities_returns_all_rows():
    ch = _FakeCH([[{"entity_id": "x"}, {"entity_id": "y"}]])
    store = ClickHouseEntityStore(ch, tenant="t_main")
    assert store.find_entities("8.8.8.8") == [{"entity_id": "x"}, {"entity_id": "y"}]


def test_store_find_entities_empty_when_none():
    store = ClickHouseEntityStore(_FakeCH([[]]), tenant="t_main")
    assert store.find_entities("nope") == []


def test_store_communicated_edges_multi_skips_query_when_either_list_empty():
    ch = _FakeCH([])  # no batches queued: any run() call would IndexError
    store = ClickHouseEntityStore(ch, tenant="t_main")
    assert store.communicated_edges_multi([], ["B"], "2026-06-15T00:00:00.000") == []
    assert store.communicated_edges_multi(["A"], [], "2026-06-15T00:00:00.000") == []
    assert ch.calls == []


def test_store_communicated_edges_multi_runs_query():
    ch = _FakeCH([[{"edge_id": "E1"}]])
    store = ClickHouseEntityStore(ch, tenant="t_main")
    assert store.communicated_edges_multi(["A"], ["B"], "2026-06-15T00:00:00.000") == [
        {"edge_id": "E1"}]
    assert len(ch.calls) == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd services/mcp-query && uv run pytest tests/test_entitystore.py -k "find_entities or communicated_edges_multi" -v`
Expected: FAIL with `AttributeError: 'ClickHouseEntityStore' object has no attribute 'find_entities'`

- [ ] **Step 3: Add the Protocol methods and store methods**

In `services/mcp-query/src/ssdf_mcp_query/entitystore.py`, add two methods to the `EntityStore` Protocol (after line 111, the `communicated_edges` line):

```python
    def find_entities(self, identifier: str) -> list[dict]: ...
    def communicated_edges_multi(self, a_ids: list[str], b_ids: list[str],
                                 since_iso: str) -> list[dict]: ...
```

And add the two implementations to `ClickHouseEntityStore`, immediately after `communicated_edges` (after line 131):

```python
    def find_entities(self, identifier: str) -> list[dict]:
        sql, params = build_entities_match_sql(identifier, self._tenant)
        return self._ch.run(sql, params)["rows"]

    def communicated_edges_multi(self, a_ids: list[str], b_ids: list[str],
                                 since_iso: str) -> list[dict]:
        if not a_ids or not b_ids:
            return []
        sql, params = build_comm_edges_multi_sql(a_ids, b_ids, since_iso, self._tenant)
        return self._ch.run(sql, params)["rows"]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd services/mcp-query && uv run pytest tests/test_entitystore.py -v`
Expected: PASS (all tests in the file, including the 4 new ones)

- [ ] **Step 5: Commit**

```bash
git add services/mcp-query/src/ssdf_mcp_query/entitystore.py services/mcp-query/tests/test_entitystore.py
git commit -m "feat(m6a): find_entities + communicated_edges_multi store methods + Protocol"
```

---

### Task 3: `_select_pair` helper in access_tools

**Files:**
- Modify: `services/mcp-query/src/ssdf_mcp_query/access_tools.py` (add module-level function after `_short_host`, line 26)
- Test: `services/mcp-query/tests/test_access_tools.py`

- [ ] **Step 1: Write the failing tests**

Append to `services/mcp-query/tests/test_access_tools.py`. Update the import at the top of the file (line 3) to also import `_select_pair`:

```python
from ssdf_mcp_query.access_tools import AccessTools, _short_host, _select_pair
```

Then append:

```python
def test_select_pair_most_sessions_wins():
    edges = [
        {"src_id": "C", "dst_id": "Sa", "last_seen": "2026-06-15 10:00:00",
         "attrs": {"sessions": "2"}},
        {"src_id": "C", "dst_id": "Sb", "last_seen": "2026-06-15 09:00:00",
         "attrs": {"sessions": "9"}},
    ]
    client_id, server_id, picked = _select_pair(edges, {"C"}, {"Sa", "Sb"})
    assert (client_id, server_id) == ("C", "Sb")
    assert [e["dst_id"] for e in picked] == ["Sb"]


def test_select_pair_last_seen_breaks_session_tie():
    edges = [
        {"src_id": "C", "dst_id": "Sa", "last_seen": "2026-06-15 10:00:00",
         "attrs": {"sessions": "5"}},
        {"src_id": "C", "dst_id": "Sb", "last_seen": "2026-06-15 11:00:00",
         "attrs": {"sessions": "5"}},
    ]
    client_id, server_id, _ = _select_pair(edges, {"C"}, {"Sa", "Sb"})
    assert (client_id, server_id) == ("C", "Sb")


def test_select_pair_maps_reversed_direction():
    # edge stored server->client must still resolve to (client, server)
    edges = [{"src_id": "S", "dst_id": "C", "last_seen": "",
              "attrs": {"sessions": "3"}}]
    client_id, server_id, _ = _select_pair(edges, {"C"}, {"S"})
    assert (client_id, server_id) == ("C", "S")


def test_select_pair_none_when_no_edges():
    assert _select_pair([], {"C"}, {"S"}) is None


def test_select_pair_skips_edges_with_both_ends_in_one_set():
    # both ends fall in the client set -> ambiguous -> skipped -> None
    edges = [{"src_id": "C1", "dst_id": "C2", "last_seen": "",
              "attrs": {"sessions": "3"}}]
    assert _select_pair(edges, {"C1", "C2"}, {"S"}) is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd services/mcp-query && uv run pytest tests/test_access_tools.py -k "select_pair" -v`
Expected: FAIL with `ImportError: cannot import name '_select_pair'`

- [ ] **Step 3: Write `_select_pair`**

In `services/mcp-query/src/ssdf_mcp_query/access_tools.py`, add after `_short_host` (after line 26):

```python
def _select_pair(edges: list[dict], client_ids: set[str], server_ids: set[str]):
    """Pick the (client_id, server_id) pair with the most summed sessions.

    Groups edges onto the pair whose client end is in client_ids and server end in
    server_ids (mapping either edge direction). Tiebreak: greatest summed sessions,
    then greatest edge last_seen, then lexicographic (client_id, server_id) for
    determinism. Returns (client_id, server_id, edges_for_pair), or None when no edge
    maps cleanly onto exactly one client id + one server id.
    """
    pairs: dict[tuple[str, str], dict] = {}
    for edge in edges:
        src, dst = edge.get("src_id"), edge.get("dst_id")
        if src in client_ids and dst in server_ids:
            key = (src, dst)
        elif dst in client_ids and src in server_ids:
            key = (dst, src)
        else:
            continue  # both ends in the same candidate set: ambiguous, skip
        bucket = pairs.setdefault(key, {"edges": [], "sessions": 0, "last_seen": ""})
        bucket["edges"].append(edge)
        bucket["sessions"] += int(edge.get("attrs", {}).get("sessions", "0") or 0)
        last_seen = edge.get("last_seen", "")
        if last_seen > bucket["last_seen"]:
            bucket["last_seen"] = last_seen
    if not pairs:
        return None
    (client_id, server_id), bucket = max(
        pairs.items(),
        key=lambda item: (item[1]["sessions"], item[1]["last_seen"], item[0]))
    return client_id, server_id, bucket["edges"]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd services/mcp-query && uv run pytest tests/test_access_tools.py -k "select_pair" -v`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add services/mcp-query/src/ssdf_mcp_query/access_tools.py services/mcp-query/tests/test_access_tools.py
git commit -m "feat(m6a): _select_pair helper picks edge-bearing client/server twin pair"
```

---

### Task 4: pair-aware resolution in `explain_access` + update fakes

**Files:**
- Modify: `services/mcp-query/src/ssdf_mcp_query/access_tools.py` (`explain_access` head, lines 38-46)
- Test: `services/mcp-query/tests/test_access_tools.py` (extend fakes; add pair tests)

- [ ] **Step 1: Update the existing fakes so they implement the two new store methods**

The rewrite makes `explain_access` call `find_entities` + `communicated_edges_multi` instead of `find_entity` + `communicated_edges`. The existing fakes must implement them or every existing test breaks. Legacy comm fixtures omit `src_id`/`dst_id`; the fake stamps the top candidate of each side so `_select_pair` maps them onto the pair under test.

In `services/mcp-query/tests/test_access_tools.py`, add two methods to `_FakeStore` (after `communicated_edges`, line 16):

```python
    def find_entities(self, identifier):
        ent = self._entities.get(identifier)
        return [ent] if ent else []

    def communicated_edges_multi(self, a_ids, b_ids, since_iso):
        # legacy fixtures omit src_id/dst_id; stamp the top candidate of each side
        # so _select_pair maps them onto the (client, server) pair under test.
        # An edge that already carries src_id/dst_id keeps its own (explicit override).
        return [{"src_id": a_ids[0], "dst_id": b_ids[0], **edge} for edge in self._comm]
```

Add the same two methods to `_StoreWithConfigured` (after `communicated_edges`, line 112):

```python
    def find_entities(self, ident):
        return [self.find_entity(ident)]

    def communicated_edges_multi(self, a_ids, b_ids, since_iso):
        return []
```

(`_StoreProv` subclasses `_FakeStore`, so it inherits both methods.)

- [ ] **Step 2: Run the existing suite to confirm it still fails on the not-yet-rewritten tool**

Run: `cd services/mcp-query && uv run pytest tests/test_access_tools.py -v`
Expected: existing tests still PASS (the tool still calls `find_entity`/`communicated_edges`, which the fakes still provide). The fakes now ALSO expose the new methods, unused until Step 3.

- [ ] **Step 3: Write the failing pair-aware tests**

Append to `services/mcp-query/tests/test_access_tools.py`:

```python
class _PairStore:
    """EntityStore double returning explicit candidate twin sets + explicit edges.

    find_entities maps the literal "client"/"server" lookup strings to the two
    candidate lists; communicated_edges_multi returns the scripted edges verbatim
    (they already carry real src_id/dst_id).
    """

    def __init__(self, client_cands, server_cands, edges, configured=None):
        self._client_cands = client_cands
        self._server_cands = server_cands
        self._edges = edges
        self._configured = configured or []

    def find_entities(self, identifier):
        if identifier == "client":
            return self._client_cands
        if identifier == "server":
            return self._server_cands
        return []

    def communicated_edges_multi(self, a_ids, b_ids, since_iso):
        return self._edges

    def governed_policies(self, ids):
        return []

    def configured_policies_for_firewalls(self, names):
        return self._configured

    def alerts_for_pair(self, ips, since_iso):
        return []


def _ent(entity_id, basis="ip_only"):
    return {"entity_id": entity_id, "name": "8.8.8.8", "identity_basis": basis,
            "identifiers": {}}


def test_server_two_twins_picks_edge_bearing():
    client_cands = [_ent("C", basis="mac")]
    server_cands = [_ent("Sa"), _ent("Sb")]   # Sa has no edge; Sb does
    edges = [{"edge_id": "E1", "src_id": "C", "dst_id": "Sb",
              "last_seen": "2026-06-15 11:22:12",
              "attrs": {"sessions": "4", "bytes": "100", "ports": "53",
                        "providers": "juniper", "observer_hosts": "vSRX-Production"}}]
    out = AccessTools(_PairStore(client_cands, server_cands, edges),
                      _FakeTopo(["fwX"], {"found": True})).explain_access("client", "server")
    assert out["server"]["entity_id"] == "Sb"
    assert out["observed_flows"]["sessions"] == 4
    assert out["firewall_basis"] == "provenance"
    assert out["firewalls"] == ["vSRX-Production"]


def test_mac_vs_iponly_picks_edge_bearing():
    client_cands = [_ent("C", basis="mac")]
    # confidence-first order puts the MAC twin first, but the edge points to the ip_only twin
    server_cands = [_ent("Smac", basis="mac"), _ent("Sip", basis="ip_only")]
    edges = [{"edge_id": "E1", "src_id": "C", "dst_id": "Sip",
              "last_seen": "2026-06-15 11:22:12",
              "attrs": {"sessions": "2", "bytes": "10", "ports": "53",
                        "providers": "juniper", "observer_hosts": "vSRX-Production"}}]
    out = AccessTools(_PairStore(client_cands, server_cands, edges),
                      _FakeTopo(["fwX"], {"found": True})).explain_access("client", "server")
    assert out["server"]["entity_id"] == "Sip"
    assert out["firewall_basis"] == "provenance"
    assert out["firewalls"] == ["vSRX-Production"]


def test_no_edge_falls_back_confidence_first():
    client_cands = [_ent("C", basis="mac")]
    server_cands = [_ent("Sa"), _ent("Sb")]
    out = AccessTools(_PairStore(client_cands, server_cands, []),
                      _FakeTopo([], {"found": False})).explain_access("client", "server")
    assert out["client"]["entity_id"] == "C"
    assert out["server"]["entity_id"] == "Sa"        # candidates[0]
    assert out["observed_flows"]["sessions"] == 0
    assert out["firewall_basis"] == "no_path_firewall"
    assert out["coverage"]["observed"] is False


def test_single_twin_each_side_unchanged():
    # regression guard: one entity per side with an edge (panosvm-style) behaves as before
    client_cands = [_ent("C", basis="mac")]
    server_cands = [_ent("S")]
    edges = [{"edge_id": "E1", "src_id": "C", "dst_id": "S",
              "last_seen": "2026-06-15 11:22:12",
              "attrs": {"sessions": "7", "bytes": "100", "ports": "53",
                        "providers": "paloalto", "observer_hosts": "panosvm.example.com"}}]
    out = AccessTools(_PairStore(client_cands, server_cands, edges),
                      _FakeTopo(["fwX"], {"found": True})).explain_access("client", "server")
    assert out["server"]["entity_id"] == "S"
    assert out["observed_flows"]["sessions"] == 7
    assert out["firewall_basis"] == "provenance"
    assert out["firewalls"] == ["panosvm"]
```

- [ ] **Step 2b: Run the new tests to verify they fail**

Run: `cd services/mcp-query && uv run pytest tests/test_access_tools.py -k "two_twins or mac_vs_iponly or no_edge_falls_back or single_twin_each_side" -v`
Expected: FAIL — `explain_access` still calls `find_entity`/`communicated_edges`; `_PairStore` only implements the new methods, so it raises `AttributeError: '_PairStore' object has no attribute 'find_entity'`.

- [ ] **Step 3: Rewrite the resolution head of `explain_access`**

In `services/mcp-query/src/ssdf_mcp_query/access_tools.py`, replace lines 38-46 (the two `find_entity` calls, the `not_found` guard, the `window` assignment, and the single `communicated_edges` call):

```python
        client_cands = self._store.find_entities(client)
        server_cands = self._store.find_entities(server)
        if not client_cands or not server_cands:
            missing = client if not client_cands else server
            return {"error": "not_found", "detail": f"no entity matches '{missing}'"}

        window = since_hours or self._window
        client_ids = [c["entity_id"] for c in client_cands]
        server_ids = [s["entity_id"] for s in server_cands]
        edges = self._store.communicated_edges_multi(client_ids, server_ids, _since(window))

        selected = _select_pair(edges, set(client_ids), set(server_ids))
        if selected is not None:
            client_id, server_id, comm_edges = selected
            client_entity = next(c for c in client_cands if c["entity_id"] == client_id)
            server_entity = next(s for s in server_cands if s["entity_id"] == server_id)
        else:
            # no candidate pair has an edge: confidence-first single pick, sessions:0
            client_entity = client_cands[0]
            server_entity = server_cands[0]
            comm_edges = []
```

Everything from line 48 onward (the `sessions`/`bytes`/`ports`/`providers` summation and the rest of the method) is unchanged.

- [ ] **Step 4: Run the full access-tools suite to verify it passes**

Run: `cd services/mcp-query && uv run pytest tests/test_access_tools.py -v`
Expected: PASS — all pre-existing tests (regression) plus the 4 new pair tests plus the 5 `_select_pair` tests.

- [ ] **Step 5: Run the entire mcp-query unit suite (no regressions elsewhere)**

Run: `cd services/mcp-query && uv run pytest -m "not integration"`
Expected: PASS (whole suite green)

- [ ] **Step 6: Commit**

```bash
git add services/mcp-query/src/ssdf_mcp_query/access_tools.py services/mcp-query/tests/test_access_tools.py
git commit -m "feat(m6a): pair-aware twin resolution in explain_access (surfaces SRX provenance)"
```

---

### Task 5: Deploy to ct106 + live proof

**Files:** none (deploy + verification only). ct106 is an editable install at `/opt/src/mcp-query/src`; ct113 public tier does not construct `AccessTools`/`ClickHouseEntityStore` and is unaffected.

- [ ] **Step 1: Sync the two changed source files to ct106**

```bash
scp services/mcp-query/src/ssdf_mcp_query/entitystore.py \
    services/mcp-query/src/ssdf_mcp_query/access_tools.py \
    root@pve3.example.com:/tmp/
ssh root@pve3.example.com "pct push 106 /tmp/entitystore.py /opt/src/mcp-query/src/ssdf_mcp_query/entitystore.py && pct push 106 /tmp/access_tools.py /opt/src/mcp-query/src/ssdf_mcp_query/access_tools.py"
```

(If a direct `pct exec ... pct push` flow is already established in prior deploys, follow that instead — the requirement is only that both files land at `/opt/src/mcp-query/src/ssdf_mcp_query/` on ct106.)

- [ ] **Step 2: Restart the service**

```bash
ssh root@pve3.example.com "pct exec 106 -- systemctl restart ssdf-mcp-query.service && pct exec 106 -- systemctl is-active ssdf-mcp-query.service"
```
Expected: `active`

- [ ] **Step 3: Live-prove SRX provenance now surfaces (the fix)**

Call the live `explain_access` MCP tool (sovereign tier) for the SRX endpoint → 8.8.8.8 and → 198.51.100.1:
- `explain_access("10.74.12.20", "8.8.8.8")`
- `explain_access("10.74.12.20", "198.51.100.1")`

Expected for both: `firewall_basis: "provenance"`, `firewalls: ["vSRX-Production"]`, `observed_flows.sessions > 0`.

- [ ] **Step 4: Live regression — panosvm path unchanged**

- `explain_access("10.74.11.20", "198.51.100.1")`

Expected: `firewall_basis: "provenance"`, `firewalls: ["panosvm"]`, `sessions > 0` (matching pre-change behavior).

- [ ] **Step 5: Live regression — not_found path unchanged**

- `explain_access("203.0.113.250", "8.8.8.8")` (an identifier that resolves to no entity)

Expected: `{"error": "not_found", "detail": "no entity matches '203.0.113.250'"}` (substitute any guaranteed-absent identifier).

---

## Self-Review

- **Spec coverage:** Component 1 (`build_entities_match_sql`, `build_comm_edges_multi_sql`, `find_entities`, `communicated_edges_multi`, Protocol) → Tasks 1-2. Component 2 (pair-aware `explain_access` + `_select_pair`) → Tasks 3-4. Test plan (entitystore builders/methods, `_select_pair` direct, pair-selection, fallback, regression) → Tasks 1-4 steps. Live proof → Task 5. All spec sections mapped.
- **Type consistency:** `find_entities(identifier) -> list[dict]`, `communicated_edges_multi(a_ids, b_ids, since_iso) -> list[dict]`, `_select_pair(edges, client_ids: set, server_ids: set) -> tuple[str, str, list[dict]] | None` — names/signatures identical across builder, store, Protocol, helper, and the `explain_access` call site (`set(client_ids)`/`set(server_ids)` passed positionally).
- **Placeholder scan:** none — every code step contains full code; the one conditional in Task 5 Step 1 ("if a direct flow is established") is an operational note, not a code placeholder.
- **Edge cases:** empty candidate list → `not_found` (Task 4); empty id list → no query (Task 2); no edge → confidence-first fallback `sessions:0` (Task 4); reversed edge direction + same-set ambiguity (Task 3).
