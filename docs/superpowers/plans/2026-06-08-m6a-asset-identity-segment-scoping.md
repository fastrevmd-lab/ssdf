# M6a Asset Identity — Segment Scoping & Duplicate Reconciliation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Asset identity MAC-anchored with IP treated as a segment-local observation, preventing and reconciling the duplicate `ip_only` twins that corrupt by-IP `explain_access` provenance.

**Architecture:** The entity resolver keys Assets by MAC when an ARP binding exists, else by a segment-scoped IP key `ip:<segment>:<ip>` (segment = normalized firewall vantage). The binding map is built from `topo_observations` `arp_entry` rows over a multi-day lookback (sticky, so a single missed pass no longer spawns a twin). A standalone `reconcile_assets` pass merges existing twins into their MAC asset and deletes them. `find_entity` orders by confidence so a MAC asset always wins a by-IP lookup.

**Tech Stack:** Python 3, `clickhouse_connect`, ClickHouse (ReplacingMergeTree), pytest. Services: `services/entity` (resolver, ct109) and `services/mcp-query` (tools, ct106).

---

## File Structure

- `services/entity/src/ssdf_entity/resolve_entities.py` — pure resolver. Gains `normalize_segment`, `build_binding_map`, and segment-scoped `asset_for`. Signature changes `topo_hosts` → `bindings`.
- `services/entity/src/ssdf_entity/chwriter.py` — CH I/O. `build_topo_hosts_sql` removed; `build_binding_sql` added; `build_flow_agg_sql` groups by observer; new `delete_entities`/`delete_edges` + reconcile-read SQL helpers.
- `services/entity/src/ssdf_entity/config.py` — add `binding_lookback_hours`.
- `services/entity/src/ssdf_entity/resolve_main.py` — wire `build_binding_sql` into `run_resolver`.
- `services/entity/src/ssdf_entity/reconcile_assets.py` — NEW. Pure `plan_reconciliation` + thin `reconcile` executor + `main`.
- `services/mcp-query/src/ssdf_mcp_query/entitystore.py` — `build_entity_match_sql` confidence-first ordering.
- Tests mirror each module under `services/*/tests/`.

**Run unit tests for entity:** `cd services/entity && uv run --with pytest pytest -m "not integration" -q`
**Run unit tests for mcp-query:** `cd services/mcp-query && uv run --with pytest pytest -m "not integration" -q`

---

### Task 1: `normalize_segment` helper

**Files:**
- Modify: `services/entity/src/ssdf_entity/resolve_entities.py`
- Test: `services/entity/tests/test_resolve_entities.py`

- [ ] **Step 1: Write the failing test**

Append to `services/entity/tests/test_resolve_entities.py`:

```python
def test_normalize_segment_strips_domain_and_lowercases():
    from ssdf_entity.resolve_entities import normalize_segment
    assert normalize_segment("panosvm.example.com") == "panosvm"
    assert normalize_segment("vSRX-test10") == "vsrx-test10"
    assert normalize_segment("FW1.local") == "fw1"


def test_normalize_segment_empty_becomes_unknown():
    from ssdf_entity.resolve_entities import normalize_segment
    assert normalize_segment("") == "unknown"
    assert normalize_segment(None) == "unknown"
    assert normalize_segment("   ") == "unknown"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd services/entity && uv run --with pytest pytest tests/test_resolve_entities.py -k normalize_segment -q`
Expected: FAIL with `ImportError: cannot import name 'normalize_segment'`.

- [ ] **Step 3: Implement the helper**

In `services/entity/src/ssdf_entity/resolve_entities.py`, after the imports block (after line 13), add:

```python
def normalize_segment(name: str | None) -> str:
    """Reduce a firewall vantage name to a comparable segment key.

    Takes the first dotted label, lowercased, so the flow-side ECS
    observer.hostname (often an FQDN) and the binding-side source_device
    (a short device name) agree. Empty/unknown collapses to 'unknown'.
    """
    label = (name or "").split(".")[0].strip().lower()
    return label or "unknown"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd services/entity && uv run --with pytest pytest tests/test_resolve_entities.py -k normalize_segment -q`
Expected: PASS (2 passed).

- [ ] **Step 5: Commit**

```bash
git add services/entity/src/ssdf_entity/resolve_entities.py services/entity/tests/test_resolve_entities.py
git commit -m "feat(m6a): add normalize_segment for firewall-vantage segment keys"
```

---

### Task 2: `build_binding_map` — segment-scoped binding + conflict detection

**Files:**
- Modify: `services/entity/src/ssdf_entity/resolve_entities.py`
- Test: `services/entity/tests/test_resolve_entities.py`

- [ ] **Step 1: Write the failing test**

Append to `services/entity/tests/test_resolve_entities.py`:

```python
def test_build_binding_map_keys_by_segment_and_ip():
    from ssdf_entity.resolve_entities import build_binding_map
    rows = [
        {"source_device": "fwA", "ip": "198.51.100.150", "mac": "aa:aa:aa:aa:aa:aa",
         "observed_at": "2026-06-08 10:00:00.000"},
        {"source_device": "fwB", "ip": "198.51.100.150", "mac": "bb:bb:bb:bb:bb:bb",
         "observed_at": "2026-06-08 10:00:00.000"},
    ]
    binding_map, conflict = build_binding_map(rows)
    assert binding_map[("fwa", "198.51.100.150")] == "aa:aa:aa:aa:aa:aa"
    assert binding_map[("fwb", "198.51.100.150")] == "bb:bb:bb:bb:bb:bb"
    assert conflict == set()  # different segments => not a conflict


def test_build_binding_map_latest_observation_wins():
    from ssdf_entity.resolve_entities import build_binding_map
    rows = [
        {"source_device": "fwA", "ip": "10.64.0.5", "mac": "aa:aa:aa:aa:aa:aa",
         "observed_at": "2026-06-08 09:00:00.000"},
        {"source_device": "fwA", "ip": "10.64.0.5", "mac": "cc:cc:cc:cc:cc:cc",
         "observed_at": "2026-06-08 11:00:00.000"},
    ]
    binding_map, conflict = build_binding_map(rows)
    assert binding_map[("fwa", "10.64.0.5")] == "cc:cc:cc:cc:cc:cc"
    assert conflict == {("fwa", "10.64.0.5")}  # same segment, two MACs => conflict


def test_build_binding_map_skips_missing_ip_or_mac():
    from ssdf_entity.resolve_entities import build_binding_map
    rows = [
        {"source_device": "fwA", "ip": "", "mac": "aa:aa:aa:aa:aa:aa",
         "observed_at": "2026-06-08 09:00:00.000"},
        {"source_device": "fwA", "ip": "10.64.0.5", "mac": "",
         "observed_at": "2026-06-08 09:00:00.000"},
    ]
    binding_map, conflict = build_binding_map(rows)
    assert binding_map == {}
    assert conflict == set()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd services/entity && uv run --with pytest pytest tests/test_resolve_entities.py -k build_binding_map -q`
Expected: FAIL with `ImportError: cannot import name 'build_binding_map'`.

- [ ] **Step 3: Implement the helper**

In `services/entity/src/ssdf_entity/resolve_entities.py`, directly below `normalize_segment`, add:

```python
def build_binding_map(bindings: list[dict]) -> tuple[dict[tuple[str, str], str], set[tuple[str, str]]]:
    """Build {(segment, ip) -> mac} (latest observation wins) and the set of
    (segment, ip) keys claimed by >1 MAC (genuine same-segment IP conflicts)."""
    latest: dict[tuple[str, str], tuple[str, str]] = {}   # key -> (observed_at, mac)
    macs_seen: dict[tuple[str, str], set[str]] = {}
    for binding in bindings:
        segment = normalize_segment(binding.get("source_device"))
        ip = binding.get("ip") or ""
        mac = (binding.get("mac") or "").lower()
        if not ip or not mac:
            continue
        key = (segment, ip)
        macs_seen.setdefault(key, set()).add(mac)
        observed_at = binding.get("observed_at") or ""
        if key not in latest or observed_at > latest[key][0]:
            latest[key] = (observed_at, mac)
    binding_map = {key: value[1] for key, value in latest.items()}
    conflict = {key for key, macs in macs_seen.items() if len(macs) > 1}
    return binding_map, conflict
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd services/entity && uv run --with pytest pytest tests/test_resolve_entities.py -k build_binding_map -q`
Expected: PASS (3 passed).

- [ ] **Step 5: Commit**

```bash
git add services/entity/src/ssdf_entity/resolve_entities.py services/entity/tests/test_resolve_entities.py
git commit -m "feat(m6a): segment-scoped binding map with same-segment conflict detection"
```

---

### Task 3: `build_binding_sql` + observer-grouped flow aggregate

**Files:**
- Modify: `services/entity/src/ssdf_entity/chwriter.py:21-46`
- Test: `services/entity/tests/test_chwriter.py`

> Note: `build_topo_hosts_sql` is left in place in this task (still imported by `resolve_main`); it is removed in Task 4 once the resolver is rewired. This keeps the suite green between tasks.

- [ ] **Step 1: Write the failing test**

In `services/entity/tests/test_chwriter.py`, update the import line at the top from:

```python
from ssdf_entity.chwriter import (
    build_flow_agg_sql, build_topo_hosts_sql, entity_rows, edge_rows,
    ENTITY_COLUMNS, ENTITY_EDGE_COLUMNS,
)
```

to:

```python
from ssdf_entity.chwriter import (
    build_flow_agg_sql, build_topo_hosts_sql, build_binding_sql,
    entity_rows, edge_rows, ENTITY_COLUMNS, ENTITY_EDGE_COLUMNS,
)
```

Replace the existing `test_flow_agg_sql_is_parameterized_and_groups_by_pair` test body so it asserts the observer grouping, and add a binding-SQL test:

```python
def test_flow_agg_sql_is_parameterized_and_groups_by_pair():
    sql, params = build_flow_agg_sql(window_hours=24, tenant="t_main")
    assert "{tenant:String}" in sql
    assert "{window_hours:UInt32}" in sql
    assert "GROUP BY src_ip, dst_ip, observer_hostname" in sql
    assert "groupUniqArray(destination_port)" in sql
    assert params == {"tenant": "t_main", "window_hours": 24}


def test_flow_agg_sql_selects_observer_hostname_per_row():
    sql, _ = build_flow_agg_sql(window_hours=24, tenant="t_main")
    assert "toString(observer_hostname) AS observer_hostname" in sql


def test_binding_sql_reads_arp_entries_with_source_device():
    sql, params = build_binding_sql(lookback_hours=168, tenant="t_main")
    assert "ssdf.topo_observations" in sql
    assert "observation_type = 'arp_entry'" in sql
    assert "source_device" in sql
    assert "replaceOne(subj_id, 'ip:', '') AS ip" in sql
    assert "replaceOne(obj_id, 'mac:', '') AS mac" in sql
    assert "{lookback_hours:UInt32}" in sql
    assert params == {"tenant": "t_main", "lookback_hours": 168}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd services/entity && uv run --with pytest pytest tests/test_chwriter.py -q`
Expected: FAIL with `ImportError: cannot import name 'build_binding_sql'`.

- [ ] **Step 3: Implement the SQL changes**

In `services/entity/src/ssdf_entity/chwriter.py`, replace `build_flow_agg_sql` (lines 21-37) with the version that selects and groups by `observer_hostname` per row (the `observer_hosts` set on the edge is rebuilt downstream by `_merge_set_attr`):

```python
def build_flow_agg_sql(window_hours: int, tenant: str) -> tuple[str, dict]:
    """Aggregate ssdf.events into per-(src_ip,dst_ip,observer) flow rows.

    Grouping by observer_hostname gives each row a single firewall vantage
    (its segment), so the resolver can scope IP identity. The COMMUNICATED_WITH
    edge's observer_hosts set is reassembled across rows in resolve_entities.
    """
    sql = (
        "SELECT toString(source_ip) AS src_ip, toString(destination_ip) AS dst_ip, "
        "toString(observer_hostname) AS observer_hostname, "
        "sum(network_bytes) AS bytes, count() AS flows, "
        "groupUniqArray(destination_port) AS ports, "
        "any(rule_name) AS rule_name, any(event_provider) AS provider, "
        "any(network_transport) AS transport, "
        "toString(min(timestamp)) AS first_seen, toString(max(timestamp)) AS last_seen "
        "FROM ssdf.events "
        "WHERE tenant_id = {tenant:String} "
        "AND timestamp >= now() - INTERVAL {window_hours:UInt32} HOUR "
        "AND source_ip IS NOT NULL AND destination_ip IS NOT NULL "
        "GROUP BY src_ip, dst_ip, observer_hostname"
    )
    return sql, {"tenant": tenant, "window_hours": window_hours}
```

Then add `build_binding_sql` directly after `build_topo_hosts_sql` (after line 46):

```python
def build_binding_sql(lookback_hours: int, tenant: str) -> tuple[str, dict]:
    """Read M4 arp_entry observations as (source_device, ip, mac, observed_at).

    Reads topo_observations (which retains source_device, unlike the flattened
    graph_nodes) over a lookback window so a transient single-pass binding drop
    does not orphan a host. subj_id is 'ip:<ip>', obj_id is 'mac:<mac>'.
    """
    sql = (
        "SELECT source_device, "
        "replaceOne(subj_id, 'ip:', '') AS ip, "
        "replaceOne(obj_id, 'mac:', '') AS mac, "
        "toString(observed_at) AS observed_at "
        "FROM ssdf.topo_observations "
        "WHERE tenant_id = {tenant:String} "
        "AND observation_type = 'arp_entry' "
        "AND observed_at >= now() - INTERVAL {lookback_hours:UInt32} HOUR"
    )
    return sql, {"tenant": tenant, "lookback_hours": lookback_hours}
```

> Note: the obsolete `test_flow_agg_sql_selects_observer_hosts` test (asserting `groupUniqArray(observer_hostname)`) must be deleted in this step — `observer_hostname` is now a grouping key, not a `groupUniqArray`. Remove that test function from `test_chwriter.py`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd services/entity && uv run --with pytest pytest tests/test_chwriter.py -q`
Expected: PASS (all chwriter tests green).

- [ ] **Step 5: Commit**

```bash
git add services/entity/src/ssdf_entity/chwriter.py services/entity/tests/test_chwriter.py
git commit -m "feat(m6a): observer-grouped flow agg + arp_entry binding SQL"
```

---

### Task 4: Rewire resolver to segment-scoped bindings

This task changes `resolve_entities`' signature (`topo_hosts` → `bindings`), makes `asset_for` segment-scoped, wires `run_resolver` + `config` to the new binding query, and removes the now-dead `build_topo_hosts_sql`. All callers and tests are updated together so the suite stays green.

**Files:**
- Modify: `services/entity/src/ssdf_entity/resolve_entities.py:51-135`
- Modify: `services/entity/src/ssdf_entity/config.py:13-36`
- Modify: `services/entity/src/ssdf_entity/resolve_main.py:1-30`
- Modify: `services/entity/src/ssdf_entity/chwriter.py:40-46` (remove `build_topo_hosts_sql`)
- Test: `services/entity/tests/test_resolve_entities.py`, `services/entity/tests/test_resolve_main.py`, `services/entity/tests/test_chwriter.py`, `services/entity/tests/test_config.py`

- [ ] **Step 1: Rewrite the resolver tests to the new `bindings` interface**

Replace the **entire** contents of `services/entity/tests/test_resolve_entities.py` with:

```python
from ssdf_entity.models import ASSET, POLICY, COMMUNICATED_WITH, GOVERNED_BY, entity_id
from ssdf_entity.resolve_entities import (
    resolve_entities, normalize_segment, build_binding_map,
)

NOW1 = "2026-06-07 00:00:00.000"
NOW2 = "2026-06-07 01:00:00.000"


def _flow(**kw):
    base = dict(src_ip="10.64.0.5", dst_ip="8.8.8.8", observer_hostname="fw1",
                bytes=1000, flows=3, ports=[443], rule_name="trust-to-untrust",
                provider="juniper", transport="tcp", first_seen=NOW1, last_seen=NOW2)
    base.update(kw)
    return base


def _binding(ip, mac, source_device="fw1", observed_at=NOW2):
    return {"source_device": source_device, "ip": ip, "mac": mac, "observed_at": observed_at}


# --- normalize_segment (Task 1) ---

def test_normalize_segment_strips_domain_and_lowercases():
    assert normalize_segment("panosvm.example.com") == "panosvm"
    assert normalize_segment("vSRX-test10") == "vsrx-test10"
    assert normalize_segment("FW1.local") == "fw1"


def test_normalize_segment_empty_becomes_unknown():
    assert normalize_segment("") == "unknown"
    assert normalize_segment(None) == "unknown"
    assert normalize_segment("   ") == "unknown"


# --- build_binding_map (Task 2) ---

def test_build_binding_map_keys_by_segment_and_ip():
    rows = [_binding("198.51.100.150", "aa:aa:aa:aa:aa:aa", "fwA", "2026-06-08 10:00:00.000"),
            _binding("198.51.100.150", "bb:bb:bb:bb:bb:bb", "fwB", "2026-06-08 10:00:00.000")]
    binding_map, conflict = build_binding_map(rows)
    assert binding_map[("fwa", "198.51.100.150")] == "aa:aa:aa:aa:aa:aa"
    assert binding_map[("fwb", "198.51.100.150")] == "bb:bb:bb:bb:bb:bb"
    assert conflict == set()


def test_build_binding_map_latest_observation_wins():
    rows = [_binding("10.64.0.5", "aa:aa:aa:aa:aa:aa", "fwA", "2026-06-08 09:00:00.000"),
            _binding("10.64.0.5", "cc:cc:cc:cc:cc:cc", "fwA", "2026-06-08 11:00:00.000")]
    binding_map, conflict = build_binding_map(rows)
    assert binding_map[("fwa", "10.64.0.5")] == "cc:cc:cc:cc:cc:cc"
    assert conflict == {("fwa", "10.64.0.5")}


def test_build_binding_map_skips_missing_ip_or_mac():
    rows = [_binding("", "aa:aa:aa:aa:aa:aa", "fwA"),
            _binding("10.64.0.5", "", "fwA")]
    binding_map, conflict = build_binding_map(rows)
    assert binding_map == {}
    assert conflict == set()


# --- resolve_entities (segment-scoped) ---

def test_ip_only_endpoints_become_segment_scoped_assets():
    entities, edges = resolve_entities([_flow()], bindings=[], tenant="t_main")
    assets = [e for e in entities if e["kind"] == ASSET]
    assert len(assets) == 2
    for a in assets:
        assert a["identity_basis"] == "ip_only"
        assert a["confidence"] == 0.5
        assert a["source"] == "observed"


def test_same_ip_different_segment_never_merges():
    flows = [_flow(src_ip="198.51.100.150", observer_hostname="fwA"),
             _flow(src_ip="198.51.100.150", observer_hostname="fwB", dst_ip="9.9.9.9")]
    entities, _ = resolve_entities(flows, bindings=[], tenant="t_main")
    srcs = [e for e in entities if e["kind"] == ASSET
            and e["identifiers"].get("ip") == "198.51.100.150"]
    assert len(srcs) == 2  # branch-reused IP across two vantages => two distinct assets


def test_mac_known_endpoint_is_mac_anchored():
    bindings = [_binding("10.64.0.5", "aa:bb:cc:dd:ee:ff")]
    entities, _ = resolve_entities([_flow()], bindings=bindings, tenant="t_main")
    src = next(e for e in entities if e["kind"] == ASSET
               and e["identifiers"].get("mac") == "aa:bb:cc:dd:ee:ff")
    assert src["identity_basis"] == "mac"
    assert src["confidence"] == 1.0
    assert src["identifiers"]["ip"] == "10.64.0.5"


def test_binding_only_matches_within_segment():
    # binding learned on fwA must not anchor a flow seen on fwB
    bindings = [_binding("10.64.0.5", "aa:bb:cc:dd:ee:ff", source_device="fwA")]
    entities, _ = resolve_entities([_flow(observer_hostname="fwB")],
                                   bindings=bindings, tenant="t_main")
    src = next(e for e in entities if e["kind"] == ASSET
               and "10.64.0.5" in e["identifiers"].values())
    assert src["identity_basis"] == "ip_only"


def test_two_ips_sharing_a_mac_collapse_to_one_asset():
    bindings = [_binding("10.64.0.5", "aa:aa:aa:aa:aa:aa"),
                _binding("10.64.0.6", "aa:aa:aa:aa:aa:aa")]
    flows = [_flow(src_ip="10.64.0.5"), _flow(src_ip="10.64.0.6")]
    entities, _ = resolve_entities(flows, bindings=bindings, tenant="t_main")
    macs = [e for e in entities if e["kind"] == ASSET
            and e["identifiers"].get("mac") == "aa:aa:aa:aa:aa:aa"]
    assert len(macs) == 1
    ips = {v for k, v in macs[0]["identifiers"].items() if k.startswith("ip")}
    assert ips == {"10.64.0.5", "10.64.0.6"}


def test_distinct_ips_never_merge():
    flows = [_flow(src_ip="10.64.0.5"), _flow(src_ip="10.64.0.6")]
    entities, _ = resolve_entities(flows, bindings=[], tenant="t_main")
    src_ips = {v for e in entities if e["kind"] == ASSET
               for k, v in e["identifiers"].items() if k.startswith("ip")}
    assert "10.64.0.5" in src_ips and "10.64.0.6" in src_ips
    assert len([e for e in entities if e["kind"] == ASSET]) == 3  # two srcs + shared dst


def test_ip_conflict_sets_flag_on_mac_asset():
    bindings = [_binding("10.64.0.5", "aa:aa:aa:aa:aa:aa", "fw1", "2026-06-08 09:00:00.000"),
                _binding("10.64.0.5", "dd:dd:dd:dd:dd:dd", "fw1", "2026-06-08 11:00:00.000")]
    entities, _ = resolve_entities([_flow(src_ip="10.64.0.5")],
                                   bindings=bindings, tenant="t_main")
    # latest binding wins => dd:.. asset, flagged with the conflicting ip
    asset = next(e for e in entities if e["kind"] == ASSET
                 and e["identifiers"].get("mac") == "dd:dd:dd:dd:dd:dd")
    assert asset["attrs"].get("ip_conflict") == "10.64.0.5"


def test_observed_policy_keyed_by_provider_and_rule():
    entities, edges = resolve_entities([_flow()], bindings=[], tenant="t_main")
    policies = [e for e in entities if e["kind"] == POLICY]
    assert len(policies) == 1
    assert policies[0]["name"] == "trust-to-untrust"
    assert policies[0]["identifiers"]["provider"] == "juniper"
    assert policies[0]["source"] == "observed"


def test_same_rule_name_different_vendor_is_distinct_policy():
    flows = [_flow(rule_name="allow-web", provider="juniper"),
             _flow(rule_name="allow-web", provider="paloalto", dst_ip="9.9.9.9")]
    entities, _ = resolve_entities(flows, bindings=[], tenant="t_main")
    assert len([e for e in entities if e["kind"] == POLICY]) == 2


def test_communicated_with_and_governed_by_edges():
    entities, edges = resolve_entities([_flow()], bindings=[], tenant="t_main")
    comm = [e for e in edges if e["edge_type"] == COMMUNICATED_WITH]
    gov = [e for e in edges if e["edge_type"] == GOVERNED_BY]
    assert len(comm) == 1 and len(gov) == 1
    assert comm[0]["attrs"]["sessions"] == "3"
    assert comm[0]["attrs"]["bytes"] == "1000"
    assert "443" in comm[0]["attrs"]["ports"]
    assert gov[0]["src_id"] == comm[0]["edge_id"]


def test_empty_rule_produces_no_governed_by():
    entities, edges = resolve_entities([_flow(rule_name="")], bindings=[], tenant="t_main")
    assert [e for e in entities if e["kind"] == POLICY] == []
    assert [e for e in edges if e["edge_type"] == GOVERNED_BY] == []
    assert [e for e in edges if e["edge_type"] == COMMUNICATED_WITH]


def test_flow_stats_accumulate_across_rows_for_same_pair():
    flows = [_flow(flows=3, bytes=1000, ports=[443], first_seen=NOW1, last_seen=NOW1),
             _flow(flows=2, bytes=500, ports=[80], first_seen=NOW2, last_seen=NOW2)]
    _, edges = resolve_entities(flows, bindings=[], tenant="t_main")
    comm = next(e for e in edges if e["edge_type"] == COMMUNICATED_WITH)
    assert comm["attrs"]["sessions"] == "5"
    assert comm["attrs"]["bytes"] == "1500"
    assert set(comm["attrs"]["ports"].split(",")) == {"80", "443"}
    assert comm["first_seen"] == NOW1 and comm["last_seen"] == NOW2


def test_observer_hosts_recorded_on_comm_edge():
    entities, edges = resolve_entities([_flow(observer_hostname="vSRX-test10")],
                                       bindings=[], tenant="t_main")
    comm = next(e for e in edges if e["edge_type"] == COMMUNICATED_WITH)
    assert comm["attrs"]["observer_hosts"] == "vSRX-test10"


def test_observer_hosts_union_across_rows():
    flows = [_flow(observer_hostname="vSRX-test10", first_seen=NOW1, last_seen=NOW1),
             _flow(observer_hostname="panosvm", first_seen=NOW2, last_seen=NOW2)]
    _, edges = resolve_entities(flows, bindings=[], tenant="t_main")
    comm = next(e for e in edges if e["edge_type"] == COMMUNICATED_WITH)
    assert set(comm["attrs"]["observer_hosts"].split(",")) == {"panosvm", "vSRX-test10"}


def test_observer_hosts_absent_defaults_empty():
    _, edges = resolve_entities([_flow(observer_hostname="")], bindings=[], tenant="t_main")
    comm = next(e for e in edges if e["edge_type"] == COMMUNICATED_WITH)
    assert comm["attrs"]["observer_hosts"] == ""
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd services/entity && uv run --with pytest pytest tests/test_resolve_entities.py -q`
Expected: FAIL — `resolve_entities()` still expects `topo_hosts` and has no segment scoping / conflict flag.

- [ ] **Step 3: Rewrite `resolve_entities`**

Replace `resolve_entities` (lines 51-135) in `services/entity/src/ssdf_entity/resolve_entities.py` with:

```python
def resolve_entities(flow_aggregates: list[dict], bindings: list[dict],
                     tenant: str) -> tuple[list[dict], list[dict]]:
    binding_map, conflict = build_binding_map(bindings)
    entities: dict[str, dict] = {}
    edges: dict[str, dict] = {}

    def asset_for(ip: str, segment: str, first_seen: str, last_seen: str) -> dict:
        mac = binding_map.get((segment, ip))
        canonical = f"mac:{mac}" if mac else f"ip:{segment}:{ip}"
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
        if mac and (segment, ip) in conflict:
            entity["attrs"]["ip_conflict"] = ip
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
        segment = normalize_segment(row.get("observer_hostname"))
        src = asset_for(row["src_ip"], segment, first_seen, last_seen)
        dst = asset_for(row["dst_ip"], segment, first_seen, last_seen)

        comm_eid = edge_id(tenant, src["entity_id"], dst["entity_id"],
                           COMMUNICATED_WITH, OBSERVED)
        comm = edges.get(comm_eid)
        if comm is None:
            comm = {
                "edge_id": comm_eid, "tenant_id": tenant,
                "src_id": src["entity_id"], "dst_id": dst["entity_id"],
                "edge_type": COMMUNICATED_WITH, "source": OBSERVED, "confidence": 1.0,
                "attrs": {"sessions": "0", "bytes": "0", "ports": "", "providers": "",
                          "transports": "", "observer_hosts": ""},
                "first_seen": "", "last_seen": "",
            }
            edges[comm_eid] = comm
        comm["attrs"]["sessions"] = str(int(comm["attrs"]["sessions"]) + int(row.get("flows", 0)))
        comm["attrs"]["bytes"] = str(int(comm["attrs"]["bytes"]) + int(row.get("bytes", 0)))
        _merge_set_attr(comm["attrs"], "ports", row.get("ports") or [])
        _merge_set_attr(comm["attrs"], "providers", [row.get("provider", "")])
        _merge_set_attr(comm["attrs"], "transports", [row.get("transport", "")])
        observer = row.get("observer_hostname")
        _merge_set_attr(comm["attrs"], "observer_hosts", [observer] if observer else [])
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

Also delete the now-unused `_build_ip_to_mac` function (lines 16-25) and update the module docstring's second paragraph to read:

```python
"""Resolve flow aggregates (+ segment-scoped ARP bindings) into Asset/Policy
entities and edges.

Pure function, deterministic. Asset identity is MAC when an ARP binding for the
flow's segment (firewall vantage) binds the IP→MAC, else a segment-local key
ip:<segment>:<ip>. Two IPs sharing a MAC collapse to one Asset; the same IP in
different segments never merges. Observed Policy is keyed (provider, rule_name).
"""
```

- [ ] **Step 4: Update `config.py` for the lookback window**

In `services/entity/src/ssdf_entity/config.py`, add `binding_lookback_hours: int` to the `Config` dataclass (after `window_hours`, line 21):

```python
    window_hours: int
    binding_lookback_hours: int
```

and in `load_config()` (after the `window_hours=...` line 35):

```python
        window_hours=int(os.environ.get("ENTITY_WINDOW_HOURS", "24")),
        binding_lookback_hours=int(os.environ.get("TOPO_BINDING_LOOKBACK_HOURS", "168")),
```

Add a config test to `services/entity/tests/test_config.py`:

```python
def test_load_config_default_binding_lookback(monkeypatch):
    monkeypatch.setenv("CH_PASSWORD", "x")
    monkeypatch.delenv("TOPO_BINDING_LOOKBACK_HOURS", raising=False)
    from ssdf_entity.config import load_config
    assert load_config().binding_lookback_hours == 168
```

- [ ] **Step 5: Rewire `resolve_main` and remove `build_topo_hosts_sql`**

Replace `services/entity/src/ssdf_entity/resolve_main.py` lines 7-30 with:

```python
from .chwriter import ClickHouseEntityWriter, build_flow_agg_sql, build_binding_sql
from .config import Config, load_config
from .resolve_entities import resolve_entities

log = logging.getLogger("ssdf_entity.resolve")


def run_resolver(writer, tenant: str, window_hours: int,
                 binding_lookback_hours: int) -> tuple[int, int]:
    flow_sql, flow_params = build_flow_agg_sql(window_hours, tenant)
    flow_aggregates = writer.query(flow_sql, flow_params)
    binding_sql, binding_params = build_binding_sql(binding_lookback_hours, tenant)
    bindings = writer.query(binding_sql, binding_params)
    entities, edges = resolve_entities(flow_aggregates, bindings, tenant)
    n_entities = writer.replace_entities(entities)
    n_edges = writer.replace_edges(edges)
    log.info("entity resolver: %d entities, %d edges upserted", n_entities, n_edges)
    return n_entities, n_edges


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    config: Config = load_config()
    writer = ClickHouseEntityWriter(config)
    run_resolver(writer, tenant=config.tenant_id, window_hours=config.window_hours,
                 binding_lookback_hours=config.binding_lookback_hours)
```

In `services/entity/src/ssdf_entity/chwriter.py`, delete `build_topo_hosts_sql` (lines 40-46) and remove its now-dead test `test_topo_hosts_sql_filters_to_host_kind` from `test_chwriter.py` (and the `build_topo_hosts_sql` name from that file's import).

Replace `services/entity/tests/test_resolve_main.py` with the binding-driven fake:

```python
from ssdf_entity.resolve_main import run_resolver


class _FakeWriter:
    def __init__(self):
        self.entities = None
        self.edges = None

    def query(self, sql, params=None):
        if "topo_observations" in sql:
            return [{"source_device": "fw1", "ip": "10.64.0.5",
                     "mac": "aa:aa:aa:aa:aa:aa", "observed_at": "2026-06-07 00:00:00.000"}]
        return [{"src_ip": "10.64.0.5", "dst_ip": "8.8.8.8", "observer_hostname": "fw1",
                 "bytes": 100, "flows": 1, "ports": [443], "rule_name": "r1",
                 "provider": "juniper", "transport": "tcp",
                 "first_seen": "2026-06-07 00:00:00.000",
                 "last_seen": "2026-06-07 00:00:00.000"}]

    def replace_entities(self, entities):
        self.entities = entities
        return len(entities)

    def replace_edges(self, edges):
        self.edges = edges
        return len(edges)


def test_run_resolver_reads_both_inputs_and_writes():
    writer = _FakeWriter()
    n_entities, n_edges = run_resolver(writer, tenant="t_main", window_hours=24,
                                       binding_lookback_hours=168)
    assert n_entities == 3        # mac-anchored src + ip-only dst + policy r1
    assert n_edges == 2           # communicated_with + governed_by
    src = next(e for e in writer.entities if e["identifiers"].get("mac"))
    assert src["identity_basis"] == "mac"
```

- [ ] **Step 6: Run the full entity unit suite**

Run: `cd services/entity && uv run --with pytest pytest -m "not integration" -q`
Expected: PASS (all entity unit tests green; no references to `topo_hosts`/`build_topo_hosts_sql` remain).

- [ ] **Step 7: Commit**

```bash
git add services/entity/src/ssdf_entity/ services/entity/tests/
git commit -m "feat(m6a): segment-scoped asset identity (MAC-anchored, IP per-vantage)"
```

---

### Task 5: `reconcile_assets` — collapse existing twins

A standalone pass that finds legacy/duplicate `ip_only` Assets whose IP resolves (by binding map, single MAC) to an existing MAC-anchored Asset, merges the twin's COMMUNICATED_WITH edge attrs into the MAC asset's edge, and deletes the twin + its edges. The planning core is pure and unit-tested; the executor is a thin CH wrapper.

> Edge handling: the twin's COMMUNICATED_WITH edges are merged (lossless) into the MAC asset's corresponding edge. The twin's GOVERNED_BY edges (keyed off the twin's comm-edge id) are deleted, not remapped — policy linkage survives via the MAC asset's own GOVERNED_BY edges to the same shared Policy entity (or is recreated on the next in-window resolver pass).

**Files:**
- Create: `services/entity/src/ssdf_entity/reconcile_assets.py`
- Modify: `services/entity/src/ssdf_entity/chwriter.py` (add reconcile-read SQL + `delete_entities`/`delete_edges`)
- Test: `services/entity/tests/test_reconcile_assets.py` (new), `services/entity/tests/test_chwriter.py`

- [ ] **Step 1: Write the failing test for reconcile-read SQL + delete methods**

Append to `services/entity/tests/test_chwriter.py`:

```python
def test_assets_by_basis_sql_filters_basis():
    from ssdf_entity.chwriter import build_assets_by_basis_sql
    sql, params = build_assets_by_basis_sql("ip_only", tenant="t_main")
    assert "ssdf.entities FINAL" in sql
    assert "identity_basis = {basis:String}" in sql
    assert "kind = 'asset'" in sql
    assert params == {"tenant": "t_main", "basis": "ip_only"}


def test_all_edges_by_type_sql():
    from ssdf_entity.chwriter import build_all_edges_by_type_sql
    sql, params = build_all_edges_by_type_sql("communicated_with", tenant="t_main")
    assert "ssdf.entity_edges FINAL" in sql
    assert "edge_type = {etype:String}" in sql
    assert params == {"tenant": "t_main", "etype": "communicated_with"}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd services/entity && uv run --with pytest pytest tests/test_chwriter.py -k "by_basis or by_type" -q`
Expected: FAIL with `ImportError: cannot import name 'build_assets_by_basis_sql'`.

- [ ] **Step 3: Implement the reconcile-read SQL + delete methods**

In `services/entity/src/ssdf_entity/chwriter.py`, add after `build_binding_sql`:

```python
_RECONCILE_ENTITY_COLS = (
    "entity_id, tenant_id, kind, name, identifiers, source, identity_basis, "
    "confidence, attrs, toString(first_seen) AS first_seen, "
    "toString(last_seen) AS last_seen"
)
_RECONCILE_EDGE_COLS = (
    "edge_id, tenant_id, src_id, dst_id, edge_type, source, confidence, attrs, "
    "toString(first_seen) AS first_seen, toString(last_seen) AS last_seen"
)


def build_assets_by_basis_sql(basis: str, tenant: str) -> tuple[str, dict]:
    """Read Asset entities with a given identity_basis (e.g. 'ip_only' or 'mac')."""
    sql = (
        f"SELECT {_RECONCILE_ENTITY_COLS} FROM ssdf.entities FINAL "
        "WHERE tenant_id = {tenant:String} AND kind = 'asset' "
        "AND identity_basis = {basis:String}"
    )
    return sql, {"tenant": tenant, "basis": basis}


def build_all_edges_by_type_sql(edge_type: str, tenant: str) -> tuple[str, dict]:
    """Read all entity edges of one type (for reconciliation merge planning)."""
    sql = (
        f"SELECT {_RECONCILE_EDGE_COLS} FROM ssdf.entity_edges FINAL "
        "WHERE tenant_id = {tenant:String} AND edge_type = {etype:String}"
    )
    return sql, {"tenant": tenant, "etype": edge_type}
```

Add two delete methods to `ClickHouseEntityWriter` (after `replace_edges`):

```python
    def delete_entities(self, entity_ids: list[str]) -> int:
        if not entity_ids:
            return 0
        self._client.command(
            "ALTER TABLE ssdf.entities DELETE "
            "WHERE tenant_id = {t:String} AND entity_id IN {ids:Array(String)} "
            "SETTINGS mutations_sync = 1",
            parameters={"t": self._config.tenant_id, "ids": entity_ids},
        )
        return len(entity_ids)

    def delete_edges(self, edge_ids: list[str]) -> int:
        if not edge_ids:
            return 0
        self._client.command(
            "ALTER TABLE ssdf.entity_edges DELETE "
            "WHERE tenant_id = {t:String} AND edge_id IN {ids:Array(String)} "
            "SETTINGS mutations_sync = 1",
            parameters={"t": self._config.tenant_id, "ids": edge_ids},
        )
        return len(edge_ids)
```

- [ ] **Step 4: Run to verify SQL tests pass**

Run: `cd services/entity && uv run --with pytest pytest tests/test_chwriter.py -q`
Expected: PASS.

- [ ] **Step 5: Write the failing test for the pure planner**

Create `services/entity/tests/test_reconcile_assets.py`:

```python
from ssdf_entity.models import ASSET, COMMUNICATED_WITH, GOVERNED_BY, entity_id, edge_id
from ssdf_entity.reconcile_assets import plan_reconciliation

TENANT = "t_main"
MAC = "aa:aa:aa:aa:aa:aa"
PEER = "8.8.8.8"
NOW1 = "2026-06-07 00:00:00.000"
NOW2 = "2026-06-08 00:00:00.000"

MAC_ID = entity_id(TENANT, ASSET, f"mac:{MAC}")
TWIN_ID = entity_id(TENANT, ASSET, "ip:198.51.100.150")        # legacy global key
PEER_ID = entity_id(TENANT, ASSET, "ip:fw1:8.8.8.8")


def _asset(eid, basis, ident, attrs=None):
    return {"entity_id": eid, "tenant_id": TENANT, "kind": ASSET, "name": "x",
            "identifiers": ident, "source": "observed", "identity_basis": basis,
            "confidence": 1.0 if basis == "mac" else 0.5, "attrs": attrs or {},
            "first_seen": NOW1, "last_seen": NOW2}


def _comm_edge(src, dst, **attrs):
    base = {"sessions": "0", "bytes": "0", "ports": "", "providers": "",
            "transports": "", "observer_hosts": ""}
    base.update({k: str(v) for k, v in attrs.items()})
    return {"edge_id": edge_id(TENANT, src, dst, COMMUNICATED_WITH, "observed"),
            "tenant_id": TENANT, "src_id": src, "dst_id": dst,
            "edge_type": COMMUNICATED_WITH, "source": "observed", "confidence": 1.0,
            "attrs": base, "first_seen": NOW1, "last_seen": NOW2}


def test_twin_with_matching_mac_is_merged_and_deleted():
    binding_map = {("fw1", "198.51.100.150"): MAC}
    mac_asset = _asset(MAC_ID, "mac", {"mac": MAC, "ip": "198.51.100.150"})
    twin = _asset(TWIN_ID, "ip_only", {"ip": "198.51.100.150"})
    mac_edge = _comm_edge(MAC_ID, PEER_ID, sessions=5, bytes=500,
                          observer_hosts="vSRX-test10")
    twin_edge = _comm_edge(TWIN_ID, PEER_ID, sessions=3, bytes=300, observer_hosts="")
    plan = plan_reconciliation(
        ip_only_assets=[twin], mac_assets=[mac_asset],
        comm_edges=[mac_edge, twin_edge], gov_edges=[],
        binding_map=binding_map, tenant=TENANT)
    assert TWIN_ID in plan["delete_entity_ids"]
    assert twin_edge["edge_id"] in plan["delete_edge_ids"]
    merged = next(e for e in plan["merged_edges"]
                  if e["edge_id"] == mac_edge["edge_id"])
    assert merged["attrs"]["sessions"] == "8"      # 5 + 3
    assert merged["attrs"]["bytes"] == "800"       # 500 + 300


def test_twin_with_no_matching_mac_is_left_alone():
    binding_map = {}  # IP not bound to any MAC
    twin = _asset(TWIN_ID, "ip_only", {"ip": "198.51.100.150"})
    plan = plan_reconciliation(
        ip_only_assets=[twin], mac_assets=[], comm_edges=[], gov_edges=[],
        binding_map=binding_map, tenant=TENANT)
    assert plan["delete_entity_ids"] == []
    assert plan["merged_edges"] == []


def test_ambiguous_ip_two_macs_is_left_alone():
    # IP appears bound to two different MACs across segments => not safe to merge
    binding_map = {("fwa", "198.51.100.150"): MAC,
                   ("fwb", "198.51.100.150"): "bb:bb:bb:bb:bb:bb"}
    mac_asset = _asset(MAC_ID, "mac", {"mac": MAC, "ip": "198.51.100.150"})
    twin = _asset(TWIN_ID, "ip_only", {"ip": "198.51.100.150"})
    plan = plan_reconciliation(
        ip_only_assets=[twin], mac_assets=[mac_asset], comm_edges=[], gov_edges=[],
        binding_map=binding_map, tenant=TENANT)
    assert plan["delete_entity_ids"] == []


def test_twin_governed_by_edges_are_deleted():
    binding_map = {("fw1", "198.51.100.150"): MAC}
    mac_asset = _asset(MAC_ID, "mac", {"mac": MAC, "ip": "198.51.100.150"})
    twin = _asset(TWIN_ID, "ip_only", {"ip": "198.51.100.150"})
    twin_edge = _comm_edge(TWIN_ID, PEER_ID, sessions=3, bytes=300)
    gov = {"edge_id": edge_id(TENANT, twin_edge["edge_id"], "pol1", GOVERNED_BY, "observed"),
           "tenant_id": TENANT, "src_id": twin_edge["edge_id"], "dst_id": "pol1",
           "edge_type": GOVERNED_BY, "source": "observed", "confidence": 1.0,
           "attrs": {}, "first_seen": NOW1, "last_seen": NOW2}
    plan = plan_reconciliation(
        ip_only_assets=[twin], mac_assets=[mac_asset],
        comm_edges=[twin_edge], gov_edges=[gov],
        binding_map=binding_map, tenant=TENANT)
    assert gov["edge_id"] in plan["delete_edge_ids"]
```

- [ ] **Step 6: Run to verify it fails**

Run: `cd services/entity && uv run --with pytest pytest tests/test_reconcile_assets.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'ssdf_entity.reconcile_assets'`.

- [ ] **Step 7: Implement `reconcile_assets.py`**

Create `services/entity/src/ssdf_entity/reconcile_assets.py`:

```python
"""Reconcile duplicate ip_only Asset twins into their MAC-anchored Asset.

A twin is an ip_only Asset whose IP resolves, via the segment-scoped binding map,
to exactly one MAC for which a MAC-anchored Asset already exists (IP and MAC agree).
Twins whose IP is unbound, or bound to multiple MACs (cross-segment reuse / conflict),
are left untouched. Confirmed twins have their COMMUNICATED_WITH edges merged into the
MAC asset's corresponding edge, then the twin and its edges are deleted.
"""

from __future__ import annotations

import logging

from .chwriter import (
    ClickHouseEntityWriter, build_assets_by_basis_sql,
    build_all_edges_by_type_sql, build_binding_sql,
)
from .config import Config, load_config
from .models import COMMUNICATED_WITH, OBSERVED, edge_id
from .resolve_entities import build_binding_map
from .resolve_entities import _merge_set_attr  # reuse comma-set union

log = logging.getLogger("ssdf_entity.reconcile")


def _ips_of(asset: dict) -> list[str]:
    return [v for k, v in asset.get("identifiers", {}).items() if k.startswith("ip")]


def _ip_to_unique_mac(binding_map: dict[tuple[str, str], str]) -> dict[str, str]:
    """Collapse {(segment, ip) -> mac} to {ip -> mac} only where the IP maps to
    exactly one MAC across all segments (otherwise it is ambiguous)."""
    macs_by_ip: dict[str, set[str]] = {}
    for (_segment, ip), mac in binding_map.items():
        macs_by_ip.setdefault(ip, set()).add(mac)
    return {ip: next(iter(macs)) for ip, macs in macs_by_ip.items() if len(macs) == 1}


def plan_reconciliation(ip_only_assets: list[dict], mac_assets: list[dict],
                        comm_edges: list[dict], gov_edges: list[dict],
                        binding_map: dict[tuple[str, str], str],
                        tenant: str) -> dict:
    ip_to_mac = _ip_to_unique_mac(binding_map)
    mac_asset_by_mac = {a["identifiers"].get("mac"): a for a in mac_assets
                        if a["identifiers"].get("mac")}
    comm_by_id = {e["edge_id"]: e for e in comm_edges}

    merged_edges: dict[str, dict] = {}
    delete_entity_ids: list[str] = []
    delete_edge_ids: list[str] = []

    for twin in ip_only_assets:
        target_mac = None
        for ip in _ips_of(twin):
            mac = ip_to_mac.get(ip)
            if mac and mac in mac_asset_by_mac:
                target_mac = mac
                break
        if target_mac is None:
            continue
        mac_id = mac_asset_by_mac[target_mac]["entity_id"]
        twin_id = twin["entity_id"]
        delete_entity_ids.append(twin_id)

        twin_comm = [e for e in comm_edges if twin_id in (e["src_id"], e["dst_id"])]
        for edge in twin_comm:
            delete_edge_ids.append(edge["edge_id"])
            new_src = mac_id if edge["src_id"] == twin_id else edge["src_id"]
            new_dst = mac_id if edge["dst_id"] == twin_id else edge["dst_id"]
            new_id = edge_id(tenant, new_src, new_dst, COMMUNICATED_WITH, OBSERVED)
            target = merged_edges.get(new_id) or dict(comm_by_id.get(new_id) or {})
            if not target:
                target = {
                    "edge_id": new_id, "tenant_id": tenant, "src_id": new_src,
                    "dst_id": new_dst, "edge_type": COMMUNICATED_WITH,
                    "source": OBSERVED, "confidence": 1.0,
                    "attrs": {"sessions": "0", "bytes": "0", "ports": "",
                              "providers": "", "transports": "", "observer_hosts": ""},
                    "first_seen": edge["first_seen"], "last_seen": edge["last_seen"],
                }
            else:
                target = dict(target)
                target["attrs"] = dict(target["attrs"])
            attrs, src_attrs = target["attrs"], edge["attrs"]
            attrs["sessions"] = str(int(attrs.get("sessions", "0") or "0")
                                    + int(src_attrs.get("sessions", "0") or "0"))
            attrs["bytes"] = str(int(attrs.get("bytes", "0") or "0")
                                 + int(src_attrs.get("bytes", "0") or "0"))
            for key in ("ports", "providers", "transports", "observer_hosts"):
                _merge_set_attr(attrs, key,
                                filter(None, (src_attrs.get(key, "") or "").split(",")))
            target["first_seen"] = min(target["first_seen"], edge["first_seen"])
            target["last_seen"] = max(target["last_seen"], edge["last_seen"])
            merged_edges[new_id] = target

            # delete governed_by edges hanging off the twin's comm edge
            for gov in gov_edges:
                if gov["src_id"] == edge["edge_id"]:
                    delete_edge_ids.append(gov["edge_id"])

    return {
        "merged_edges": list(merged_edges.values()),
        "delete_entity_ids": delete_entity_ids,
        "delete_edge_ids": delete_edge_ids,
    }


def reconcile(writer: ClickHouseEntityWriter, tenant: str,
              binding_lookback_hours: int) -> dict:
    ip_only = writer.query(*build_assets_by_basis_sql("ip_only", tenant))
    mac_assets = writer.query(*build_assets_by_basis_sql("mac", tenant))
    comm_edges = writer.query(*build_all_edges_by_type_sql(COMMUNICATED_WITH, tenant))
    gov_edges = writer.query(*build_all_edges_by_type_sql("governed_by", tenant))
    bindings = writer.query(*build_binding_sql(binding_lookback_hours, tenant))
    binding_map, _conflict = build_binding_map(bindings)
    plan = plan_reconciliation(ip_only, mac_assets, comm_edges, gov_edges,
                               binding_map, tenant)
    writer.replace_edges(plan["merged_edges"])
    writer.delete_edges(plan["delete_edge_ids"])
    writer.delete_entities(plan["delete_entity_ids"])
    log.info("reconcile: %d twins deleted, %d edges merged, %d edges deleted",
             len(plan["delete_entity_ids"]), len(plan["merged_edges"]),
             len(plan["delete_edge_ids"]))
    return plan


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    config: Config = load_config()
    writer = ClickHouseEntityWriter(config)
    reconcile(writer, tenant=config.tenant_id,
              binding_lookback_hours=config.binding_lookback_hours)


if __name__ == "__main__":
    main()
```

> `writer.query(*build_...())` relies on `ClickHouseEntityWriter.query(sql, params=None)` accepting `(sql, params)` positionally — it does (see chwriter.py).

- [ ] **Step 8: Run reconcile tests**

Run: `cd services/entity && uv run --with pytest pytest tests/test_reconcile_assets.py -q`
Expected: PASS (4 passed).

- [ ] **Step 9: Run the full entity suite**

Run: `cd services/entity && uv run --with pytest pytest -m "not integration" -q`
Expected: PASS.

- [ ] **Step 10: Commit**

```bash
git add services/entity/src/ssdf_entity/ services/entity/tests/
git commit -m "feat(m6a): reconcile_assets pass to merge+delete stale ip_only twins"
```

---

### Task 6: Confidence-first ordering in `find_entity`

**Files:**
- Modify: `services/mcp-query/src/ssdf_mcp_query/entitystore.py:24-31`
- Test: `services/mcp-query/tests/test_entitystore.py` (or the existing entitystore test module)

- [ ] **Step 1: Locate the entitystore test file**

Run: `cd services/mcp-query && ls tests/ | grep -i entitystore`
Expected: a file such as `test_entitystore.py`. If none exists, create `services/mcp-query/tests/test_entitystore.py`.

- [ ] **Step 2: Write the failing test**

Add to that test file (adjust the import if the module path differs):

```python
def test_entity_match_sql_orders_by_confidence_then_last_seen():
    from ssdf_mcp_query.entitystore import build_entity_match_sql
    sql, params = build_entity_match_sql("198.51.100.150", tenant="t_main")
    assert "ORDER BY confidence DESC, entities.last_seen DESC LIMIT 1" in sql
    assert params["tenant"] == "t_main"
```

- [ ] **Step 3: Run to verify it fails**

Run: `cd services/mcp-query && uv run --with pytest pytest tests/ -k confidence -q`
Expected: FAIL — current SQL orders by `entities.last_seen DESC` only.

- [ ] **Step 4: Implement the ordering change**

In `services/mcp-query/src/ssdf_mcp_query/entitystore.py`, change the `ORDER BY` in `build_entity_match_sql` (line 29) from:

```python
        "ORDER BY entities.last_seen DESC LIMIT 1"
```

to:

```python
        "ORDER BY confidence DESC, entities.last_seen DESC LIMIT 1"
```

- [ ] **Step 5: Run to verify it passes**

Run: `cd services/mcp-query && uv run --with pytest pytest tests/ -k confidence -q`
Expected: PASS.

- [ ] **Step 6: Run the full mcp-query unit suite**

Run: `cd services/mcp-query && uv run --with pytest pytest -m "not integration" -q`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add services/mcp-query/src/ssdf_mcp_query/entitystore.py services/mcp-query/tests/
git commit -m "fix(m6a): find_entity prefers MAC asset (confidence-first) on by-IP lookup"
```

---

### Task 7: Update docs (CLAUDE.md + STATUS.md)

**Files:**
- Modify: `CLAUDE.md`
- Modify: `docs/superpowers/STATUS.md`

- [ ] **Step 1: Add the M6a-fix commands to CLAUDE.md**

Under the M6a section in `CLAUDE.md`, add bullets describing the new behavior and the reconcile entry point:

```markdown
- **M6a identity fix (segment-scoped, 2026-06-08):** Asset identity is MAC-anchored; the IP-only fallback is now `ip:<segment>:<ip>` where `segment` = normalized firewall vantage (`normalize_segment`: first dotted label, lowercased — aligns ECS `observer.hostname` with topo `source_device`). The binding map is built from `ssdf.topo_observations` `arp_entry` over `TOPO_BINDING_LOOKBACK_HOURS` (default 168) so a transient single-pass binding drop no longer spawns a duplicate. Same-segment same-IP/different-MAC sets `attrs.ip_conflict`. `find_entity` orders `confidence DESC, last_seen DESC` so a MAC asset wins a by-IP lookup.
- Reconcile existing twins (one-shot, run as `ssdf_entity` on ct109): `cd services/entity && CH_HOST=<ip> CH_USER=ssdf_entity CH_PASSWORD=<pw> uv run python -m ssdf_entity.reconcile_assets` — merges each ip_only twin's COMMUNICATED_WITH edge into its MAC asset and `ALTER TABLE … DELETE`s the twin (only when IP→single MAC and that MAC asset exists; `mutations_sync=1`).
```

- [ ] **Step 2: Add a STATUS.md ledger row**

In `docs/superpowers/STATUS.md`, add a row to the as-built table recording the M6a identity fix (segment-scoped identity + reconciliation), referencing this plan and spec. Match the existing row format in that file.

- [ ] **Step 3: Commit**

```bash
git add CLAUDE.md docs/superpowers/STATUS.md
git commit -m "docs(m6a): record segment-scoped identity fix + reconcile_assets"
```

---

## Deployment (after all tasks merge)

1. Deploy `services/entity` to ct109 (existing venv `/opt/ssdf-entity`): pull, no schema migration needed (identity lives in `entity_id` values, not columns). The `ssdf-entity.timer` picks up the new resolver automatically. Ensure `/etc/ssdf-entity/ENV.local` may set `TOPO_BINDING_LOOKBACK_HOURS` (default 168 is fine).
2. Run the reconcile pass once on ct109 as `ssdf_entity`:
   `CH_HOST=198.51.100.151 CH_USER=ssdf_entity CH_PASSWORD=<pw> /opt/ssdf-entity/bin/python -m ssdf_entity.reconcile_assets`
3. Deploy the mcp-query ordering change to ct106 editable install (`/opt/src/mcp-query/src`), restart `ssdf-mcp-query`.
4. Live-verify: `explain_access` by IP for `198.51.100.150` now returns the MAC asset with `firewall_basis:provenance` (the by-IP caveat from M6c-B is resolved).

---

## Self-Review

**Spec coverage:**
- Identity model (MAC primary, IP segment-local) → Tasks 1, 4. ✓
- Segment normalization → Task 1. ✓
- Sticky segment-aware binding map (lookback) → Tasks 2, 3, 4. ✓
- Observer-grouped flow agg → Task 3. ✓
- Conflict flag → Tasks 2, 4. ✓
- Reconciliation (merge-then-delete) → Task 5. ✓
- find_entity confidence-first → Task 6. ✓
- Files-touched list matches spec → all covered. ✓
- Docs → Task 7. ✓

**Placeholder scan:** No TBD/TODO; every code step shows full code; every command has expected output. ✓

**Type consistency:** `normalize_segment(name)`, `build_binding_map(bindings) -> (dict, set)`, `resolve_entities(flow_aggregates, bindings, tenant)`, `build_binding_sql(lookback_hours, tenant)`, `plan_reconciliation(ip_only_assets, mac_assets, comm_edges, gov_edges, binding_map, tenant)`, `reconcile(writer, tenant, binding_lookback_hours)` — names/signatures consistent across tasks. `_merge_set_attr` reused from `resolve_entities`. Edge/entity dict shapes match `ENTITY_EDGE_COLUMNS`/`ENTITY_COLUMNS` insertion order. ✓
