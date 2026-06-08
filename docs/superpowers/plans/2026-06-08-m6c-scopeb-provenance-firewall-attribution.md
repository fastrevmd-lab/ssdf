# M6c scope B — provenance-based firewall attribution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `explain_access` attribute the on-path firewall from the flow's *logging device* (provenance) so a real transit pair yields `coverage.configured > 0`, falling back to topology only when provenance is absent.

**Architecture:** Add a normalized `observer_hostname` column at ingest (Vector), aggregate it per flow in the entity resolver onto the COMMUNICATED_WITH edge as `observer_hosts`, and have `explain_access` prefer that provenance set over the structurally-wrong L2-topology `enforcement_points` heuristic.

**Tech Stack:** ClickHouse (DDL), Vector VRL (`infra/vector/vector.toml`), Python 3.11 (`services/entity`, `services/mcp-query`), pytest via `uv run --with pytest pytest`.

**Design spec:** `docs/superpowers/specs/2026-06-08-m6c-scopeb-provenance-firewall-attribution-design.md`

**Worktree:** `/home/mharman/SSDF-m6c-scopeb` (branch `m6c-scopeb-provenance`, off `origin/main`). All paths below are relative to this worktree.

---

### Task 1: ClickHouse migration — `observer_hostname` column

**Files:**
- Create: `infra/clickhouse/006_observer_hostname.sql`

- [ ] **Step 1: Write the migration**

Create `infra/clickhouse/006_observer_hostname.sql`:

```sql
-- M6c scope B: logging device (ECS observer.hostname) as a typed column so the
-- entity resolver can attribute the on-path firewall from flow provenance
-- instead of the L2-topology heuristic. Idempotent.
ALTER TABLE ssdf.events
  ADD COLUMN IF NOT EXISTS observer_hostname LowCardinality(String) DEFAULT '';
```

- [ ] **Step 2: Commit**

```bash
git add infra/clickhouse/006_observer_hostname.sql
git commit -m "feat(m6c-b): add observer_hostname column migration"
```

Note: This is applied to the live ct104 ClickHouse in Task 7 (deploy), not now. `ssdf_ro`/`ssdf_entity` already hold table-level SELECT, so no grant change.

---

### Task 2: Vector `srx_ecs` — emit `observer_hostname` + unit test

**Files:**
- Modify: `infra/vector/vector.toml` (the `srx_ecs` output map, line 94-96; add a `[[tests]]` block after line 407)

- [ ] **Step 1: Add a failing Vector unit test**

In `infra/vector/vector.toml`, immediately after the `session_deny_maps_to_ecs` test block (after line 407, before the `# ---------------- PAN-OS unit tests ----------------` comment), insert:

```toml
[[tests]]
name = "srx_observer_hostname_from_syslog_host"
[[tests.inputs]]
insert_at = "srx_ecs"
type = "raw"
value = '<14>1 2026-06-08T12:00:00.000Z vSRX-test10 RT_FLOW - RT_FLOW_SESSION_CLOSE [junos@2636.1.1.1.2.36 source-address="10.65.1.10" source-port="51514" destination-address="10.66.2.20" destination-port="443" protocol-id="6" policy-name="baseline-permit(global)" source-zone-name="trust" destination-zone-name="untrust" bytes-from-client="1500" bytes-from-server="6000" username="N/A"]'
[[tests.outputs]]
extract_from = "srx_ecs"
[[tests.outputs.conditions]]
type = "vrl"
source = '''
assert_eq!(.observer_hostname, "vSRX-test10")
assert_eq!(.rule_name, "baseline-permit(global)")
'''
```

- [ ] **Step 2: Run the test to verify it fails**

Run (on ct102 where Vector is installed, or any host with the `vector` binary):
```bash
ssh root@ct102 "cd /etc/vector && vector test /root/vector.toml"   # after pushing the toml
# OR locally if vector is installed:
vector test infra/vector/vector.toml
```
Expected: FAIL — `srx_observer_hostname_from_syslog_host` errors with the new assertion (`.observer_hostname` is unset / not equal to `"vSRX-test10"`).

- [ ] **Step 3: Add `observer_hostname` to the `srx_ecs` output map**

In `infra/vector/vector.toml`, in the `. = {...}` map of `transforms.srx_ecs`, add a line after the `observer_egress_zone` line (line 96). The block becomes:

```toml
        "rule_name": string(fields."policy-name") ?? "",
        "observer_ingress_zone": string(fields."source-zone-name") ?? "",
        "observer_egress_zone": string(fields."destination-zone-name") ?? "",
        "observer_hostname": string(parsed.hostname) ?? "",
        "user_name": user,
```

(`parsed` is the `parse_syslog(raw)` result; `.hostname` is the RFC5424 HOSTNAME token, `vSRX-test10` live.)

- [ ] **Step 4: Run the test to verify it passes**

Run: `vector test infra/vector/vector.toml`
Expected: PASS for `srx_observer_hostname_from_syslog_host` AND all three pre-existing SRX tests (`session_close_maps_to_ecs`, `session_create_maps_to_ecs`, `session_deny_maps_to_ecs`) — they do not assert `observer_hostname`, so they stay green.

- [ ] **Step 5: Commit**

```bash
git add infra/vector/vector.toml
git commit -m "feat(m6c-b): srx_ecs emits observer_hostname from syslog HOSTNAME"
```

---

### Task 3: Vector `panos_ecs` — emit `observer_hostname` + unit test

**Files:**
- Modify: `infra/vector/vector.toml` (the `panos_ecs` base-event block, after line 200; add a `[[tests]]` block after the new SRX test from Task 2)

The PAN-OS source field is **decided by this test**, per spec §4.2. Primary attempt: `string(parsed.hostname)`. The live PAN-OS header is BSD/RFC3164 (`<pri>MMM dd HH:MM:SS host ,<CSV>`); `parse_syslog` extracts `.hostname` (e.g. `panosvm.example.com`) *before* the leading-comma CSV corruption that affects appname, so `parsed.hostname` is expected to be populated. If Step 4 shows it empty, apply the Step 3b fallback.

- [ ] **Step 1: Add a failing Vector unit test**

In `infra/vector/vector.toml`, immediately after the `srx_observer_hostname_from_syslog_host` test block added in Task 2, insert:

```toml
[[tests]]
name = "panos_observer_hostname_from_syslog_host"
[[tests.inputs]]
insert_at = "panos_ecs"
type = "raw"
value = '<14>Jun 06 23:20:00 panosvm.example.com ,2026/06/06 23:20:00,007054000270810,TRAFFIC,end,,2026/06/06 23:20:00,10.74.11.50,198.51.100.20,0.0.0.0,0.0.0.0,allow-trust-to-untrust,,,ssl,vsys1,trust,untrust,ethernet1/2,ethernet1/1,,,40001,1,52344,443,0,0,0x0,tcp,allow,8000,3000,5000,40,2026/06/06 23:19:30,30,any,,1001,0x0,10.74.11.0-10.74.11.255,US,,22,18,tcp-fin'
[[tests.outputs]]
extract_from = "panos_ecs"
[[tests.outputs.conditions]]
type = "vrl"
source = '''
assert_eq!(.observer_hostname, "panosvm.example.com")
'''
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `vector test infra/vector/vector.toml`
Expected: FAIL — `panos_observer_hostname_from_syslog_host` errors (`.observer_hostname` unset).

- [ ] **Step 3: Add `observer_hostname` to the `panos_ecs` base event**

In `infra/vector/vector.toml`, in `transforms.panos_ecs`, add an assignment right after the `ev.observer_egress_zone = ""` default (line 200). The base-event defaults become:

```toml
ev.rule_name = ""
ev.observer_ingress_zone = ""
ev.observer_egress_zone = ""
ev.observer_hostname = string(parsed.hostname) ?? ""
ev.user_name = ""
ev.raw = raw
```

(`parsed` is the `parse_syslog(raw)` result computed at line 113. This sets `observer_hostname` for every PAN-OS log_type branch since it is on the base event before the `if log_type ==` branches.)

- [ ] **Step 3b: FALLBACK — only if Step 4 shows `observer_hostname` empty**

If and only if Step 4's run reports `observer_hostname` is `""` (parse_syslog did not populate `.hostname` for the PAN-OS header shape), replace the Step 3 line with a CSV-derived fallback. The syslog host token is the second whitespace field of the header; derive it from the header prefix that the existing regex (line 125) strips. Add after line 126 (`if cerr == null { csv = ... }`):

```toml
host_hdr = ""
hm, hmerr = parse_regex(raw, r'^<\d+>\w+\s+\d+\s+[\d:]+\s+(?P<host>\S+)\s')
if hmerr == null { host_hdr = string(hm.host) ?? "" }
```

and set the base-event line to:

```toml
ev.observer_hostname = host_hdr
```

Re-run Step 4. Choose whichever path makes the test pass; commit only the chosen path.

- [ ] **Step 4: Run the test to verify it passes**

Run: `vector test infra/vector/vector.toml`
Expected: PASS for `panos_observer_hostname_from_syslog_host` AND all pre-existing PAN-OS tests (`panos_traffic_end_allow_maps_to_ecs` … `panos_config_maps_admin_and_command`) — none assert `observer_hostname`.

- [ ] **Step 5: Commit**

```bash
git add infra/vector/vector.toml
git commit -m "feat(m6c-b): panos_ecs emits observer_hostname from syslog HOSTNAME"
```

---

### Task 4: Entity flow-agg SQL — `groupUniqArray(observer_hostname)`

**Files:**
- Modify: `services/entity/src/ssdf_entity/chwriter.py:21-36` (`build_flow_agg_sql`)
- Test: `services/entity/tests/test_chwriter.py`

- [ ] **Step 1: Write a failing test**

In `services/entity/tests/test_chwriter.py`, add after `test_flow_agg_sql_is_parameterized_and_groups_by_pair` (line 13):

```python
def test_flow_agg_sql_selects_observer_hosts():
    sql, _ = build_flow_agg_sql(window_hours=24, tenant="t_main")
    assert "groupUniqArray(observer_hostname) AS observer_hosts" in sql
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd services/entity && uv run --with pytest pytest tests/test_chwriter.py::test_flow_agg_sql_selects_observer_hosts -v`
Expected: FAIL — `assert "groupUniqArray(observer_hostname) AS observer_hosts" in sql`.

- [ ] **Step 3: Add the column to the SELECT**

In `services/entity/src/ssdf_entity/chwriter.py`, in `build_flow_agg_sql`, add the `groupUniqArray` line after the `any(network_transport)` line (line 28). The SELECT becomes:

```python
    sql = (
        "SELECT toString(source_ip) AS src_ip, toString(destination_ip) AS dst_ip, "
        "sum(network_bytes) AS bytes, count() AS flows, "
        "groupUniqArray(destination_port) AS ports, "
        "any(rule_name) AS rule_name, any(event_provider) AS provider, "
        "any(network_transport) AS transport, "
        "groupUniqArray(observer_hostname) AS observer_hosts, "
        "toString(min(timestamp)) AS first_seen, toString(max(timestamp)) AS last_seen "
        "FROM ssdf.events "
        "WHERE tenant_id = {tenant:String} "
        "AND timestamp >= now() - INTERVAL {window_hours:UInt32} HOUR "
        "AND source_ip IS NOT NULL AND destination_ip IS NOT NULL "
        "GROUP BY src_ip, dst_ip"
    )
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd services/entity && uv run --with pytest pytest tests/test_chwriter.py -v`
Expected: PASS (new test + the 3 existing chwriter tests).

- [ ] **Step 5: Commit**

```bash
git add services/entity/src/ssdf_entity/chwriter.py services/entity/tests/test_chwriter.py
git commit -m "feat(m6c-b): flow-agg SQL collects observer_hosts per pair"
```

---

### Task 5: Entity resolver — `observer_hosts` on COMMUNICATED_WITH edge

**Files:**
- Modify: `services/entity/src/ssdf_entity/resolve_entities.py:104-114` (comm-edge default attrs + merge)
- Test: `services/entity/tests/test_resolve_entities.py`

- [ ] **Step 1: Write failing tests**

In `services/entity/tests/test_resolve_entities.py`, add after `test_communicated_with_and_governed_by_edges` (line 81):

```python
def test_observer_hosts_recorded_on_comm_edge():
    entities, edges = resolve_entities([_flow(observer_hosts=["vSRX-test10"])],
                                       topo_hosts=[], tenant="t_main")
    comm = next(e for e in edges if e["edge_type"] == COMMUNICATED_WITH)
    assert comm["attrs"]["observer_hosts"] == "vSRX-test10"


def test_observer_hosts_union_across_rows():
    flows = [_flow(observer_hosts=["vSRX-test10"], first_seen=NOW1, last_seen=NOW1),
             _flow(observer_hosts=["panosvm"], first_seen=NOW2, last_seen=NOW2)]
    _, edges = resolve_entities(flows, topo_hosts=[], tenant="t_main")
    comm = next(e for e in edges if e["edge_type"] == COMMUNICATED_WITH)
    assert set(comm["attrs"]["observer_hosts"].split(",")) == {"panosvm", "vSRX-test10"}


def test_observer_hosts_absent_defaults_empty():
    _, edges = resolve_entities([_flow()], topo_hosts=[], tenant="t_main")
    comm = next(e for e in edges if e["edge_type"] == COMMUNICATED_WITH)
    assert comm["attrs"]["observer_hosts"] == ""
```

(`_flow()` does not set `observer_hosts`; the resolver must default it and tolerate its absence.)

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd services/entity && uv run --with pytest pytest tests/test_resolve_entities.py -k observer_hosts -v`
Expected: FAIL — `KeyError: 'observer_hosts'` (attr not present on the comm edge).

- [ ] **Step 3: Add default attr + merge in `resolve_entities`**

In `services/entity/src/ssdf_entity/resolve_entities.py`, in the comm-edge construction, add `"observer_hosts": ""` to the default attrs dict (lines 104-105):

```python
                "attrs": {"sessions": "0", "bytes": "0", "ports": "", "providers": "",
                          "transports": "", "observer_hosts": ""},
```

Then add a merge call after the `transports` merge (line 113):

```python
        _merge_set_attr(comm["attrs"], "ports", row.get("ports") or [])
        _merge_set_attr(comm["attrs"], "providers", [row.get("provider", "")])
        _merge_set_attr(comm["attrs"], "transports", [row.get("transport", "")])
        _merge_set_attr(comm["attrs"], "observer_hosts", row.get("observer_hosts") or [])
```

(`_merge_set_attr` already drops empty strings, so an empty list leaves `observer_hosts` as `""`.)

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd services/entity && uv run --with pytest pytest tests/test_resolve_entities.py -v`
Expected: PASS (3 new tests + all 9 existing — none of which assert `observer_hosts`, and the default empty string does not perturb them).

- [ ] **Step 5: Commit**

```bash
git add services/entity/src/ssdf_entity/resolve_entities.py services/entity/tests/test_resolve_entities.py
git commit -m "feat(m6c-b): resolver carries observer_hosts onto COMMUNICATED_WITH edge"
```

---

### Task 6: `explain_access` — provenance-primary firewall attribution

**Files:**
- Modify: `services/mcp-query/src/ssdf_mcp_query/access_tools.py:48-86,101` (attribution + observed-controls basis + response field)
- Test: `services/mcp-query/tests/test_access_tools.py`

- [ ] **Step 1: Write failing tests**

In `services/mcp-query/tests/test_access_tools.py`, add three tests at the end of the file (after line 163). They use the existing `_FakeStore`/`_FakeTopo` doubles:

```python
def test_explain_access_provenance_primary_attributes_logging_firewall():
    ents = _client_server()
    comm = [{"edge_id": "E1", "attrs": {"sessions": "1", "bytes": "10",
                                        "ports": "443", "providers": "juniper",
                                        "transports": "tcp",
                                        "observer_hosts": "vSRX-test10"}}]

    class _StoreProv(_FakeStore):
        def configured_policies_for_firewalls(self, names):
            assert names == ["vSRX-test10"]
            return [{"firewall": "vSRX-test10",
                     "policy": {"name": "baseline-permit(global)", "attrs": {"enabled": "true"}}}]

    # topo would say "topology" if consulted; provenance must win and NOT consult it
    class _TopoBoom(_FakeTopo):
        def enforcement_points(self, src, dst):
            raise AssertionError("enforcement_points must not be called when provenance present")

    store = _StoreProv(ents, comm, [])
    out = AccessTools(store, _TopoBoom(["fwX"], {"found": True})).explain_access("10.64.0.5", "8.8.8.8")
    assert out["firewall_basis"] == "provenance"
    assert out["firewalls"] == ["vSRX-test10"]
    assert out["coverage"]["configured"] == 1


def test_explain_access_falls_back_to_topology_when_no_provenance():
    ents = _client_server()
    comm = [{"edge_id": "E1", "attrs": {"sessions": "1", "bytes": "10",
                                        "ports": "443", "providers": "juniper",
                                        "transports": "tcp", "observer_hosts": ""}}]
    store = _FakeStore(ents, comm, [])
    topo = _FakeTopo(["vSRX-test10"], {"found": True, "hops": 3})
    out = AccessTools(store, topo).explain_access("10.64.0.5", "8.8.8.8")
    assert out["firewall_basis"] == "topology"
    assert out["firewalls"] == ["vSRX-test10"]


def test_explain_access_no_provenance_no_topology_is_no_path_firewall():
    ents = _client_server()
    comm = [{"edge_id": "E1", "attrs": {"sessions": "1", "bytes": "10",
                                        "ports": "443", "providers": "juniper",
                                        "transports": "tcp", "observer_hosts": ""}}]
    store = _FakeStore(ents, comm, [])
    out = AccessTools(store, _FakeTopo([], {"found": False})).explain_access("10.64.0.5", "8.8.8.8")
    assert out["firewall_basis"] == "no_path_firewall"
    assert out["coverage"]["configured"] == 0
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd services/mcp-query && uv run --with pytest pytest tests/test_access_tools.py -k "provenance or fall_back or no_path_firewall" -v`
Expected: FAIL — `KeyError: 'firewall_basis'` (top-level field does not exist yet) and the `_TopoBoom` assertion fires (topology is still consulted unconditionally).

- [ ] **Step 3: Replace topology-only attribution with provenance-primary**

In `services/mcp-query/src/ssdf_mcp_query/access_tools.py`, replace lines 48-51:

```python
        # Firewall attribution comes from topology, NOT the event stream (see spec §3).
        enforcement = self._topo.enforcement_points(client, server)
        firewalls = enforcement.get("firewalls", [])
        attributed_fw = firewalls[0] if len(firewalls) == 1 else None
```

with provenance-primary attribution (see spec §4.4):

```python
        # Provenance-primary firewall attribution (spec §4.4): the firewall that LOGGED
        # the flow is, by definition, on its path. Fall back to the L2-topology heuristic
        # only when no provenance is present (it cannot attribute transit firewalls).
        observer_hosts: set[str] = set()
        for edge in comm_edges:
            observer_hosts.update(_csv_list(edge.get("attrs", {}).get("observer_hosts", "")))
        if observer_hosts:
            firewalls = sorted(observer_hosts)
            firewall_basis = "provenance"
        else:
            firewalls = self._topo.enforcement_points(client, server).get("firewalls", [])
            firewall_basis = "topology" if firewalls else "no_path_firewall"
        attributed_fw = firewalls[0] if len(firewalls) == 1 else None
```

- [ ] **Step 4: Reconcile the observed-controls block and add the response field**

In the same file, in the observed-`controls` loop (lines 80-86), replace the two hardcoded `"topology"`/`attributed_fw` lines so the observed story matches the resolved attribution:

```python
                controls.append({
                    "firewall": attributed_fw,
                    "vendor": policy["identifiers"].get("provider", ""),
                    "rule": policy.get("name", ""),
                    "source": policy.get("source", "observed"),
                    "firewall_basis": firewall_basis,
                })
```

Then add `firewall_basis` to the returned dict. After the `"firewalls": firewalls,` line (line 101), add:

```python
            "firewalls": firewalls,
            "firewall_basis": firewall_basis,
```

- [ ] **Step 5: Run the full access_tools test file**

Run: `cd services/mcp-query && uv run --with pytest pytest tests/test_access_tools.py -v`
Expected: PASS for the 3 new tests AND all existing tests. Note the existing `test_observed_flow_with_controls_and_coverage` (line 48) supplies a comm edge WITHOUT `observer_hosts` → provenance set empty → falls back to topology → its assertions `out["controls"][0]["firewall_basis"] == "topology"` and `out["controls"][0]["firewall"] == "vSRX-test10"` still hold. `test_firewall_omitted_when_topology_ambiguous` (line 82, two topo firewalls, no provenance) keeps `attributed_fw is None` and `out["firewalls"] == ["fw1","fw2"]`.

- [ ] **Step 6: Run the entire mcp-query unit suite (guard against regressions)**

Run: `cd services/mcp-query && uv run --with pytest pytest -m "not integration" -v`
Expected: PASS (all unit tests).

- [ ] **Step 7: Commit**

```bash
git add services/mcp-query/src/ssdf_mcp_query/access_tools.py services/mcp-query/tests/test_access_tools.py
git commit -m "feat(m6c-b): explain_access attributes firewall by flow provenance"
```

---

### Task 7: Deploy + live end-to-end validation

Ordered per spec §7 — the column must exist before Vector emits it.

**Files:** none (deployment only). Hosts: ct104 (ClickHouse .151), ct102 (Vector), ct109 (entity resolver .153), ct106 (mcp-query). Access via `ssh root@pve3.example.com` then `pct exec <vmid>`.

- [ ] **Step 1: Apply the ClickHouse migration to ct104**

```bash
ssh root@pve3.example.com "pct exec 104 -- clickhouse-client --multiquery" < infra/clickhouse/006_observer_hostname.sql
ssh root@pve3.example.com "pct exec 104 -- clickhouse-client --query \"DESCRIBE ssdf.events\" | grep observer_hostname"
```
Expected: the second command prints `observer_hostname	LowCardinality(String)	DEFAULT	''`.

- [ ] **Step 2: Push and reload Vector on ct102**

Copy the updated `infra/vector/vector.toml` to ct102's Vector config path (as currently deployed — confirm path with `pct exec 102 -- systemctl cat vector | grep -i config`), then:
```bash
ssh root@pve3.example.com "pct exec 102 -- vector validate --no-environment /etc/vector/vector.toml"
ssh root@pve3.example.com "pct exec 102 -- systemctl reload vector || pct exec 102 -- systemctl restart vector"
```
Expected: `vector validate` reports Validated; service reloads without error.

- [ ] **Step 3: Push updated `services/entity` to ct109**

Sync the `services/entity` package to `/opt/ssdf-entity` on ct109 (match the existing deploy mechanism — see `services/entity/infra/ENV.local` / install notes). The 5-min `ssdf-entity.timer` picks up the new code. To force one pass immediately:
```bash
ssh root@pve3.example.com "pct exec 109 -- systemctl start ssdf-entity.service"
```

- [ ] **Step 4: Push updated `services/mcp-query` to ct106 and restart**

Sync `services/mcp-query` to ct106, then restart the MCP service:
```bash
ssh root@pve3.example.com "pct exec 106 -- systemctl restart ssdf-mcp-query.service"
```

- [ ] **Step 5: Generate fresh transit traffic (preferred live-proof path)**

The 12 pre-existing real rows predate the column (read `observer_hostname=''`), so generate fresh cross-zone transit through vSRX-test10 (e.g. drive a connection from `198.51.100.150` to `203.0.113.1`) so a new RT_FLOW row carries `observer_hostname="vSRX-test10"`. Wait for one Vector flush (≤5s batch) + one `ssdf-entity.timer` cycle (≤5 min), or re-run Step 3 to force the resolver pass.

  **Fallback (only if generating transit is impractical):** backfill the existing rows:
  ```sql
  ALTER TABLE ssdf.events UPDATE observer_hostname = 'vSRX-test10'
    WHERE event_provider = 'juniper' AND raw ILIKE '%vSRX-test10%' AND observer_hostname = '';
  ```
  then force a resolver pass (Step 3).

- [ ] **Step 6: Verify the comm edge carries `observer_hosts`**

```bash
ssh root@pve3.example.com "pct exec 104 -- clickhouse-client --query \"SELECT attrs['observer_hosts'] FROM ssdf.entity_edges FINAL WHERE edge_type='COMMUNICATED_WITH' AND attrs['observer_hosts'] != '' LIMIT 5\""
```
Expected: at least one row showing `vSRX-test10`.

- [ ] **Step 7: Verify `explain_access` end-to-end**

Call the live `explain_access` MCP tool (ct106) for the transit pair used in Step 5, e.g. `explain_access("198.51.100.150", "203.0.113.1")` (add an explicit `since_hours` wide enough to cover the fresh row if needed).
Expected response fields:
- `firewall_basis == "provenance"`
- `firewalls == ["vSRX-test10"]`
- `coverage.configured >= 1`

- [ ] **Step 8: Update STATUS.md + CLAUDE.md and commit**

- Mark M6c scope B done in `docs/superpowers/STATUS.md` (note: provenance-based attribution; `coverage.configured>0` proven end-to-end on the transit pair; record which proof path was used — fresh traffic vs backfill).
- Add a `### M6c (scope B)` bullet to `CLAUDE.md` documenting `observer_hostname`, the `006_observer_hostname.sql` migration, and the provenance-primary `firewall_basis` field on `explain_access`.

```bash
git add docs/superpowers/STATUS.md CLAUDE.md
git commit -m "docs(m6c-b): record provenance firewall attribution as built/live"
```

---

## Notes for the implementer

- **Tests:** Python via `uv run --with pytest pytest` (pytest is a dev optional-dep, not in the default venv). Vector via the `vector test` binary (installed on ct102, not the dev host).
- **Honesty contract:** provenance attributes only firewalls that *logged* the flow. A silently-logging-disabled on-path firewall contributes nothing — reported as absence, never a fabricated topology claim. `firewall_basis` exposes which mechanism attributed.
- **`enforcement_points` (topo_tools.py) is NOT modified** — it remains the fallback and an independent topology tool.
- **No new infra, no new LXC, no MCP tool added/renamed** — `explain_access` gains one response field (`firewall_basis`).
