# M4 Firewall-Node Tagging Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `panosvm` and `vSRX-test10` resolve as `device` nodes with `attrs.role == "firewall"` in `ssdf.graph_nodes`, so M4 `enforcement_points` can attribute them on a path (closing the scope-A part of issue #6).

**Architecture:** Each M4 firewall collector (junos, panos) emits one extra `device_inventory` observation tagging its own device `role=firewall`. The resolver already turns `device_inventory.role` into `device.attrs.role` and merges it by name onto the existing device node — so no resolver, schema, or `enforcement_points` change is needed.

**Tech Stack:** Python 3.11, pytest, the existing `services/topo` package; deploy via systemd timer on Proxmox LXC ct109 (no Docker).

**Spec:** `docs/superpowers/specs/2026-06-08-m4-firewall-node-tagging-design.md`

---

## File structure

- `services/topo/src/ssdf_topo/collectors/base.py` — gains `firewall_inventory(...)` helper (shared, DRY).
- `services/topo/src/ssdf_topo/collectors/junos.py` — `collect()` appends the helper per device.
- `services/topo/src/ssdf_topo/collectors/panos.py` — `collect()` appends the helper for its device.
- `services/topo/tests/test_collector_base.py` — unit test for the helper.
- `services/topo/tests/test_collector_junos.py` — unit test for junos `collect()` emission.
- `services/topo/tests/test_collector_panos.py` — unit test for panos `collect()` emission.
- `services/topo/tests/test_resolve.py` — merge-by-name guard test.
- `services/topo/tests/test_integration.py` — live ct109 role assertion.
- `CLAUDE.md`, `docs/superpowers/STATUS.md` — record scope-A done.

---

## Task 1: `firewall_inventory` helper

**Files:**
- Modify: `services/topo/src/ssdf_topo/collectors/base.py`
- Test: `services/topo/tests/test_collector_base.py`

- [ ] **Step 1: Write the failing test**

Append to `services/topo/tests/test_collector_base.py`:

```python
def test_firewall_inventory_builds_role_tagged_observation():
    from ssdf_topo.collectors.base import firewall_inventory

    obs = firewall_inventory("junos", "vSRX-test10", "2026-06-08T00:00:00+00:00")

    assert obs.observation_type == "device_inventory"
    assert obs.collector == "junos"
    assert obs.source_device == "vSRX-test10"
    assert obs.layer == "l2"
    assert obs.subj_kind == "device"
    assert obs.subj_id == "device:vSRX-test10"
    assert obs.attrs["role"] == "firewall"
    assert obs.attrs["name"] == "vSRX-test10"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd services/topo && uv run pytest tests/test_collector_base.py::test_firewall_inventory_builds_role_tagged_observation -v`
Expected: FAIL with `ImportError: cannot import name 'firewall_inventory'`.

- [ ] **Step 3: Write minimal implementation**

In `services/topo/src/ssdf_topo/collectors/base.py`, after the imports and before `REGISTRY`, add:

```python
def firewall_inventory(collector: str, source_device: str, now: str) -> Observation:
    """Build a device_inventory observation tagging `source_device` as a firewall.

    Emitted by collectors whose target device is inherently a firewall (SRX, PAN-OS)
    so the resolver tags the resulting device node `attrs.role="firewall"`, which
    `enforcement_points` requires to attribute the firewall to a path.
    """
    return Observation(
        observed_at=now,
        collector=collector,
        source_device=source_device,
        layer="l2",
        observation_type="device_inventory",
        subj_kind="device",
        subj_id=f"device:{source_device}",
        attrs={"role": "firewall", "name": source_device},
    )
```

(`Observation` is already imported at `base.py:9`.)

- [ ] **Step 4: Run test to verify it passes**

Run: `cd services/topo && uv run pytest tests/test_collector_base.py -v`
Expected: PASS (all tests in the file).

- [ ] **Step 5: Commit**

```bash
git add services/topo/src/ssdf_topo/collectors/base.py services/topo/tests/test_collector_base.py
git commit -m "feat(m4): firewall_inventory helper for role-tagged device_inventory obs"
```

---

## Task 2: Junos collector emits the firewall inventory

**Files:**
- Modify: `services/topo/src/ssdf_topo/collectors/junos.py:139-160`
- Test: `services/topo/tests/test_collector_junos.py`

- [ ] **Step 1: Write the failing test**

Append to `services/topo/tests/test_collector_junos.py`:

```python
def test_collect_emits_firewall_inventory_per_device():
    from ssdf_topo.collectors.junos import JunosCollector

    class _EmptyClient:
        def call_tool(self, name, args=None):
            return ""  # parsers yield no rows on empty text

    obs = JunosCollector(["vSRX-test10", "vSRX-test11"]).collect(_EmptyClient(), NOW)

    inv = [o for o in obs if o.observation_type == "device_inventory"]
    assert {o.source_device for o in inv} == {"vSRX-test10", "vSRX-test11"}
    assert all(o.attrs["role"] == "firewall" for o in inv)
    assert all(o.collector == "junos" for o in inv)
    assert len(inv) == 2
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd services/topo && uv run pytest tests/test_collector_junos.py::test_collect_emits_firewall_inventory_per_device -v`
Expected: FAIL — `assert 0 == 2` (no device_inventory observations emitted yet).

- [ ] **Step 3: Write minimal implementation**

In `services/topo/src/ssdf_topo/collectors/junos.py`, update the import at the top of the file (it currently imports only `Observation` from `..models`) to also import the helper. Add near the existing imports:

```python
from .base import register, firewall_inventory
```

(If `register` is already imported from `.base`, just add `firewall_inventory` to that import.) Then inside `collect()`, append one inventory observation per device. The loop body ends after the arp block (`junos.py:159`); add as the last statement inside `for dev in self.devices:`:

```python
            observations.append(firewall_inventory("junos", dev, now))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd services/topo && uv run pytest tests/test_collector_junos.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add services/topo/src/ssdf_topo/collectors/junos.py services/topo/tests/test_collector_junos.py
git commit -m "feat(m4): junos collector tags its devices role=firewall"
```

---

## Task 3: PAN-OS collector emits the firewall inventory

**Files:**
- Modify: `services/topo/src/ssdf_topo/collectors/panos.py` (`collect()` return)
- Test: `services/topo/tests/test_collector_panos.py`

- [ ] **Step 1: Write the failing test**

Append to `services/topo/tests/test_collector_panos.py`:

```python
def test_collect_emits_firewall_inventory():
    from ssdf_topo.collectors.panos import PanosCollector

    empty_envelope = (
        '{"result":"<response status=\\"success\\"><result></result></response>"}'
    )

    class _EmptyClient:
        def call_tool(self, name, args=None):
            return empty_envelope

    obs = PanosCollector("panosvm").collect(_EmptyClient(), NOW)

    inv = [o for o in obs if o.observation_type == "device_inventory"]
    assert len(inv) == 1
    assert inv[0].source_device == "panosvm"
    assert inv[0].attrs["role"] == "firewall"
    assert inv[0].collector == "panos"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd services/topo && uv run pytest tests/test_collector_panos.py::test_collect_emits_firewall_inventory -v`
Expected: FAIL — `assert 0 == 1`.

- [ ] **Step 3: Write minimal implementation**

In `services/topo/src/ssdf_topo/collectors/panos.py`, add `firewall_inventory` to the `.base` import (the file imports `register` from `.base`; add the helper there):

```python
from .base import register, firewall_inventory
```

Then change the `collect()` return (currently `return parse_lldp_xml(...) + parse_arp_xml(...)`) to append the inventory observation:

```python
        return (
            parse_lldp_xml(lldp_text, self.device, now)
            + parse_arp_xml(arp_text, self.device, now)
            + [firewall_inventory("panos", self.device, now)]
        )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd services/topo && uv run pytest tests/test_collector_panos.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add services/topo/src/ssdf_topo/collectors/panos.py services/topo/tests/test_collector_panos.py
git commit -m "feat(m4): panos collector tags its device role=firewall"
```

---

## Task 4: Resolver merge-by-name guard test

**Files:**
- Test: `services/topo/tests/test_resolve.py` (no production code change)

This locks in the spec's load-bearing assumption: a `device_inventory(role=firewall)` and a
same-named lldp/mac observation resolve to **one** device node carrying the role.

- [ ] **Step 1: Write the failing-then-passing test**

Append to `services/topo/tests/test_resolve.py`:

```python
def test_device_inventory_role_merges_onto_named_device_node():
    from ssdf_topo.models import Observation
    from ssdf_topo.resolver.resolve import resolve_graph

    now = "2026-06-08T00:00:00+00:00"
    mac_obs = Observation(
        observed_at=now, collector="junos", source_device="vSRX-test10",
        layer="l2", observation_type="mac_entry",
        subj_kind="host", subj_id="mac:aa:bb:cc:dd:ee:01",
        obj_kind="device", obj_id="device:vSRX-test10",
        attrs={"vlan": "10", "port": "ge-0/0/0"},
    )
    inv_obs = Observation(
        observed_at=now, collector="junos", source_device="vSRX-test10",
        layer="l2", observation_type="device_inventory",
        subj_kind="device", subj_id="device:vSRX-test10",
        attrs={"role": "firewall", "name": "vSRX-test10"},
    )

    nodes, _edges = resolve_graph([mac_obs, inv_obs], [], "t_main")

    fw = [n for n in nodes if n["kind"] == "device" and n["name"] == "vSRX-test10"]
    assert len(fw) == 1, "device_inventory must merge onto the named device node, not duplicate it"
    assert fw[0]["attrs"]["role"] == "firewall"
```

- [ ] **Step 2: Run the test**

Run: `cd services/topo && uv run pytest tests/test_resolve.py::test_device_inventory_role_merges_onto_named_device_node -v`
Expected: PASS (the resolver already supports this; the test guards it). If it FAILS, stop — the
merge assumption is wrong and the spec needs revisiting before proceeding.

- [ ] **Step 3: Commit**

```bash
git add services/topo/tests/test_resolve.py
git commit -m "test(m4): guard device_inventory role merges onto named device node"
```

---

## Task 5: Live integration assertion + deploy to ct109

**Files:**
- Modify: `services/topo/tests/test_integration.py`

- [ ] **Step 1: Add a role assertion to the live integration test**

In `services/topo/tests/test_integration.py`, after the existing `rows`/`assert` block in
`test_collect_then_resolve_populates_graph` (after line 49), append:

```python
    fw_rows = writer.query(
        "SELECT name FROM ssdf.graph_nodes FINAL "
        "WHERE tenant_id = {t:String} AND kind = 'device' "
        "AND attrs['role'] = 'firewall'",
        {"t": config.tenant_id},
    )
    fw_names = {r["name"] for r in fw_rows}
    assert "vSRX-test10" in fw_names, f"vSRX-test10 not tagged firewall; got {fw_names}"
```

(PAN-OS is only asserted if `panos` is in the enabled collectors for the run; vSRX-test10 is the
always-present device, so it is the reliable assertion.)

- [ ] **Step 2: Run the full unit suite locally (must stay green)**

Run: `cd services/topo && uv run pytest -m "not integration" -q`
Expected: all pass.

- [ ] **Step 3: Commit the test**

```bash
git add services/topo/tests/test_integration.py
git commit -m "test(m4): live assertion that firewalls are tagged role=firewall"
```

- [ ] **Step 4: Deploy updated `services/topo` to ct109**

The package is installed editable from a source dir on ct109. Determine it and sync the three
changed source files, then trigger one pass:

```bash
# discover the installed editable source path
ssh root@pve3.example.com "pct exec 109 -- /opt/ssdf-topo/bin/python -c \"import ssdf_topo, os; print(os.path.dirname(ssdf_topo.__file__))\""
```

Sync the three changed files (`collectors/base.py`, `collectors/junos.py`,
`collectors/panos.py`) from the repo into that path on ct109 (via `pct push` from the pve host, or
re-`pip install -e` the synced source tree — match however M4/M6b are deployed on this host). Then:

```bash
ssh root@pve3.example.com "pct exec 109 -- systemctl start ssdf-topo.service"
```

- [ ] **Step 5: Verify in ClickHouse (ct104)**

```bash
ssh root@pve3.example.com "pct exec 104 -- clickhouse-client --query \"SELECT name, attrs['role'] AS role FROM ssdf.graph_nodes FINAL WHERE tenant_id='t_main' AND kind='device' AND attrs['role']='firewall' ORDER BY name\""
```

Expected: rows for `vSRX-test10` (and `panosvm` if the panos collector is enabled on ct109),
each with `role = firewall`.

- [ ] **Step 6: Run live integration on ct109 (optional confirmation)**

If the live env file is present, run the integration test on ct109 (mirrors the M4 command in
`CLAUDE.md`); expect `test_collect_then_resolve_populates_graph` to pass including the new
firewall assertion.

---

## Task 6: Documentation + close issue #6 (scope A)

**Files:**
- Modify: `CLAUDE.md` (M4 section)
- Modify: `docs/superpowers/STATUS.md`

- [ ] **Step 1: Note the change in `CLAUDE.md`**

In the `### M4 (topology graph ...)` block, add a bullet:

```markdown
- Firewall device nodes: the junos/panos collectors emit a `device_inventory` observation tagging
  their own device `role=firewall`, so `enforcement_points` can attribute them on a path. (Closes
  issue #6 scope A — the M6b→M4 bridge; live `coverage.configured>0` end-to-end is scope B.)
```

- [ ] **Step 2: Update `docs/superpowers/STATUS.md`**

In the M6b forward-roadmap entry's "M4↔M6b name-bridge gap" note, record that scope A
(firewall-role nodes now emitted by M4 collectors) is done, and that issue #6 remains open
tracking scope B (live end-to-end `coverage.configured>0`, which needs host↔firewall L2/L3
connectivity observations). Update the M6b as-built table row's bridge-gap parenthetical
accordingly.

- [ ] **Step 3: Commit**

```bash
git add CLAUDE.md docs/superpowers/STATUS.md
git commit -m "docs(m4): record firewall-node tagging (issue #6 scope A done)"
```

- [ ] **Step 4: Comment on issue #6**

Post a comment on issue #6 noting scope A is implemented and deployed (firewalls now tagged
`role=firewall` in `ssdf.graph_nodes`, proven live), and that the issue stays open for scope B
(end-to-end live attribution requiring host↔firewall connectivity). Do **not** auto-close — scope B
is still open under milestone M6c.

---

## Final review

- [ ] Run the full unit suite: `cd services/topo && uv run pytest -m "not integration" -q` — all green.
- [ ] Dispatch a code-reviewer over the whole branch against this plan + the spec.
- [ ] Use superpowers:finishing-a-development-branch to open the PR (include the live CH proof
  that `vSRX-test10`/`panosvm` carry `attrs.role='firewall'`).

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-06-08-m4-firewall-node-tagging.md`.
Two execution options:

1. **Subagent-Driven (recommended)** — fresh subagent per task, two-stage review between tasks.
2. **Inline Execution** — execute tasks in this session with checkpoints.

Which approach?
