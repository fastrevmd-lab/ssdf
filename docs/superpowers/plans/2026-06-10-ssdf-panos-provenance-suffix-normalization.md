# PAN-OS Provenance Suffix Normalization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bridge PAN-OS provenance firewalls to their configured policy in `explain_access` by normalizing FQDN `observer.hostname` values to their first DNS label at the read-time matching point, without breaking the live-proven vSRX path.

**Architecture:** Single-file read-path change in `services/mcp-query`. Add a pure `_short_host` helper (first DNS label, case-preserved, IP-guarded) and apply it in the provenance branch of `explain_access` so `observer_hosts` values match Firewall entities' short `device_name`. No ingest, schema, resolver, or stored-data changes.

**Tech Stack:** Python 3, `uv`, pytest, FastMCP; ClickHouse-backed EntityStore (mocked in unit tests).

---

### Task 1: `_short_host` helper (TDD)

**Files:**
- Modify: `services/mcp-query/src/ssdf_mcp_query/access_tools.py:1-16`
- Test: `services/mcp-query/tests/test_access_tools.py`

- [ ] **Step 1: Write the failing test**

Add to `services/mcp-query/tests/test_access_tools.py` (import `_short_host` alongside the existing `AccessTools` import — adjust the existing import line to `from ssdf_mcp_query.access_tools import AccessTools, _short_host`):

```python
import pytest

@pytest.mark.parametrize("raw,expected", [
    ("panosvm.example.com", "panosvm"),     # FQDN → short label (the PAN-OS fix)
    ("vSRX-test10", "vSRX-test10"),         # dot-free, case preserved (vSRX path intact)
    ("198.51.100.1", "198.51.100.1"),         # IPv4 guard: not truncated at first dot
    ("fe80::1", "fe80::1"),                 # IPv6 guard: unchanged
    ("PANOSVM.example.com", "PANOSVM"),     # case preserved
])
def test_short_host(raw, expected):
    assert _short_host(raw) == expected
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd services/mcp-query && uv run pytest tests/test_access_tools.py::test_short_host -v`
Expected: FAIL with `ImportError: cannot import name '_short_host'`.

- [ ] **Step 3: Write minimal implementation**

In `services/mcp-query/src/ssdf_mcp_query/access_tools.py`, add `import ipaddress` to the imports block (after `import datetime as _dt`), and add the helper directly below `_csv_list`:

```python
import ipaddress
```

```python
def _short_host(name: str) -> str:
    """First DNS label of a hostname, case preserved. A bare IP is returned unchanged."""
    try:
        ipaddress.ip_address(name)   # IP guard: never dot-split an address
        return name
    except ValueError:
        return name.split(".", 1)[0]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd services/mcp-query && uv run pytest tests/test_access_tools.py::test_short_host -v`
Expected: PASS (all 5 parametrized cases).

- [ ] **Step 5: Commit**

```bash
git add services/mcp-query/src/ssdf_mcp_query/access_tools.py services/mcp-query/tests/test_access_tools.py
git commit -m "$(cat <<'EOF'
feat(m6c): add _short_host helper for provenance suffix normalization

First DNS label, case-preserved, IP-guarded. Pure helper; not yet wired
into explain_access.

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: Apply normalization in the provenance branch (TDD)

**Files:**
- Modify: `services/mcp-query/src/ssdf_mcp_query/access_tools.py:54-55`
- Test: `services/mcp-query/tests/test_access_tools.py`

- [ ] **Step 1: Write the failing PAN-OS bridge test**

Add to `services/mcp-query/tests/test_access_tools.py`. This mirrors the existing `test_explain_access_provenance_primary_attributes_logging_firewall` but uses an FQDN `observer_hosts` and asserts the store is queried with the short name:

```python
def test_explain_access_provenance_normalizes_panos_fqdn():
    ents = _client_server()
    comm = [{"edge_id": "E1", "attrs": {"sessions": "1", "bytes": "10",
                                        "ports": "443", "providers": "paloalto",
                                        "transports": "tcp",
                                        "observer_hosts": "panosvm.example.com"}}]

    class _StoreProv(_FakeStore):
        def configured_policies_for_firewalls(self, names):
            assert names == ["panosvm"]   # normalized from panosvm.example.com
            return [{"firewall": "panosvm",
                     "policy": {"name": "transit-permit", "attrs": {"enabled": "true"}}}]

    class _TopoBoom(_FakeTopo):
        def enforcement_points(self, src, dst):
            raise AssertionError("enforcement_points must not be called when provenance present")

    store = _StoreProv(ents, comm, [])
    out = AccessTools(store, _TopoBoom(["fwX"], {"found": True})).explain_access(
        "10.64.0.5", "8.8.8.8")
    assert out["firewall_basis"] == "provenance"
    assert out["firewalls"] == ["panosvm"]
    assert out["coverage"]["configured"] == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd services/mcp-query && uv run pytest tests/test_access_tools.py::test_explain_access_provenance_normalizes_panos_fqdn -v`
Expected: FAIL — `configured_policies_for_firewalls` receives `["panosvm.example.com"]`, tripping the inner `assert names == ["panosvm"]`.

- [ ] **Step 3: Write minimal implementation**

In `services/mcp-query/src/ssdf_mcp_query/access_tools.py`, change the provenance branch (line 55):

```python
        if observer_hosts:
            firewalls = sorted({_short_host(h) for h in observer_hosts})
            firewall_basis = "provenance"
```

(Only the `firewalls = ...` line changes — `firewall_basis`, the `else` topology branch, and `attributed_fw` are untouched.)

- [ ] **Step 4: Run test to verify it passes**

Run: `cd services/mcp-query && uv run pytest tests/test_access_tools.py::test_explain_access_provenance_normalizes_panos_fqdn -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add services/mcp-query/src/ssdf_mcp_query/access_tools.py services/mcp-query/tests/test_access_tools.py
git commit -m "$(cat <<'EOF'
fix(m6c): normalize provenance hostnames to short label in explain_access

PAN-OS observer.hostname (panosvm.example.com) now matches the Firewall
entity device_name (panosvm), bridging provenance to configured policy.

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: vSRX regression guard (TDD)

**Files:**
- Test: `services/mcp-query/tests/test_access_tools.py`

This locks in that the live-proven vSRX path (dot-free, mixed-case `vSRX-test10`) is unaffected by the normalization. The existing `test_explain_access_provenance_primary_attributes_logging_firewall` already covers vSRX provenance; this task confirms it still passes after Task 2 and adds an explicit assertion that the short name is preserved verbatim if not already present.

- [ ] **Step 1: Confirm the existing vSRX provenance test still passes**

Run: `cd services/mcp-query && uv run pytest tests/test_access_tools.py::test_explain_access_provenance_primary_attributes_logging_firewall -v`
Expected: PASS — `firewalls == ["vSRX-test10"]`, `coverage.configured == 1`. (The `_short_host` of a dot-free name is a no-op, so behavior is unchanged.)

- [ ] **Step 2: Add an explicit case-preservation regression test**

Add to `services/mcp-query/tests/test_access_tools.py`:

```python
def test_explain_access_provenance_preserves_mixed_case_short_name():
    ents = _client_server()
    comm = [{"edge_id": "E1", "attrs": {"sessions": "1", "bytes": "10",
                                        "ports": "443", "providers": "juniper",
                                        "transports": "tcp",
                                        "observer_hosts": "vSRX-test10"}}]

    class _StoreProv(_FakeStore):
        def configured_policies_for_firewalls(self, names):
            assert names == ["vSRX-test10"]   # unchanged: dot-free, case preserved
            return [{"firewall": "vSRX-test10",
                     "policy": {"name": "baseline-permit(global)", "attrs": {"enabled": "true"}}}]

    store = _StoreProv(ents, comm, [])
    out = AccessTools(store, _FakeTopo(["fwX"], {"found": True})).explain_access(
        "10.64.0.5", "8.8.8.8")
    assert out["firewall_basis"] == "provenance"
    assert out["firewalls"] == ["vSRX-test10"]
```

- [ ] **Step 3: Run the regression test**

Run: `cd services/mcp-query && uv run pytest tests/test_access_tools.py::test_explain_access_provenance_preserves_mixed_case_short_name -v`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add services/mcp-query/tests/test_access_tools.py
git commit -m "$(cat <<'EOF'
test(m6c): regression guard — provenance preserves mixed-case short name

Locks in that vSRX-test10 (dot-free) survives _short_host untouched.

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
EOF
)"
```

---

### Task 4: Full unit-suite check + docs

**Files:**
- Modify: `CLAUDE.md` (M6c scope B section — add the normalization note)
- Modify: `docs/superpowers/STATUS.md` (M6c-B carve-out → bridged note)

- [ ] **Step 1: Run the full non-integration suite**

Run: `cd services/mcp-query && uv run pytest -m "not integration" -v`
Expected: PASS, including all prior access_tools, entitystore, classification, auth, audit, wrapper, and server-audit tests plus the 3 new tests.

- [ ] **Step 2: Update CLAUDE.md M6c scope B note**

In `CLAUDE.md`, in the "M6c scope B" section, update the proof-caveat line that currently reads `PAN-OS provenance also doesn't yet bridge to configured policy (observer = panosvm.example.com vs Firewall entity panosvm — domain-suffix mismatch)` to note it is now bridged at read time:

```
- **Provenance suffix normalization (M6c-B follow-up):** `explain_access` normalizes each `observer_hosts` value to its first DNS label (`_short_host`, case-preserved, IP-guarded) before matching Firewall entities, so PAN-OS `panosvm.example.com` bridges to `device_name=panosvm`. vSRX (`vSRX-test10`, dot-free) is a no-op. Unit-proven; not yet live-proven end-to-end (no PAN-OS transit flow exists in the lab — same M5/M6c-B carve-out).
```

- [ ] **Step 3: Update STATUS.md**

In `docs/superpowers/STATUS.md`, find the M6c-B carve-out note about PAN-OS not bridging to configured policy and append that the read-time `_short_host` normalization closes the FQDN/short-name mismatch (unit-proven, live-proof still pending PAN-OS transit traffic).

- [ ] **Step 4: Commit**

```bash
git add CLAUDE.md docs/superpowers/STATUS.md
git commit -m "$(cat <<'EOF'
docs(m6c): record provenance suffix normalization bridge

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Self-Review

- **Spec coverage:** `_short_host` helper (Task 1) ✔; provenance-branch application (Task 2) ✔; behavior matrix cases — FQDN→short, dot-free unchanged, IPv4/IPv6 guard, case preserved — covered by Task 1 parametrize + Task 2/3 ✔; vSRX regression (Task 3) ✔; caveat carried into docs (Task 4) ✔. Out-of-scope items (no ingest/schema/resolver change) are honored — only `access_tools.py` is touched.
- **Placeholder scan:** none — all test bodies and the implementation diff are spelled out.
- **Type consistency:** helper name `_short_host` used identically in Tasks 1–2; fixtures `_FakeStore`, `_FakeTopo`, `_client_server`, and the `_StoreProv` override pattern match the existing test module; `firewalls`, `firewall_basis`, `coverage.configured` field names match `access_tools.py`.
