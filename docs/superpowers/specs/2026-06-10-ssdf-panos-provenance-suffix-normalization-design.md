# SSDF — PAN-OS provenance suffix normalization (M6c-B follow-up)

**Date:** 2026-06-10
**Status:** design approved, pre-implementation
**Scope:** single-file read-path fix in `services/mcp-query`

## Problem

`explain_access` attributes the on-path firewall from flow provenance (M6c-B): the
firewall that *logged* a flow is on its path, surfaced via the `observer_hosts` edge
attribute (normalized ECS `observer.hostname` collected per pair). When provenance is
present it sets:

```python
firewalls = sorted(observer_hosts)        # access_tools.py
```

and bridges to configured policy via
`configured_policies_for_firewalls(firewalls)`, which matches Firewall entities by
**exact equality** on `identifiers['device_name']` (`entitystore.py`
`build_firewall_match_sql` → `device_name IN {names}`).

The two sides disagree on form for PAN-OS:

| side | value | source |
|---|---|---|
| provenance (`observer_hosts`) | `panosvm.example.com` (FQDN) | PAN-OS syslog HOSTNAME |
| M6b Firewall entity (`device_name`) | `panosvm` (short) | `PANOS_DEVICE` env |

`panosvm.example.com` ≠ `panosvm` ⇒ no Firewall matches ⇒
`configured_basis = "firewall_name_unmatched"`, `coverage.configured = 0`.

**vSRX is unaffected today** because its `observer.hostname` is already the short
`vSRX-test10`, equal to its `device_name`. So vSRX is the live-proven path and PAN-OS
is the carve-out (documented in `STATUS.md` M6c-B notes).

## Goal

Bridge PAN-OS provenance to its configured policy by reconciling the FQDN-vs-short-name
mismatch, **without** breaking the live-proven vSRX path and **without** touching the
ingest pipeline, resolver, stored events, or stored edges.

## Approach (chosen: read-time normalization)

Normalize the provenance hostnames to their first DNS label at the single bridge point
in `explain_access`, mirroring the spirit of M6a's `normalize_segment` (reconcile FQDN
vs short name at the *matching* layer) but on the pure read path — no migration, no
re-ingest, reversible.

Rejected alternatives:

- **Ingest-time (Vector `*_ecs` transforms):** redefines the ECS `observer.hostname`
  column (conventionally an FQDN), touches the live ingest path, and needs M6c-B
  re-validation plus re-ingest of historical rows. Over-invasive.
- **Resolver-time (`observer_hosts` edge attr):** mutates stored data and needs a
  backfill resolver pass. Changes data rather than its interpretation.

## Design

Single file: `services/mcp-query/src/ssdf_mcp_query/access_tools.py`.

### Helper

```python
import ipaddress

def _short_host(name: str) -> str:
    """First DNS label of a hostname, case preserved. A bare IP is returned unchanged."""
    try:
        ipaddress.ip_address(name)   # IP guard: never dot-split an address
        return name
    except ValueError:
        return name.split(".", 1)[0]
```

- **Case is preserved.** Lowercasing would break vSRX: its `device_name` is mixed-case
  `vSRX-test10`, and a lowercased `vsrx-test10` would no longer match. `split(".", 1)[0]`
  on a dot-free name is a no-op, so vSRX passes through untouched.
- **IP guard.** `ipaddress.ip_address` accepts both IPv4 and IPv6; a bare address (e.g.
  a device that emits its IP as the syslog HOSTNAME) is returned verbatim instead of
  being truncated at the first dot.

### Application

Only the provenance branch changes:

```python
if observer_hosts:
    firewalls = sorted({_short_host(h) for h in observer_hosts})
    firewall_basis = "provenance"
else:
    firewalls = self._topo.enforcement_points(client, server).get("firewalls", [])
    firewall_basis = "topology" if firewalls else "no_path_firewall"
```

The topology-fallback branch is untouched. `attributed_fw = firewalls[0] if
len(firewalls) == 1 else None` still holds; set-comprehension dedups any FQDN/short
collision onto one short name.

### Behavior matrix

| `observer.hostname` | `_short_host` | effect |
|---|---|---|
| `panosvm.example.com` | `panosvm` | matches `device_name=panosvm` → `coverage.configured>0` |
| `vSRX-test10` | `vSRX-test10` | unchanged — live-proven path intact |
| `198.51.100.1` | `198.51.100.1` | IP guard, not mangled |
| `PANOSVM.example.com` | `PANOSVM` | case preserved |

### Side effect (intended)

The `firewalls` response field becomes vendor-consistent: both PAN-OS and SRX report
short device names. No other response field changes shape.

## Testing

Unit (`services/mcp-query/tests/test_access_tools.py`, `-m "not integration"`):

1. `_short_host` cases: `panosvm.example.com`→`panosvm`; `vSRX-test10`→`vSRX-test10`
   (dot-free, case preserved); `198.51.100.1`→`198.51.100.1` (IPv4 guard); a bare IPv6
   →unchanged; `PANOSVM.example.com`→`PANOSVM` (case preserved).
2. `explain_access` with a mocked `EntityStore`: a `COMMUNICATED_WITH` edge carrying
   `observer_hosts="panosvm.example.com"` and a `panosvm` Firewall with a configured
   policy yields `firewall_basis="provenance"`, `firewalls=["panosvm"]`,
   `configured_basis="topology"`, and `coverage.configured == 1`.
3. Regression: an edge with `observer_hosts="vSRX-test10"` still yields
   `firewalls=["vSRX-test10"]` and bridges unchanged.

## Caveat (carried into STATUS.md)

This fix is **unit-test-provable** but **not live-provable end-to-end** until PAN-OS
transit traffic exists in the lab — the same M5/M6c-B carve-out (PAN-OS logs no transit
flows yet, so no `panosvm` provenance edge exists to resolve live). The vSRX path stays
the live-proven one; this change is verified by unit tests and a manual mocked check.

## Out of scope

- No ingest/Vector changes, no schema migration, no resolver/backfill.
- No fuzzy or case-insensitive matching beyond domain-suffix stripping (YAGNI; the M6b
  contract already requires `device_name` to equal the M4 `source_device` short name).
- No change to the topology-fallback attribution path.
