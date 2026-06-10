# SSDF — P0 ingest hardening (H1 + H2)

**Date:** 2026-06-10
**Status:** design approved, pre-implementation
**Scope:** ct102 ingest host firewall (new) + `infra/vector/vector.toml` VRL (both transforms)
**Source:** `docs/security/2026-06-10-vulnerability-review.md` P0 findings H1, H2

## Problem

Two P0/High findings, one shared root cause — **unauthenticated network-level trust of syslog**:

- **H1 — Unauthenticated, world-bound UDP syslog ingest.** `vector.toml:7` binds
  `0.0.0.0:514` (SRX) and `:14` binds `0.0.0.0:515` (PAN-OS) with no source allow-list.
  Any host with LAN reach can inject arbitrary rows into `ssdf.events` (spoofed
  src/dst IPs, zones, `rule_name`, `user_name`) — log poisoning of the system of record.
- **H2 — Spoofable `observer_hostname` is load-bearing for firewall attribution.**
  `vector.toml:97` (SRX) and `:202` (PAN-OS) set `observer_hostname` straight from the
  syslog HOSTNAME header. M6c-B treats `observer_hostname → observer_hosts` as the
  *primary* evidence that a firewall is on a flow's path (`firewall_basis:provenance`),
  consumed by `explain_access`. A spoofed UDP packet claiming `hostname=vSRX-test10`
  can fabricate access-path conclusions.

Fixing H1 (source allow-listing at the host) substantially mitigates H2; H2's VRL change
is defense-in-depth for any spoofed-but-source-allowed packet.

## Lab facts (verified 2026-06-10)

- ct102 = `198.51.100.150`, Debian 12 bookworm, `nft` present at `/sbin/nft`.
- Current nftables ruleset: default `table inet filter` with input/forward/output base
  chains, **all `policy accept`** — no filtering today.
- Whole lab is one flat `198.51.100.0/24`, so binding Vector to an interface cannot
  isolate device traffic (devices share the subnet). Source-IP filtering is required.
- Legitimate syslog senders (chosen scope: **whole vSRX test fleet + panosvm**):
  - vSRX test fleet occupies `198.51.100.220`–`198.51.100.242` (per srxoutpost
    `reference_proxmox.md`: test3=.220, test1=.221, test2=.224, test4=.226, test5=.227,
    test6=.228, test7=.229, test8–20=.230–.242).
  - panosvm = `198.51.100.225` (inside that range).
  - ⇒ single allow range **`198.51.100.220-198.51.100.242`** covers all senders.
  - Device hostnames (H2): vSRX devices report `vSRX-test<N>`; panosvm reports
    `panosvm.example.com`.

## Goal

Restrict which sources may reach UDP 514/515 (H1), and stop `observer_hostname` from
being trusted as provenance unless it names a known device (H2) — **without** changing
the event schema, the read path, or the live-proven vSRX provenance path.

## H1 — Design: nftables source allow-list on ct102

### New files (tracked in repo)

- `infra/firewall/ct102-ingest.nft` — dedicated nftables table, idempotent.
- `scripts/apply_ct102_nftables.sh` — copies the rule file to ct102, wires persistence,
  loads it live, and verifies.

### Rule file `infra/firewall/ct102-ingest.nft`

A dedicated table (`inet ssdf_ingest`) so the existing `inet filter` table is untouched.
The base chain's `policy accept` means it only ever *drops* disallowed syslog — all other
traffic passes. The `table … / delete table …` prologue makes reloads idempotent.

```
#!/usr/sbin/nft -f

# SSDF ingest hardening (security review 2026-06-10, finding H1).
# Restrict UDP 514 (SRX) / 515 (PAN-OS) to the vSRX test fleet + panosvm.
# Dedicated table; does not touch the default `inet filter` table.

table inet ssdf_ingest
delete table inet ssdf_ingest
table inet ssdf_ingest {
    chain input {
        type filter hook input priority filter; policy accept;

        # Allowed syslog senders: vSRX test fleet + panosvm (198.51.100.220-.242).
        udp dport { 514, 515 } ip saddr 198.51.100.220-198.51.100.242 accept

        # Everything else hitting the ingest ports is dropped.
        udp dport { 514, 515 } drop
    }
}
```

### Apply script `scripts/apply_ct102_nftables.sh`

POSIX `sh`, run from a workstation with root SSH to pve3. Idempotent; safe to re-run.

```sh
#!/bin/sh
# Apply SSDF ingest firewall (finding H1) to ct102 via pve3.
# Usage: ./scripts/apply_ct102_nftables.sh
set -eu

PVE_HOST="${PVE_HOST_SSH:-root@pve3.example.com}"
CTID="${SSDF_VECTOR_CTID:-102}"
RULE_SRC="$(dirname "$0")/../infra/firewall/ct102-ingest.nft"
RULE_DST="/etc/nftables.d/ssdf-ingest.nft"

[ -f "$RULE_SRC" ] || { echo "missing $RULE_SRC" >&2; exit 1; }

# Push the rule file into the container.
ssh "$PVE_HOST" "pct exec $CTID -- mkdir -p /etc/nftables.d"
ssh "$PVE_HOST" "pct push $CTID '$RULE_SRC' '$RULE_DST' --perms 644" \
    2>/dev/null \
  || ssh "$PVE_HOST" "cat > /tmp/ssdf-ingest.nft && pct push $CTID /tmp/ssdf-ingest.nft '$RULE_DST'" \
       < "$RULE_SRC"

# Ensure /etc/nftables.conf includes our drop-in (idempotent), enable + reload service.
ssh "$PVE_HOST" "pct exec $CTID -- sh -c '
  grep -qF \"include \\\"$RULE_DST\\\"\" /etc/nftables.conf 2>/dev/null \
    || echo \"include \\\"$RULE_DST\\\"\" >> /etc/nftables.conf
  nft -f $RULE_DST
  systemctl enable --now nftables.service
'"

# Verify the table loaded.
echo '=== ssdf_ingest table on ct102 ==='
ssh "$PVE_HOST" "pct exec $CTID -- nft list table inet ssdf_ingest"
```

Notes:
- `pct push` is the primary path; the `cat | pct push /tmp` fallback covers older `pct`
  without `--perms`. The implementer should pick whichever `pct push` form works live and
  drop the other — do not ship a guess.
- `include` is appended to `/etc/nftables.conf` only if absent, so reboot persistence
  survives without duplicating lines.

### Verification

- `nft list table inet ssdf_ingest` shows the two rules.
- From an allowed host (any vSRX / panosvm): syslog still lands in `ssdf.events`.
- From a non-allowed host: `logger -n 198.51.100.150 -P 514 -d test` produces **no** new
  row (manual check; not automatable in unit tests).

## H2 — Design: known-device gate in the VRL transforms

Both `srx_ecs` and `panos_ecs` compute `observer_hostname` from the syslog HOSTNAME.
Add a gate: normalize to the first DNS label, lowercase **for the membership test only**,
and accept iff it matches a known device. Unknown ⇒ blank the field (`""`). The **stored
value keeps its original case** so the M6c-B exact-match bridge (`vSRX-test10`) is intact.

### Known-device test (VRL, identical logic in both transforms)

```
obs = string(parsed.hostname) ?? ""
short = downcase(split(obs, ".")[0] ?? "")
known = false
if short == "panosvm" { known = true }
_m, _e = parse_regex(short, r'^vsrx-test\d')
if _e == null { known = true }
if !known { obs = "" }
```

- `split(obs, ".")[0]` → first label: `panosvm.example.com`→`panosvm`,
  `vSRX-test10`→`vSRX-test10` (no dot, no-op). Empty hostname → `""` → not known → stays "".
- Pattern `^vsrx-test\d` matches the whole fleet (honors the "survives onboarding new
  test devices" scope) without enumerating each name. `panosvm` is matched exactly.
- This is deliberately broad (a pattern, not a fixed list) per the chosen allow-list
  scope; H1 is the primary control, and provenance only *bridges* when a Firewall entity
  of that exact name exists, so an allowed-but-nonexistent name fabricates nothing.

### Application

- **SRX (`srx_ecs`):** compute `obs` (above) immediately before the `. = { … }` object
  literal, then change the literal's line from
  `"observer_hostname": string(parsed.hostname) ?? "",` to `"observer_hostname": obs,`.
- **PAN-OS (`panos_ecs`):** compute `obs` (above) immediately before
  `ev.observer_hostname = …`, then change that line to `ev.observer_hostname = obs`.

The ~6-line gate is duplicated per transform (VRL has no cross-transform helpers; the
toml already duplicates patterns by design). No schema change, no read-path change.

### Tests (`vector test infra/vector/vector.toml`, run on ct102)

Existing tests that must still pass (regression):
- `srx_observer_hostname_from_syslog_host` — host `vSRX-test10` ⇒ `observer_hostname ==
  "vSRX-test10"` (known, case preserved).
- `panos_observer_hostname_from_syslog_host` — host `panosvm.example.com` ⇒
  `observer_hostname == "panosvm.example.com"` (known).

New tests:
- `srx_observer_hostname_unknown_is_blanked` — a SRX RT_FLOW line with HOSTNAME
  `evil-host` ⇒ `observer_hostname == ""`, other fields (e.g. `rule_name`) unaffected.
- `panos_observer_hostname_unknown_is_blanked` — a PAN-OS TRAFFIC line with HOSTNAME
  `attacker.example.com` ⇒ `observer_hostname == ""`, `event_action == "flow_end"`.

## Order & risk

1. **H1 first** (biggest risk reduction): land the rule file + script, apply to ct102,
   verify allowed senders still ingest. Reversible: `nft delete table inet ssdf_ingest`.
2. **H2 second** (VRL gate + tests): unit-test-provable offline via `vector test`; deploy
   by pushing the updated `vector.toml` to ct102 and restarting Vector.

Both are reversible and touch no schema, no stored rows, no read path.

## Out of scope

- Per-port source tightening (514↔vSRX-only, 515↔panosvm-only) — future hardening; the
  chosen scope is one fleet range for both ports.
- L1 (TLS transport), L3 (MCP bind), M1 (query timeout) and the other review findings —
  separate backlog items.
- No change to `explain_access`, the entity resolver, or the M6c-B read-path
  `_short_host` normalization.
