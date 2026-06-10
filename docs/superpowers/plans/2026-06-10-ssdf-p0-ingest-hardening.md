# SSDF P0 Ingest Hardening (H1 + H2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop unauthenticated syslog injection into `ssdf.events` (H1) and stop spoofable `observer_hostname` from fabricating firewall provenance (H2).

**Architecture:** H1 adds a dedicated nftables table on the Vector ingest host (ct102) that drops UDP 514/515 except from the vSRX fleet + panosvm (`198.51.100.220-198.51.100.242`). H2 adds a known-device gate inside both VRL transforms in `vector.toml` that blanks `observer_hostname` unless it normalizes to a known device name. No schema, read-path, or `explain_access` changes.

**Tech Stack:** nftables (Debian 12 on ct102), Vector 0.56.0 VRL + `vector test`, Proxmox `pct` over SSH to `root@pve3.example.com`.

---

## Environment & preconditions (read first)

- **ct102** = `198.51.100.150`, Debian 12, `nft` at `/sbin/nft`, current ruleset = default
  `inet filter` (all chains `policy accept`, no filtering).
- **Vector** is installed ONLY on ct102 (`/bin/vector`, v0.56.0). Run all `vector test`
  invocations there. The live config is `/etc/vector/vector.toml`; the service is
  `vector.service` (drop-in `/etc/systemd/system/vector.service.d/env.conf` supplies
  `CH_HOST`).
- **As of 2026-06-09 `vector.service` is `failed`** — its ClickHouse sink healthcheck
  cannot reach ct104 (`Connection refused`) because ct104/ClickHouse is down for the pve3
  upgrade. The config loads cleanly; this is purely environmental.
  - `vector test` does NOT exercise the sink, so **H2 unit tests pass regardless**.
  - **H2 live deploy (Task 6) is BLOCKED until ClickHouse (ct104) is reachable** and
    `vector validate` passes again. Do Tasks 4–5 now; gate Task 6 on CH being up.
  - H1 (Tasks 1–3) is independent of Vector/CH state.
- **Proven remote-exec path** (used for every ct102 command below): SSH to pve3, then
  `pct exec 102 -- …`. To get a local file into the container, pipe it through pve3:
  `cat <file> | ssh root@pve3.example.com "cat > /tmp/<f> && pct push 102 /tmp/<f> <dst>"`.

### `vector test` runner (used in Tasks 4 & 5)

Push the working repo copy to a scratch path on ct102 and test it there (never clobber
the live `/etc/vector/vector.toml` during TDD):

```bash
cat infra/vector/vector.toml \
  | ssh root@pve3.example.com "cat > /tmp/vt.toml && pct push 102 /tmp/vt.toml /tmp/vt.toml" \
  && ssh root@pve3.example.com "pct exec 102 -- vector test /tmp/vt.toml"
```

---

## File Structure

- **Create** `infra/firewall/ct102-ingest.nft` — dedicated nftables table for ingest source
  allow-listing (H1). Single responsibility: drop UDP 514/515 from non-allowed sources.
- **Create** `scripts/apply_ct102_nftables.sh` — idempotent apply/verify script for the
  above (H1).
- **Modify** `infra/vector/vector.toml` — add the known-device gate to `srx_ecs` (before
  the `. = {…}` literal at line 77; change line 97) and `panos_ecs` (before line 202;
  change line 202); add two `[[tests]]` cases (H2).

---

### Task 1: H1 — nftables rule file

**Files:**
- Create: `infra/firewall/ct102-ingest.nft`

- [ ] **Step 1: Create the rule file**

Create `infra/firewall/ct102-ingest.nft` with exactly:

```
#!/usr/sbin/nft -f

# SSDF ingest hardening (security review 2026-06-10, finding H1).
# Restrict UDP 514 (SRX) / 515 (PAN-OS) to the vSRX test fleet + panosvm.
# Dedicated table; does not touch the default `inet filter` table.
# The `table ... / delete table ...` prologue makes reloads idempotent.

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

- [ ] **Step 2: Validate syntax on ct102 (check-only, does not load)**

```bash
cat infra/firewall/ct102-ingest.nft \
  | ssh root@pve3.example.com "cat > /tmp/ssdf-ingest.nft && pct push 102 /tmp/ssdf-ingest.nft /tmp/ssdf-ingest.nft" \
  && ssh root@pve3.example.com "pct exec 102 -- nft -c -f /tmp/ssdf-ingest.nft && echo NFT_SYNTAX_OK"
```

Expected: prints `NFT_SYNTAX_OK` with no nft error lines. (`nft -c` parses and checks
against the live ruleset without applying.)

- [ ] **Step 3: Commit**

```bash
git add infra/firewall/ct102-ingest.nft
git commit -m "feat(infra): nftables ingest allow-list for ct102 (H1)"
```

---

### Task 2: H1 — apply/verify script

**Files:**
- Create: `scripts/apply_ct102_nftables.sh`

- [ ] **Step 1: Create the script**

Create `scripts/apply_ct102_nftables.sh` with exactly:

```sh
#!/bin/sh
# Apply the SSDF ingest firewall (security review finding H1) to ct102 via pve3.
# Idempotent; safe to re-run. Usage: ./scripts/apply_ct102_nftables.sh
set -eu

PVE_HOST="${PVE_HOST_SSH:-root@pve3.example.com}"
CTID="${SSDF_VECTOR_CTID:-102}"
RULE_SRC="$(dirname "$0")/../infra/firewall/ct102-ingest.nft"
RULE_DST="/etc/nftables.d/ssdf-ingest.nft"

[ -f "$RULE_SRC" ] || { echo "missing $RULE_SRC" >&2; exit 1; }

# Push the rule file into the container (via a pve3 scratch copy).
ssh "$PVE_HOST" "pct exec $CTID -- mkdir -p /etc/nftables.d"
cat "$RULE_SRC" | ssh "$PVE_HOST" "cat > /tmp/ssdf-ingest.nft && pct push $CTID /tmp/ssdf-ingest.nft $RULE_DST"

# Ensure /etc/nftables.conf includes our drop-in (idempotent), load it, enable service.
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

- [ ] **Step 2: Make it executable and shell-lint it**

```bash
chmod +x scripts/apply_ct102_nftables.sh
sh -n scripts/apply_ct102_nftables.sh && echo SH_SYNTAX_OK
```

Expected: prints `SH_SYNTAX_OK`, no output from `sh -n`.

- [ ] **Step 3: Commit**

```bash
git add scripts/apply_ct102_nftables.sh
git commit -m "feat(infra): apply script for ct102 ingest firewall (H1)"
```

---

### Task 3: H1 — apply live to ct102 and verify (ops step, no commit)

**Files:** none (runtime action). CH state irrelevant — nftables is independent.

- [ ] **Step 1: Apply**

```bash
./scripts/apply_ct102_nftables.sh
```

Expected: ends with the `=== ssdf_ingest table on ct102 ===` header followed by the
table dump showing both `udp dport { 514, 515 } ip saddr 198.51.100.220-198.51.100.242 accept`
and `udp dport { 514, 515 } drop` rules.

- [ ] **Step 2: Confirm persistence wiring**

```bash
ssh root@pve3.example.com "pct exec 102 -- sh -c 'grep ssdf-ingest /etc/nftables.conf; systemctl is-enabled nftables.service'"
```

Expected: the `include "/etc/nftables.d/ssdf-ingest.nft"` line, then `enabled`.

- [ ] **Step 3: Functional check — disallowed source is dropped**

From any host whose IP is NOT in `198.51.100.220-198.51.100.242` (e.g. this workstation),
send a test syslog packet and confirm no error and (once CH is up) no new row. The drop is
silent, so verify the counter increments instead:

```bash
# Re-run after sending a packet from a non-allowed host; the drop rule's counter should be >0.
ssh root@pve3.example.com "pct exec 102 -- nft list table inet ssdf_ingest"
```

Note: a definitive end-to-end "row did/didn't appear" check requires ClickHouse (ct104) to
be back up. The rule itself is in force immediately regardless.

---

### Task 4: H2 — SRX `observer_hostname` known-device gate

**Files:**
- Modify: `infra/vector/vector.toml` (add `[[tests]]` case; insert gate before line 77; change line 97)

- [ ] **Step 1: Add the failing test**

In `infra/vector/vector.toml`, immediately after the existing
`panos_observer_hostname_from_syslog_host` test block (ends ~line 438), add:

```toml
[[tests]]
name = "srx_observer_hostname_unknown_is_blanked"
[[tests.inputs]]
insert_at = "srx_ecs"
type = "raw"
value = '<14>1 2026-06-08T12:00:00.000Z evil-host RT_FLOW - RT_FLOW_SESSION_CLOSE [junos@2636.1.1.1.2.36 source-address="10.65.1.10" source-port="51514" destination-address="10.66.2.20" destination-port="443" protocol-id="6" policy-name="baseline-permit(global)" source-zone-name="trust" destination-zone-name="untrust" bytes-from-client="1500" bytes-from-server="6000" username="N/A"]'
[[tests.outputs]]
extract_from = "srx_ecs"
[[tests.outputs.conditions]]
type = "vrl"
source = '''
assert_eq!(.observer_hostname, "")
assert_eq!(.rule_name, "baseline-permit(global)")
'''
```

- [ ] **Step 2: Run the test runner — verify it FAILS**

Use the `vector test` runner from the preconditions section.

Expected: `srx_observer_hostname_unknown_is_blanked` FAILS — actual `observer_hostname` is
`"evil-host"`, not `""`. (The existing `srx_observer_hostname_from_syslog_host` test still
passes.)

- [ ] **Step 3: Implement the gate in `srx_ecs`**

In the `srx_ecs` transform, insert these lines immediately before the `. = {` object
literal (currently line 77), at the same 4-space indentation, inside the `else` block where
`parsed` is valid:

```
    obs_host = string(parsed.hostname) ?? ""
    _obs_parts = split(obs_host, ".")
    _obs_short = downcase(string(_obs_parts[0]) ?? "")
    _obs_known = false
    if _obs_short == "panosvm" { _obs_known = true }
    _om, _oe = parse_regex(_obs_short, r'^vsrx-test\d')
    if _oe == null { _obs_known = true }
    if !_obs_known { obs_host = "" }
```

Then change the object-literal line (currently line 97) from:

```
        "observer_hostname": string(parsed.hostname) ?? "",
```

to:

```
        "observer_hostname": obs_host,
```

- [ ] **Step 4: Run the test runner — verify it PASSES**

Use the `vector test` runner again.

Expected: ALL tests pass, including `srx_observer_hostname_unknown_is_blanked` (now `""`)
AND the regression `srx_observer_hostname_from_syslog_host` (host `vSRX-test10` ⇒
`observer_hostname == "vSRX-test10"`, case preserved).

- [ ] **Step 5: Commit**

```bash
git add infra/vector/vector.toml
git commit -m "feat(vector): gate SRX observer_hostname to known devices (H2)"
```

---

### Task 5: H2 — PAN-OS `observer_hostname` known-device gate

**Files:**
- Modify: `infra/vector/vector.toml` (add `[[tests]]` case; insert gate before line 202; change line 202)

- [ ] **Step 1: Add the failing test**

In `infra/vector/vector.toml`, immediately after the test block added in Task 4, add:

```toml
[[tests]]
name = "panos_observer_hostname_unknown_is_blanked"
[[tests.inputs]]
insert_at = "panos_ecs"
type = "raw"
value = '<14>Jun 06 23:20:00 attacker.example.com ,2026/06/06 23:20:00,007054000270810,TRAFFIC,end,,2026/06/06 23:20:00,10.74.11.50,198.51.100.20,0.0.0.0,0.0.0.0,allow-trust-to-untrust,,,ssl,vsys1,trust,untrust,ethernet1/2,ethernet1/1,,,40001,1,52344,443,0,0,0x0,tcp,allow,8000,3000,5000,40,2026/06/06 23:19:30,30,any,,1001,0x0,10.74.11.0-10.74.11.255,US,,22,18,tcp-fin'
[[tests.outputs]]
extract_from = "panos_ecs"
[[tests.outputs.conditions]]
type = "vrl"
source = '''
assert_eq!(.observer_hostname, "")
assert_eq!(.event_action, "flow_end")
'''
```

- [ ] **Step 2: Run the test runner — verify it FAILS**

Use the `vector test` runner.

Expected: `panos_observer_hostname_unknown_is_blanked` FAILS — actual `observer_hostname`
is `"attacker.example.com"`, not `""`.

- [ ] **Step 3: Implement the gate in `panos_ecs`**

In the `panos_ecs` transform, insert these lines immediately before
`ev.observer_hostname = string(parsed.hostname) ?? ""` (currently line 202), at the same
indentation:

```
obs_host = string(parsed.hostname) ?? ""
_obs_parts = split(obs_host, ".")
_obs_short = downcase(string(_obs_parts[0]) ?? "")
_obs_known = false
if _obs_short == "panosvm" { _obs_known = true }
_om, _oe = parse_regex(_obs_short, r'^vsrx-test\d')
if _oe == null { _obs_known = true }
if !_obs_known { obs_host = "" }
```

Then change line 202 from:

```
ev.observer_hostname = string(parsed.hostname) ?? ""
```

to:

```
ev.observer_hostname = obs_host
```

- [ ] **Step 4: Run the test runner — verify it PASSES**

Use the `vector test` runner.

Expected: ALL tests pass, including `panos_observer_hostname_unknown_is_blanked` (now `""`)
AND the regression `panos_observer_hostname_from_syslog_host` (host `panosvm.example.com` ⇒
`observer_hostname == "panosvm.example.com"`).

- [ ] **Step 5: Commit**

```bash
git add infra/vector/vector.toml
git commit -m "feat(vector): gate PAN-OS observer_hostname to known devices (H2)"
```

---

### Task 6: H2 — deploy updated `vector.toml` to ct102 (ops step, no commit)

**Files:** none (runtime action).

**PRECONDITION:** ClickHouse (ct104) must be reachable so the Vector sink healthcheck
passes — otherwise `vector.service` will not start (see Environment notes). Confirm the
ClickHouse HTTP port is open from ct102 first (CH_HOST lives in the service drop-in):

```bash
ssh root@pve3.example.com "pct exec 102 -- bash -c '
  CH=\$(grep -oP \"CH_HOST=\K[^\" ]+\" /etc/systemd/system/vector.service.d/env.conf)
  echo \"CH_HOST=\$CH\"
  timeout 3 bash -c \"echo > /dev/tcp/\$CH/8123\" 2>/dev/null && echo CH_UP || echo CH_DOWN
'"
```

Expected: `CH_UP`. If `CH_DOWN`, **stop** — wait for the pve3 upgrade to finish and ct104
to come back, then retry. (The restart in Step 1 + the journal in Step 2 are the
authoritative gate either way: a failed sink healthcheck will surface there.)

- [ ] **Step 1: Push the updated config and restart**

```bash
cat infra/vector/vector.toml \
  | ssh root@pve3.example.com "cat > /tmp/vt.toml && pct push 102 /tmp/vt.toml /etc/vector/vector.toml" \
  && ssh root@pve3.example.com "pct exec 102 -- systemctl restart vector.service && pct exec 102 -- systemctl is-active vector.service"
```

Expected: prints `active`.

- [ ] **Step 2: Confirm clean startup**

```bash
ssh root@pve3.example.com "pct exec 102 -- journalctl -u vector.service --no-pager -n 8"
```

Expected: no `Healthcheck failed` / `ERROR` lines; Vector reports started and listening.

- [ ] **Step 3: (post-CH-recovery) Spot-check live attribution unchanged**

Once flows are ingesting again, confirm a known-device flow still carries provenance and
an unknown HOSTNAME would not. The live-proven vSRX path must be intact:
`explain_access` for the vSRX-test10 flow still returns `firewall_basis:provenance`,
`firewalls:[vSRX-test10]`. (Manual check via the mcp-query tool on ct106.)

---

## Notes for the implementer

- The H2 gate is intentionally a broad pattern (`^vsrx-test\d` + exact `panosvm`), matching
  the approved "whole vSRX test fleet + panosvm" scope — H1 is the primary control. Do NOT
  narrow it to a fixed list unless the spec changes.
- The gate logic is duplicated in both transforms by design (VRL has no cross-transform
  helpers; the toml already duplicates patterns). Keep the two copies identical.
- If VRL rejects `downcase(string(_obs_parts[0]) ?? "")` on a type/fallibility check, the
  `vector test` error will say so; the idiom mirrors the existing `string(f[N]) ?? ""`
  pattern used throughout `panos_ecs`, so it should type-check. Do not change the stored
  value's case — only `_obs_short` is lowercased, for the membership test.
```
