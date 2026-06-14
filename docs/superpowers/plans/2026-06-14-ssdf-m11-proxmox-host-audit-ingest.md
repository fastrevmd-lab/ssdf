# M11 — Proxmox host audit ingest Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ingest the pve3 Proxmox hypervisor host's auth + admin-action syslog
(`pvedaemon`/`pveproxy`/`sshd`) into `ssdf.events` via a new Vector UDP/517 source +
VRL transform, queryable through the existing MCP tools.

**Architecture:** rsyslog on pve3 forwards `auth`/`authpriv`/`daemon` facilities (RFC5424)
to Vector ct102 UDP/517. A `proxmox_sec` filter keeps only the known security lines; a
`proxmox_ecs` remap parses them (`parse_syslog` + per-appname regex) into the ECS-subset
with `event_provider="proxmox"`. Proxmox-specific detail rides `ext.proxmox.*` (no schema
migration). nftables on ct102 allows UDP/517 only from the pve3 host IP.

**Tech Stack:** Vector VRL (TOML config on ct102), nftables, rsyslog, ClickHouse.

**Spec:** `docs/superpowers/specs/2026-06-14-ssdf-m11-proxmox-host-audit-ingest-design.md`

---

## File structure

- **Modify** `infra/vector/vector.toml` — add `[sources.proxmox_syslog]`, `[transforms.proxmox_sec]`,
  `[transforms.proxmox_ecs]`, add `proxmox_ecs` to `[sinks.clickhouse].inputs`, and a
  `[[tests]]` suite. This is the only code file; it is the single home for vendor log formats.
- **Modify** `infra/firewall/ct102-ingest.nft` — add the UDP/517 allow + extend the drop set.
- **Create** `onboarding/proxmox/rsyslog.md` — operator runbook.
- **Modify** `docs/superpowers/STATUS.md`, `CLAUDE.md` — milestone docs.

## How to run Vector tests

Vector is installed on ct102, not the dev host. Push the file and run there:

```bash
scp infra/vector/vector.toml root@pve3.example.com:/tmp/vector.toml
ssh root@pve3.example.com "pct push 102 /tmp/vector.toml /tmp/vector.toml && pct exec 102 -- bash -c 'cd /tmp && vector test vector.toml'"
```

Run a single test by name: append its name to `vector test vector.toml` is not supported;
`vector test` runs all. The full suite must stay green (existing 20 + the new Proxmox tests).

---

## Task 1: Vector source + filter + transform scaffold (auth_success branch)

**Files:**
- Modify: `infra/vector/vector.toml`

- [ ] **Step 1: Add the UDP source** after the `[sources.unifi_syslog]` block (ends at line ~25)

```toml
# Proxmox (M11) — the pve3 hypervisor host forwards auth + admin-action syslog
# (pvedaemon/pveproxy/sshd) via rsyslog on a separate UDP port. RFC5424 framing
# (PRI + ISO-8601 offset timestamp), so the transform uses parse_syslog.
[sources.proxmox_syslog]
type = "socket"
mode = "udp"
address = "0.0.0.0:517"
max_length = 102400
```

- [ ] **Step 2: Add the `proxmox_sec` filter** immediately after the `[transforms.unifi_ips]`
block (i.e. after its closing `'''`, before the `[sinks.clickhouse]` comment block at line ~505)

```toml
# Keep only the known Proxmox security lines (pvedaemon/pveproxy auth+task, sshd
# logins); drop systemd/pvescheduler/kernel noise so ssdf.events is not flooded.
# parse_syslog runs here too because appname lives inside the raw RFC5424 line.
[transforms.proxmox_sec]
type = "filter"
inputs = ["proxmox_syslog"]
condition.type = "vrl"
condition.source = '''
result = false
parsed, err = parse_syslog(string(.message) ?? "")
if err == null {
    app = downcase(string(parsed.appname) ?? "")
    msg = string(parsed.message) ?? ""
    is_app = app == "pvedaemon" || app == "pveproxy" || app == "sshd"
    is_sec = contains(msg, "successful auth for user") ||
        contains(msg, "authentication failure") ||
        contains(msg, "starting task UPID:") ||
        contains(msg, "end task UPID:") ||
        starts_with(msg, "Accepted ") ||
        starts_with(msg, "Failed password for ")
    result = is_app && is_sec
}
result
'''
```

- [ ] **Step 3: Add the `proxmox_ecs` transform scaffold** (parse_syslog + parse_error +
pvedaemon `auth_success`) immediately after the `proxmox_sec` block

```toml
# Parse the Proxmox security line -> ECS subset. event_provider="proxmox".
# observer_hostname stays empty (it is the firewall-provenance field, P0/H2);
# the node name rides ext.proxmox.node. Per-message regexes are NOT $-anchored,
# so the socket trailing newline is a non-issue (parse_syslog frames the datagram).
[transforms.proxmox_ecs]
type = "remap"
inputs = ["proxmox_sec"]
source = '''
raw = string(.message) ?? ""
parsed, perr = parse_syslog(raw)

ev = {}
ev.event_id = uuid_v4()
ev.tenant_id = "t_main"
ev.event_provider = "proxmox"
ev.event_kind = "event"
ev.event_category = ["host"]
ev.event_action = "unknown"
ev.event_outcome = "unknown"
ev.observer_hostname = ""
ev.user_name = ""
ev.raw = raw

ext = {}

if perr != null {
    ev.timestamp = now()
    ev.event_action = "parse_error"
    ev.ext = ext
    . = ev
} else {
    ts = parsed.timestamp
    if ts != null { ev.timestamp = ts } else { ev.timestamp = now() }

    appname = downcase(string(parsed.appname) ?? "")
    msg = string(parsed.message) ?? ""
    ext = set!(ext, ["proxmox.appname"], appname)
    node = string(parsed.hostname) ?? ""
    if node != "" { ext = set!(ext, ["proxmox.node"], node) }

    # pvedaemon/pveproxy auth success: "<root@pam> successful auth for user 'root@pam'"
    asm, aserr = parse_regex(msg, r"successful auth for user '(?P<user>[^']+)'")
    if aserr == null {
        ev.event_category = ["authentication"]
        ev.event_action = "auth_success"
        ev.event_outcome = "success"
        ev.user_name = string(asm.user) ?? ""
    }

    ev.ext = ext
    . = ev
}
'''
```

- [ ] **Step 4: Add the first test** at the end of the `[[tests]]` section (end of file)

```toml
# ---------------- Proxmox (M11) unit tests ----------------

[[tests]]
name = "proxmox_pvedaemon_auth_success"
[[tests.inputs]]
insert_at = "proxmox_ecs"
type = "raw"
value = "<86>1 2026-06-14T20:00:00.123456+00:00 pve3 pvedaemon 1234 - - <root@pam> successful auth for user 'root@pam'"
[[tests.outputs]]
extract_from = "proxmox_ecs"
[[tests.outputs.conditions]]
type = "vrl"
source = '''
assert_eq!(.event_provider, "proxmox")
assert_eq!(.event_category, ["authentication"])
assert_eq!(.event_action, "auth_success")
assert_eq!(.event_outcome, "success")
assert_eq!(.user_name, "root@pam")
assert_eq!(.ext."proxmox.node", "pve3")
assert_eq!(.ext."proxmox.appname", "pvedaemon")
'''
```

- [ ] **Step 5: Run the full suite to verify it passes (existing 20 + this 1 = 21)**

Run:
```bash
scp infra/vector/vector.toml root@pve3.example.com:/tmp/vector.toml
ssh root@pve3.example.com "pct push 102 /tmp/vector.toml /tmp/vector.toml && pct exec 102 -- bash -c 'cd /tmp && vector test vector.toml'"
```
Expected: `21 tests passed` (or "Test ... passed" lines with 0 failures).

- [ ] **Step 6: Commit**

```bash
git add infra/vector/vector.toml
git commit -m "feat(m11): proxmox_syslog source + proxmox_sec filter + auth_success parse"
```

---

## Task 2: auth_failure branch (rhost → source_ip)

**Files:**
- Modify: `infra/vector/vector.toml`

- [ ] **Step 1: Add the failing test** at the end of the `[[tests]]` section

```toml
[[tests]]
name = "proxmox_auth_failure_with_rhost"
[[tests.inputs]]
insert_at = "proxmox_ecs"
type = "raw"
value = "<86>1 2026-06-14T20:01:00.000000+00:00 pve3 pvedaemon 1234 - - authentication failure; rhost=198.51.100.9 user=root@pam msg=password failure"
[[tests.outputs]]
extract_from = "proxmox_ecs"
[[tests.outputs.conditions]]
type = "vrl"
source = '''
assert_eq!(.event_category, ["authentication"])
assert_eq!(.event_action, "auth_failure")
assert_eq!(.event_outcome, "failure")
assert_eq!(.user_name, "root@pam")
assert_eq!(.source_ip, "198.51.100.9")
'''
```

- [ ] **Step 2: Run to verify it fails**

Run the push+`vector test` command from Task 1 Step 5.
Expected: FAIL — `proxmox_auth_failure_with_rhost` asserts `event_action == "auth_failure"`
but the scaffold leaves it `"unknown"` (the message has no "successful auth" match).

- [ ] **Step 3: Add the auth_failure branch.** In `[transforms.proxmox_ecs]`, replace the
auth-success block with success + failure, parsing rhost before success:

Replace:
```toml
    # pvedaemon/pveproxy auth success: "<root@pam> successful auth for user 'root@pam'"
    asm, aserr = parse_regex(msg, r"successful auth for user '(?P<user>[^']+)'")
    if aserr == null {
        ev.event_category = ["authentication"]
        ev.event_action = "auth_success"
        ev.event_outcome = "success"
        ev.user_name = string(asm.user) ?? ""
    }
```
with:
```toml
    # pvedaemon/pveproxy auth failure: "authentication failure; rhost=<ip> user=<u> msg=..."
    afm, aferr = parse_regex(msg, r'authentication failure;\s*rhost=(?P<ip>\S+)\s+user=(?P<user>\S+)')
    if aferr == null {
        ev.event_category = ["authentication"]
        ev.event_action = "auth_failure"
        ev.event_outcome = "failure"
        ev.user_name = string(afm.user) ?? ""
        ev.source_ip = afm.ip
    } else {
        # pvedaemon/pveproxy auth success: "<root@pam> successful auth for user 'root@pam'"
        asm, aserr = parse_regex(msg, r"successful auth for user '(?P<user>[^']+)'")
        if aserr == null {
            ev.event_category = ["authentication"]
            ev.event_action = "auth_success"
            ev.event_outcome = "success"
            ev.user_name = string(asm.user) ?? ""
        }
    }
```

- [ ] **Step 4: Run to verify both tests pass (22 total)**

Run the push+`vector test` command. Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add infra/vector/vector.toml
git commit -m "feat(m11): proxmox auth_failure branch with rhost->source_ip"
```

---

## Task 3: sshd login branch (Accepted / Failed password)

**Files:**
- Modify: `infra/vector/vector.toml`

- [ ] **Step 1: Add two failing tests** at the end of the `[[tests]]` section

```toml
[[tests]]
name = "proxmox_sshd_accepted_publickey"
[[tests.inputs]]
insert_at = "proxmox_ecs"
type = "raw"
value = "<38>1 2026-06-14T20:02:00.000000+00:00 pve3 sshd 2222 - - Accepted publickey for root from 198.51.100.5 port 51000 ssh2: ED25519 SHA256:abc"
[[tests.outputs]]
extract_from = "proxmox_ecs"
[[tests.outputs.conditions]]
type = "vrl"
source = '''
assert_eq!(.event_category, ["authentication"])
assert_eq!(.event_action, "auth_success")
assert_eq!(.event_outcome, "success")
assert_eq!(.user_name, "root")
assert_eq!(.source_ip, "198.51.100.5")
assert_eq!(.source_port, 51000)
'''

[[tests]]
name = "proxmox_sshd_failed_invalid_user"
[[tests.inputs]]
insert_at = "proxmox_ecs"
type = "raw"
value = "<38>1 2026-06-14T20:03:00.000000+00:00 pve3 sshd 2223 - - Failed password for invalid user admin from 203.0.113.7 port 40222 ssh2"
[[tests.outputs]]
extract_from = "proxmox_ecs"
[[tests.outputs.conditions]]
type = "vrl"
source = '''
assert_eq!(.event_action, "auth_failure")
assert_eq!(.event_outcome, "failure")
assert_eq!(.user_name, "admin")
assert_eq!(.source_ip, "203.0.113.7")
assert_eq!(.source_port, 40222)
assert_eq!(.ext."proxmox.invalid_user", "true")
'''
```

- [ ] **Step 2: Run to verify they fail**

Run the push+`vector test` command.
Expected: FAIL — sshd lines have no "authentication failure"/"successful auth" match, so
`event_action` stays `"unknown"`.

- [ ] **Step 3: Add the sshd branch.** In `[transforms.proxmox_ecs]`, wrap the existing
pvedaemon/pveproxy auth block in an `appname == "sshd"` else-branch. Replace:
```toml
    # pvedaemon/pveproxy auth failure: "authentication failure; rhost=<ip> user=<u> msg=..."
    afm, aferr = parse_regex(msg, r'authentication failure;\s*rhost=(?P<ip>\S+)\s+user=(?P<user>\S+)')
```
with:
```toml
    if appname == "sshd" {
        # "Accepted publickey for root from 198.51.100.5 port 51000 ssh2: ..."
        am, amerr = parse_regex(msg, r'Accepted \S+ for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)')
        if amerr == null {
            ev.event_category = ["authentication"]
            ev.event_action = "auth_success"
            ev.event_outcome = "success"
            ev.user_name = string(am.user) ?? ""
            ev.source_ip = am.ip
            ev.source_port = to_int(am.port) ?? null
        } else {
            # "Failed password for [invalid user ]bob from 1.2.3.4 port 5 ssh2"
            fm, fmerr = parse_regex(msg, r'Failed password for (?P<invalid>invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)')
            if fmerr == null {
                ev.event_category = ["authentication"]
                ev.event_action = "auth_failure"
                ev.event_outcome = "failure"
                ev.user_name = string(fm.user) ?? ""
                ev.source_ip = fm.ip
                ev.source_port = to_int(fm.port) ?? null
                if (string(fm.invalid) ?? "") != "" { ext = set!(ext, ["proxmox.invalid_user"], "true") }
            }
        }
    } else {
    # pvedaemon/pveproxy auth failure: "authentication failure; rhost=<ip> user=<u> msg=..."
    afm, aferr = parse_regex(msg, r'authentication failure;\s*rhost=(?P<ip>\S+)\s+user=(?P<user>\S+)')
```
Then close the new `else {` block: change the existing block's trailing `}` (the one that
closes the `if aferr == null { ... } else { ...success... }`) so a closing `}` for the
`appname == "sshd" else` wrapper is added. The final structure must be:
```toml
    if appname == "sshd" {
        ... sshd accepted/failed ...
    } else {
        afm, aferr = parse_regex(...)
        if aferr == null {
            ... pvedaemon auth_failure ...
        } else {
            asm, aserr = parse_regex(...)
            if aserr == null {
                ... pvedaemon auth_success ...
            }
        }
    }
```

- [ ] **Step 4: Run to verify all pass (24 total)**

Run the push+`vector test` command. Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add infra/vector/vector.toml
git commit -m "feat(m11): proxmox sshd login branch (accepted/failed, source_ip+port)"
```

---

## Task 4: task audit branch (UPID parse) + realm

**Files:**
- Modify: `infra/vector/vector.toml`

- [ ] **Step 1: Add two failing tests** at the end of the `[[tests]]` section

```toml
[[tests]]
name = "proxmox_task_qmstart_maps_to_config"
[[tests.inputs]]
insert_at = "proxmox_ecs"
type = "raw"
value = "<86>1 2026-06-14T20:04:00.000000+00:00 pve3 pvedaemon 1234 - - <root@pam> starting task UPID:pve3:00001A2B:0000ABCD:686D1234:qmstart:210:root@pam:"
[[tests.outputs]]
extract_from = "proxmox_ecs"
[[tests.outputs.conditions]]
type = "vrl"
source = '''
assert_eq!(.event_category, ["configuration"])
assert_eq!(.event_action, "task_qmstart")
assert_eq!(.user_name, "root@pam")
assert_eq!(.ext."proxmox.task_type", "qmstart")
assert_eq!(.ext."proxmox.vmid", "210")
assert_eq!(.ext."proxmox.realm", "pam")
assert_eq!(.ext."proxmox.upid", "UPID:pve3:00001A2B:0000ABCD:686D1234:qmstart:210:root@pam:")
'''

[[tests]]
name = "proxmox_task_end_ok"
[[tests.inputs]]
insert_at = "proxmox_ecs"
type = "raw"
value = "<86>1 2026-06-14T20:04:05.000000+00:00 pve3 pvedaemon 1234 - - <root@pam> end task UPID:pve3:00001A2B:0000ABCD:686D1234:qmstart:210:root@pam: OK"
[[tests.outputs]]
extract_from = "proxmox_ecs"
[[tests.outputs.conditions]]
type = "vrl"
source = '''
assert_eq!(.event_category, ["configuration"])
assert_eq!(.event_action, "task_end_qmstart")
assert_eq!(.event_outcome, "success")
assert_eq!(.ext."proxmox.task_status", "OK")
assert_eq!(.ext."proxmox.task_type", "qmstart")
'''
```

- [ ] **Step 2: Run to verify they fail**

Run the push+`vector test` command.
Expected: FAIL — task lines fall through to the pvedaemon auth branch and never match, so
`event_action` stays `"unknown"`.

- [ ] **Step 3: Add the task branch + realm.** In `[transforms.proxmox_ecs]`, insert the task
block as the FIRST thing inside the `else {` (non-sshd) branch, before the
`afm, aferr = parse_regex(...)` auth-failure line. Replace:
```toml
    } else {
    # pvedaemon/pveproxy auth failure: "authentication failure; rhost=<ip> user=<u> msg=..."
    afm, aferr = parse_regex(msg, r'authentication failure;\s*rhost=(?P<ip>\S+)\s+user=(?P<user>\S+)')
```
with:
```toml
    } else {
    # pvedaemon task audit: "<u> starting|end task UPID:node:..:dtype:dID:user: [status]"
    tm, tmerr = parse_regex(msg, r'(?P<phase>starting|end) task (?P<upid>UPID:\S+)')
    if tmerr == null {
        upid = string(tm.upid) ?? ""
        ext = set!(ext, ["proxmox.upid"], upid)
        ev.event_category = ["configuration"]
        # UPID:node:pid:pstart:starttime:dtype:dID:user:
        um, umerr = parse_regex(upid, r'UPID:(?P<node>[^:]*):[^:]*:[^:]*:[^:]*:(?P<dtype>[^:]*):(?P<dID>[^:]*):(?P<user>[^:]*):')
        dtype = ""
        if umerr == null {
            dtype = string(um.dtype) ?? ""
            if dtype != "" { ext = set!(ext, ["proxmox.task_type"], dtype) }
            vmid = string(um.dID) ?? ""
            if vmid != "" { ext = set!(ext, ["proxmox.vmid"], vmid) }
            tuser = string(um.user) ?? ""
            if tuser != "" { ev.user_name = tuser }
        }
        phase = string(tm.phase) ?? ""
        if phase == "end" {
            ev.event_action = "task_end_" + dtype
            if contains(msg, " OK") {
                ev.event_outcome = "success"
                ext = set!(ext, ["proxmox.task_status"], "OK")
            } else {
                ev.event_outcome = "failure"
                sm, smerr = parse_regex(msg, r'end task UPID:\S+ (?P<status>.+)')
                if smerr == null { ext = set!(ext, ["proxmox.task_status"], string(sm.status) ?? "") }
            }
        } else {
            ev.event_action = "task_" + dtype
        }
    } else {
    # pvedaemon/pveproxy auth failure: "authentication failure; rhost=<ip> user=<u> msg=..."
    afm, aferr = parse_regex(msg, r'authentication failure;\s*rhost=(?P<ip>\S+)\s+user=(?P<user>\S+)')
```
Then add ONE extra closing `}` to balance the new `if tmerr == null { ... } else {` — place
it just before the `ev.ext = ext` line at the end of the success path. The non-sshd branch
structure becomes:
```toml
    } else {
        if tmerr == null { ... task ... } else {
            if aferr == null { ... auth_failure ... } else {
                if aserr == null { ... auth_success ... }
            }
        }
    }
```

- [ ] **Step 4: Add realm extraction.** In `[transforms.proxmox_ecs]`, immediately before the
final `ev.ext = ext` line (inside the `else` that follows `if perr != null`), add:
```toml
    # realm from user_name (root@pam -> pam)
    rm, rmerr = parse_regex(ev.user_name, r'@(?P<realm>\S+)$')
    if rmerr == null { ext = set!(ext, ["proxmox.realm"], string(rm.realm) ?? "") }

```

- [ ] **Step 5: Run to verify all pass (26 total)**

Run the push+`vector test` command. Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add infra/vector/vector.toml
git commit -m "feat(m11): proxmox task-audit branch (UPID type/vmid/user) + realm"
```

---

## Task 5: filter-drop test + trailing-newline regression

**Files:**
- Modify: `infra/vector/vector.toml`

- [ ] **Step 1: Add two tests** at the end of the `[[tests]]` section

```toml
[[tests]]
name = "proxmox_sec_filter_drops_systemd_noise"
no_outputs_from = ["proxmox_sec"]
[[tests.inputs]]
insert_at = "proxmox_sec"
type = "raw"
value = "<30>1 2026-06-14T20:05:00.000000+00:00 pve3 systemd 1 - - Started Session 42 of user root."
[[tests.outputs]]
extract_from = "proxmox_sec"
[[tests.outputs.conditions]]
type = "vrl"
source = '''
assert!(true)
'''

[[tests]]
name = "proxmox_trailing_newline_still_parses"
[[tests.inputs]]
insert_at = "proxmox_ecs"
type = "raw"
value = '''
<38>1 2026-06-14T20:06:00.000000+00:00 pve3 sshd 2224 - - Accepted password for root from 198.51.100.6 port 51999 ssh2
'''
[[tests.outputs]]
extract_from = "proxmox_ecs"
[[tests.outputs.conditions]]
type = "vrl"
source = '''
assert_eq!(.event_action, "auth_success")
assert_eq!(.source_ip, "198.51.100.6")
assert_eq!(.source_port, 51999)
'''
```

Note: a `no_outputs_from` test cannot also have an output-extracting `[[tests.outputs]]`
that expects events — but `proxmox_sec` is a filter so the dropped event produces no output;
the `assert!(true)` condition is never evaluated because no event reaches it. If `vector test`
rejects the combined form, remove the `[[tests.outputs]]` block entirely and keep only
`name` + `no_outputs_from` + `[[tests.inputs]]` (matching the `unifi_cef_threat_filter_drops_non_detection`
pattern at the `unifi` tests, which uses `no_outputs_from` with no outputs block).

- [ ] **Step 2: Run to verify behavior**

Run the push+`vector test` command. Expected: both pass. If `proxmox_sec_filter_drops_systemd_noise`
errors on the outputs block, apply the fallback in the note (drop the outputs block) and re-run.

- [ ] **Step 3: Commit**

```bash
git add infra/vector/vector.toml
git commit -m "test(m11): proxmox filter-drop + trailing-newline regression"
```

---

## Task 6: Wire proxmox_ecs into the ClickHouse sink + local validate

**Files:**
- Modify: `infra/vector/vector.toml`

- [ ] **Step 1: Add `proxmox_ecs` to the sink inputs.** In `[sinks.clickhouse]`, change:
```toml
inputs = ["srx_ecs", "panos_ecs", "unifi_ips"]
```
to:
```toml
inputs = ["srx_ecs", "panos_ecs", "unifi_ips", "proxmox_ecs"]
```

- [ ] **Step 2: Validate config syntax locally** (no live sinks)

Run: `CH_HOST=127.0.0.1 vector validate --no-environment infra/vector/vector.toml`
Expected: `Validated`.

- [ ] **Step 3: Re-run the full test suite on ct102**

Run the push+`vector test` command from Task 1 Step 5.
Expected: all pass (existing 20 + ~6 new Proxmox tests).

- [ ] **Step 4: Commit**

```bash
git add infra/vector/vector.toml
git commit -m "feat(m11): route proxmox_ecs to the ClickHouse sink"
```

---

## Task 7: nftables UDP/517 allow for the pve3 host

**Files:**
- Modify: `infra/firewall/ct102-ingest.nft`

- [ ] **Step 1: Determine the pve3 host LAN source IP** (the address rsyslog will send from)

Run: `ssh root@pve3.example.com "ip -4 route get 198.51.100.150 | sed -n 's/.*src \\([0-9.]*\\).*/\\1/p'"`
Record the printed IP (e.g. `198.51.100.x`); call it `<PVE3_LAN_IP>` below.

- [ ] **Step 2: Add the UDP/517 allow + extend the drop.** In `infra/firewall/ct102-ingest.nft`,
after the UniFi block (`udp dport 516 ip saddr 198.51.100.30 accept`), add:
```
        # Proxmox (M11): rsyslog from the pve3 hypervisor host on UDP 517
        # (pvedaemon/pveproxy/sshd auth + admin-action audit stream).
        udp dport 517 ip saddr <PVE3_LAN_IP> accept
```
(substitute the real IP from Step 1) and change the drop line:
```
        udp dport { 514, 515, 516 } drop
```
to:
```
        udp dport { 514, 515, 516, 517 } drop
```
Also update the file header comment `UDP 514 (SRX) / 515 (PAN-OS) / 516 (UniFi)` to append
`/ 517 (Proxmox host)`.

- [ ] **Step 3: Apply to ct102**

Run: `./scripts/apply_ct102_nftables.sh`
Expected: success; then verify:
`ssh root@pve3.example.com "pct exec 102 -- nft list table inet ssdf_ingest"` shows the
`udp dport 517 ip saddr <PVE3_LAN_IP> accept` rule and `517` in the drop set.

- [ ] **Step 4: Commit**

```bash
git add infra/firewall/ct102-ingest.nft
git commit -m "feat(m11): nftables allow UDP/517 from pve3 host on ct102 ingest"
```

---

## Task 8: Onboarding runbook

**Files:**
- Create: `onboarding/proxmox/rsyslog.md`

- [ ] **Step 1: Write the runbook**

```markdown
# Proxmox host audit → SSDF (M11 onboarding)

SSDF ingests the pve3 hypervisor host's auth + admin-action syslog
(`pvedaemon`/`pveproxy`/`sshd`) via remote rsyslog. SSDF never configures the source in
its own data path; the operator applies the rsyslog drop-in on pve3.

## 0. Verify the host clock is UTC (do this FIRST)
SSDF stores event time from the syslog timestamp. Run on pve3:
  timedatectl
Confirm `Time zone: ... (UTC, +0000)`. The rsyslog template below forwards RFC5424
(ISO-8601 with offset), so a UTC host clock yields correct stored time — fix the clock
before relying on parsed times (the PAN-OS/SRX local-time skew lesson).

## 1. rsyslog drop-in (forward to Vector)
Create `/etc/rsyslog.d/49-ssdf.conf` on pve3:

  auth,authpriv,daemon.*  @198.51.100.150:517;RSYSLOG_SyslogProtocol23Format

(single `@` = UDP; `RSYSLOG_SyslogProtocol23Format` = RFC5424 with offset timestamp.)
The facility filter is the coarse gate; Vector's `proxmox_sec` filter does the fine
`pvedaemon|pveproxy|sshd` + known-pattern gate, so non-security daemon noise is dropped
at ingest.

## 2. Restart + verify on the wire
On pve3:  systemctl restart rsyslog
On ct102: tcpdump -n -A -i any udp port 517 -c 20
Trip an event (e.g. from another host: `ssh baduser@pve3` with a wrong password) and
confirm the line arrives.

## 3. Deployment-specific values (used by the nft allow-list + ext.proxmox.node)
  - PVE3_LAN_IP    = <the src IP from `ip -4 route get 198.51.100.150` on pve3>
                     (nft allow-list source on ct102; see infra/firewall/ct102-ingest.nft)
  - NODE_HOSTNAME  = pve3   (rides ext.proxmox.node)

## 4. Captured samples (real lines — fill at live-proof; these are the VRL test fixtures)
ParseSyslog yields appname + message; the proxmox_ecs transform maps them as:
  - pvedaemon "successful auth for user 'root@pam'"        -> authentication / auth_success
  - pvedaemon "authentication failure; rhost=<ip> user=<u>"-> authentication / auth_failure (source_ip)
  - sshd "Accepted <m> for <u> from <ip> port <p>"          -> authentication / auth_success (source_ip+port)
  - sshd "Failed password for [invalid user] <u> from <ip>"-> authentication / auth_failure
  - pvedaemon "starting task UPID:..:<dtype>:<vmid>:<u>:"   -> configuration / task_<dtype>
  - pvedaemon "end task UPID:.. OK"                          -> configuration / task_end_<dtype> (success)
(paste the real captured lines here after §2)
```

- [ ] **Step 2: Commit**

```bash
git add onboarding/proxmox/rsyslog.md
git commit -m "docs(m11): Proxmox host rsyslog onboarding runbook"
```

---

## Task 9: Operator deploy to ct102 + live proof

**Files:** none (deploy + verify). This task is operator-gated (requires applying the
rsyslog drop-in on pve3 and that ClickHouse ct104 is up — Vector's CH-sink healthcheck
fails if CH is down).

- [ ] **Step 1: Apply the rsyslog drop-in on pve3** per the runbook §1, then
`systemctl restart rsyslog`.

- [ ] **Step 2: Deploy the Vector config to ct102** (same pattern as prior milestones):
push `infra/vector/vector.toml`, `vector validate` it against the live (TLS) CH sink, back
up the running config, `mv` into place, `systemctl restart vector.service`, confirm
`active` and that UDP/517 is listening:
`ssh root@pve3.example.com "pct exec 102 -- ss -lunp | grep :517"`.

- [ ] **Step 3: Trigger live events.**
  - Auth: one **failed** SSH login + one **successful** login to pve3 from a known host IP.
  - Task: one action on a **scratch VMID only** (never the protected VMIDs in
    `~/.claude/CLAUDE.md`) — e.g. create+destroy a throwaway snapshot/backup — to emit a
    `task_*` line.

- [ ] **Step 4: Confirm rows landed** (query ct104; use the live TLS client envs):
```sql
SELECT event_action, event_outcome, user_name, source_ip,
       ext['proxmox.task_type'] AS task, ext['proxmox.node'] AS node, timestamp
FROM ssdf.events
WHERE event_provider='proxmox'
ORDER BY timestamp DESC LIMIT 20
```
Expected: ≥1 `auth_failure` (with `source_ip`), ≥1 `auth_success`, ≥1 `task_*` row, all with
UTC-correct timestamps (within seconds of `now()`), and no `parse_error` rows.

- [ ] **Step 5: Backfill the runbook §4** with the real captured lines and reconcile any VRL
test fixture that differs from the wire (re-run `vector test`; keep green). Commit:
```bash
git add onboarding/proxmox/rsyslog.md infra/vector/vector.toml
git commit -m "docs(m11): backfill real captured Proxmox samples + fixture reconcile"
```

---

## Task 10: Milestone docs + memory, merge

**Files:**
- Modify: `docs/superpowers/STATUS.md`, `CLAUDE.md`
- Modify (memory): `~/.claude/projects/-home-mharman-SSDF/memory/` (project memory + MEMORY.md pointer)

- [ ] **Step 1: Add the M11 as-built row** to the STATUS.md table (after the M9 row) and an
M11 entry to the forward roadmap "Later sources" line (mark Proxmox ✅ done), and bump
`**Last updated:**` to the implementation date. Mirror the M9 row's detail level (source,
transport, key facts, live proof).

- [ ] **Step 2: Add an M11 command section to CLAUDE.md** after the M9 section (before
"Future Rust/Python components..."), documenting: vector tests on ct102; the
CEF-vs-syslog difference (Proxmox uses `parse_syslog`, RFC5424 from rsyslog); UDP/517;
`proxmox_sec` filter + `proxmox_ecs` transform; nft UDP/517 ⇐ pve3 host; `ext.proxmox.*`
(no schema change); RFC5424-for-UTC; ingest-only boundary; runbook path.

- [ ] **Step 3: Write the M11 project memory** file and add a one-line pointer to `MEMORY.md`
(after the M9 line), capturing only non-obvious facts (parse_syslog not regex-slice;
RFC5424 forwarding chosen to avoid the UTC trap; ingest-only; pve3 host is the sender;
observer_hostname intentionally empty).

- [ ] **Step 4: Commit the docs**

```bash
git add docs/superpowers/STATUS.md CLAUDE.md
git commit -m "docs(m11): record Proxmox host audit ingest in STATUS.md + CLAUDE.md"
```

- [ ] **Step 5: Merge to main + push** (after the user confirms live proof is green):
```bash
git checkout main && git merge --no-ff m11-proxmox-ingest && git push
```
(adjust the branch name to the actual working branch).

---

## Self-review notes

- **Spec coverage:** source/filter/transform (Tasks 1–6), nftables (7), runbook (8),
  testing+live-proof (9), docs+memory (10) — every spec section maps to a task.
- **No new MCP tool / no schema migration / ext-map only** — honored (no `services/` or
  `infra/clickhouse/` changes anywhere in the plan).
- **observer_hostname empty / H2 gate untouched** — `proxmox_ecs` sets it to `""` and never
  imports the srx/panos device-gate logic.
- **Trailing-newline lesson** — non-`$`-anchored regexes + a regression test (Task 5).
