# M11 — Proxmox host audit ingest (rsyslog → Vector → ClickHouse)

**Date:** 2026-06-14
**Status:** Design approved, pre-implementation
**Milestone:** M11 (M9 = UniFi IPS; M10 reserved for the derived-findings layer)

## Goal

Add the **pve3 Proxmox hypervisor host** as a security **event source** into
`ssdf.events`, capturing the host's **authentication + admin-action audit stream**
(`pvedaemon` / `pveproxy` / `sshd`). This is the "who logged into / acted on my
infrastructure host" story for the box that runs the entire SSDF stack.

This reuses the established syslog-ingest pattern (SRX/PAN-OS/UniFi): one new Vector
UDP source + a filter + a VRL transform → normalized ECS-subset rows in `ssdf.events`,
queryable through the existing generic MCP tools.

## Scope / boundary (what this is NOT)

- **Ingest-only.** No new MCP tool, no resolver/entity-graph changes, no ClickHouse
  schema migration. Events are immediately queryable via the existing `run_sql`,
  `query_flows`, `top_talkers`, `describe_schema` tools.
- **Distinct from the existing M4 Proxmox *topology* collector** (`services/topo/.../proxmox.py`),
  which pulls VM/NIC inventory into `topo_observations` via proxmox-mcp. That stays untouched.
- **Distinct from proxmox-mcp**, which owns Proxmox *management*. SSDF's read-only event
  fabric only stores + queries.
- **No PVE API poller.** Transport is rsyslog push, consistent with every other SSDF
  event source. (A pull-based poller was considered and rejected as a new, heavier
  ingest pattern with weaker auth-failure coverage.)

## Architecture & data flow

```
pve3 host rsyslog ──UDP/517──► Vector ct102 ──► ClickHouse ssdf.events
  (daemon + auth/authpriv        [sources.proxmox_syslog]            (event_provider="proxmox")
   facilities, RFC5424)          → [transforms.proxmox_sec]   (filter: keep pvedaemon|
                                     pveproxy|sshd security lines, drop everything else)
                                 → [transforms.proxmox_ecs]   (parse_syslog + per-appname
                                     regex → ECS-subset)
```

- **Port allocation:** UDP **517** (514 = SRX, 515 = PAN-OS, 516 = UniFi). Each source is
  a separate UDP port to avoid collision.
- **Source** `[sources.proxmox_syslog]`: `type="socket"`, `mode="udp"`,
  `address="0.0.0.0:517"`, `max_length=102400` — identical shape to the existing sources.
- rsyslog forwards **standard RFC5424 syslog with a PRI**, so the transform uses
  **`parse_syslog(raw)`** (like SRX/PAN-OS — *not* the regex-slice UniFi needed for
  PRI-less CEF). `parse_syslog` yields `.appname` (pvedaemon/pveproxy/sshd), `.hostname`
  (pve3), `.timestamp` (with offset), `.message`.

## Filter transform — `proxmox_sec`

`type="filter"`, `inputs=["proxmox_syslog"]`. Keep an event iff:
- `parse_syslog` succeeds AND `.appname ∈ {pvedaemon, pveproxy, sshd}`, AND
- `.message` matches one of the known security patterns below (auth success/failure,
  task start/end, sshd accepted/failed).

Everything else (systemd, pvescheduler, kernel, pveproxy worker chatter, sshd
`Connection closed [preauth]` noise) is dropped, so `ssdf.events` is not flooded. This
mirrors UniFi's `unifi_cef_threat` gate.

## Transform — `proxmox_ecs` (event mapping)

`type="remap"`, `inputs=["proxmox_sec"]`. `event_provider="proxmox"`, `event_kind="event"`.
Branch on `.appname` and regex-parse `.message`:

| Source line (message) | event_category | event_action | event_outcome | populated fields |
|---|---|---|---|---|
| `<u> successful auth for user '<u>'` (pvedaemon/pveproxy) | authentication | `auth_success` | success | `user_name` |
| `authentication failure; rhost=<ip> user=<u> msg=...` | authentication | `auth_failure` | failure | `user_name`, `source_ip` |
| `<u> starting task UPID:<node>:..:<dtype>:<dID>:<u>:` | configuration | `task_<dtype>` | (outcome unset/started) | `user_name`, ext `proxmox.upid/vmid/task_type` |
| `<u> end task UPID:.. OK` / `... <error>` | configuration | `task_end_<dtype>` | success / failure | `user_name`, ext `proxmox.task_status` |
| `Accepted <method> for <u> from <ip> port <p> ssh2` (sshd) | authentication | `auth_success` | success | `user_name`, `source_ip`, `source_port` |
| `Failed password for [invalid user] <u> from <ip> port <p>` (sshd) | authentication | `auth_failure` | failure | `user_name`, `source_ip`, ext `proxmox.invalid_user` |

**UPID parsing.** The Proxmox task identifier
`UPID:<node>:<pid_hex>:<pstart_hex>:<starttime_hex>:<dtype>:<dID>:<user>:` is split to
extract **task type** (`dtype`: qmstart/qmstop/qmcreate/qmdestroy/vzdump/vzstart/…),
**vmid** (`dID`), and **user**. This is the admin-action audit value.

### Schema mapping (no new columns)

- **Top-level typed columns:** `event_kind`, `event_category`, `event_action`,
  `event_outcome`, `event_provider`, `user_name`, `source_ip` (Nullable IPv4 — only for
  remote auth), `source_port` (Nullable UInt16), `timestamp`, `raw`.
- **`ext` Map(String,String)** (`skip_unknown_fields=false` routes non-schema fields here):
  `proxmox.appname`, `proxmox.node`, `proxmox.upid`, `proxmox.vmid`, `proxmox.task_type`,
  `proxmox.task_status`, `proxmox.realm`, `proxmox.invalid_user`.
- **`observer_hostname` left empty.** It is the firewall-provenance field (P0/H2 gates it
  to known firewall devices); pve3 is not a firewall, so the node name rides
  `ext.proxmox.node`. The H2 gate in `srx_ecs`/`panos_ecs` is unchanged.
- **No CH migration** — `ext` map absorbs all Proxmox-specific fields.

### Time / UTC

rsyslog RFC3164 timestamps carry no timezone. The runbook configures rsyslog to forward
**RFC5424** (`;RSYSLOG_SyslogProtocol23Format`), whose ISO-8601 timestamp includes the
offset, so `parse_syslog` stores correct UTC — sidestepping the recurring local-time
skew trap (PAN-OS/SRX lesson). The runbook also includes the standard §0 "confirm pve3
clock is UTC" check.

### Robustness

Per-message regexes are **not `$`-anchored**, and `parse_syslog` consumes the framed
datagram, so the socket-source trailing newline (the UniFi live-bug) is a non-issue by
construction. A trailing-newline regression test pins this.

## nftables (ingest allow-list)

`infra/firewall/ct102-ingest.nft`, applied by `./scripts/apply_ct102_nftables.sh`
(idempotent). Add a UDP/517 allow from the **pve3 host LAN IP** and extend the drop set:

```
# Proxmox (M11): rsyslog from the pve3 hypervisor host on UDP 517.
udp dport 517 ip saddr <PVE3_LAN_IP> accept
...
udp dport { 514, 515, 516, 517 } drop
```

The concrete pve3 LAN source IP is captured in the runbook §3 during onboarding (as the
UniFi controller `.30` was captured live) and written into the nft file at apply time.

## Onboarding runbook — `onboarding/proxmox/rsyslog.md`

Applied by the operator on pve3 (SSDF never configures the source device in its data path):
- **§0 UTC check** — `timedatectl` on pve3 shows UTC.
- **§1 rsyslog drop-in** `/etc/rsyslog.d/49-ssdf.conf` forwarding `auth`, `authpriv`,
  `daemon` facilities to `198.51.100.150:517` over UDP in RFC5424 format
  (`;RSYSLOG_SyslogProtocol23Format`). Facility filter is the coarse gate; Vector's
  `proxmox_sec` does the fine appname + pattern gate.
- **§2** restart rsyslog; verify on ct102 with `tcpdump -n -A -i any udp port 517`.
- **§3** record deployment values: pve3 host LAN IP + hostname (→ nft allow-list +
  `ext.proxmox.node`).
- **§4** captured sample lines — filled at live-proof; these become the VRL `[[tests]]`
  fixtures.

## Testing

**Unit tests** (`[[tests]]` in `vector.toml`; run on ct102 `vector test vector.toml` —
the existing 20 tests must stay green):
- `proxmox_pvedaemon_auth_success`
- `proxmox_auth_failure_with_rhost` (asserts `source_ip`)
- `proxmox_task_qmstart_maps_to_config` (asserts `ext['proxmox.task_type']` + `vmid`)
- `proxmox_task_end_ok` (asserts `event_outcome=success`)
- `proxmox_sshd_accepted_publickey` (asserts `source_ip` + `source_port`)
- `proxmox_sshd_failed_invalid_user` (asserts `auth_failure` + `proxmox.invalid_user`)
- `proxmox_sec_filter_drops_systemd_noise` (`no_outputs_from = ["proxmox_sec"]`)
- `proxmox_trailing_newline_still_parses` (pins the newline non-issue)

**Local validation:** `CH_HOST=127.0.0.1 vector validate --no-environment infra/vector/vector.toml`.

## Live proof

After deploying nft + Vector to ct102 (both gated on ClickHouse being up — Vector's
CH-sink healthcheck fails if ct104 is down):
1. Trigger zero-risk auth: one **failed** SSH login + one **successful** login to pve3
   from a known IP.
2. Trigger one task on a **scratch VMID only** (never the protected list in
   `~/.claude/CLAUDE.md`) — e.g. snapshot/backup a throwaway — to emit a `task_*` line.
3. Query:
   ```sql
   SELECT event_action, user_name, source_ip, ext['proxmox.task_type'] AS task, timestamp
   FROM ssdf.events WHERE event_provider='proxmox' ORDER BY timestamp DESC LIMIT 20
   ```
   Confirm ≥1 `auth_failure` (with `source_ip`), ≥1 `auth_success`, ≥1 `task_*` row, all
   with UTC-correct timestamps, returned through the existing `run_sql`/`query_flows`.

## Done criteria

- `vector test` green (existing 20 + the new Proxmox suite).
- nft shows the UDP/517 rule; `include` makes it reboot-persistent.
- Live: the three event classes above land in `ssdf.events` with correct typed columns
  and `ext.proxmox.*`, UTC-correct, coexisting with the other providers.
- Docs: STATUS.md as-built row + forward-roadmap update, CLAUDE.md M11 section, the
  onboarding runbook, and the M11 project memory.

## Files touched

- `infra/vector/vector.toml` — new `proxmox_syslog` source, `proxmox_sec` filter,
  `proxmox_ecs` transform, `[[tests]]` suite.
- `infra/firewall/ct102-ingest.nft` — UDP/517 allow + drop.
- `onboarding/proxmox/rsyslog.md` — new runbook.
- `docs/superpowers/STATUS.md`, `CLAUDE.md` — milestone docs.

## Out of scope (deferred, recorded here so they are not silently dropped)

- A dedicated `auth_events(...)` MCP tool or wiring failed-auth into `explain_access` —
  speculative until the eval layer shows agents struggle to answer infra-auth questions
  with the generic tools.
- pve-firewall accept/drop ingest — the host firewall is not enabled with logging here,
  so there is nothing to parse (YAGNI).
- Ingesting from cluster peers beyond pve3 (single-host lab).
