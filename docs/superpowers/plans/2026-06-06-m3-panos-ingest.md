# M3 — PAN-OS Ingest Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Onboard a second telemetry source — PAN-OS firewall `panosvm` (VM 900) — into the existing `ssdf.events` ClickHouse store via the M1 Vector-VRL pattern, proving the ECS-subset schema generalizes to a 2nd vendor.

**Architecture:** PAN-OS Log Forwarding → UDP syslog (CSV) → **new** Vector source on ct102:515 → new `panos_ecs` VRL transform (CSV positional parse, branch by log Type) → same `ssdf.events` sink. No schema change. M2 MCP read server picks up PAN-OS rows automatically.

**Tech Stack:** Vector VRL (TOML), PAN-OS 12.1 default syslog CSV format, ClickHouse, panos-mcp for onboarding.

---

## Ground truth (live device, captured 2026-06-06)

- **Device:** `panosvm` in panos-mcp inventory, mgmt `198.51.100.225`, **PAN-OS 12.1.5**, PA-VM, serial `007054000270810`.
- **Zones:** `untrust` (eth1/1), `trust` (eth1/2, 10.74.11.1/24), `DMZ`. Data subnets: untrust 198.51.100.0/24, trust 10.74.11.0/24, plus address objects in 10.50.x / 10.80.x.
- **Rules:** 5 security rules, all `log-end yes` → TRAFFIC logs are being generated now.
- **`hostname-type-in-syslog FQDN`** → forwarded syslog hostname = `panosvm.example.com`. Timezone US/Eastern.
- **No** existing syslog-server-profile / log-forwarding-profile / device log-settings — onboarding creates them.
- **Infra:** Vector = LXC ct102 `198.51.100.150`; ClickHouse = ct104 `198.51.100.151:8123` db `ssdf` table `events`; M2 read MCP = ct106 `198.51.100.152:30032`.

## Decisions (locked with user)

- **Scope:** ALL PAN-OS log types (TRAFFIC, THREAT, plus SYSTEM/CONFIG/etc.). TRAFFIC maps to the flow columns; others map to event metadata + `ext`/`raw`.
- **Topology:** NEW separate Vector UDP source on **port 515** (SRX keeps 514). Both transforms feed the one `ssdf.events` sink.
- **Schema:** UNCHANGED. `source_ip`/`destination_ip` are `Nullable(IPv4)` — IPv4 only. IPv6 addresses must be left NULL (do not crash the row); the literal value is preserved in `raw`.
- **Conventions:** `event_provider = "paloalto"`; vendor extras under `ext` keyed `panw.panos.*` namespace.
- **Onboarding transport:** UDP to ct102:515, syslog format **BSD** (default), which yields the PAN-OS default CSV payload.

## Existing schema (`infra/clickhouse/001_events.sql`) — DO NOT CHANGE

Typed columns: `timestamp DateTime64(3,'UTC')`, `event_id String`, `tenant_id`, `event_kind`, `event_category Array(String)`, `event_action`, `event_outcome`, `event_provider`, `source_ip Nullable(IPv4)`, `source_port Nullable(UInt16)`, `source_bytes Nullable(UInt64)`, `destination_ip Nullable(IPv4)`, `destination_port Nullable(UInt16)`, `destination_bytes Nullable(UInt64)`, `network_transport`, `network_bytes Nullable(UInt64)`, `rule_name String`, `observer_ingress_zone`, `observer_egress_zone`, `user_name String`, `ext Map(String,String)`, `raw String`.

## PAN-OS 12.1 default syslog CSV field order (1-indexed within the CSV payload)

The forwarded line is `<pri>BSD-timestamp hostname <CSV...>`. After `parse_syslog`, the CSV payload is the `.message`. Split on `,`. **FUTURE_USE fields are empty placeholders — keep the positions.** Field 4 ("Type") selects the layout.

**Common header (fields 1–31, identical for TRAFFIC and THREAT):**
1 FUTURE_USE · 2 ReceiveTime · 3 SerialNumber · 4 **Type** · 5 Subtype · 6 FUTURE_USE · 7 GeneratedTime · 8 SourceAddress · 9 DestinationAddress · 10 NATSourceIP · 11 NATDestinationIP · 12 RuleName · 13 SourceUser · 14 DestinationUser · 15 Application · 16 VirtualSystem · 17 SourceZone · 18 DestinationZone · 19 InboundInterface · 20 OutboundInterface · 21 LogAction · 22 FUTURE_USE · 23 SessionID · 24 RepeatCount · 25 SourcePort · 26 DestinationPort · 27 NATSourcePort · 28 NATDestinationPort · 29 Flags · 30 Protocol · 31 Action

**TRAFFIC-only (fields 32+):**
32 Bytes(total) · 33 BytesSent · 34 BytesReceived · 35 Packets · 36 StartTime · 37 ElapsedTime · 38 Category(URL) · 39 FUTURE_USE · 40 SequenceNumber · 41 ActionFlags · 42 SourceCountry · 43 DestinationCountry · 44 FUTURE_USE · 45 PacketsSent · 46 PacketsReceived · 47 SessionEndReason · (48+ device-group/vsys-name/devicename/tunnel/… — ignore, keep in raw)

**THREAT-only (fields 32+):**
32 Misc/URL/Filename · 33 ThreatID/Name · 34 Category · 35 Severity · 36 Direction · 37 SequenceNumber · 38 ActionFlags · 39 SourceCountry · 40 DestinationCountry · (41+ … — ignore, keep in raw)

**SYSTEM (different short layout):** 1 FUTURE_USE · 2 ReceiveTime · 3 Serial · 4 Type(SYSTEM) · 5 Subtype · 6 FUTURE_USE · 7 GeneratedTime · 8 VirtualSystem · 9 EventID · 10 Object · 11 FUTURE_USE · 12 FUTURE_USE · 13 Module · 14 Severity · 15 Description · …

**CONFIG (different short layout):** 1 FUTURE_USE · 2 ReceiveTime · 3 Serial · 4 Type(CONFIG) · 5 Subtype · 6 FUTURE_USE · 7 GeneratedTime · 8 Host · 9 VirtualSystem · 10 Command · 11 Admin · 12 Client · 13 Result · 14 ConfigurationPath · …

> Positions are documented-stable but MUST be re-validated against a real forwarded line at the gated live step (Task 4). The Elastic `panw` module is the cross-reference.

## Mapping rules (PAN-OS → ssdf.events)

- `event_provider = "paloalto"`, `tenant_id = "t_main"`, `event_id = uuid_v4()`, `event_kind = "event"`, `timestamp = GeneratedTime` (field 7; parse as UTC-best-effort), `raw = original line`.
- **Type=TRAFFIC** → `event_category = ["network"]`; `event_action = "flow_" + lowercase(Subtype)` (start/end/drop/deny); `event_outcome`: `allow`→success, `deny`/`drop`/`reset-*`→failure, else unknown. Map src/dst addr/port, `network_transport = lowercase(Protocol)`, `rule_name`, zones (17→ingress, 18→egress), `user_name = SourceUser` (`""` if empty), `source_bytes = BytesSent`, `destination_bytes = BytesReceived`, `network_bytes = Bytes(total)`.
- **Type=THREAT** → `event_category = ["network","intrusion_detection"]`; `event_action = "threat_" + lowercase(Subtype)`; `event_outcome` from Action; same 5-tuple/zone/user mapping (no byte fields). Stash ThreatID/Severity/Category/Direction in `ext`.
- **Type=SYSTEM** → `event_category = ["host"]`, `event_action = "system_" + lowercase(Subtype)`, no network fields.
- **Type=CONFIG** → `event_category = ["configuration"]`, `event_action = "config_" + lowercase(Subtype)`, `user_name = Admin`.
- **Any other / unparseable Type** → `event_kind="event"`, `event_action="unknown"`, everything in `ext` + `raw`.
- **IPv4 guard:** before assigning `source_ip`/`destination_ip`, only assign if the value matches an IPv4 dotted-quad (`parse_regex` or `is_ipv4`-style check). If not IPv4 (empty/`::`/IPv6), leave the column unset (NULL). The literal is always in `raw`.
- **`ext`:** put the meaningful non-core PAN-OS fields under `panw.panos.*` keys (e.g. `panw.panos.subtype`, `panw.panos.application`, `panw.panos.session_id`, `panw.panos.nat_source_ip`, `panw.panos.threat_id`, `panw.panos.severity`, `panw.panos.session_end_reason`). All `ext` values are strings.

---

## Task 1: PAN-OS Vector source + `panos_ecs` VRL transform + unit tests

**Files:**
- Modify: `infra/vector/vector.toml` (add source `panos_syslog` UDP :515; add transform `panos_ecs`; add `panos_ecs` to the clickhouse sink `inputs`; add `[[tests]]`)

- [ ] **Step 1: Add the new source** after the existing `[sources.srx_syslog]` block:

```toml
[sources.panos_syslog]
type = "socket"
mode = "udp"
address = "0.0.0.0:515"
max_length = 102400
```

- [ ] **Step 2: Add the `panos_ecs` transform** (inputs = `["panos_syslog"]`). Implement the mapping rules above. Skeleton to flesh out — parse syslog header, split CSV, branch on `fields[3]` (0-indexed field 4 = Type):

```toml
[transforms.panos_ecs]
type = "remap"
inputs = ["panos_syslog"]
source = '''
raw = .message
parsed, perr = parse_syslog(raw)
csv = raw
if perr == null { csv = string(parsed.message) ?? raw }
f = split(csv, ",")

# helper: safe element access returns "" when out of range
get = {}   # VRL has no closures; index directly with defaulting below

log_type = "unknown"
if length(f) > 3 { log_type = upcase(string(f[3]) ?? "") }

ev = {
    "event_id": uuid_v4(),
    "tenant_id": "t_main",
    "event_kind": "event",
    "event_provider": "paloalto",
    "event_action": "unknown",
    "event_outcome": "unknown",
    "raw": raw,
}

# ... branch on log_type, fill typed columns + ext (panw.panos.*),
#     apply IPv4 guard on source_ip/destination_ip,
#     set timestamp from field 7 (index 6) via parse_timestamp/best-effort.
. = ev
'''
```

Notes for the implementer:
- VRL has **no closures/helper funcs**; access CSV elements as `string(f[N]) ?? ""` guarding length, or build a small pattern of `if length(f) > N`.
- IPv4 guard: `ip, ip_err = parse_regex(val, r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')` then assign only if `ip_err == null`.
- Numeric columns via `to_int(...)`; leave NULL by simply not setting the key when source field empty (don't force 0 for unknown ports — but matching M1, `to_int("")` returns 0; that's acceptable for bytes, but for ports prefer leaving unset when empty).
- `network_transport`: lowercase Protocol; map blank/unknown to `"unknown"`.
- `ext` values must all be strings; build the map explicitly with the `panw.panos.*` keys listed above (skip empty values).
- timestamp: `ts, tserr = parse_timestamp(string(f[6]) ?? "", "%Y/%m/%d %H:%M:%S")`; on error fall back to `parsed.timestamp` then `now()`. PAN-OS GeneratedTime is device-local (US/Eastern) — set it as-is for v0 (note the TZ caveat in a comment; do not over-engineer TZ conversion).

- [ ] **Step 3: Wire the sink** — change the clickhouse sink inputs line from `inputs = ["srx_ecs"]` to `inputs = ["srx_ecs", "panos_ecs"]`.

- [ ] **Step 4: Add `[[tests]]`** covering (use realistic PAN-OS 12.1 CSV lines built from the field tables above; FQDN host `panosvm.example.com`; an example TRAFFIC `end`/`allow` line, a TRAFFIC `deny` line, a THREAT `vulnerability` line, a SYSTEM line, and a malformed line). Each test asserts the mapped ECS columns and at least one `ext."panw.panos.*"` value. Include one TRAFFIC line carrying an IPv6 source address asserting `source_ip` is unset (NULL) while `raw` retains it.

Example TRAFFIC test input (allow/end) — adjust to your exact field count:
```
<14>Jun 06 23:20:00 panosvm.example.com ,2026/06/06 23:20:00,007054000270810,TRAFFIC,end,,2026/06/06 23:20:00,10.74.11.50,198.51.100.20,0.0.0.0,0.0.0.0,allow-trust-to-untrust,,,ssl,vsys1,trust,untrust,ethernet1/2,ethernet1/1,,,40001,1,52344,443,0,0,0x0,tcp,allow,8000,3000,5000,40,2026/06/06 23:19:30,30,any,,1001,0x0,10.74.11.0-10.74.11.255,US,,22,18,tcp-fin
```
Assert: `event_action == "flow_end"`, `event_outcome == "success"`, `event_provider == "paloalto"`, `source_ip == "10.74.11.50"`, `destination_ip == "198.51.100.20"`, `source_port == 52344`, `destination_port == 443`, `network_transport == "tcp"`, `source_bytes == 3000`, `destination_bytes == 5000`, `network_bytes == 8000`, `rule_name == "allow-trust-to-untrust"`, `observer_ingress_zone == "trust"`, `observer_egress_zone == "untrust"`, `ext."panw.panos.session_id" == "40001"`, `ext."panw.panos.session_end_reason" == "tcp-fin"`.

- [ ] **Step 5: Run unit tests** — `vector test infra/vector/vector.toml`. Expected: all tests (existing SRX + new PAN-OS) PASS.

- [ ] **Step 6: Validate config** — `CH_HOST=127.0.0.1 vector validate --no-environment infra/vector/vector.toml`. Expected: validated.

- [ ] **Step 7: Commit** — `git add infra/vector/vector.toml && git commit -m "feat(m3): PAN-OS syslog source + panos_ecs VRL transform"`

## Task 2: PAN-OS onboarding artifact

**Files:**
- Create: `onboarding/panos/log-forwarding.set` (PAN-OS set-format commands)
- Create: `onboarding/panos/README.md` (substitutions + how it's applied via panos-mcp)

- [ ] **Step 1: Write `onboarding/panos/log-forwarding.set`** — set-format config that, when loaded+committed on `panosvm`, forwards ALL log types to ct102:515 UDP. Must include:
  - A shared syslog server profile `SSDF` with server entry → `198.51.100.150`, transport UDP, port 515, format BSD.
  - A log-forwarding profile `SSDF-LF` (vsys1) with match-list entries for log-types `traffic`, `threat`, `url`, `wildfire`, `data`, `tunnel`, `auth`, `decryption` each → syslog `SSDF`.
  - Attach `SSDF-LF` to each of the 5 vsys1 security rules (`set ... rulebase security rules <name> log-setting SSDF-LF`). Rule names: `drifttest1`, `allow-trust-to-dmz`, `allow-corp-to-internet`, `allow-untrust-to-trust`, `allow-trust-to-untrust`.
  - Device log-settings for system + config + correlation + globalprotect + hipmatch → syslog `SSDF` (so non-session logs are also forwarded).
  - Comments noting substitutions: `<vector-host-ip>=198.51.100.150`, `<vector-port>=515`.

- [ ] **Step 2: Write `onboarding/panos/README.md`** — explain: applied via `panos-mcp` (`load_and_commit_pan_config` or `render_and_apply_j2_template`) against host `panosvm`; the as-built ct102 must have the new UDP:515 source live first; how to verify (`show log traffic` / wire capture). Mirror the tone of `onboarding/srx/stream-config.set`.

- [ ] **Step 3: Commit** — `git add onboarding/panos && git commit -m "feat(m3): PAN-OS log-forwarding onboarding artifact"`

## Task 3: Docs + status + memory

**Files:**
- Modify: `CLAUDE.md` (add an "### M3 (PAN-OS ingest)" block under Commands)
- Modify: `docs/superpowers/STATUS.md` (add M3 row; mark in-progress/done as appropriate)

- [ ] **Step 1: CLAUDE.md** — add M3 commands block: how to unit-test (`vector test infra/vector/vector.toml`), where the PAN-OS source listens (ct102 UDP:515), onboarding artifact path, the panos-mcp apply path, and a sample ClickHouse query filtering `event_provider='paloalto'`.
- [ ] **Step 2: STATUS.md** — add an M3 row to the as-built milestones table (status reflecting reality at commit time) and tick the forward-roadmap M3 bullet.
- [ ] **Step 3: Commit** — `git add CLAUDE.md docs/superpowers/STATUS.md && git commit -m "docs(m3): record PAN-OS ingest commands + status"`

## Task 4 (GATED — controller runs live, not a subagent)

Performed by the controller after Tasks 1–3 pass review, on explicit user go-ahead:
1. Add the `panos_syslog` UDP:515 source to the live ct102 vector.toml; reload Vector; confirm listening.
2. Apply `onboarding/panos/log-forwarding.set` to `panosvm` via panos-mcp (diff → review → commit).
3. Generate / wait for real traffic; **capture a real forwarded line and validate the CSV field positions** in `panos_ecs` against it (correct positions if drift).
4. Confirm rows land in `ssdf.events` with `event_provider='paloalto'` and correct typed columns; confirm they're queryable through the M2 MCP (ct106).
5. Update `infra/ENV.local` / memory with as-built PAN-OS onboarding coords.
