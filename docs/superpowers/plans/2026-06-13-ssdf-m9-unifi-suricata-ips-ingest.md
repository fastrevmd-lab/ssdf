# SSDF M9 — UniFi Suricata IPS + Flow Ingest Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ingest the UniFi Gateway Max's Suricata IPS/IDS alerts *and* traffic flows via remote
syslog into `ssdf.events`, and surface alerts to agents through a new `detections` field on
`explain_access`.

**Architecture:** Third vendor on the established M5 ingest pattern — a new Vector UDP source
(:516) + one VRL transform (`unifi_ips`) normalizing UniFi syslog into the existing `ssdf.events`
schema; H1 nftables allow-list + H2 device-gate extensions; a query-side `detections` enrichment
on `explain_access`. No new service, no new host, no ClickHouse migration.

**Tech Stack:** Vector VRL, ClickHouse, Python/FastMCP, Proxmox LXC (ct102 Vector, ct106 MCP),
`unifi-mcp` (read-only investigation only).

**Spec:** `docs/superpowers/specs/2026-06-13-ssdf-m9-unifi-suricata-ips-ingest-design.md`

**Capture-first (Approach A):** the exact UniFi syslog wire format is unknown until captured
live. Phase 0 captures real alert + flow samples; the VRL baseline below assumes Suricata
**EVE JSON** (UniFi's Suricata emits eve.json). If the captured samples differ, adjust field
extraction in Tasks 3–4 and **use the captured lines as the test fixtures** — do not invent data.

**Deployment-specific values** (recorded into the runbook in Task 1, substituted where marked):
- `GATEWAY_HOSTNAME` — the short hostname the gateway stamps in syslog (lowercased for the H2
  membership test). Baseline placeholder used below: `gatewaymax`.
- `GATEWAY_SRC_IP` — the gateway's LAN source IP for syslog. Baseline: `198.51.100.1`.

---

## File Structure

| File | Responsibility | Task(s) |
|---|---|---|
| `onboarding/unifi/ips-syslog.md` (new) | Operator runbook: enable IPS + remote syslog; captured format/hostname/source-IP findings | 1 |
| `infra/vector/vector.toml` (modify) | `unifi_syslog` source, `unifi_ips` transform, sink `inputs`, H2 gate, VRL unit tests | 2–5 |
| `infra/firewall/ct102-ingest.nft` (modify) | UDP 516 + gateway source IP allow-list | 6 |
| `services/mcp-query/src/ssdf_mcp_query/entitystore.py` (modify) | `build_alerts_for_pair_sql` + `alerts_for_pair` store method + Protocol | 7 |
| `services/mcp-query/src/ssdf_mcp_query/access_tools.py` (modify) | `detections` enrichment in `explain_access` | 8 |
| `services/mcp-query/tests/test_access_tools.py` (modify) | `_FakeStore.alerts_for_pair` + detections unit tests | 8 |
| `services/mcp-query/tests/test_entitystore.py` (modify/new) | `build_alerts_for_pair_sql` unit test | 7 |

**Test environments:**
- VRL tests run **on ct102** (the Vector binary is not on the dev host):
  `ssh root@pve3.example.com "pct exec 102 -- bash -lc 'cd /etc/vector && vector test <path>'"`,
  or push the toml and run `vector test infra/vector/vector.toml` there.
- Python tests run locally: `cd services/mcp-query && uv run pytest -m "not integration"`.

---

# Phase 0 — Operator prerequisites + live capture (gates the VRL)

### Task 1: Onboarding runbook, enable IPS + syslog, capture real samples

**Files:**
- Create: `onboarding/unifi/ips-syslog.md`

- [ ] **Step 1: Write the onboarding runbook**

Create `onboarding/unifi/ips-syslog.md`:

```markdown
# UniFi Gateway Max — Suricata IPS + traffic flows → SSDF (M9 onboarding)

SSDF ingests UniFi IPS/IDS alerts + traffic flows via remote syslog (the gateway's
flow-query API is unavailable on this controller — every v2 traffic-flows endpoint
404s, confirmed 2026-06-13). SSDF never applies device config in its own data path;
the steps below are applied by the operator in the UniFi Network application.

## 1. Enable Threat Management (Suricata IPS/IDS)
UniFi Network → Settings → Security → Threat Management → enable
(Detection or Detection+Prevention). This starts Suricata on the Gateway Max.

## 2. Enable remote syslog with IPS alerts + flows
UniFi Network → Settings → System → Logging / Remote Logging:
  - Server:  198.51.100.150   Port: 516   Protocol: UDP
  - Enable "IPS/IDS alerts" (or "Debug"/contents that include Suricata events)
  - Enable traffic/flow logging if presented as a separate toggle

## 3. Record deployment-specific values (used by the VRL + nftables)
After one alert/flow arrives, on ct102:
  tcpdump -n -A -i any udp port 516 -c 5
Record:
  - GATEWAY_HOSTNAME = <short hostname the gateway stamps>  (e.g. gatewaymax)
  - GATEWAY_SRC_IP   = <source IP of the udp/516 packets>   (e.g. 198.51.100.1)
  - WIRE_FORMAT      = EVE-JSON | other  (paste one full alert line + one flow line)

## 4. Captured samples (paste real lines — these become the VRL unit-test fixtures)
ALERT:  <paste>
FLOW:   <paste>
```

- [ ] **Step 2 (operator-gated): Enable IPS + remote syslog**

Operator performs runbook steps 1–2 in the UniFi Network application (sender →
`198.51.100.150:516/udp`). No SSDF code runs here.

- [ ] **Step 3 (operator-gated): Capture real samples on ct102**

```bash
ssh root@pve3.example.com "pct exec 102 -- timeout 120 tcpdump -n -A -i any udp port 516 -c 10"
```

Expected: at least one line containing a Suricata record. Paste a full **alert** line and a
full **flow** line into the runbook §4, and record `GATEWAY_HOSTNAME`, `GATEWAY_SRC_IP`,
`WIRE_FORMAT` in §3. **If `WIRE_FORMAT` is not EVE JSON**, note the actual structure — Tasks
3–4 extraction must be adjusted to match it.

- [ ] **Step 4: Commit the runbook with captured findings**

```bash
git add onboarding/unifi/ips-syslog.md
git commit -m "docs(m9): UniFi IPS+syslog onboarding runbook with captured wire-format findings"
```

---

# Phase 1 — Ingest: Vector source + VRL transform (TDD via `vector test`)

### Task 2: Add the `unifi_syslog` source + passthrough `unifi_ips` transform + wire the sink

**Files:**
- Modify: `infra/vector/vector.toml`

- [ ] **Step 1: Add the source after the `panos_syslog` source block**

In `infra/vector/vector.toml`, after the `[sources.panos_syslog]` block (around line 15), add:

```toml
# UniFi Gateway Max — Suricata IPS alerts + traffic flows on a separate UDP port.
[sources.unifi_syslog]
type = "socket"
mode = "udp"
address = "0.0.0.0:516"
max_length = 102400
```

- [ ] **Step 2: Add a minimal `unifi_ips` transform after the `panos_ecs` transform**

Immediately after the `panos_ecs` transform block (before the `[sinks.clickhouse]` block), add a
minimal transform that emits a well-formed base event (parsing is added in Tasks 3–5):

```toml
# UniFi Suricata eve.json over syslog -> ECS subset. Branch on event_type:
# alert -> intrusion_detection; flow/netflow -> network. IPv4-guard typed IPs
# (IPv6 kept in ext+raw). Parsing filled in incrementally (M9 Tasks 3-5).
[transforms.unifi_ips]
type = "remap"
inputs = ["unifi_syslog"]
source = '''
raw = string(.message) ?? ""
ev = {}
ev = set!(ev, ["timestamp"], now())
ev.event_id = uuid_v4()
ev.tenant_id = "t_main"
ev.event_provider = "unifi"
ev.event_kind = "event"
ev.event_category = ["network"]
ev.event_action = "unknown"
ev.event_outcome = "unknown"
ev.network_transport = "unknown"
ev.rule_name = ""
ev.observer_ingress_zone = ""
ev.observer_egress_zone = ""
ev.observer_hostname = ""
ev.user_name = ""
ev.ext = {}
ev.raw = raw
. = ev
'''
```

- [ ] **Step 3: Add `unifi_ips` to the ClickHouse sink inputs**

In `[sinks.clickhouse]`, change:

```toml
inputs = ["srx_ecs", "panos_ecs"]
```

to:

```toml
inputs = ["srx_ecs", "panos_ecs", "unifi_ips"]
```

- [ ] **Step 4: Validate the config on ct102**

```bash
ssh root@pve3.example.com "pct exec 102 -- bash -lc 'cd /tmp && cat > m9.toml'" < infra/vector/vector.toml
ssh root@pve3.example.com "pct exec 102 -- bash -lc 'cd /tmp && CH_HOST=127.0.0.1 vector validate --no-environment m9.toml'"
```

Expected: `Validated`. (Validate only checks structure; the existing 14 tests still pass since
no test references `unifi_ips` yet.)

- [ ] **Step 5: Commit**

```bash
git add infra/vector/vector.toml
git commit -m "feat(m9): unifi_syslog UDP:516 source + base unifi_ips transform wired to CH sink"
```

### Task 3: Parse UniFi EVE-JSON **alerts** (TDD)

**Files:**
- Modify: `infra/vector/vector.toml` (the `unifi_ips` transform body + a new `[[tests]]`)

- [ ] **Step 1: Write the failing test**

Append to `infra/vector/vector.toml` (use your **captured** alert line from Task 1 §4 in
`value`; the baseline below is a standard EVE-JSON alert — adjust the asserted fields if your
capture differs):

```toml
[[tests]]
name = "unifi_alert_allowed_maps_to_ecs"
[[tests.inputs]]
insert_at = "unifi_ips"
type = "raw"
value = '<29>1 2026-06-13T12:00:00.000000+00:00 gatewaymax suricata - - - {"timestamp":"2026-06-13T12:00:00.000000+0000","event_type":"alert","src_ip":"198.51.100.50","src_port":51514,"dest_ip":"198.51.100.20","dest_port":443,"proto":"TCP","app_proto":"tls","alert":{"action":"allowed","signature_id":2027865,"signature":"ET POLICY Suspicious TLS","category":"Potentially Bad Traffic","severity":2}}'
[[tests.outputs]]
extract_from = "unifi_ips"
[[tests.outputs.conditions]]
type = "vrl"
source = '''
assert_eq!(.event_kind, "alert")
assert_eq!(.event_category, ["intrusion_detection"])
assert_eq!(.event_action, "alert_potentially-bad-traffic")
assert_eq!(.event_outcome, "detection")
assert_eq!(.event_provider, "unifi")
assert_eq!(.source_ip, "198.51.100.50")
assert_eq!(.destination_ip, "198.51.100.20")
assert_eq!(.source_port, 51514)
assert_eq!(.destination_port, 443)
assert_eq!(.network_transport, "tcp")
assert_eq!(.ext."unifi.ips.signature", "ET POLICY Suspicious TLS")
assert_eq!(.ext."unifi.ips.signature_id", "2027865")
assert_eq!(.ext."unifi.ips.category", "Potentially Bad Traffic")
assert_eq!(.ext."unifi.ips.severity", "2")
assert_eq!(.ext."unifi.ips.app_proto", "tls")
'''
```

- [ ] **Step 2: Run it to verify it fails**

```bash
ssh root@pve3.example.com "pct exec 102 -- bash -lc 'cd /tmp && cat > m9.toml'" < infra/vector/vector.toml
ssh root@pve3.example.com "pct exec 102 -- bash -lc 'cd /tmp && vector test m9.toml'"
```

Expected: FAIL on `unifi_alert_allowed_maps_to_ecs` (base transform emits `event_kind=event`,
`event_action=unknown`).

- [ ] **Step 3: Replace the `unifi_ips` transform body with the parsing implementation**

Replace the `source = '''...'''` block of `[transforms.unifi_ips]` with:

```toml
source = '''
raw = string(.message) ?? ""
parsed, perr = parse_syslog(raw)

# UniFi wraps the Suricata eve.json record in a syslog line; slice from the first
# "{" to the last "}" so any tag/prefix before the JSON body is ignored.
json_body = raw
bm, berr = parse_regex(raw, r'(?P<j>\{.*\})')
if berr == null { json_body = string(bm.j) ?? raw }
doc, derr = parse_json(json_body)
if derr != null { doc = {} }

# timestamp: prefer the eve record, then syslog, else now
event_ts = now()
if perr == null && exists(parsed.timestamp) { event_ts = parsed.timestamp }
ts_str = string(doc.timestamp) ?? ""
ts, tserr = parse_timestamp(ts_str, "%Y-%m-%dT%H:%M:%S%.f%z")
if tserr == null { event_ts = ts }

etype = downcase(string(doc.event_type) ?? "")

ev = {}
ev = set!(ev, ["timestamp"], event_ts)
ev.event_id = uuid_v4()
ev.tenant_id = "t_main"
ev.event_provider = "unifi"
ev.event_kind = "event"
ev.event_category = ["network"]
ev.event_action = "unknown"
ev.event_outcome = "unknown"
ev.network_transport = "unknown"
ev.rule_name = ""
ev.observer_ingress_zone = ""
ev.observer_egress_zone = ""
ev.observer_hostname = ""
ev.user_name = ""
ev.raw = raw

ext = {}

proto = downcase(string(doc.proto) ?? "")
if proto != "" { ev.network_transport = proto }

src_ip = string(doc.src_ip) ?? ""
dst_ip = string(doc.dest_ip) ?? ""
_sm, _se = parse_regex(src_ip, r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
if _se == null {
    ev.source_ip = src_ip
} else if src_ip != "" {
    ext = set!(ext, ["unifi.ips.src_ip"], src_ip)
}
_dm, _de = parse_regex(dst_ip, r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
if _de == null {
    ev.destination_ip = dst_ip
} else if dst_ip != "" {
    ext = set!(ext, ["unifi.ips.dest_ip"], dst_ip)
}

if doc.src_port != null { ev.source_port = to_int(doc.src_port) ?? null }
if doc.dest_port != null { ev.destination_port = to_int(doc.dest_port) ?? null }

app = string(doc.app_proto) ?? ""
if app != "" { ext = set!(ext, ["unifi.ips.app_proto"], app) }

if etype == "alert" {
    ev.event_kind = "alert"
    ev.event_category = ["intrusion_detection"]
    alert = object(doc.alert) ?? {}
    cat = string(alert.category) ?? ""
    sig = string(alert.signature) ?? ""
    act = downcase(string(alert.action) ?? "")
    cat_slug = replace(downcase(cat), " ", "-")
    ev.event_action = "alert_" + cat_slug
    if act == "blocked" || act == "dropped" {
        ev.event_outcome = "failure"
    } else {
        ev.event_outcome = "detection"
    }
    if sig != "" { ext = set!(ext, ["unifi.ips.signature"], sig) }
    if alert.signature_id != null { ext = set!(ext, ["unifi.ips.signature_id"], to_string(alert.signature_id) ?? "") }
    if cat != "" { ext = set!(ext, ["unifi.ips.category"], cat) }
    if alert.severity != null { ext = set!(ext, ["unifi.ips.severity"], to_string(alert.severity) ?? "") }
} else if etype == "flow" || etype == "netflow" {
    ev.event_kind = "event"
    ev.event_category = ["network"]
    fl = object(doc.flow) ?? {}
    state = downcase(string(fl.state) ?? "")
    if state == "" { state = "record" }
    ev.event_action = "flow_" + state
    ev.event_outcome = "success"
    sb = to_int(fl.bytes_toserver) ?? null
    db = to_int(fl.bytes_toclient) ?? null
    if sb != null { ev.source_bytes = sb }
    if db != null { ev.destination_bytes = db }
    if sb != null && db != null { ev.network_bytes = sb + db }
} else {
    ev.event_action = "unknown"
    if etype != "" { ext = set!(ext, ["unifi.event_type"], etype) }
}

ev.ext = ext
. = ev
'''
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
ssh root@pve3.example.com "pct exec 102 -- bash -lc 'cd /tmp && cat > m9.toml'" < infra/vector/vector.toml
ssh root@pve3.example.com "pct exec 102 -- bash -lc 'cd /tmp && vector test m9.toml'"
```

Expected: `unifi_alert_allowed_maps_to_ecs` PASSES; all prior tests still pass.

- [ ] **Step 5: Commit**

```bash
git add infra/vector/vector.toml
git commit -m "feat(m9): parse UniFi EVE-JSON alerts to ECS (intrusion_detection)"
```

### Task 4: Parse UniFi **flows** + blocked-alert outcome (TDD)

**Files:**
- Modify: `infra/vector/vector.toml` (two new `[[tests]]`)

- [ ] **Step 1: Write the failing tests**

Append to `infra/vector/vector.toml` (replace `value` with your captured **flow** line from Task
1 §4 if it differs from the EVE-flow baseline):

```toml
[[tests]]
name = "unifi_flow_maps_to_ecs"
[[tests.inputs]]
insert_at = "unifi_ips"
type = "raw"
value = '<29>1 2026-06-13T12:01:00.000000+00:00 gatewaymax suricata - - - {"timestamp":"2026-06-13T12:01:00.000000+0000","event_type":"flow","src_ip":"198.51.100.50","src_port":51520,"dest_ip":"198.51.100.20","dest_port":443,"proto":"TCP","app_proto":"tls","flow":{"state":"closed","bytes_toserver":3000,"bytes_toclient":5000}}'
[[tests.outputs]]
extract_from = "unifi_ips"
[[tests.outputs.conditions]]
type = "vrl"
source = '''
assert_eq!(.event_kind, "event")
assert_eq!(.event_category, ["network"])
assert_eq!(.event_action, "flow_closed")
assert_eq!(.event_outcome, "success")
assert_eq!(.event_provider, "unifi")
assert_eq!(.source_ip, "198.51.100.50")
assert_eq!(.destination_ip, "198.51.100.20")
assert_eq!(.destination_port, 443)
assert_eq!(.network_transport, "tcp")
assert_eq!(.source_bytes, 3000)
assert_eq!(.destination_bytes, 5000)
assert_eq!(.network_bytes, 8000)
'''

[[tests]]
name = "unifi_alert_blocked_is_failure"
[[tests.inputs]]
insert_at = "unifi_ips"
type = "raw"
value = '<29>1 2026-06-13T12:02:00.000000+00:00 gatewaymax suricata - - - {"timestamp":"2026-06-13T12:02:00.000000+0000","event_type":"alert","src_ip":"198.51.100.99","src_port":40000,"dest_ip":"198.51.100.8","dest_port":80,"proto":"TCP","alert":{"action":"blocked","signature_id":2010935,"signature":"ET WEB_SERVER SQL Injection","category":"Web Application Attack","severity":1}}'
[[tests.outputs]]
extract_from = "unifi_ips"
[[tests.outputs.conditions]]
type = "vrl"
source = '''
assert_eq!(.event_kind, "alert")
assert_eq!(.event_action, "alert_web-application-attack")
assert_eq!(.event_outcome, "failure")
assert_eq!(.ext."unifi.ips.severity", "1")
'''
```

- [ ] **Step 2: Run to verify they pass (the Task-3 implementation already covers them)**

```bash
ssh root@pve3.example.com "pct exec 102 -- bash -lc 'cd /tmp && cat > m9.toml'" < infra/vector/vector.toml
ssh root@pve3.example.com "pct exec 102 -- bash -lc 'cd /tmp && vector test m9.toml'"
```

Expected: both PASS. If `unifi_flow_maps_to_ecs` fails because your captured flow uses different
keys (e.g. not `flow.bytes_toserver`), adjust the flow branch in the `unifi_ips` transform to
read the real keys, then re-run.

- [ ] **Step 3: Commit**

```bash
git add infra/vector/vector.toml
git commit -m "test(m9): UniFi flow mapping + blocked-alert failure outcome"
```

### Task 5: H2 known-device gate + IPv6/unknown-host/malformed guards (TDD)

**Files:**
- Modify: `infra/vector/vector.toml` (transform body + three new `[[tests]]`)

- [ ] **Step 1: Write the failing tests**

Append to `infra/vector/vector.toml` (substitute `gatewaymax` with your captured
`GATEWAY_HOSTNAME` in the first test):

```toml
[[tests]]
name = "unifi_observer_hostname_known_passes"
[[tests.inputs]]
insert_at = "unifi_ips"
type = "raw"
value = '<29>1 2026-06-13T12:03:00.000000+00:00 gatewaymax suricata - - - {"timestamp":"2026-06-13T12:03:00.000000+0000","event_type":"alert","src_ip":"198.51.100.50","dest_ip":"198.51.100.20","proto":"TCP","alert":{"action":"allowed","signature_id":1,"signature":"x","category":"Misc","severity":3}}'
[[tests.outputs]]
extract_from = "unifi_ips"
[[tests.outputs.conditions]]
type = "vrl"
source = '''
assert_eq!(.observer_hostname, "gatewaymax")
'''

[[tests]]
name = "unifi_observer_hostname_unknown_is_blanked"
[[tests.inputs]]
insert_at = "unifi_ips"
type = "raw"
value = '<29>1 2026-06-13T12:03:00.000000+00:00 evil-host suricata - - - {"timestamp":"2026-06-13T12:03:00.000000+0000","event_type":"alert","src_ip":"198.51.100.50","dest_ip":"198.51.100.20","proto":"TCP","alert":{"action":"allowed","signature_id":1,"signature":"x","category":"Misc","severity":3}}'
[[tests.outputs]]
extract_from = "unifi_ips"
[[tests.outputs.conditions]]
type = "vrl"
source = '''
assert_eq!(.observer_hostname, "")
assert_eq!(.event_kind, "alert")
'''

[[tests]]
name = "unifi_ipv6_source_left_null_kept_in_ext"
[[tests.inputs]]
insert_at = "unifi_ips"
type = "raw"
value = '<29>1 2026-06-13T12:04:00.000000+00:00 gatewaymax suricata - - - {"timestamp":"2026-06-13T12:04:00.000000+0000","event_type":"alert","src_ip":"2001:db8::1","dest_ip":"198.51.100.20","proto":"TCP","alert":{"action":"allowed","signature_id":1,"signature":"x","category":"Misc","severity":3}}'
[[tests.outputs]]
extract_from = "unifi_ips"
[[tests.outputs.conditions]]
type = "vrl"
source = '''
assert!(!exists(.source_ip))
assert_eq!(.destination_ip, "198.51.100.20")
assert_eq!(.ext."unifi.ips.src_ip", "2001:db8::1")
'''

[[tests]]
name = "unifi_malformed_line_is_unknown"
[[tests.inputs]]
insert_at = "unifi_ips"
type = "raw"
value = '<29>1 2026-06-13T12:05:00.000000+00:00 gatewaymax suricata - - - not-json-garbage'
[[tests.outputs]]
extract_from = "unifi_ips"
[[tests.outputs.conditions]]
type = "vrl"
source = '''
assert_eq!(.event_action, "unknown")
assert_eq!(.event_provider, "unifi")
assert!(!exists(.source_ip))
'''
```

- [ ] **Step 2: Run to verify the two hostname tests FAIL**

```bash
ssh root@pve3.example.com "pct exec 102 -- bash -lc 'cd /tmp && cat > m9.toml'" < infra/vector/vector.toml
ssh root@pve3.example.com "pct exec 102 -- bash -lc 'cd /tmp && vector test m9.toml'"
```

Expected: `unifi_observer_hostname_known_passes` FAILS (current transform always sets
`observer_hostname=""`). The IPv6 and malformed tests already PASS (Task-3 logic).

- [ ] **Step 3: Add the H2 gate to the transform body**

In the `unifi_ips` transform, replace the line:

```
ev.observer_hostname = ""
```

with (substitute `gatewaymax` with the captured `GATEWAY_HOSTNAME`; stored value keeps original
case per the M6c-B bridge rule — only the membership test lowercases):

```
obs_host = string(parsed.hostname) ?? ""
_obs_parts = split(obs_host, ".")
_obs_short = downcase(string(_obs_parts[0]) ?? "")
_obs_known = false
if _obs_short == "gatewaymax" { _obs_known = true }
if !_obs_known { obs_host = "" }
ev.observer_hostname = obs_host
```

- [ ] **Step 4: Run all tests to verify they pass**

```bash
ssh root@pve3.example.com "pct exec 102 -- bash -lc 'cd /tmp && cat > m9.toml'" < infra/vector/vector.toml
ssh root@pve3.example.com "pct exec 102 -- bash -lc 'cd /tmp && vector test m9.toml'"
```

Expected: ALL tests pass (the original 14 + the 6 new UniFi tests = 20).

- [ ] **Step 5: Commit**

```bash
git add infra/vector/vector.toml
git commit -m "feat(m9): H2 known-device gate for UniFi gateway + IPv6/unknown/malformed guards"
```

---

# Phase 2 — Ingest hardening: nftables allow-list (H1)

### Task 6: Extend the ct102 ingest allow-list to UDP 516 + the gateway source IP

**Files:**
- Modify: `infra/firewall/ct102-ingest.nft`

- [ ] **Step 1: Update the rule file**

In `infra/firewall/ct102-ingest.nft`, replace the chain body:

```
        # Allowed syslog senders: vSRX test fleet + panosvm (198.51.100.220-.242).
        udp dport { 514, 515 } ip saddr 198.51.100.220-198.51.100.242 accept

        # Everything else hitting the ingest ports is dropped.
        udp dport { 514, 515 } drop
```

with (substitute `198.51.100.1` with the captured `GATEWAY_SRC_IP`):

```
        # Allowed syslog senders: vSRX test fleet + panosvm (198.51.100.220-.242).
        udp dport { 514, 515 } ip saddr 198.51.100.220-198.51.100.242 accept

        # UniFi Gateway Max (M9): IPS alerts + flows on UDP 516 from the gateway.
        udp dport 516 ip saddr 198.51.100.1 accept

        # Everything else hitting the ingest ports is dropped.
        udp dport { 514, 515, 516 } drop
```

Also update the file's header comment `# Restrict UDP 514 (SRX) / 515 (PAN-OS)...` to mention
`516 (UniFi)`.

- [ ] **Step 2: Verify the script targets this file (no code change expected)**

```bash
grep -n "ct102-ingest.nft\|ssdf_ingest" scripts/apply_ct102_nftables.sh
```

Expected: the script pushes `infra/firewall/ct102-ingest.nft` and reloads the `inet ssdf_ingest`
table. (Deployment of this rule is Task 9.)

- [ ] **Step 3: Commit**

```bash
git add infra/firewall/ct102-ingest.nft
git commit -m "feat(m9): nftables allow UDP 516 from UniFi gateway on ct102 ingest"
```

---

# Phase 3 — `explain_access` detections enrichment (TDD, Python — no format dependency)

### Task 7: `alerts_for_pair` store method + builder (TDD)

**Files:**
- Modify: `services/mcp-query/src/ssdf_mcp_query/entitystore.py`
- Test: `services/mcp-query/tests/test_entitystore.py`

- [ ] **Step 1: Write the failing test**

Add to `services/mcp-query/tests/test_entitystore.py` (create the file with this content if it
does not exist):

```python
from ssdf_mcp_query.entitystore import build_alerts_for_pair_sql


def test_build_alerts_for_pair_sql_filters_provider_kind_ips_and_window():
    sql, params = build_alerts_for_pair_sql(
        ["198.51.100.50", "198.51.100.20"], "2026-06-13T00:00:00.000", "t_main")
    assert "event_provider = 'unifi'" in sql
    assert "event_kind = 'alert'" in sql
    assert "timestamp >= {since:String}" in sql
    assert "toString(source_ip) IN {ips:Array(String)}" in sql
    assert "toString(destination_ip) IN {ips:Array(String)}" in sql
    assert params["ips"] == ["198.51.100.50", "198.51.100.20"]
    assert params["since"] == "2026-06-13T00:00:00.000"
    assert params["tenant"] == "t_main"
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd services/mcp-query && uv run pytest tests/test_entitystore.py::test_build_alerts_for_pair_sql_filters_provider_kind_ips_and_window -v
```

Expected: FAIL with `ImportError: cannot import name 'build_alerts_for_pair_sql'`.

- [ ] **Step 3: Add the builder + store method + Protocol entry**

In `services/mcp-query/src/ssdf_mcp_query/entitystore.py`, add the builder after
`build_configured_governed_sql` (around line 82):

```python
def build_alerts_for_pair_sql(ips: list[str], since_iso: str,
                              tenant: str) -> tuple[str, dict]:
    # UniFi IPS alerts (M9) touching either endpoint IP in-window. source_ip/
    # destination_ip are Nullable(IPv4); compare via toString to match the
    # dotted-quad params without IPv4-cast fragility. IPv6 alerts (kept only in
    # ext/raw) do not match here by design (events schema is IPv4-only).
    sql = (
        "SELECT toString(timestamp) AS timestamp, toString(source_ip) AS source_ip, "
        "toString(destination_ip) AS destination_ip, "
        "ext['unifi.ips.signature'] AS signature, "
        "ext['unifi.ips.signature_id'] AS signature_id, "
        "ext['unifi.ips.category'] AS category, "
        "ext['unifi.ips.severity'] AS severity "
        "FROM ssdf.events "
        "WHERE tenant_id = {tenant:String} AND event_provider = 'unifi' "
        "AND event_kind = 'alert' AND timestamp >= {since:String} AND ("
        "toString(source_ip) IN {ips:Array(String)} OR "
        "toString(destination_ip) IN {ips:Array(String)}) "
        "ORDER BY timestamp DESC"
    )
    return sql, {"tenant": tenant, "ips": ips, "since": since_iso}
```

Add `alerts_for_pair` to the `EntityStore` Protocol (after the
`configured_policies_for_firewalls` line):

```python
    def alerts_for_pair(self, ips: list[str], since_iso: str) -> list[dict]: ...
```

Add the method to `ClickHouseEntityStore` (after `configured_policies_for_firewalls`):

```python
    def alerts_for_pair(self, ips: list[str], since_iso: str) -> list[dict]:
        if not ips:
            return []
        sql, params = build_alerts_for_pair_sql(ips, since_iso, self._tenant)
        return self._ch.run(sql, params)["rows"]
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
cd services/mcp-query && uv run pytest tests/test_entitystore.py::test_build_alerts_for_pair_sql_filters_provider_kind_ips_and_window -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add services/mcp-query/src/ssdf_mcp_query/entitystore.py services/mcp-query/tests/test_entitystore.py
git commit -m "feat(m9): alerts_for_pair store method + builder for UniFi IPS alerts"
```

### Task 8: `detections` field on `explain_access` (TDD)

**Files:**
- Modify: `services/mcp-query/src/ssdf_mcp_query/access_tools.py`
- Test: `services/mcp-query/tests/test_access_tools.py`

- [ ] **Step 1: Add `alerts_for_pair` to the test `_FakeStore` and write the failing test**

In `services/mcp-query/tests/test_access_tools.py`, add a method to `_FakeStore` (after
`configured_policies_for_firewalls`):

```python
    def alerts_for_pair(self, ips, since_iso):
        return getattr(self, "_alerts", [])
```

Then append a new test:

```python
def test_detections_populated_from_unifi_alerts():
    ents = _client_server()
    comm = [{"edge_id": "E1", "attrs": {"sessions": "3", "bytes": "100",
                                        "ports": "443", "providers": "unifi",
                                        "transports": "tcp"}}]
    store = _FakeStore(ents, comm, [])
    store._alerts = [{"timestamp": "2026-06-13 12:00:00.000",
                      "source_ip": "10.64.0.5", "destination_ip": "8.8.8.8",
                      "signature": "ET POLICY Suspicious TLS", "signature_id": "2027865",
                      "category": "Potentially Bad Traffic", "severity": "2"}]
    topo = _FakeTopo([], {"found": False})
    out = AccessTools(store, topo).explain_access("10.64.0.5", "8.8.8.8")
    assert len(out["detections"]) == 1
    det = out["detections"][0]
    assert det["signature"] == "ET POLICY Suspicious TLS"
    assert det["signature_id"] == "2027865"
    assert det["category"] == "Potentially Bad Traffic"
    assert det["severity"] == "2"


def test_detections_empty_when_no_alerts():
    ents = _client_server()
    comm = [{"edge_id": "E1", "attrs": {"sessions": "1", "bytes": "1",
                                        "ports": "443", "providers": "unifi", "transports": "tcp"}}]
    store = _FakeStore(ents, comm, [])   # no _alerts attribute -> []
    topo = _FakeTopo([], {"found": False})
    out = AccessTools(store, topo).explain_access("10.64.0.5", "8.8.8.8")
    assert out["detections"] == []
```

- [ ] **Step 2: Run to verify both fail**

```bash
cd services/mcp-query && uv run pytest tests/test_access_tools.py::test_detections_populated_from_unifi_alerts tests/test_access_tools.py::test_detections_empty_when_no_alerts -v
```

Expected: FAIL with `KeyError: 'detections'`.

- [ ] **Step 3: Implement the enrichment in `explain_access`**

In `services/mcp-query/src/ssdf_mcp_query/access_tools.py`, build the candidate IP set and query
alerts. Insert this block just **before** the final `return {` (after the `controls` loop, around
line 105):

```python
        # M9: UniFi IPS detections touching either endpoint, same window. Candidate IPs
        # come from the lookup args + entity identifiers (IPv4 only — events are IPv4).
        alert_ips: set[str] = set()
        for candidate in (client, server,
                          *client_entity.get("identifiers", {}).values(),
                          *server_entity.get("identifiers", {}).values()):
            try:
                ipaddress.IPv4Address(candidate)
                alert_ips.add(candidate)
            except (ipaddress.AddressValueError, ValueError):
                continue
        detections = []
        for alert in self._store.alerts_for_pair(sorted(alert_ips), _since(window)):
            detections.append({
                "timestamp": alert.get("timestamp", ""),
                "signature": alert.get("signature", ""),
                "signature_id": alert.get("signature_id", ""),
                "category": alert.get("category", ""),
                "severity": alert.get("severity", ""),
                "source_ip": alert.get("source_ip", ""),
                "destination_ip": alert.get("destination_ip", ""),
            })
```

Then add `"detections": detections,` to the returned dict (e.g. right after the `"controls"`
line):

```python
            "controls": controls,
            "detections": detections,
```

- [ ] **Step 4: Run the new tests + the full access-tools suite**

```bash
cd services/mcp-query && uv run pytest tests/test_access_tools.py -v
```

Expected: the two new tests PASS and all existing access-tools tests still PASS.

- [ ] **Step 5: Run the whole mcp-query unit suite**

```bash
cd services/mcp-query && uv run pytest -m "not integration"
```

Expected: all green (existing suite + the new entitystore + access-tools tests).

- [ ] **Step 6: Commit**

```bash
git add services/mcp-query/src/ssdf_mcp_query/access_tools.py services/mcp-query/tests/test_access_tools.py
git commit -m "feat(m9): explain_access detections field from UniFi IPS alerts"
```

---

# Phase 4 — Deploy + live verification (operator-gated)

### Task 9: Deploy ingest (nftables + Vector) on ct102 and live-verify

**Files:** none (deployment of Tasks 2–6 artifacts)

- [ ] **Step 1: Apply the nftables allow-list**

```bash
./scripts/apply_ct102_nftables.sh
ssh root@pve3.example.com "pct exec 102 -- nft list table inet ssdf_ingest"
```

Expected: the table shows the 514/515 accept rule, the new `udp dport 516 ip saddr
<GATEWAY_SRC_IP> accept` rule, and the `udp dport { 514, 515, 516 } drop` rule.

- [ ] **Step 2: Deploy the Vector config (CH must be up — the sink healthcheck gates restart)**

```bash
scp infra/vector/vector.toml root@pve3.example.com:/tmp/vector.toml.new
ssh root@pve3.example.com "pct push 102 /tmp/vector.toml.new /etc/vector/vector.toml.new"
ssh root@pve3.example.com "pct exec 102 -- bash -lc 'vector validate /etc/vector/vector.toml.new'"
ssh root@pve3.example.com "pct exec 102 -- bash -lc 'cp /etc/vector/vector.toml /etc/vector/vector.toml.bak && mv /etc/vector/vector.toml.new /etc/vector/vector.toml && systemctl restart vector.service'"
ssh root@pve3.example.com "pct exec 102 -- bash -lc 'systemctl is-active vector.service && ss -lunp | grep -E \":51[456]\"'"
```

Expected: `vector validate` passes (CH sink healthcheck OK), service `active`, and **three** UDP
sockets listening (514, 515, 516).

> NOTE: the live ct102 Vector env uses TLS to ClickHouse (`CH_PROTO=https CH_HTTP_PORT=8443`
> drop-in + an appended `[sinks.clickhouse.tls] ca_file=...`). The deployed `vector.toml` on the
> host must retain that host-appended tls block — do not overwrite it away. Confirm the running
> file still has the tls block after the `mv` (re-append if the new file lacks it), per CLAUDE.md
> "Vector (ct102)".

- [ ] **Step 3: Live-verify alerts + flows land in ClickHouse**

```bash
ssh root@pve3.example.com "pct exec 104 -- clickhouse-client --query \
  \"SELECT event_kind, event_action, observer_hostname, count() FROM ssdf.events \
    WHERE event_provider='unifi' AND timestamp > now() - INTERVAL 1 HOUR \
    GROUP BY event_kind, event_action, observer_hostname ORDER BY count() DESC\""
```

Expected: nonzero rows; alert rows with `event_kind=alert`, flow rows with `event_kind=event`,
and `observer_hostname` = the captured gateway hostname (not blank). If blank, the H2 gate token
does not match the real stamped hostname — fix Task 5's `GATEWAY_HOSTNAME` and redeploy.

- [ ] **Step 4: Commit any deploy-found fixes**

If Step 3 surfaced a hostname/format fix, apply it to `infra/vector/vector.toml`, re-run the
ct102 `vector test`, redeploy, and:

```bash
git add infra/vector/vector.toml
git commit -m "fix(m9): reconcile UniFi VRL with live wire format (deploy finding)"
```

### Task 10: Deploy `explain_access` enrichment on ct106 and live-verify `detections`

**Files:** none (deployment of Tasks 7–8 artifacts)

- [ ] **Step 1: Sync the mcp-query source to ct106 and restart**

```bash
scp services/mcp-query/src/ssdf_mcp_query/entitystore.py services/mcp-query/src/ssdf_mcp_query/access_tools.py root@pve3.example.com:/tmp/
ssh root@pve3.example.com "pct push 106 /tmp/entitystore.py /opt/src/mcp-query/src/ssdf_mcp_query/entitystore.py && pct push 106 /tmp/access_tools.py /opt/src/mcp-query/src/ssdf_mcp_query/access_tools.py"
ssh root@pve3.example.com "pct exec 106 -- systemctl restart ssdf-mcp-query.service && pct exec 106 -- systemctl is-active ssdf-mcp-query.service"
```

Expected: service `active`.

- [ ] **Step 2: Live-verify `detections` via the sovereign MCP**

After a real IPS alert exists between two endpoints (Task 9 Step 3), call `explain_access` for
that client/server pair through the sovereign MCP edge (the local `.mcp.json` `ssdf-mcp-query`
client) and confirm the response includes a populated `detections` array with the Suricata
`signature`/`signature_id`/`category`/`severity`.

Expected: `detections` non-empty for the alerted pair; empty for a pair with no alerts. The
public tier (`ssdf-mcp-public`) does **not** expose `explain_access`, so no public check applies.

- [ ] **Step 3: Update STATUS.md**

Add an M9 row to the as-built table and mark the M9 forward-roadmap item done, with honest live
findings (captured wire format, gateway hostname, any deploy fixes). Follow the existing M-row
format.

```bash
git add docs/superpowers/STATUS.md
git commit -m "docs(m9): mark UniFi Suricata IPS+flow ingest done (live-verified)"
```

- [ ] **Step 4: Finish the branch**

Use superpowers:finishing-a-development-branch → PR titled
`M9: UniFi Suricata IPS + flow ingest (third vendor, first detection-class source)`, with the
captured wire format, live row counts, and a sample `explain_access` `detections` result in the
description.

---

## Self-review notes (coverage map)

- Spec §4 architecture → Tasks 2–5 (source+transform), 6 (nftables), 7–8 (detections). ✔
- Spec §5.1 source → Task 2. §5.2 transform → Tasks 3–4. §5.3 H2 gate → Task 5. §5.4 H1 nftables → Task 6. ✔
- Spec §6.1 alert mapping → Task 3. §6.2 flow mapping → Task 4. ✔
- Spec §7 classification (no code change) → covered by construction (no `classification.py` task; `security_log` already sovereign-only). ✔
- Spec §8 `detections` → Tasks 7–8. ✔
- Spec §9 testing → VRL tests (Tasks 3–5), Python tests (Tasks 7–8), live (Tasks 9–10). ✔
- Spec §10 deploy → Tasks 9–10. §11 files → all present in the File Structure table. ✔
- Spec §12 out-of-scope → no tasks (correct: no FLAGGED_BY edges, no UniFi rule collection, no schema migration). ✔
