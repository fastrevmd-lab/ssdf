# SSDF M1 — SRX → Vector(ECS) → ClickHouse Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up a single, working telemetry pipe — Junos/SRX security logs → Vector (parse + normalize to an ECS subset via VRL) → ClickHouse — so time-ranged/filtered flow queries against real vSRX data are answerable via SQL.

**Architecture:** SRX streams `sd-syslog` (RFC5424) security logs to a Vector collector on a Proxmox LXC. A Vector `remap` (VRL) transform parses RT_FLOW events and emits a **flat** ECS-subset record (ECS field names flattened with `_`, e.g. `source.ip` → `source_ip`). Vector's ClickHouse sink writes those records to one `events` table on a ClickHouse LXC. No Rust service, no message bus, no graph, no Python — those return in later milestones behind seams.

**Tech Stack:** Vector (syslog source + VRL + ClickHouse sink), ClickHouse (MergeTree), Proxmox LXC (Debian 12), `rust-junosmcp` for device onboarding. TDD uses Vector's built-in unit-test runner (`vector test`).

**Spec:** `docs/superpowers/specs/2026-06-06-ssdf-v0-simplified-design.md` (§4 Milestone 1, §5 roadmap).

---

## File Structure

```
SSDF/
├── infra/
│   ├── clickhouse/
│   │   └── 001_events.sql          # ssdf.events table DDL (ECS-subset flat columns + raw + ext)
│   └── vector/
│       └── vector.toml             # syslog source + VRL remap (SRX RT_FLOW → ECS) + clickhouse sink + unit tests
├── onboarding/
│   └── srx/
│       └── stream-config.set       # Junos `set` commands to push security logs to the collector
├── tests/
│   └── fixtures/srx/
│       ├── session_close.txt       # one sd-syslog RT_FLOW_SESSION_CLOSE line
│       ├── session_create.txt      # one sd-syslog RT_FLOW_SESSION_CREATE line
│       └── session_deny.txt        # one sd-syslog RT_FLOW_SESSION_DENY line
├── scripts/
│   └── apply_clickhouse_schema.sh  # applies 001_events.sql and asserts the table exists
└── docs/superpowers/...            # spec + this plan
```

Each file has one responsibility: DDL is store-only; `vector.toml` owns parse+normalize+sink and its own tests; onboarding owns device-side config; fixtures are the test corpus.

**ECS field → ClickHouse column mapping (the M1 contract).** ECS dotted names are flattened with `_` for storage and query ergonomics; the VRL emits these exact flat keys:

| ECS field | Column | Type |
|---|---|---|
| `@timestamp` | `timestamp` | `DateTime64(3, 'UTC')` |
| `event.id` | `event_id` | `String` |
| `tenant_id` | `tenant_id` | `LowCardinality(String)` |
| `event.kind` | `event_kind` | `LowCardinality(String)` |
| `event.category` | `event_category` | `Array(LowCardinality(String))` |
| `event.action` | `event_action` | `LowCardinality(String)` |
| `event.outcome` | `event_outcome` | `LowCardinality(String)` |
| `event.provider` | `event_provider` | `LowCardinality(String)` |
| `source.ip` | `source_ip` | `Nullable(IPv4)` |
| `source.port` | `source_port` | `Nullable(UInt16)` |
| `source.bytes` | `source_bytes` | `Nullable(UInt64)` |
| `destination.ip` | `destination_ip` | `Nullable(IPv4)` |
| `destination.port` | `destination_port` | `Nullable(UInt16)` |
| `destination.bytes` | `destination_bytes` | `Nullable(UInt64)` |
| `network.transport` | `network_transport` | `LowCardinality(String)` |
| `network.bytes` | `network_bytes` | `Nullable(UInt64)` |
| `rule.name` | `rule_name` | `String` |
| `observer.ingress.zone` | `observer_ingress_zone` | `LowCardinality(String)` |
| `observer.egress.zone` | `observer_egress_zone` | `LowCardinality(String)` |
| `user.name` | `user_name` | `String` |
| (full vendor SD map) | `ext` | `Map(String, String)` |
| (original syslog line) | `raw` | `String` |

---

## Task 1: Scaffold the M1 directory structure

**Files:**
- Create: `infra/.gitkeep`, `onboarding/.gitkeep`, `tests/fixtures/srx/.gitkeep`, `scripts/.gitkeep`

- [ ] **Step 1: Create the directory skeleton**

```bash
mkdir -p infra/clickhouse infra/vector onboarding/srx tests/fixtures/srx scripts
touch infra/clickhouse/.gitkeep infra/vector/.gitkeep onboarding/srx/.gitkeep tests/fixtures/srx/.gitkeep scripts/.gitkeep
```

- [ ] **Step 2: Verify the layout**

Run: `find infra onboarding tests scripts -type d | sort`
Expected output:
```
infra
infra/clickhouse
infra/vector
onboarding
onboarding/srx
scripts
tests
tests/fixtures
tests/fixtures/srx
```

- [ ] **Step 3: Commit**

```bash
git add infra onboarding tests scripts
git commit -m "chore(m1): scaffold infra/onboarding/tests/scripts layout"
```

---

## Task 2: ClickHouse events schema

**Files:**
- Create: `infra/clickhouse/001_events.sql`
- Create: `scripts/apply_clickhouse_schema.sh`

- [ ] **Step 1: Write the DDL**

Create `infra/clickhouse/001_events.sql`:

```sql
CREATE DATABASE IF NOT EXISTS ssdf;

CREATE TABLE IF NOT EXISTS ssdf.events
(
    timestamp             DateTime64(3, 'UTC'),
    event_id              String,
    tenant_id             LowCardinality(String) DEFAULT 't_main',
    event_kind            LowCardinality(String),
    event_category        Array(LowCardinality(String)),
    event_action          LowCardinality(String),
    event_outcome         LowCardinality(String),
    event_provider        LowCardinality(String),
    source_ip             Nullable(IPv4),
    source_port           Nullable(UInt16),
    source_bytes          Nullable(UInt64),
    destination_ip        Nullable(IPv4),
    destination_port      Nullable(UInt16),
    destination_bytes     Nullable(UInt64),
    network_transport     LowCardinality(String),
    network_bytes         Nullable(UInt64),
    rule_name             String,
    observer_ingress_zone LowCardinality(String),
    observer_egress_zone  LowCardinality(String),
    user_name             String,
    ext                   Map(String, String),
    raw                   String
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (tenant_id, timestamp, event_action)
TTL toDateTime(timestamp) + INTERVAL 30 DAY;
```

- [ ] **Step 2: Write the apply+verify script**

Create `scripts/apply_clickhouse_schema.sh`:

```bash
#!/usr/bin/env bash
# Applies the ClickHouse DDL and asserts the events table exists.
# Usage: CH_HOST=<ip> ./scripts/apply_clickhouse_schema.sh
set -euo pipefail
CH_HOST="${CH_HOST:-127.0.0.1}"
SQL_FILE="$(dirname "$0")/../infra/clickhouse/001_events.sql"

clickhouse-client --host "$CH_HOST" --multiquery < "$SQL_FILE"

COLS=$(clickhouse-client --host "$CH_HOST" --query \
  "SELECT count() FROM system.columns WHERE database='ssdf' AND table='events'")
if [ "$COLS" -lt 22 ]; then
  echo "FAIL: ssdf.events has $COLS columns (expected >= 22)"; exit 1
fi
echo "OK: ssdf.events present with $COLS columns"
```

- [ ] **Step 3: Make the script executable**

Run: `chmod +x scripts/apply_clickhouse_schema.sh`

- [ ] **Step 4: Commit**

```bash
git add infra/clickhouse/001_events.sql scripts/apply_clickhouse_schema.sh
git commit -m "feat(m1): add ClickHouse ssdf.events schema + apply/verify script"
```

> Note: this script is exercised against a live ClickHouse in Task 4. It is committed here so the schema is reviewable independently.

---

## Task 3: Provision the M1 LXCs on Proxmox

> Environment: Proxmox host `pve3.example.com` (root SSH via `~/.ssh/id_ed25519`). Reserved VMIDs to NEVER touch: 100, 301, 500, 600, 601, 900. Pick two free IDs (this plan uses **620 = clickhouse**, **621 = vector**; confirm free first). Record the assigned container IPs in `infra/ENV.local` (gitignored) for later tasks.

**Files:**
- Create: `infra/ENV.local` (gitignored — holds `CH_HOST` / `VECTOR_HOST` IPs)
- Modify: `.gitignore`

- [ ] **Step 1: Ignore the local env file**

Append to `.gitignore`:

```
# M1 local infra coordinates (host-specific, not for VCS)
infra/ENV.local
```

- [ ] **Step 2: Confirm the chosen VMIDs are free**

Run: `ssh root@pve3.example.com "pct list && qm list" | grep -E '\b62[01]\b' || echo "620/621 are free"`
Expected: `620/621 are free` (if not, choose other IDs and substitute throughout).

- [ ] **Step 3: Create the ClickHouse container (VMID 620)**

Run (adjust `--storage`/`--bridge`/template to match the node; list templates with `pveam available`/`pveam list local`):

```bash
ssh root@pve3.example.com 'pct create 620 local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst \
  --hostname ssdf-clickhouse --cores 2 --memory 4096 --rootfs local-lvm:20 \
  --net0 name=eth0,bridge=vmbr0,ip=dhcp --unprivileged 1 --features nesting=1 --onboot 1 && \
  pct start 620'
```

- [ ] **Step 4: Create the Vector container (VMID 621)**

```bash
ssh root@pve3.example.com 'pct create 621 local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst \
  --hostname ssdf-vector --cores 2 --memory 2048 --rootfs local-lvm:10 \
  --net0 name=eth0,bridge=vmbr0,ip=dhcp --unprivileged 1 --onboot 1 && \
  pct start 621'
```

- [ ] **Step 5: Capture the container IPs**

```bash
ssh root@pve3.example.com "pct exec 620 -- ip -4 -o addr show eth0 | awk '{print \$4}' | cut -d/ -f1"
ssh root@pve3.example.com "pct exec 621 -- ip -4 -o addr show eth0 | awk '{print \$4}' | cut -d/ -f1"
```

Write the results into `infra/ENV.local`:

```bash
CH_HOST=<clickhouse-620-ip>
VECTOR_HOST=<vector-621-ip>
```

- [ ] **Step 6: Install ClickHouse on 620**

```bash
ssh root@pve3.example.com 'pct exec 620 -- bash -lc "apt-get update && apt-get install -y apt-transport-https ca-certificates curl gnupg && \
  curl -fsSL https://packages.clickhouse.com/rpm/lts/repodata/repomd.xml.key | gpg --dearmor -o /usr/share/keyrings/clickhouse-keyring.gpg && \
  echo \"deb [signed-by=/usr/share/keyrings/clickhouse-keyring.gpg] https://packages.clickhouse.com/deb stable main\" > /etc/apt/sources.list.d/clickhouse.list && \
  DEBIAN_FRONTEND=noninteractive apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y clickhouse-server clickhouse-client && \
  systemctl enable --now clickhouse-server"'
```

Then allow remote connections (Vector + your workstation reach it over HTTP/native):

```bash
ssh root@pve3.example.com 'pct exec 620 -- bash -lc "mkdir -p /etc/clickhouse-server/config.d && printf \"<clickhouse><listen_host>0.0.0.0</listen_host></clickhouse>\n\" > /etc/clickhouse-server/config.d/listen.xml && systemctl restart clickhouse-server"'
```

- [ ] **Step 7: Install Vector on 621** (apt package → provides the systemd unit)

```bash
ssh root@pve3.example.com 'pct exec 621 -- bash -lc "apt-get update && apt-get install -y curl gnupg ca-certificates && \
  curl -1sLf https://repositories.timber.io/public/vector/gpg.3543DB2D0A2BC4B8.key | gpg --dearmor -o /usr/share/keyrings/vector-archive-keyring.gpg && \
  echo \"deb [signed-by=/usr/share/keyrings/vector-archive-keyring.gpg] https://repositories.timber.io/public/vector/deb/debian bookworm main\" > /etc/apt/sources.list.d/vector.list && \
  apt-get update && apt-get install -y vector"'
```

- [ ] **Step 8: Verify both services**

```bash
source infra/ENV.local
ssh root@pve3.example.com "pct exec 620 -- clickhouse-client --query 'SELECT version()'"
ssh root@pve3.example.com "pct exec 621 -- vector --version"
```

Expected: a ClickHouse version string and a `vector x.y.z` string.

- [ ] **Step 9: Commit**

```bash
git add .gitignore
git commit -m "chore(m1): provision ClickHouse(620)+Vector(621) LXCs; gitignore infra/ENV.local"
```

---

## Task 4: Apply and verify the ClickHouse schema on the live node

**Files:** (none new — exercises Task 2 artifacts)

- [ ] **Step 1: Copy the DDL to the ClickHouse container and apply it**

```bash
scp infra/clickhouse/001_events.sql root@pve3.example.com:/tmp/001_events.sql
ssh root@pve3.example.com "pct push 620 /tmp/001_events.sql /tmp/001_events.sql"
ssh root@pve3.example.com "pct exec 620 -- bash -lc 'clickhouse-client --multiquery < /tmp/001_events.sql'"
```

- [ ] **Step 2: Verify the table exists with the expected columns**

Run:
```bash
ssh root@pve3.example.com "pct exec 620 -- clickhouse-client --query \"SELECT count() FROM system.columns WHERE database='ssdf' AND table='events'\""
```
Expected: `22`

- [ ] **Step 3: Commit (record verification in the plan checkboxes only — no file change)**

No commit needed; this task validates Task 2. If the column count differs, fix `001_events.sql` and re-run Steps 1–2, then commit the fix:

```bash
git add infra/clickhouse/001_events.sql
git commit -m "fix(m1): correct ClickHouse events schema to 22 columns"
```

---

## Task 5: SRX sd-syslog test fixtures

> These are representative documented RT_FLOW lines used to build and unit-test the VRL. Task 8 validates them against **real** vSRX output and corrects field names if the running Junos version differs (spec flagged the wire format as verify-during-impl).

**Files:**
- Create: `tests/fixtures/srx/session_close.txt`
- Create: `tests/fixtures/srx/session_create.txt`
- Create: `tests/fixtures/srx/session_deny.txt`

- [ ] **Step 1: Write the SESSION_CLOSE fixture**

Create `tests/fixtures/srx/session_close.txt` (single line, no trailing newline issues):

```
<14>1 2026-06-06T12:00:00.000Z srx-test10 RT_FLOW - RT_FLOW_SESSION_CLOSE [junos@2636.1.1.1.2.36 reason="TCP RST" source-address="10.65.1.10" source-port="51514" destination-address="10.66.2.20" destination-port="443" service-name="junos-https" application="HTTPS" protocol-id="6" policy-name="trust-to-untrust" source-zone-name="trust" destination-zone-name="untrust" session-id-32="40000123" packets-from-client="12" bytes-from-client="1500" packets-from-server="10" bytes-from-server="6000" elapsed-time="5" username="alice"]
```

- [ ] **Step 2: Write the SESSION_CREATE fixture**

Create `tests/fixtures/srx/session_create.txt`:

```
<14>1 2026-06-06T12:00:01.000Z srx-test10 RT_FLOW - RT_FLOW_SESSION_CREATE [junos@2636.1.1.1.2.36 source-address="10.65.1.11" source-port="52020" destination-address="10.66.2.21" destination-port="22" service-name="junos-ssh" application="SSH" protocol-id="6" policy-name="trust-to-untrust" source-zone-name="trust" destination-zone-name="untrust" session-id-32="40000124" username="bob"]
```

- [ ] **Step 3: Write the SESSION_DENY fixture**

Create `tests/fixtures/srx/session_deny.txt`:

```
<14>1 2026-06-06T12:00:02.000Z srx-test10 RT_FLOW - RT_FLOW_SESSION_DENY [junos@2636.1.1.1.2.36 source-address="10.73.9.9" source-port="40000" destination-address="10.66.2.22" destination-port="3389" service-name="junos-rdp" application="RDP" protocol-id="6" policy-name="default-deny" source-zone-name="untrust" destination-zone-name="trust" username="N/A"]
```

- [ ] **Step 4: Commit**

```bash
git add tests/fixtures/srx/
git commit -m "test(m1): add SRX sd-syslog RT_FLOW fixtures (close/create/deny)"
```

---

## Task 6: Vector pipeline — VRL normalizer with unit tests (TDD)

> TDD via Vector's built-in test runner. We write the `remap` transform plus `[[tests]]` blocks; `vector test` runs the transform against inline inputs and asserts the ECS output. Build the test first (it fails because the transform is empty), then implement the VRL.

**Files:**
- Create: `infra/vector/vector.toml`

- [ ] **Step 1: Write the config with an empty transform + failing unit tests**

Create `infra/vector/vector.toml`:

```toml
# SSDF M1 — SRX security logs (sd-syslog) -> ECS subset -> ClickHouse.
# CH_HOST is injected via environment at runtime (see infra/ENV.local).

[sources.srx_syslog]
type = "socket"
mode = "udp"
address = "0.0.0.0:514"
max_length = 102400

[transforms.srx_ecs]
type = "remap"
inputs = ["srx_syslog"]
source = '''
. = { "raw": .message }
'''

[sinks.clickhouse]
type = "clickhouse"
inputs = ["srx_ecs"]
endpoint = "http://${CH_HOST}:8123"
database = "ssdf"
table = "events"
skip_unknown_fields = false
date_time_best_effort = true

[sinks.clickhouse.batch]
max_events = 1000
timeout_secs = 5

# ---------------- unit tests ----------------

[[tests]]
name = "session_close_maps_to_ecs"
[[tests.inputs]]
insert_at = "srx_ecs"
type = "raw"
value = '<14>1 2026-06-06T12:00:00.000Z srx-test10 RT_FLOW - RT_FLOW_SESSION_CLOSE [junos@2636.1.1.1.2.36 reason="TCP RST" source-address="10.65.1.10" source-port="51514" destination-address="10.66.2.20" destination-port="443" service-name="junos-https" application="HTTPS" protocol-id="6" policy-name="trust-to-untrust" source-zone-name="trust" destination-zone-name="untrust" session-id-32="40000123" packets-from-client="12" bytes-from-client="1500" packets-from-server="10" bytes-from-server="6000" elapsed-time="5" username="alice"]'
[[tests.outputs]]
extract_from = "srx_ecs"
[[tests.outputs.conditions]]
type = "vrl"
source = '''
assert_eq!(.event_action, "flow_session_close")
assert_eq!(.event_kind, "event")
assert_eq!(.event_category, ["network"])
assert_eq!(.event_provider, "juniper")
assert_eq!(.source_ip, "10.65.1.10")
assert_eq!(.source_port, 51514)
assert_eq!(.destination_ip, "10.66.2.20")
assert_eq!(.destination_port, 443)
assert_eq!(.network_transport, "tcp")
assert_eq!(.source_bytes, 1500)
assert_eq!(.destination_bytes, 6000)
assert_eq!(.network_bytes, 7500)
assert_eq!(.rule_name, "trust-to-untrust")
assert_eq!(.observer_ingress_zone, "trust")
assert_eq!(.observer_egress_zone, "untrust")
assert_eq!(.user_name, "alice")
assert_eq!(.ext."session-id-32", "40000123")
'''

[[tests]]
name = "session_deny_maps_to_ecs"
[[tests.inputs]]
insert_at = "srx_ecs"
type = "raw"
value = '<14>1 2026-06-06T12:00:02.000Z srx-test10 RT_FLOW - RT_FLOW_SESSION_DENY [junos@2636.1.1.1.2.36 source-address="10.73.9.9" source-port="40000" destination-address="10.66.2.22" destination-port="3389" service-name="junos-rdp" application="RDP" protocol-id="6" policy-name="default-deny" source-zone-name="untrust" destination-zone-name="trust" username="N/A"]'
[[tests.outputs]]
extract_from = "srx_ecs"
[[tests.outputs.conditions]]
type = "vrl"
source = '''
assert_eq!(.event_action, "flow_session_deny")
assert_eq!(.event_outcome, "failure")
assert_eq!(.source_ip, "10.73.9.9")
assert_eq!(.destination_port, 3389)
assert_eq!(.rule_name, "default-deny")
'''
```

- [ ] **Step 2: Run the tests to verify they FAIL**

Run (on the workstation if Vector is installed locally, else copy to the 621 container and run there):
```bash
vector test infra/vector/vector.toml
```
Expected: FAIL — assertions error because `srx_ecs` currently only sets `.raw` (e.g. `assert_eq!(.event_action, ...)` fails: field is null).

- [ ] **Step 3: Implement the VRL transform**

Replace the `[transforms.srx_ecs]` `source` field in `infra/vector/vector.toml` with:

```toml
source = '''
raw = .message
parsed, err = parse_syslog(raw)
if err != null {
    . = { "raw": raw, "event_kind": "event", "event_action": "parse_error" }
} else {
    # Flatten all structured-data elements (Junos puts RT_FLOW params under one SD id).
    fields = {}
    sd = object(parsed.structured_data) ?? {}
    for_each(sd) -> |_id, kv| {
        m = object(kv) ?? {}
        fields = merge(fields, m)
    }

    action = downcase(string(parsed.msgid) ?? "")
    event_action = "unknown"
    event_outcome = "unknown"
    if action == "rt_flow_session_create" {
        event_action = "flow_session_create"; event_outcome = "success"
    } else if action == "rt_flow_session_close" {
        event_action = "flow_session_close"; event_outcome = "success"
    } else if action == "rt_flow_session_deny" {
        event_action = "flow_session_deny"; event_outcome = "failure"
    }

    proto_id = to_int(fields."protocol-id") ?? 0
    transport = "unknown"
    if proto_id == 6 { transport = "tcp" }
    else if proto_id == 17 { transport = "udp" }
    else if proto_id == 1 { transport = "icmp" }

    src_bytes = to_int(fields."bytes-from-client") ?? null
    dst_bytes = to_int(fields."bytes-from-server") ?? null
    net_bytes = null
    if src_bytes != null && dst_bytes != null { net_bytes = src_bytes + dst_bytes }

    user = string(fields.username) ?? ""
    if user == "N/A" { user = "" }

    . = {
        "timestamp": parsed.timestamp,
        "event_id": uuid_v4(),
        "tenant_id": "t_main",
        "event_kind": "event",
        "event_category": ["network"],
        "event_action": event_action,
        "event_outcome": event_outcome,
        "event_provider": "juniper",
        "source_ip": fields."source-address",
        "source_port": to_int(fields."source-port") ?? null,
        "source_bytes": src_bytes,
        "destination_ip": fields."destination-address",
        "destination_port": to_int(fields."destination-port") ?? null,
        "destination_bytes": dst_bytes,
        "network_transport": transport,
        "network_bytes": net_bytes,
        "rule_name": string(fields."policy-name") ?? "",
        "observer_ingress_zone": string(fields."source-zone-name") ?? "",
        "observer_egress_zone": string(fields."destination-zone-name") ?? "",
        "user_name": user,
        "ext": map_values(fields) -> |v| { string(v) ?? "" },
        "raw": raw
    }
}
'''
```

- [ ] **Step 4: Run the tests to verify they PASS**

Run: `vector test infra/vector/vector.toml`
Expected: `Running tests` → both `session_close_maps_to_ecs` and `session_deny_maps_to_ecs` report `test passed`.

- [ ] **Step 5: Validate the full config (source+sink) parses**

Run: `CH_HOST=127.0.0.1 vector validate --no-environment infra/vector/vector.toml`
Expected: `Validated`. (`--no-environment` skips the live ClickHouse connection check; we only validate config correctness here.)

- [ ] **Step 6: Commit**

```bash
git add infra/vector/vector.toml
git commit -m "feat(m1): Vector VRL normalizer mapping SRX RT_FLOW to ECS (+unit tests)"
```

---

## Task 7: Deploy the Vector pipeline to the collector LXC

**Files:** (none new — deploys Task 6 artifact)

- [ ] **Step 1: Push the config to the Vector container**

```bash
source infra/ENV.local
scp infra/vector/vector.toml root@pve3.example.com:/tmp/vector.toml
ssh root@pve3.example.com "pct push 621 /tmp/vector.toml /etc/vector/vector.toml"
```

- [ ] **Step 2: Set CH_HOST for the Vector service and start it**

```bash
source infra/ENV.local
ssh root@pve3.example.com "pct exec 621 -- bash -lc 'mkdir -p /etc/systemd/system/vector.service.d && printf \"[Service]\nEnvironment=CH_HOST=${CH_HOST}\n\" > /etc/systemd/system/vector.service.d/env.conf && systemctl daemon-reload && systemctl enable --now vector && systemctl restart vector'"
```

- [ ] **Step 3: Confirm Vector is listening on UDP/514 and healthy**

```bash
ssh root@pve3.example.com "pct exec 621 -- bash -lc 'systemctl is-active vector && ss -ulnp | grep :514'"
```
Expected: `active` and a line showing `*:514` bound by vector.

- [ ] **Step 4: Smoke-test end-to-end with a fixture line**

Install netcat in the container, send the fixture to Vector's UDP listener, then query ClickHouse:
```bash
ssh root@pve3.example.com "pct exec 621 -- bash -lc 'apt-get install -y netcat-openbsd >/dev/null 2>&1 || true'"
FIX=$(cat tests/fixtures/srx/session_close.txt)
ssh root@pve3.example.com "pct exec 621 -- bash -lc \"printf '%s' '$FIX' | nc -u -w1 127.0.0.1 514\""
sleep 7
ssh root@pve3.example.com "pct exec 620 -- clickhouse-client --query \"SELECT event_action, source_ip, destination_port, network_bytes FROM ssdf.events WHERE rule_name='trust-to-untrust' ORDER BY timestamp DESC LIMIT 1\""
```
Expected one row: `flow_session_close   10.65.1.10   443   7500`

- [ ] **Step 5: Commit (no file change; record success here)**

If the row appears, M1 plumbing works with synthetic data. If the sink errored, check `pct exec 621 -- journalctl -u vector -n 50` and fix `vector.toml` (commit any fix with `fix(m1): ...`).

---

## Task 8: Onboard a real vSRX and validate live data

> Uses `rust-junosmcp` (MCP endpoint `http://198.51.100.194:30031/mcp`; devices vSRX-test10/11/16/17/18/19-20). This points a real vSRX's security logs at the Vector collector and proves the pipe on live data. If real field names differ from the fixtures, correct the VRL + fixtures and re-run Task 6 tests.

**Files:**
- Create: `onboarding/srx/stream-config.set`

- [ ] **Step 1: Write the Junos onboarding config**

Create `onboarding/srx/stream-config.set` (replace `<vector-621-ip>` and `<srx-src-ip>` from `infra/ENV.local` / device facts when applying):

```
set security log mode stream
set security log source-address <srx-src-ip>
set security log stream SSDF format sd-syslog
set security log stream SSDF category all
set security log stream SSDF host <vector-621-ip> port 514
```

- [ ] **Step 2: Apply the config to vSRX-test10 via the Junos MCP**

Use the `rust-junosmcp` tools (e.g. `load_and_commit_config`) to apply the five `set` statements above to **vSRX-test10**, substituting the real Vector container IP (`VECTOR_HOST` in `infra/ENV.local`) and the SRX's data-plane source address. Confirm the commit succeeds.

- [ ] **Step 3: Capture a REAL sd-syslog sample for fixture validation**

Generate traffic through the SRX (or wait for ambient flows), then read what Vector received:
```bash
ssh root@pve3.example.com "pct exec 621 -- journalctl -u vector -n 20 --no-pager | grep RT_FLOW | tail -1"
```
Compare the real SD parameter names (e.g. `source-address`, `bytes-from-client`, `policy-name`) against `tests/fixtures/srx/*.txt`. If any differ, update the fixtures **and** the VRL field references in `infra/vector/vector.toml`, then re-run `vector test infra/vector/vector.toml` until green, redeploy (Task 7 Step 1–2), and commit:
```bash
git add tests/fixtures/srx/ infra/vector/vector.toml
git commit -m "fix(m1): align VRL+fixtures to live vSRX sd-syslog field names"
```

- [ ] **Step 4: Verify real events are landing in ClickHouse**

```bash
ssh root@pve3.example.com "pct exec 620 -- clickhouse-client --query \"SELECT count(), min(timestamp), max(timestamp) FROM ssdf.events WHERE event_provider='juniper'\""
```
Expected: a non-zero count with a recent `max(timestamp)`.

- [ ] **Step 5: Commit the onboarding artifact**

```bash
git add onboarding/srx/stream-config.set
git commit -m "feat(m1): add vSRX stream-mode onboarding config (applied via rust-junosmcp)"
```

---

## Task 9: M1 acceptance — the "done" query + docs

**Files:**
- Modify: `CLAUDE.md` (replace the "no commands exist yet" guidance for the M1 pipeline)

- [ ] **Step 1: Run the acceptance query (the M1 "done" criterion)**

"Denied flows from a host in the last hour" — run against live data (substitute a real source host seen in your traffic):
```bash
ssh root@pve3.example.com "pct exec 620 -- clickhouse-client --query \"SELECT timestamp, source_ip, destination_ip, destination_port, rule_name FROM ssdf.events WHERE event_action='flow_session_deny' AND timestamp > now() - INTERVAL 1 HOUR ORDER BY timestamp DESC LIMIT 50\""
```
Expected: zero or more rows, returning without error, with correctly typed columns. M1 is **done** when this (and an allowed-flow variant) returns real SRX data.

- [ ] **Step 2: Record real commands in CLAUDE.md**

In `CLAUDE.md`, under "## Commands", replace the "No build, lint, test, or run commands exist yet" paragraph with:

```markdown
## Commands

### M1 (SRX → Vector → ClickHouse)
- Run Vector unit tests: `vector test infra/vector/vector.toml`
- Validate Vector config: `CH_HOST=127.0.0.1 vector validate --no-environment infra/vector/vector.toml`
- Apply ClickHouse schema: `CH_HOST=<ip> ./scripts/apply_clickhouse_schema.sh`
- Query events: `clickhouse-client --host <ch-host> --query "SELECT ... FROM ssdf.events ..."`
- Infra runs on Proxmox LXC (no Docker): ClickHouse=ct620, Vector=ct621 on pve3.example.com.
- SRX onboarding applied via rust-junosmcp using onboarding/srx/stream-config.set.
```

- [ ] **Step 3: Commit**

```bash
git add CLAUDE.md
git commit -m "docs(m1): record real M1 commands; mark SRX->ClickHouse pipe done"
```

---

## Done criteria (M1)

- `vector test infra/vector/vector.toml` passes (RT_FLOW → ECS mapping verified).
- ClickHouse `ssdf.events` exists (22 columns) on ct620.
- A real vSRX (test10) streams `sd-syslog` security logs to Vector (ct621), normalized to the ECS subset, landing in ClickHouse.
- The acceptance query (denied/allowed flows by host + time window) returns real data via SQL.
- No Rust service, message bus, graph, Python, or Docker introduced — all parked behind seams per the spec.
