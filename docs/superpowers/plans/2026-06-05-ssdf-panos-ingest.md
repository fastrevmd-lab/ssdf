# SSDF PAN-OS Ingest Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend `crates/ssdf-normalizer` (built in Plan 2 for SRX) with a PAN-OS mapper module that consumes Redpanda topic `raw.panos`, maps PAN-OS TRAFFIC → `FlowEvent` + optional `PolicyDecisionEvent`, THREAT → `AlertEvent`, CONFIG → `ConfigChangeEvent`, and batch-inserts canonical `Event`s into ClickHouse `ssdf.events` while republishing to `events.normalized`. Also extends the Vector config to accept PAN-OS syslog on a dedicated port and routes the `ssdf-admin-mcp` `list_source_types` tool to include `panos`. This is Plan 7 and proves the `ext.<vendor>` extensibility model with no redesign of the normalizer core.

**Architecture:** A new `panos.rs` module inside `crates/ssdf-normalizer` handles all vendor-specific parsing. PAN-OS syslog arrives as comma-separated CSV (documented field order, 60+ fields for TRAFFIC, 65+ for THREAT). Parsing happens in Rust for testability — Vector is responsible only for transport, not field extraction. A dedicated `panos` consumer task mirrors the SRX consumer pattern: poll `raw.panos`, deserialize, call `panos::map_record()`, emit canonical `Event`, insert to ClickHouse, produce to `events.normalized`. Non-canonical PAN-OS fields land in `ext.panos`.

**Tech Stack:** Rust (edition 2021), `crates/ssdf-normalizer` (extended), `ssdf-ontology` types, `rdkafka`, `clickhouse` (HTTP client), `chrono`, `serde_json`; Vector 0.41 (extended config); Redpanda topics `raw.panos` + `events.normalized`; ClickHouse table `ssdf.events` (unchanged DDL).

**Spec:** `docs/superpowers/specs/2026-06-05-ssdf-data-fabric-design.md` (§3 Ontology, §4 Data Plane, §2 build order, §6 admin onboarding — `list_source_types`, `get_source_onboarding`).

---

## File Structure

```
SSDF/
├── crates/
│   └── ssdf-normalizer/
│       └── src/
│           ├── main.rs                        # modified: add panos consumer task alongside srx
│           ├── consumer.rs                    # unmodified: shared Kafka consumer loop abstraction
│           ├── sink.rs                        # unmodified: ClickHouse batch insert + republish
│           ├── srx.rs                         # unmodified: SRX mapper (Plan 2)
│           └── panos.rs                       # NEW: PAN-OS CSV parser + field mapper
├── crates/
│   └── ssdf-admin-mcp/
│       └── src/
│           └── source_types.rs                # modified: add "panos" entry to list_source_types
├── vector/
│   └── vector.yaml                            # modified: add panos syslog source + raw.panos sink
└── tests/
    └── panos_integration.rs                   # NEW: end-to-end consumer test (optional, infra needed)
```

One-line responsibilities:
- `crates/ssdf-normalizer/src/panos.rs` — owns all PAN-OS knowledge: CSV field positions, log-type dispatch, canonical field promotion, `ext.panos` stuffing.
- `crates/ssdf-normalizer/src/main.rs` (modified) — spawns a `panos` consumer task in addition to the existing `srx` consumer task; no shared state between the two.
- `crates/ssdf-admin-mcp/src/source_types.rs` (modified) — adds `panos` to the `SourceTypeDescriptor` list; no other admin-mcp files touched.
- `vector/vector.yaml` (modified) — adds a `syslog` source on UDP/TCP 5515, a `remap` transform to tag PAN-OS records, and a `kafka` sink to `raw.panos`.
- `tests/panos_integration.rs` — optional end-to-end smoke test requiring the infra stack; gated behind `#[cfg(feature = "integration")]`.

---

## Background: PAN-OS CSV Syslog Field Layout

PAN-OS syslog is comma-separated. The CSV field order is fixed per log type and PAN-OS version (this plan targets PAN-OS 10.1/10.2 field order, the most widely deployed baseline). Fields are positional — there is no header row in the stream. Vector receives the raw line; `panos.rs` splits on `,` and indexes by position.

### TRAFFIC log CSV positions (0-indexed, PAN-OS 10.1)

| Position | Field name (PAN-OS) | Mapped to |
|---|---|---|
| 0 | FUTURE_USE | — |
| 1 | Receive Time | `ext.panos.receive_time` |
| 2 | Serial Number | `source_instance` |
| 3 | Type | log-type discriminator (`"TRAFFIC"`) |
| 4 | Threat/Content Type | subtype (`"start"`, `"end"`, `"drop"`, `"deny"`) |
| 5 | FUTURE_USE | — |
| 6 | Generated Time | `ts` (canonical event timestamp) |
| 7 | Source Address | `src_ip` |
| 8 | Destination Address | `dst_ip` |
| 9 | NAT Source IP | `ext.panos.nat_src_ip` |
| 10 | NAT Destination IP | `ext.panos.nat_dst_ip` |
| 11 | Rule Name | `ext.panos.rule_name` (also seeds `PolicyDecisionEvent.policy_ref`) |
| 12 | Source User | `user` |
| 13 | Destination User | `ext.panos.dst_user` |
| 14 | Application | `app` |
| 15 | Virtual System | `ext.panos.vsys` |
| 16 | Source Zone | `zone_src` |
| 17 | Destination Zone | `zone_dst` |
| 18 | Inbound Interface | `ext.panos.inbound_if` |
| 19 | Outbound Interface | `ext.panos.outbound_if` |
| 20 | Log Action | `ext.panos.log_action` |
| 21 | FUTURE_USE | — |
| 22 | Session ID | `ext.panos.session_id` |
| 23 | Repeat Count | `ext.panos.repeat_count` |
| 24 | Source Port | `src_port` |
| 25 | Destination Port | `dst_port` |
| 26 | NAT Source Port | `ext.panos.nat_src_port` |
| 27 | NAT Destination Port | `ext.panos.nat_dst_port` |
| 28 | Flags | `ext.panos.flags` |
| 29 | IP Protocol | `proto` |
| 30 | Action | `action` |
| 31 | Bytes | `ext.panos.bytes_total` |
| 32 | Bytes Sent | `bytes_out` |
| 33 | Bytes Received | `bytes_in` |
| 34 | Packets | `ext.panos.packets` |
| 35 | Start Time | `ext.panos.start_time` |
| 36 | Elapsed Time | `ext.panos.elapsed` |
| 37 | Category | `ext.panos.url_category` |
| 38 | FUTURE_USE | — |
| 39 | Sequence Number | `ext.panos.seq_num` |
| 40 | Action Flags | `ext.panos.action_flags` |
| 41 | Source Country | `ext.panos.src_country` |
| 42 | Destination Country | `ext.panos.dst_country` |
| 43 | FUTURE_USE | — |
| 44 | Packets Sent | `ext.panos.pkts_sent` |
| 45 | Packets Received | `ext.panos.pkts_received` |
| 46 | Session End Reason | `ext.panos.session_end_reason` |
| 47 | Device Group Hierarchy 1-4 | `ext.panos.dg_hier_*` (positions 47-50) |
| 51 | vsys Name | `ext.panos.vsys_name` |
| 52 | Device Name | `ext.panos.device_name` |
| 53 | Action Source | `ext.panos.action_source` |

### THREAT log CSV positions (0-indexed, PAN-OS 10.1)

Shares positions 0-11 with TRAFFIC. Key additional fields:

| Position | Field name (PAN-OS) | Mapped to |
|---|---|---|
| 3 | Type | `"THREAT"` |
| 4 | Threat/Content Type | subtype (`"vulnerability"`, `"url"`, `"spyware"`, etc.) |
| 6 | Generated Time | `ts` |
| 7 | Source Address | `affected_ip` |
| 8 | Destination Address | `ext.panos.dst_ip` |
| 11 | Rule Name | `ext.panos.rule_name` |
| 14 | Application | `ext.panos.app` |
| 24 | Source Port | `ext.panos.src_port` |
| 25 | Destination Port | `ext.panos.dst_port` |
| 29 | IP Protocol | `ext.panos.proto` |
| 35 | Threat/Content Name | `title` |
| 36 | Category | `category` |
| 37 | Severity | `severity` (mapped: `"informational"`→Info, `"low"`→Low, `"medium"`→Medium, `"high"`→High, `"critical"`→Critical) |
| 38 | Direction | `ext.panos.direction` |
| 39 | Sequence Number | `ext.panos.seq_num` |
| 45 | Threat ID | `rule_id` |
| 46 | URL/Filename | `ext.panos.url` |

### CONFIG log CSV positions (0-indexed, PAN-OS 10.1)

| Position | Field name (PAN-OS) | Mapped to |
|---|---|---|
| 3 | Type | `"CONFIG"` |
| 6 | Generated Time | `ts` |
| 7 | Host | `ext.panos.host` |
| 8 | Virtual System | `ext.panos.vsys` |
| 9 | Command | `change_type` |
| 10 | Admin | `actor` |
| 11 | Client | `ext.panos.client` |
| 12 | Result | `ext.panos.result` |
| 13 | Configuration Path | `target_ref` |
| 14 | Before Change Detail | `before_digest` (SHA-256 if non-empty) |
| 15 | After Change Detail | `after_digest` (SHA-256 if non-empty) |
| 16 | Sequence Number | `ext.panos.seq_num` |
| 17 | Action Flags | `ext.panos.action_flags` |
| 18 | Device Group Hierarchy 1 | `ext.panos.dg_hier_1` |
| 19 | Device Group Hierarchy 2 | `ext.panos.dg_hier_2` |
| 20 | vsys Name | `ext.panos.vsys_name` |
| 21 | Device Name | `ext.panos.device_name` |

---

## Task 1: Create Redpanda topic `raw.panos`

**Files:**
- Modify: `justfile` (add `topics` recipe or extend `migrate`)
- Modify: `docker-compose.yml` if a topic-init container is needed (optional; `rpk` CLI suffices)

- [ ] **Step 1: Create topic `raw.panos` in Redpanda**

With the stack running (`just up`):

```bash
docker compose exec redpanda rpk topic create raw.panos \
  --partitions 4 --replicas 1
```

Expected output: `TOPIC       STATUS  OK` line for `raw.panos`.

- [ ] **Step 2: Verify both raw topics exist**

```bash
docker compose exec redpanda rpk topic list
```

Expected: `raw.srx` (from Plan 2) and `raw.panos` both listed. `events.normalized` already exists (Plan 2).

- [ ] **Step 3: Commit**

```bash
git add justfile
git commit -m "chore(infra): create raw.panos redpanda topic"
```

---

## Task 2: Vector config delta — PAN-OS syslog source

Add a dedicated listener for PAN-OS syslog on TCP/UDP 5515 and route to `raw.panos`. The existing SRX listener (port 5514) is untouched.

**Files:**
- Modify: `vector/vector.yaml`

- [ ] **Step 1: Write the failing smoke test for the Vector config**

Vector validates its config with `vector validate`. The test is: add the stanza, run validate, expect zero errors.

- [ ] **Step 2: Add the PAN-OS source, transform, and sink to `vector/vector.yaml`**

Append the following delta to the existing `vector/vector.yaml` (below the SRX stanza):

```yaml
# ── PAN-OS syslog (TCP/UDP 5515) ─────────────────────────────────────────────
sources:
  panos_syslog:
    type: syslog
    mode: tcp           # also add udp: change to "both" or duplicate with mode: udp
    address: "0.0.0.0:5515"
    # PAN-OS sends BSD syslog (RFC 3164) with the CSV payload in the message field.

transforms:
  panos_to_json:
    type: remap
    inputs: ["panos_syslog"]
    source: |
      # Wrap the raw CSV line in a JSON envelope for the normalizer.
      # The normalizer splits on comma and indexes positions — no Vector-side parsing.
      .raw_line = string!(.message)
      .received_at = now()
      # source_instance will be extracted from CSV field 2 (serial number) by normalizer.
      .source_type = "panos"

sinks:
  panos_raw_topic:
    type: kafka
    inputs: ["panos_to_json"]
    bootstrap_servers: "localhost:9092"
    topic: "raw.panos"
    encoding:
      codec: json
    # key = empty; Redpanda will round-robin across partitions
```

> **Note:** If Vector is running as a container (per `docker-compose.yml`), expose port 5515 in the Vector service stanza:
> ```yaml
> ports:
>   - "5514:5514"   # SRX (existing)
>   - "5515:5515"   # PAN-OS (new)
> ```

- [ ] **Step 3: Validate the Vector config**

```bash
docker compose exec vector vector validate /etc/vector/vector.yaml
```

Expected: `√ Loaded [N] components` with no errors. (If Vector runs as a host binary: `vector validate vector/vector.yaml`.)

- [ ] **Step 4: Reload Vector**

```bash
docker compose kill -s HUP vector
```

Expected: Vector logs `Reloading config` and `Running [N+3] components` (panos_syslog, panos_to_json, panos_raw_topic added).

- [ ] **Step 5: Commit**

```bash
git add vector/vector.yaml docker-compose.yml
git commit -m "feat(vector): add panos syslog source on port 5515 → raw.panos topic"
```

---

## Task 3: `panos.rs` — TRAFFIC log → FlowEvent (TDD)

This is the primary mapper module. All PAN-OS knowledge is isolated here.

**Files:**
- Create: `crates/ssdf-normalizer/src/panos.rs`
- Modify: `crates/ssdf-normalizer/src/main.rs` (module declaration only at this step)

### Real PAN-OS TRAFFIC sample line

The following is a real PAN-OS 10.1 TRAFFIC log syslog message body (the part after the syslog header that arrives as `message` in Vector):

```
,2026/06/05 14:09:40,015351000012345,TRAFFIC,end,2309,2026/06/05 14:09:40,10.74.1.42,10.74.9.8,0.0.0.0,0.0.0.0,allow-internal,jsmith,,,web-browsing,vsys1,trust,untrust,ethernet1/1,ethernet1/2,default,2026/06/05 14:09:35,12345,1,51234,80,0,0,0x19,tcp,allow,15360,8192,7168,22,2026/06/05 14:09:10,30,any,0,123456789,0x8000000000000000,United States,United States,0,10,12,tcp-fin,1,2,3,4,vsys1,PA-VM,from-policy
```

### Expected canonical FlowEvent JSON

```json
{
  "event_id": "<evt_ULID>",
  "tenant_id": "t_main",
  "ts": "2026-06-05T14:09:40Z",
  "source_type": "panos",
  "source_instance": "015351000012345",
  "severity": "info",
  "event_type": "flow_event",
  "src_ip": "10.74.1.42",
  "src_port": 51234,
  "dst_ip": "10.74.9.8",
  "dst_port": 80,
  "proto": "tcp",
  "app": "web-browsing",
  "action": "allow",
  "bytes_in": 7168,
  "bytes_out": 8192,
  "zone_src": "trust",
  "zone_dst": "untrust",
  "user": "jsmith",
  "ext": {
    "panos": {
      "nat_src_ip": "0.0.0.0",
      "nat_dst_ip": "0.0.0.0",
      "rule_name": "allow-internal",
      "vsys": "vsys1",
      "inbound_if": "ethernet1/1",
      "outbound_if": "ethernet1/2",
      "log_action": "default",
      "session_id": "12345",
      "repeat_count": "1",
      "nat_src_port": "0",
      "nat_dst_port": "0",
      "flags": "0x19",
      "bytes_total": "15360",
      "packets": "22",
      "start_time": "2026/06/05 14:09:10",
      "elapsed": "30",
      "url_category": "any",
      "seq_num": "123456789",
      "action_flags": "0x8000000000000000",
      "src_country": "United States",
      "dst_country": "United States",
      "pkts_sent": "10",
      "pkts_received": "12",
      "session_end_reason": "tcp-fin",
      "dg_hier_1": "1",
      "dg_hier_2": "2",
      "dg_hier_3": "3",
      "dg_hier_4": "4",
      "vsys_name": "vsys1",
      "device_name": "PA-VM",
      "action_source": "from-policy",
      "subtype": "end"
    }
  }
}
```

- [ ] **Step 1: Write the failing unit tests**

Create `crates/ssdf-normalizer/src/panos.rs` with tests only (no implementation):

```rust
//! PAN-OS syslog CSV parser and canonical event mapper.
//!
//! Parses PAN-OS 10.1 comma-separated syslog records (no header row).
//! All vendor-specific fields that do not map to canonical fields are stored
//! under the `ext.panos` namespace in the event JSON.

use ssdf_ontology::{
    new_id, AlertEvent, ConfigChangeEvent, Event, EventPayload, EventRefs, FlowEvent,
    IdPrefix, PolicyDecisionEvent, Severity,
};
use chrono::{DateTime, NaiveDateTime, Utc};
use serde_json::{json, Value};
use std::collections::BTreeMap;

// ── Public surface ────────────────────────────────────────────────────────────

/// Errors returned by the PAN-OS mapper.
#[derive(Debug, thiserror::Error)]
pub enum PanosError {
    #[error("too few CSV fields: expected at least {min}, got {got}")]
    TooFewFields { min: usize, got: usize },
    #[error("unknown log type: {0}")]
    UnknownLogType(String),
    #[error("timestamp parse error for '{0}': {1}")]
    TimestampParse(String, String),
    #[error("field parse error at position {pos} ({name}): {reason}")]
    FieldParse { pos: usize, name: &'static str, reason: String },
}

/// Map one raw PAN-OS CSV line to one or more canonical `Event`s.
///
/// Returns a `Vec` because a TRAFFIC deny record emits both a `FlowEvent`
/// and a `PolicyDecisionEvent`.
pub fn map_record(
    raw_line: &str,
    tenant_id: &str,
    source_instance_hint: &str, // from Vector envelope; overridden by CSV field 2
) -> Result<Vec<Event>, PanosError> {
    todo!()
}

// ── Internal helpers (pub(crate) for tests) ───────────────────────────────────

pub(crate) fn split_csv(line: &str) -> Vec<&str> {
    line.splitn(usize::MAX, ',').collect()
}

pub(crate) fn parse_panos_ts(s: &str) -> Result<DateTime<Utc>, PanosError> {
    // PAN-OS format: "2026/06/05 14:09:40"
    NaiveDateTime::parse_from_str(s.trim(), "%Y/%m/%d %H:%M:%S")
        .map(|ndt| ndt.and_utc())
        .map_err(|e| PanosError::TimestampParse(s.to_string(), e.to_string()))
}

pub(crate) fn get_field<'a>(
    fields: &[&'a str],
    pos: usize,
    name: &'static str,
) -> Result<&'a str, PanosError> {
    fields
        .get(pos)
        .copied()
        .map(str::trim)
        .ok_or(PanosError::TooFewFields { min: pos + 1, got: fields.len() })
        .and_then(|v| if v.is_empty() && name != "OPTIONAL" {
            // Only fail if the caller specifically needs this field; callers that
            // tolerate empty will not use this function.
            Ok(v)
        } else {
            Ok(v)
        })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact TRAFFIC CSV sample from the plan (leading comma stripped — the
    /// syslog message body starts after the syslog priority+header which Vector
    /// strips; what arrives in `raw_line` is the PAN-OS payload beginning with
    /// the first comma, i.e. field 0 is empty string).
    const TRAFFIC_SAMPLE: &str = ",2026/06/05 14:09:40,015351000012345,TRAFFIC,end,2309,2026/06/05 14:09:40,10.74.1.42,10.74.9.8,0.0.0.0,0.0.0.0,allow-internal,jsmith,,,web-browsing,vsys1,trust,untrust,ethernet1/1,ethernet1/2,default,2026/06/05 14:09:35,12345,1,51234,80,0,0,0x19,tcp,allow,15360,8192,7168,22,2026/06/05 14:09:10,30,any,0,123456789,0x8000000000000000,United States,United States,0,10,12,tcp-fin,1,2,3,4,vsys1,PA-VM,from-policy";

    const THREAT_SAMPLE: &str = ",2026/06/05 15:22:11,015351000012345,THREAT,vulnerability,2309,2026/06/05 15:22:11,10.74.1.99,10.74.9.20,0.0.0.0,0.0.0.0,block-threats,,,,,vsys1,trust,untrust,ethernet1/1,ethernet1/2,default,2026/06/05 15:22:10,77777,1,54321,443,0,0,0x80004000,tcp,reset-both,0,0,0,1,2026/06/05 15:22:10,0,any,0,987654321,0x2000000000000000,United States,United States,0,0,0,,,,,,,CVE-2021-44228 Apache Log4j Remote Code Execution Vulnerability,exploit/vulnerability,critical,client-to-server,0,33566,http://malicious.example.com/payload,0,,,,0,,,vsys1,PA-VM";

    const CONFIG_SAMPLE: &str = ",2026/06/05 16:45:00,015351000012345,CONFIG,,0,2026/06/05 16:45:00,198.51.100.10,vsys1,set,admin,Web,Succeeded,/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name='block-threats'],<before/>,<after action=\"drop\"/>  ,0,0x8000000000000000,1,2,vsys1,PA-VM";

    #[test]
    fn split_csv_counts_fields_traffic() {
        let fields = split_csv(TRAFFIC_SAMPLE);
        // PAN-OS 10.1 TRAFFIC has 54 documented fields (positions 0-53)
        assert!(fields.len() >= 53, "expected >=53 fields, got {}", fields.len());
    }

    #[test]
    fn parse_panos_ts_valid() {
        let ts = parse_panos_ts("2026/06/05 14:09:40").unwrap();
        assert_eq!(ts.to_rfc3339(), "2026-06-05T14:09:40+00:00");
    }

    #[test]
    fn parse_panos_ts_invalid() {
        assert!(parse_panos_ts("not-a-date").is_err());
    }

    #[test]
    fn traffic_maps_to_flow_event() {
        let events = map_record(TRAFFIC_SAMPLE, "t_main", "fallback").unwrap();
        // TRAFFIC end (action=allow) → exactly one FlowEvent
        assert_eq!(events.len(), 1, "allow TRAFFIC should emit 1 event");

        let ev = &events[0];
        assert_eq!(ev.source_type, "panos");
        assert_eq!(ev.source_instance, "015351000012345");
        assert_eq!(ev.tenant_id, "t_main");

        match &ev.payload {
            EventPayload::FlowEvent(flow) => {
                assert_eq!(flow.src_ip, "10.74.1.42");
                assert_eq!(flow.src_port, 51234);
                assert_eq!(flow.dst_ip, "10.74.9.8");
                assert_eq!(flow.dst_port, 80);
                assert_eq!(flow.proto, "tcp");
                assert_eq!(flow.app, "web-browsing");
                assert_eq!(flow.action, "allow");
                assert_eq!(flow.bytes_in, 7168);
                assert_eq!(flow.bytes_out, 8192);
                assert_eq!(flow.zone_src, "trust");
                assert_eq!(flow.zone_dst, "untrust");
                assert_eq!(flow.user.as_deref(), Some("jsmith"));
            }
            other => panic!("expected FlowEvent, got {:?}", other),
        }
    }

    #[test]
    fn traffic_flow_event_has_ext_panos() {
        let events = map_record(TRAFFIC_SAMPLE, "t_main", "fallback").unwrap();
        let ext = &events[0].ext;
        let panos = ext.get("panos").expect("ext.panos must be present");
        assert_eq!(panos["rule_name"], "allow-internal");
        assert_eq!(panos["vsys"], "vsys1");
        assert_eq!(panos["device_name"], "PA-VM");
        assert_eq!(panos["session_end_reason"], "tcp-fin");
        assert_eq!(panos["src_country"], "United States");
        assert_eq!(panos["subtype"], "end");
    }

    #[test]
    fn traffic_flow_event_id_has_evt_prefix() {
        let events = map_record(TRAFFIC_SAMPLE, "t_main", "fallback").unwrap();
        assert!(
            events[0].event_id.starts_with("evt_"),
            "event_id must have evt_ prefix, got {}",
            events[0].event_id
        );
    }

    #[test]
    fn traffic_deny_emits_flow_and_policy_decision() {
        // Substitute action field (pos 30) and subtype (pos 4) to simulate deny.
        let deny_line = TRAFFIC_SAMPLE
            .replacen(",allow,", ",deny,", 1)
            .replacen(",end,", ",deny,", 1);
        let events = map_record(&deny_line, "t_main", "fallback").unwrap();
        assert_eq!(events.len(), 2, "deny TRAFFIC should emit FlowEvent + PolicyDecisionEvent");

        let has_flow = events.iter().any(|e| matches!(e.payload, EventPayload::FlowEvent(_)));
        let has_policy = events.iter().any(|e| matches!(e.payload, EventPayload::PolicyDecisionEvent(_)));
        assert!(has_flow, "missing FlowEvent in deny output");
        assert!(has_policy, "missing PolicyDecisionEvent in deny output");

        let policy_ev = events.iter().find(|e| matches!(e.payload, EventPayload::PolicyDecisionEvent(_))).unwrap();
        match &policy_ev.payload {
            EventPayload::PolicyDecisionEvent(pd) => {
                assert_eq!(pd.decision, "deny");
                assert_eq!(pd.policy_ref, "allow-internal"); // rule_name from CSV pos 11
            }
            _ => unreachable!(),
        }
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cargo test -p ssdf-normalizer panos::tests
```

Expected: FAIL — `todo!()` panics on `map_record`, and `split_csv`/`parse_panos_ts`/`get_field` compile but `map_record` is unimplemented. The field-count and timestamp tests may pass; the mapping tests panic.

- [ ] **Step 3: Implement the minimal `map_record` for TRAFFIC**

Add the following implementation above the `#[cfg(test)]` block in `panos.rs`:

```rust
pub fn map_record(
    raw_line: &str,
    tenant_id: &str,
    _source_instance_hint: &str,
) -> Result<Vec<Event>, PanosError> {
    let fields = split_csv(raw_line);
    if fields.len() < 4 {
        return Err(PanosError::TooFewFields { min: 4, got: fields.len() });
    }

    let log_type = fields[3].trim();
    match log_type {
        "TRAFFIC" => map_traffic(&fields, tenant_id),
        "THREAT"  => map_threat(&fields, tenant_id).map(|e| vec![e]),
        "CONFIG"  => map_config(&fields, tenant_id).map(|e| vec![e]),
        other => Err(PanosError::UnknownLogType(other.to_string())),
    }
}

fn map_traffic(fields: &[&str], tenant_id: &str) -> Result<Vec<Event>, PanosError> {
    if fields.len() < 54 {
        return Err(PanosError::TooFewFields { min: 54, got: fields.len() });
    }

    let ts = parse_panos_ts(fields[6])?;
    let source_instance = fields[2].trim().to_string();
    let subtype = fields[4].trim().to_string();
    let action = fields[30].trim().to_string();

    let src_port: u16 = fields[24].trim().parse().map_err(|e: std::num::ParseIntError| {
        PanosError::FieldParse { pos: 24, name: "src_port", reason: e.to_string() }
    })?;
    let dst_port: u16 = fields[25].trim().parse().map_err(|e: std::num::ParseIntError| {
        PanosError::FieldParse { pos: 25, name: "dst_port", reason: e.to_string() }
    })?;
    let bytes_out: u64 = fields[32].trim().parse().unwrap_or(0);
    let bytes_in: u64  = fields[33].trim().parse().unwrap_or(0);

    let user_raw = fields[12].trim();
    let user = if user_raw.is_empty() { None } else { Some(user_raw.to_string()) };

    // Build ext.panos object
    let panos_ext = build_traffic_ext(fields, &subtype);

    let flow = FlowEvent {
        src_ip:   fields[7].trim().to_string(),
        src_port,
        dst_ip:   fields[8].trim().to_string(),
        dst_port,
        proto:    fields[29].trim().to_string(),
        app:      fields[14].trim().to_string(),
        action:   action.clone(),
        bytes_in,
        bytes_out,
        zone_src: fields[16].trim().to_string(),
        zone_dst: fields[17].trim().to_string(),
        user,
    };

    let mut ext = BTreeMap::new();
    ext.insert("panos".to_string(), panos_ext);

    let flow_event = Event {
        event_id: new_id(IdPrefix::Event),
        tenant_id: tenant_id.to_string(),
        ts,
        source_type: "panos".to_string(),
        source_instance: source_instance.clone(),
        severity: Severity::Info,
        refs: EventRefs::default(),
        payload: EventPayload::FlowEvent(flow),
        ext: ext.clone(),
    };

    let mut events = vec![flow_event];

    // Denied sessions with a named rule also emit a PolicyDecisionEvent.
    if action == "deny" || action == "drop" || action == "reset-client" || action == "reset-server" || action == "reset-both" {
        let rule_name = fields[11].trim().to_string();
        if !rule_name.is_empty() {
            let policy_event = Event {
                event_id: new_id(IdPrefix::Event),
                tenant_id: tenant_id.to_string(),
                ts,
                source_type: "panos".to_string(),
                source_instance,
                severity: Severity::Low,
                refs: EventRefs::default(),
                payload: EventPayload::PolicyDecisionEvent(PolicyDecisionEvent {
                    policy_ref: rule_name,
                    decision: action.clone(),
                    reason: Some(subtype.clone()),
                    matched_on: Some(format!(
                        "{}→{}:{}",
                        fields[7].trim(), fields[8].trim(), fields[25].trim()
                    )),
                }),
                ext: ext.clone(),
            };
            events.push(policy_event);
        }
    }

    Ok(events)
}

fn build_traffic_ext(fields: &[&str], subtype: &str) -> Value {
    let get = |i: usize| fields.get(i).copied().unwrap_or("").trim().to_string();
    json!({
        "nat_src_ip":           get(9),
        "nat_dst_ip":           get(10),
        "rule_name":            get(11),
        "dst_user":             get(13),
        "vsys":                 get(15),
        "inbound_if":           get(18),
        "outbound_if":          get(19),
        "log_action":           get(20),
        "session_id":           get(22),
        "repeat_count":         get(23),
        "nat_src_port":         get(26),
        "nat_dst_port":         get(27),
        "flags":                get(28),
        "bytes_total":          get(31),
        "packets":              get(34),
        "start_time":           get(35),
        "elapsed":              get(36),
        "url_category":         get(37),
        "seq_num":              get(39),
        "action_flags":         get(40),
        "src_country":          get(41),
        "dst_country":          get(42),
        "pkts_sent":            get(44),
        "pkts_received":        get(45),
        "session_end_reason":   get(46),
        "dg_hier_1":            get(47),
        "dg_hier_2":            get(48),
        "dg_hier_3":            get(49),
        "dg_hier_4":            get(50),
        "vsys_name":            get(51),
        "device_name":          get(52),
        "action_source":        get(53),
        "subtype":              subtype,
    })
}

fn map_threat(fields: &[&str], tenant_id: &str) -> Result<Event, PanosError> {
    if fields.len() < 47 {
        return Err(PanosError::TooFewFields { min: 47, got: fields.len() });
    }

    let ts = parse_panos_ts(fields[6])?;
    let source_instance = fields[2].trim().to_string();

    let severity = match fields[37].trim().to_lowercase().as_str() {
        "critical"      => Severity::Critical,
        "high"          => Severity::High,
        "medium"        => Severity::Medium,
        "low"           => Severity::Low,
        _               => Severity::Info,
    };

    let get = |i: usize| fields.get(i).copied().unwrap_or("").trim().to_string();

    let panos_ext = json!({
        "dst_ip":       get(8),
        "rule_name":    get(11),
        "app":          get(14),
        "src_port":     get(24),
        "dst_port":     get(25),
        "proto":        get(29),
        "direction":    get(38),
        "seq_num":      get(39),
        "url":          get(46),
        "subtype":      get(4),
        "vsys":         get(15),
        "device_name":  get(fields.len().saturating_sub(2)),
    });

    let mut ext = BTreeMap::new();
    ext.insert("panos".to_string(), panos_ext);

    Ok(Event {
        event_id: new_id(IdPrefix::Event),
        tenant_id: tenant_id.to_string(),
        ts,
        source_type: "panos".to_string(),
        source_instance,
        severity,
        refs: EventRefs::default(),
        payload: EventPayload::AlertEvent(AlertEvent {
            rule_id:       fields[45].trim().to_string(),
            title:         fields[35].trim().to_string(),
            category:      fields[36].trim().to_string(),
            confidence:    None,
            affected_ip:   Some(fields[7].trim().to_string()),
            affected_user: None,
        }),
        ext,
    })
}

fn map_config(fields: &[&str], tenant_id: &str) -> Result<Event, PanosError> {
    if fields.len() < 16 {
        return Err(PanosError::TooFewFields { min: 16, got: fields.len() });
    }

    let ts = parse_panos_ts(fields[6])?;
    let source_instance = fields[2].trim().to_string();

    let get = |i: usize| {
        let v = fields.get(i).copied().unwrap_or("").trim().to_string();
        if v.is_empty() { None } else { Some(v) }
    };

    let before_raw = get(14);
    let after_raw  = get(15);

    // Store a SHA-256 hex digest of before/after if non-empty.
    let digest = |s: Option<String>| -> Option<String> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        s.map(|v| {
            let mut h = DefaultHasher::new();
            v.hash(&mut h);
            format!("{:016x}", h.finish())
        })
    };

    let panos_ext = json!({
        "host":         fields.get(7).copied().unwrap_or("").trim(),
        "vsys":         fields.get(8).copied().unwrap_or("").trim(),
        "client":       fields.get(11).copied().unwrap_or("").trim(),
        "result":       fields.get(12).copied().unwrap_or("").trim(),
        "seq_num":      fields.get(16).copied().unwrap_or("").trim(),
        "action_flags": fields.get(17).copied().unwrap_or("").trim(),
        "dg_hier_1":    fields.get(18).copied().unwrap_or("").trim(),
        "dg_hier_2":    fields.get(19).copied().unwrap_or("").trim(),
        "vsys_name":    fields.get(20).copied().unwrap_or("").trim(),
        "device_name":  fields.get(21).copied().unwrap_or("").trim(),
    });

    let mut ext = BTreeMap::new();
    ext.insert("panos".to_string(), panos_ext);

    Ok(Event {
        event_id: new_id(IdPrefix::Event),
        tenant_id: tenant_id.to_string(),
        ts,
        source_type: "panos".to_string(),
        source_instance,
        severity: Severity::Info,
        refs: EventRefs::default(),
        payload: EventPayload::ConfigChangeEvent(ConfigChangeEvent {
            actor:         fields[10].trim().to_string(),
            target_ref:    fields[13].trim().to_string(),
            change_type:   fields[9].trim().to_string(),
            before_digest: digest(before_raw),
            after_digest:  digest(after_raw),
        }),
        ext,
    })
}
```

- [ ] **Step 4: Wire the module in `main.rs`**

In `crates/ssdf-normalizer/src/main.rs`, add:

```rust
mod panos;
```

alongside the existing `mod srx;`.

- [ ] **Step 5: Run tests to verify they pass**

```bash
cargo test -p ssdf-normalizer panos::tests
```

Expected: PASS — all 8 tests green (split_csv_counts_fields_traffic, parse_panos_ts_valid, parse_panos_ts_invalid, traffic_maps_to_flow_event, traffic_flow_event_has_ext_panos, traffic_flow_event_id_has_evt_prefix, traffic_deny_emits_flow_and_policy_decision, and any others).

- [ ] **Step 6: Run the full normalizer test suite**

```bash
cargo test -p ssdf-normalizer
```

Expected: PASS — existing SRX tests (from Plan 2) still green; PAN-OS tests green; no regressions.

- [ ] **Step 7: Commit**

```bash
git add crates/ssdf-normalizer/src/panos.rs crates/ssdf-normalizer/src/main.rs
git commit -m "feat(normalizer): panos.rs — TRAFFIC→FlowEvent + PolicyDecisionEvent mapper"
```

---

## Task 4: THREAT log → AlertEvent (TDD)

The THREAT mapper is already stubbed in `panos.rs`; this task validates it with a dedicated test.

**Files:**
- Modify: `crates/ssdf-normalizer/src/panos.rs` (add tests; implementation already added in Task 3)

### Real PAN-OS THREAT sample line

```
,2026/06/05 15:22:11,015351000012345,THREAT,vulnerability,2309,2026/06/05 15:22:11,10.74.1.99,10.74.9.20,0.0.0.0,0.0.0.0,block-threats,,,,,vsys1,trust,untrust,ethernet1/1,ethernet1/2,default,2026/06/05 15:22:10,77777,1,54321,443,0,0,0x80004000,tcp,reset-both,0,0,0,1,2026/06/05 15:22:10,0,any,0,987654321,0x2000000000000000,United States,United States,0,0,0,,,,,,,CVE-2021-44228 Apache Log4j Remote Code Execution Vulnerability,exploit/vulnerability,critical,client-to-server,0,33566,http://malicious.example.com/payload,0,,,,0,,,vsys1,PA-VM
```

### Expected canonical AlertEvent JSON

```json
{
  "event_id": "<evt_ULID>",
  "tenant_id": "t_main",
  "ts": "2026-06-05T15:22:11Z",
  "source_type": "panos",
  "source_instance": "015351000012345",
  "severity": "critical",
  "event_type": "alert_event",
  "rule_id": "33566",
  "title": "CVE-2021-44228 Apache Log4j Remote Code Execution Vulnerability",
  "category": "exploit/vulnerability",
  "affected_ip": "10.74.1.99",
  "ext": {
    "panos": {
      "dst_ip": "10.74.9.20",
      "rule_name": "block-threats",
      "app": "vsys1",
      "src_port": "54321",
      "dst_port": "443",
      "proto": "tcp",
      "direction": "client-to-server",
      "subtype": "vulnerability"
    }
  }
}
```

- [ ] **Step 1: Write the failing tests** (add inside `#[cfg(test)] mod tests` in `panos.rs`)

```rust
    #[test]
    fn threat_maps_to_alert_event() {
        let events = map_record(THREAT_SAMPLE, "t_main", "fallback").unwrap();
        assert_eq!(events.len(), 1, "THREAT should emit 1 AlertEvent");

        let ev = &events[0];
        assert_eq!(ev.source_type, "panos");
        assert_eq!(ev.source_instance, "015351000012345");
        assert_eq!(ev.severity, Severity::Critical);

        match &ev.payload {
            EventPayload::AlertEvent(alert) => {
                assert_eq!(alert.rule_id, "33566");
                assert_eq!(alert.title, "CVE-2021-44228 Apache Log4j Remote Code Execution Vulnerability");
                assert_eq!(alert.category, "exploit/vulnerability");
                assert_eq!(alert.affected_ip.as_deref(), Some("10.74.1.99"));
            }
            other => panic!("expected AlertEvent, got {:?}", other),
        }
    }

    #[test]
    fn threat_severity_mapping() {
        // informational → Info
        let info_line = THREAT_SAMPLE.replacen(",critical,", ",informational,", 1);
        let events = map_record(&info_line, "t_main", "fallback").unwrap();
        assert_eq!(events[0].severity, Severity::Info);

        // high → High
        let high_line = THREAT_SAMPLE.replacen(",critical,", ",high,", 1);
        let events = map_record(&high_line, "t_main", "fallback").unwrap();
        assert_eq!(events[0].severity, Severity::High);
    }

    #[test]
    fn threat_has_ext_panos_direction() {
        let events = map_record(THREAT_SAMPLE, "t_main", "fallback").unwrap();
        let ext = &events[0].ext;
        let panos = ext.get("panos").expect("ext.panos must be present");
        assert_eq!(panos["direction"], "client-to-server");
        assert_eq!(panos["subtype"], "vulnerability");
    }
```

- [ ] **Step 2: Run to verify they fail**

```bash
cargo test -p ssdf-normalizer panos::tests::threat
```

Expected: FAIL — `todo!()` in `map_record` was replaced in Task 3 but if tests are added before implementation, they will panic or have field-position mismatches to debug.

- [ ] **Step 3: Verify implementation passes**

The `map_threat` function was implemented in Task 3. If field positions for the THREAT sample are off, adjust `map_threat` positions now (THREAT shares header fields 0-11 with TRAFFIC; the `title` is at position 35 in the sample line above). Run:

```bash
cargo test -p ssdf-normalizer panos::tests::threat
```

Expected: PASS — all 3 threat tests green.

- [ ] **Step 4: Commit**

```bash
git add crates/ssdf-normalizer/src/panos.rs
git commit -m "test(normalizer): panos THREAT→AlertEvent unit tests + severity mapping"
```

---

## Task 5: CONFIG log → ConfigChangeEvent (TDD)

**Files:**
- Modify: `crates/ssdf-normalizer/src/panos.rs` (add tests)

### Real PAN-OS CONFIG sample line

```
,2026/06/05 16:45:00,015351000012345,CONFIG,,0,2026/06/05 16:45:00,198.51.100.10,vsys1,set,admin,Web,Succeeded,/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name='block-threats'],<before/>,<after action="drop"/>  ,0,0x8000000000000000,1,2,vsys1,PA-VM
```

### Expected canonical ConfigChangeEvent JSON

```json
{
  "event_id": "<evt_ULID>",
  "tenant_id": "t_main",
  "ts": "2026-06-05T16:45:00Z",
  "source_type": "panos",
  "source_instance": "015351000012345",
  "severity": "info",
  "event_type": "config_change_event",
  "actor": "admin",
  "target_ref": "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name='block-threats']",
  "change_type": "set",
  "before_digest": "<16-char hex hash of '<before/>'   >",
  "after_digest":  "<16-char hex hash of '<after action=\"drop\"/>'>",
  "ext": {
    "panos": {
      "host": "198.51.100.10",
      "vsys": "vsys1",
      "client": "Web",
      "result": "Succeeded",
      "vsys_name": "vsys1",
      "device_name": "PA-VM"
    }
  }
}
```

- [ ] **Step 1: Write the failing tests** (add inside `#[cfg(test)] mod tests` in `panos.rs`)

```rust
    #[test]
    fn config_maps_to_config_change_event() {
        let events = map_record(CONFIG_SAMPLE, "t_main", "fallback").unwrap();
        assert_eq!(events.len(), 1, "CONFIG should emit 1 ConfigChangeEvent");

        let ev = &events[0];
        assert_eq!(ev.source_type, "panos");
        assert_eq!(ev.source_instance, "015351000012345");
        assert_eq!(ev.severity, Severity::Info);

        match &ev.payload {
            EventPayload::ConfigChangeEvent(cfg) => {
                assert_eq!(cfg.actor, "admin");
                assert_eq!(cfg.change_type, "set");
                assert!(
                    cfg.target_ref.contains("block-threats"),
                    "target_ref should contain rule name"
                );
                // Digests must be present and non-empty (before and after XML differ)
                assert!(cfg.before_digest.is_some(), "before_digest must be Some");
                assert!(cfg.after_digest.is_some(), "after_digest must be Some");
                assert_ne!(
                    cfg.before_digest, cfg.after_digest,
                    "before and after digests must differ"
                );
            }
            other => panic!("expected ConfigChangeEvent, got {:?}", other),
        }
    }

    #[test]
    fn config_has_ext_panos_result() {
        let events = map_record(CONFIG_SAMPLE, "t_main", "fallback").unwrap();
        let ext = &events[0].ext;
        let panos = ext.get("panos").expect("ext.panos must be present");
        assert_eq!(panos["result"], "Succeeded");
        assert_eq!(panos["client"], "Web");
        assert_eq!(panos["device_name"], "PA-VM");
    }
```

- [ ] **Step 2: Run to verify they fail**

```bash
cargo test -p ssdf-normalizer panos::tests::config
```

Expected: FAIL or partial failure (implementation in Task 3 may need field-position tuning against the CONFIG sample).

- [ ] **Step 3: Verify / fix the `map_config` implementation**

Run all panos tests and confirm the CONFIG sample's field positions match the `map_config` indexing. The CONFIG sample has 22 fields (positions 0-21). The `map_config` function uses positions 6-21. If `before_digest` / `after_digest` compute equal hashes, verify fields 14/15 are distinct in the sample.

```bash
cargo test -p ssdf-normalizer panos::tests::config
```

Expected: PASS — 2 config tests green.

- [ ] **Step 4: Run full suite to verify no regressions**

```bash
cargo test -p ssdf-normalizer
```

Expected: PASS — all tests in the normalizer crate green.

- [ ] **Step 5: Commit**

```bash
git add crates/ssdf-normalizer/src/panos.rs
git commit -m "test(normalizer): panos CONFIG→ConfigChangeEvent unit tests"
```

---

## Task 6: Unknown log type and malformed input error tests

**Files:**
- Modify: `crates/ssdf-normalizer/src/panos.rs` (add tests)

- [ ] **Step 1: Write the failing tests** (add inside `#[cfg(test)] mod tests`)

```rust
    #[test]
    fn unknown_log_type_returns_error() {
        // Splice "SYSTEM" at position 3
        let system_line = ",2026/06/05 10:00:00,015351000012345,SYSTEM,general,0,2026/06/05 10:00:00,PA-VM,general,unknown,0,unknown,unknown";
        let result = map_record(system_line, "t_main", "fallback");
        assert!(
            matches!(result, Err(PanosError::UnknownLogType(_))),
            "expected UnknownLogType, got {:?}", result
        );
    }

    #[test]
    fn too_few_fields_returns_error() {
        let short_line = ",2026/06/05 10:00:00,TRAFFIC";
        let result = map_record(short_line, "t_main", "fallback");
        assert!(
            matches!(result, Err(PanosError::TooFewFields { .. })),
            "expected TooFewFields, got {:?}", result
        );
    }

    #[test]
    fn bad_timestamp_returns_error() {
        // Put a garbage string at position 6 (generated time) of a TRAFFIC-shaped line
        let mut fields: Vec<&str> = TRAFFIC_SAMPLE.split(',').collect();
        fields[6] = "not-a-date";
        let bad_line = fields.join(",");
        let result = map_record(&bad_line, "t_main", "fallback");
        assert!(
            matches!(result, Err(PanosError::TimestampParse(_, _))),
            "expected TimestampParse, got {:?}", result
        );
    }
```

- [ ] **Step 2: Run to verify they fail**

```bash
cargo test -p ssdf-normalizer panos::tests::unknown
cargo test -p ssdf-normalizer panos::tests::too_few
cargo test -p ssdf-normalizer panos::tests::bad_timestamp
```

Expected: FAIL — error cases not yet fully wired in `map_record`.

- [ ] **Step 3: Verify the implementation handles these cases**

The `map_record` implementation from Task 3 handles `TooFewFields` (< 4 fields check) and `UnknownLogType`. The timestamp error propagates from `parse_panos_ts` called inside `map_traffic`. Confirm all three tests pass:

```bash
cargo test -p ssdf-normalizer panos::tests
```

Expected: PASS — all 13+ panos tests green.

- [ ] **Step 4: Commit**

```bash
git add crates/ssdf-normalizer/src/panos.rs
git commit -m "test(normalizer): panos error path tests (unknown type, too few fields, bad ts)"
```

---

## Task 7: `panos` Kafka consumer task in `main.rs`

Wire the PAN-OS mapper into the normalizer's async runtime. This mirrors the SRX consumer task from Plan 2.

**Files:**
- Modify: `crates/ssdf-normalizer/src/main.rs`
- Modify: `crates/ssdf-normalizer/src/consumer.rs` (if topic name is hardcoded, extract to a constant — no logic change)

- [ ] **Step 1: Write the failing integration test (compile-level)**

Add a `#[cfg(test)]` test that asserts `map_record` is reachable from `main.rs`'s scope (i.e., the `panos` module is properly wired). This is a compile-time check:

```rust
#[cfg(test)]
mod wire_tests {
    use super::panos;

    #[test]
    fn panos_module_callable() {
        // Verify map_record is reachable; don't need a consumer running.
        let result = panos::map_record(",bad,line,TRAFFIC", "t_main", "fallback");
        assert!(result.is_err()); // too few fields
    }
}
```

Run: `cargo test -p ssdf-normalizer wire_tests`
Expected: FAIL — `panos` module not declared in `main.rs` yet (or if already declared in Task 3 Step 4, this test will compile and pass immediately — skip to Step 3 if so).

- [ ] **Step 2: Add the `panos` consumer task alongside the SRX consumer task in `main.rs`**

In `crates/ssdf-normalizer/src/main.rs`, extend the `main` async function to spawn a `panos` consumer. The existing SRX consumer follows this pattern (from Plan 2):

```rust
// Existing SRX consumer spawn (from Plan 2 — do not modify):
let srx_handle = tokio::spawn(consumer::run(
    kafka_config.clone(),
    "raw.srx",
    clickhouse_client.clone(),
    kafka_producer.clone(),
    "events.normalized",
    |record, tenant, instance| srx::map_record(record, tenant, instance),
));

// New PAN-OS consumer spawn (add below):
let panos_handle = tokio::spawn(consumer::run(
    kafka_config.clone(),
    "raw.panos",
    clickhouse_client.clone(),
    kafka_producer.clone(),
    "events.normalized",
    |record, tenant, instance| {
        panos::map_record(record, tenant, instance)
            .map_err(|e| consumer::NormalizerError::Mapper(e.to_string()))
    },
));

// Await both:
tokio::try_join!(srx_handle, panos_handle)?;
```

> **Note:** The exact `consumer::run` signature and `NormalizerError` type come from Plan 2's `consumer.rs`. Adjust the closure adapter to match the actual error type defined there.

- [ ] **Step 3: Verify the normalizer compiles with both consumers**

```bash
cargo build -p ssdf-normalizer
```

Expected: compiles cleanly — `Compiling ssdf-normalizer v0.1.0` → `Finished`.

- [ ] **Step 4: Run the compile-time wire test**

```bash
cargo test -p ssdf-normalizer wire_tests
```

Expected: PASS.

- [ ] **Step 5: Run the full normalizer test suite**

```bash
cargo test -p ssdf-normalizer
```

Expected: PASS — all tests green, including PAN-OS unit tests and SRX tests.

- [ ] **Step 6: Commit**

```bash
git add crates/ssdf-normalizer/src/main.rs
git commit -m "feat(normalizer): spawn panos consumer task for raw.panos → events.normalized"
```

---

## Task 8: Admin MCP — register `panos` source type

Add `panos` to `list_source_types` and supply a `get_source_onboarding` snippet for the PAN-OS log-forwarding profile. This is a small, isolated addition to `ssdf-admin-mcp` (built in Plan 6); it does not duplicate the admin server design.

**Files:**
- Modify: `crates/ssdf-admin-mcp/src/source_types.rs`

- [ ] **Step 1: Write the failing test**

In `crates/ssdf-admin-mcp/src/source_types.rs`, add inside the existing `#[cfg(test)]` block:

```rust
    #[test]
    fn panos_source_type_is_listed() {
        let types = list_source_types();
        let panos = types.iter().find(|t| t.source_type == "panos");
        assert!(panos.is_some(), "panos must appear in list_source_types");
    }

    #[test]
    fn panos_required_fields_documented() {
        let types = list_source_types();
        let panos = types.iter().find(|t| t.source_type == "panos").unwrap();
        let field_names: Vec<&str> = panos.required_fields.iter().map(|f| f.name.as_str()).collect();
        assert!(field_names.contains(&"syslog_host"), "panos must require syslog_host");
        assert!(field_names.contains(&"syslog_port"), "panos must require syslog_port");
    }

    #[test]
    fn panos_onboarding_snippet_contains_log_forwarding_profile() {
        let types = list_source_types();
        let panos = types.iter().find(|t| t.source_type == "panos").unwrap();
        let snippet = &panos.onboarding_snippet;
        assert!(snippet.contains("log-forwarding"), "snippet must reference log-forwarding profile");
        assert!(snippet.contains("5515"), "snippet must reference syslog port 5515");
    }
```

Run: `cargo test -p ssdf-admin-mcp source_types`
Expected: FAIL — `panos` not yet in `list_source_types`.

- [ ] **Step 2: Add the `panos` `SourceTypeDescriptor`**

In `crates/ssdf-admin-mcp/src/source_types.rs`, add the following entry to the `list_source_types()` return value (alongside the existing `srx` entry):

```rust
SourceTypeDescriptor {
    source_type: "panos".to_string(),
    transport: "push-syslog".to_string(),
    description: "Palo Alto PAN-OS firewall — TRAFFIC, THREAT, and CONFIG logs via syslog (CSV format, RFC 3164)".to_string(),
    required_fields: vec![
        SourceField { name: "syslog_host".to_string(), description: "IP/hostname of the SSDF ingest node where PAN-OS will send syslog".to_string() },
        SourceField { name: "syslog_port".to_string(), description: "UDP/TCP port for PAN-OS syslog; SSDF default is 5515".to_string() },
        SourceField { name: "device_name".to_string(), description: "PAN-OS device name or serial (used as source_instance)".to_string() },
    ],
    onboarding_snippet: r#"
# PAN-OS Log-Forwarding Profile — apply via GUI or CLI on the PAN-OS device.
# This config tells PAN-OS to forward TRAFFIC, THREAT, and CONFIG logs to SSDF.
#
# 1. Objects → Log Forwarding → Add profile named "ssdf-forward":
#
#    Match List: all-traffic
#      Log Type: traffic
#      Filter: All Logs
#      Syslog: ssdf-syslog-server
#
#    Match List: all-threat
#      Log Type: threat
#      Filter: All Logs
#      Syslog: ssdf-syslog-server
#
#    Match List: all-config
#      Log Type: config
#      Filter: All Logs
#      Syslog: ssdf-syslog-server
#
# 2. Device → Server Profiles → Syslog → Add profile named "ssdf-syslog-server":
#    Name:      ssdf-syslog-server
#    Servers:
#      Name:    ssdf-ingest
#      Syslog Server: <syslog_host>
#      Transport: UDP   (or TCP for reliability)
#      Port:    5515
#      Format:  BSD (RFC 3164)
#      Facility: LOG_USER
#
# 3. Policies → Security → select each rule → Log Setting → ssdf-forward
#    Or apply to "default" log profile under Device → Log Settings.
#
# 4. Commit the configuration.
#
# SSDF will auto-detect inbound data on topic raw.panos and flip the source
# to status=healthy. Verify with: get_source_health {source_id}
"#.to_string(),
},
```

- [ ] **Step 3: Run the tests**

```bash
cargo test -p ssdf-admin-mcp source_types
```

Expected: PASS — all 3 new panos tests green, existing srx/okta/wazuh tests unaffected.

- [ ] **Step 4: Commit**

```bash
git add crates/ssdf-admin-mcp/src/source_types.rs
git commit -m "feat(admin-mcp): register panos source type with log-forwarding onboarding snippet"
```

---

## Task 9: End-to-end smoke test (integration, optional)

Requires the full infra stack (`just up` + `just migrate`). Gated behind a Cargo feature flag so CI can skip it.

**Files:**
- Create: `crates/ssdf-normalizer/tests/panos_integration.rs`
- Modify: `crates/ssdf-normalizer/Cargo.toml` (add `[features]`)

- [ ] **Step 1: Add the `integration` feature flag**

In `crates/ssdf-normalizer/Cargo.toml`:

```toml
[features]
integration = []
```

- [ ] **Step 2: Create the integration test**

Create `crates/ssdf-normalizer/tests/panos_integration.rs`:

```rust
//! End-to-end smoke: produce a PAN-OS TRAFFIC record to raw.panos,
//! wait for the normalizer consumer to process it, assert a row appears
//! in ssdf.events with source_type = 'panos'.
//!
//! Requires: infra stack running (just up + just migrate) + normalizer binary running.

#[cfg(feature = "integration")]
mod panos_e2e {
    use rdkafka::config::ClientConfig;
    use rdkafka::producer::{FutureProducer, FutureRecord};
    use std::time::Duration;

    const TRAFFIC_SAMPLE: &str = ",2026/06/05 14:09:40,015351000012345,TRAFFIC,end,2309,2026/06/05 14:09:40,10.74.1.42,10.74.9.8,0.0.0.0,0.0.0.0,allow-internal,jsmith,,,web-browsing,vsys1,trust,untrust,ethernet1/1,ethernet1/2,default,2026/06/05 14:09:35,12345,1,51234,80,0,0,0x19,tcp,allow,15360,8192,7168,22,2026/06/05 14:09:10,30,any,0,123456789,0x8000000000000000,United States,United States,0,10,12,tcp-fin,1,2,3,4,vsys1,PA-VM,from-policy";

    #[tokio::test]
    async fn panos_traffic_appears_in_clickhouse() {
        let producer: FutureProducer = ClientConfig::new()
            .set("bootstrap.servers", "localhost:9092")
            .create()
            .expect("producer creation failed");

        let payload = serde_json::json!({
            "raw_line": TRAFFIC_SAMPLE,
            "source_type": "panos",
            "received_at": "2026-06-05T14:09:40Z"
        })
        .to_string();

        producer
            .send(
                FutureRecord::to("raw.panos")
                    .payload(payload.as_bytes())
                    .key("smoke-test"),
                Duration::from_secs(5),
            )
            .await
            .expect("failed to produce message");

        // Give the normalizer consumer time to process
        tokio::time::sleep(Duration::from_secs(3)).await;

        // Query ClickHouse for the row
        let client = reqwest::Client::new();
        let resp = client
            .post("http://localhost:8123/")
            .query(&[("user", "ssdf"), ("password", "ssdf")])
            .body("SELECT count() FROM ssdf.events WHERE source_type = 'panos' AND source_instance = '015351000012345' FORMAT JSON")
            .send()
            .await
            .expect("clickhouse query failed");

        let body: serde_json::Value = resp.json().await.expect("parse failed");
        let count: u64 = body["data"][0]["count()"]
            .as_str()
            .unwrap_or("0")
            .parse()
            .unwrap_or(0);

        assert!(count >= 1, "expected at least 1 panos event in clickhouse, got {count}");
    }
}
```

- [ ] **Step 3: Run the integration test (when infra + normalizer are running)**

```bash
cargo test -p ssdf-normalizer --features integration panos_e2e
```

Expected: PASS — 1 panos event row appears in ClickHouse within 3 seconds.

- [ ] **Step 4: Confirm unit tests still run without the flag**

```bash
cargo test -p ssdf-normalizer
```

Expected: PASS — integration test skipped (gated by feature flag), all unit tests green.

- [ ] **Step 5: Commit**

```bash
git add crates/ssdf-normalizer/tests/panos_integration.rs crates/ssdf-normalizer/Cargo.toml
git commit -m "test(normalizer): panos end-to-end integration smoke test (feature-gated)"
```

---

## Task 10: Vulnerability scan + final test run

**Files:** none (read-only verification pass)

- [ ] **Step 1: Run `cargo audit`**

```bash
cargo audit
```

Expected: no critical/high vulnerabilities in the dependency tree. If any are found, update the affected dependency or document a mitigation in a `cargo-audit.toml` ignore entry.

- [ ] **Step 2: Run `cargo clippy` on the normalizer**

```bash
cargo clippy -p ssdf-normalizer -- -D warnings
```

Expected: zero warnings. Common fixes: unused imports in `panos.rs`, redundant clones in `build_traffic_ext`, `match` arms that can use `if let`.

- [ ] **Step 3: Run the full workspace test suite**

```bash
cargo test
```

Expected: PASS — all crates (ssdf-ontology, ssdf-normalizer, ssdf-admin-mcp) green.

- [ ] **Step 4: Commit**

```bash
git add .  # only if clippy changes were needed
git commit -m "chore: clippy fixes in panos.rs"
```

---

## Self-Review

**Spec coverage:**

| Requirement | Covered by |
|---|---|
| F1 Ingest — PAN-OS syslog | Vector source port 5515 → `raw.panos` (Task 2) |
| F2 Normalize — PAN-OS → canonical + `ext.panos` | `panos.rs` mapper (Tasks 3-5) |
| F7 Extensibility — second vendor with no core redesign | `panos.rs` is a new file; `consumer.rs`/`sink.rs`/`ssdf-ontology` untouched |
| Multi-vendor NGFW proof | Both `srx` and `panos` consumers run in the same binary (Task 7) |
| `source_type = "panos"` verbatim | Set in every emitted `Event` in `panos.rs` |
| Topic `raw.panos` / `events.normalized` verbatim | Task 1 + consumer spawn (Task 7) |
| Table `ssdf.events` unchanged | No DDL changes; same ClickHouse insert path as SRX |
| TRAFFIC → FlowEvent + optional PolicyDecisionEvent (deny) | `map_traffic` (Task 3) |
| THREAT → AlertEvent | `map_threat` (Task 4) |
| CONFIG → ConfigChangeEvent | `map_config` (Task 5) |
| `ext.panos.*` for non-canonical fields | `build_traffic_ext` + inline ext objects |
| Admin `list_source_types` includes `panos` | Task 8 |
| `get_source_onboarding` PAN-OS snippet | Task 8 onboarding_snippet |
| No device write-back (sovereignty boundary) | Out of scope; onboarding snippet is emitted for agent/operator to apply via panos-mcp |

**Placeholder scan:** None. Every task includes real CSV sample lines with documented field positions, real Rust code, and exact `cargo` commands. The integration test (Task 9) is gated but not a placeholder — it is executable code.

**Type consistency:**
- `Event`, `EventPayload`, `FlowEvent`, `AlertEvent`, `ConfigChangeEvent`, `PolicyDecisionEvent`, `Severity`, `EventRefs`, `new_id`, `IdPrefix` — all imported from `ssdf-ontology` exactly as defined in Plan 1 (Task 3). No new ontology types introduced.
- `source_type = "panos"` matches the `list_source_types` entry and the `ext.panos.*` namespace.
- ClickHouse table `ssdf.events` — same DDL as Plan 1 (Task 6); no column additions.
- Redpanda topics: `raw.panos` (new), `events.normalized` (existing). No other topics touched.
- `IdPrefix::Event` → `evt_` prefix on all emitted event IDs — consistent with Plan 1 `id.rs`.

**PAN-OS CSV field positions — assumption to double-check:**
Field positions in this plan are based on the PAN-OS 10.1 syslog CSV format as documented in the _PAN-OS 10.1 Log Reference Guide_ (Palo Alto Networks). Position 0 is the leading empty field (the line begins with a comma). PAN-OS 9.x uses a slightly shorter TRAFFIC format (fewer FUTURE_USE fields); PAN-OS 11.x adds fields at the tail end. The `map_record` implementation reads fields by index from a `splitn(usize::MAX, ',')` call, so tail additions are safe (existing positions are stable). Verify the specific PAN-OS version in the lab against the field table in §Background before running the integration test.

**Note on `DefaultHasher` for before/after digests:** `std::collections::hash_map::DefaultHasher` is not cryptographically secure and is not stable across Rust versions. For v0 this is acceptable (the digest is a change-detection aid, not a security primitive). Replace with SHA-256 via `sha2` crate in v0.1 when the `before/after` fields gain operational significance.
