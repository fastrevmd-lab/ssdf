# SSDF SRX Ingest Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Get Juniper SRX firewall flow/policy/threat syslog into the canonical `ssdf.events` ClickHouse store end-to-end: Vector (syslog collector) → Redpanda topic `raw.srx` → `ssdf-normalizer` Rust binary (parses SRX records into canonical `Event`s, batch-inserts to ClickHouse, republishes to `events.normalized`).

**Architecture:** Vector runs in Docker, listens on UDP/TCP 5514, parses each syslog line into a JSON envelope and produces to the `raw.srx` Redpanda topic. The `ssdf-normalizer` Rust binary consumes `raw.srx`, applies per-message-type parsers to produce canonical `Event` values (from `ssdf-ontology`), batch-inserts rows to `ssdf.events` in ClickHouse, and re-publishes the full canonical Event JSON to the `events.normalized` topic for downstream consumers (Plan 4 Entity Resolution). Non-canonical SRX fields are preserved under the `ext` map with key `srx`.

**Tech Stack:** Rust (edition 2021, async via `tokio`), `rdkafka` (librdkafka bindings for Redpanda), `clickhouse` crate (HTTP client), `serde`/`serde_json`, `chrono`; `ssdf-ontology` via workspace path dep; Vector `0.40.0-debian` syslog→kafka; Docker Compose extension of the Plan 1 compose file.

**Spec:** `docs/superpowers/specs/2026-06-05-ssdf-data-fabric-design.md` (§3 Ontology — events; §4 Data Plane — Ingest, Bus, Processing).

---

## File Structure

```
SSDF/
├── Cargo.toml                                     # workspace root — add ssdf-normalizer to members
├── docker-compose.yml                             # add vector service
├── vector/
│   └── vector.yaml                                # Vector syslog source + kafka sink config
└── crates/
    └── ssdf-normalizer/
        ├── Cargo.toml                             # binary crate, deps: tokio, rdkafka, clickhouse, serde_json, ssdf-ontology
        └── src/
            ├── main.rs                            # tokio entrypoint, wires consumer + writer loops
            ├── config.rs                          # Config struct (env-driven: broker URL, CH URL, etc.)
            ├── consumer.rs                        # rdkafka consumer loop: reads raw.srx, dispatches to parser
            ├── parser/
            │   ├── mod.rs                         # parse_srx_record(raw: &RawSrxRecord) -> Result<Event>
            │   ├── flow.rs                        # RT_FLOW_SESSION_CLOSE → FlowEvent
            │   ├── idp.rs                         # RT_IDP / IDP_ATTACK → AlertEvent
            │   ├── policy.rs                      # RT_FLOW_SESSION_DENY + permit → PolicyDecisionEvent
            │   └── config_change.rs               # UI_COMMIT_COMPLETED → ConfigChangeEvent
            ├── writer/
            │   ├── mod.rs                         # BatchWriter: buffer Events, flush to ClickHouse
            │   └── clickhouse.rs                  # insert_batch(events: &[Event]) → ClickHouse HTTP
            └── publisher.rs                       # republish canonical Event JSON to events.normalized
```

Each file has a single responsibility. The parser sub-modules are the only place vendor-specific SRX log format knowledge lives (per spec §8 pitfall: "Connectors own all vendor weirdness").

---

## SRX Log Format Reference

SRX emits syslog in structured-data (RFC 5424 / Junos RT_FLOW) format. The lines Vector receives look like:

```
<14>1 2026-06-05T14:09:40.123Z srx-test10.lab.local RT_FLOW - - [junos@2636.1.1.1.2.26 source-address="10.68.2.7" source-port="51000" destination-address="10.68.9.3" destination-port="445" service-name="junos-smb" nat-source-address="10.68.2.7" nat-source-port="51000" nat-destination-address="10.68.9.3" nat-destination-port="445" src-nat-rule-name="None" dst-nat-rule-name="None" protocol-id="6" policy-name="trust-to-server" source-zone-name="trust" destination-zone-name="server" session-id-32="120043" packets-from-client="22" bytes-from-client="1200" packets-from-server="14" bytes-from-server="4096" elapsed-time="3" application="UNKNOWN" nested-application="smb" username="N/A" roles="N/A" packet-incoming-interface="ge-0/0/1.0" encrypted="No" reason="TCP FIN"] RT_FLOW_SESSION_CLOSE
```

Vector extracts this into a JSON object and publishes to `raw.srx`. The normalizer then maps it to a canonical `FlowEvent`:

```json
{
  "event_id": "evt_01J3ZXHQK9VVFM7PABCDE12345",
  "tenant_id": "t_main",
  "event_type": "flow_event",
  "ts": "2026-06-05T14:09:40.123Z",
  "source_type": "srx",
  "source_instance": "srx-test10.lab.local",
  "severity": "info",
  "refs": {},
  "src_ip": "10.68.2.7",
  "src_port": 51000,
  "dst_ip": "10.68.9.3",
  "dst_port": 445,
  "proto": "tcp",
  "app": "smb",
  "action": "allow",
  "bytes_in": 1200,
  "bytes_out": 4096,
  "zone_src": "trust",
  "zone_dst": "server",
  "ext": {
    "srx": {
      "session_id": "120043",
      "policy_name": "trust-to-server",
      "reason": "TCP FIN",
      "elapsed_time": 3,
      "packets_from_client": 22,
      "packets_from_server": 14,
      "nat_src_ip": "10.68.2.7",
      "nat_dst_ip": "10.68.9.3",
      "interface": "ge-0/0/1.0",
      "encrypted": false
    }
  }
}
```

The `ext.srx` object carries every SRX-specific field that has no canonical home. The canonical columns (`src_ip`, `dst_ip`, etc.) are promoted out of it.

---

## Task 1: Add Vector service to docker-compose + create Vector config

**Files:**
- Modify: `docker-compose.yml`
- Create: `vector/vector.yaml`

- [ ] **Step 1: Create the Vector configuration** `vector/vector.yaml`

This config listens on syslog UDP+TCP 5514, parses the structured-data block out of each RFC 5424 line, merges the syslog envelope fields (host, timestamp), and sinks to Redpanda topic `raw.srx`.

```yaml
# vector/vector.yaml
data_dir: /var/lib/vector

sources:
  srx_syslog:
    type: syslog
    address: "0.0.0.0:5514"
    mode: udp
    max_length: 65536

  srx_syslog_tcp:
    type: syslog
    address: "0.0.0.0:5514"
    mode: tcp
    max_length: 65536

transforms:
  enrich_srx:
    type: remap
    inputs: ["srx_syslog", "srx_syslog_tcp"]
    source: |
      # Preserve the RFC 5424 hostname as source_instance
      .source_instance = .hostname
      # Preserve the structured_data map (Junos RT_FLOW fields land here)
      .srx_fields = .structured_data
      # Normalise the timestamp to RFC 3339 string
      .received_at = format_timestamp!(now(), format: "%+")
      # Tag all records with the source type for the normalizer
      .source_type = "srx"

sinks:
  redpanda_raw_srx:
    type: kafka
    inputs: ["enrich_srx"]
    bootstrap_servers: "redpanda:9092"
    topic: "raw.srx"
    encoding:
      codec: json
    batch:
      max_bytes: 1048576
      timeout_secs: 1
    buffer:
      type: memory
      max_events: 50000
      when_full: block
```

- [ ] **Step 2: Add the `vector` service to `docker-compose.yml`**

Add the following service block to the `services:` section of the existing `docker-compose.yml` (after the `minio` service):

```yaml
  vector:
    image: timberio/vector:0.40.0-debian
    volumes:
      - ./vector/vector.yaml:/etc/vector/vector.yaml:ro
    ports:
      - "5514:5514/udp"
      - "5514:5514/tcp"
    command: ["--config", "/etc/vector/vector.yaml"]
    depends_on:
      - redpanda
```

- [ ] **Step 3: Create the `raw.srx` and `events.normalized` topics in Redpanda**

Add a one-shot `rpk-init` service that runs on `just migrate` (or run manually after `just up`):

```bash
docker compose exec redpanda rpk topic create raw.srx \
  --partitions 4 \
  --replicas 1 \
  --topic-config retention.ms=86400000

docker compose exec redpanda rpk topic create events.normalized \
  --partitions 4 \
  --replicas 1 \
  --topic-config retention.ms=86400000
```

Expected output:
```
TOPIC           STATUS
raw.srx         OK
events.normalized  OK
```

Verify:
```bash
docker compose exec redpanda rpk topic list
```
Expected: both topics listed.

- [ ] **Step 4: Bring up the updated stack and confirm Vector starts**

```bash
docker compose up -d
docker compose logs vector --tail 20
```

Expected: Vector logs `Starting Vector...` and `Vector has started.` with no `ERROR` lines.

- [ ] **Step 5: Smoke-test the syslog → raw.srx pipeline with a real SRX line**

```bash
echo '<14>1 2026-06-05T14:09:40.123Z srx-test10.lab.local RT_FLOW - - [junos@2636.1.1.1.2.26 source-address="10.68.2.7" source-port="51000" destination-address="10.68.9.3" destination-port="445" service-name="junos-smb" protocol-id="6" policy-name="trust-to-server" source-zone-name="trust" destination-zone-name="server" session-id-32="120043" bytes-from-client="1200" bytes-from-server="4096" application="UNKNOWN" nested-application="smb" username="N/A" reason="TCP FIN"] RT_FLOW_SESSION_CLOSE' \
  | nc -u -w1 127.0.0.1 5514

docker compose exec redpanda rpk topic consume raw.srx --num 1
```

Expected: one JSON record printed with fields including `source_type: "srx"`, `source_instance: "srx-test10.lab.local"`, and `srx_fields` containing the structured-data map.

- [ ] **Step 6: Commit**

```bash
git add vector/vector.yaml docker-compose.yml
git commit -m "feat(ingest): add Vector syslog collector + raw.srx / events.normalized topics"
```

---

## Task 2: Scaffold the `ssdf-normalizer` crate

**Files:**
- Modify: `Cargo.toml` (workspace root)
- Create: `crates/ssdf-normalizer/Cargo.toml`
- Create: `crates/ssdf-normalizer/src/main.rs`
- Create: `crates/ssdf-normalizer/src/config.rs`

- [ ] **Step 1: Add `ssdf-normalizer` to the workspace members in `Cargo.toml`**

```toml
[workspace]
resolver = "2"
members = ["crates/ssdf-ontology", "crates/ssdf-normalizer"]

[workspace.package]
edition = "2021"
license = "Apache-2.0"

[workspace.dependencies]
ulid = "1"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
chrono = { version = "0.4", features = ["serde"] }
tokio = { version = "1", features = ["full"] }
rdkafka = { version = "0.36", features = ["cmake-build"] }
clickhouse = "0.11"
anyhow = "1"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
```

- [ ] **Step 2: Create `crates/ssdf-normalizer/Cargo.toml`**

```toml
[package]
name = "ssdf-normalizer"
version = "0.1.0"
edition.workspace = true
license.workspace = true

[[bin]]
name = "ssdf-normalizer"
path = "src/main.rs"

[dependencies]
ssdf-ontology = { path = "../ssdf-ontology" }
tokio.workspace = true
rdkafka.workspace = true
clickhouse.workspace = true
serde.workspace = true
serde_json.workspace = true
chrono.workspace = true
anyhow.workspace = true
tracing.workspace = true
tracing-subscriber.workspace = true

[dev-dependencies]
# No extra dev deps needed; unit tests use only std + serde_json + ssdf-ontology
```

- [ ] **Step 3: Create `crates/ssdf-normalizer/src/config.rs`**

```rust
//! Environment-driven configuration for ssdf-normalizer.

use anyhow::{Context, Result};

#[derive(Debug, Clone)]
pub struct Config {
    /// Redpanda broker list (comma-separated host:port).
    pub kafka_brokers: String,
    /// Consumer group id.
    pub kafka_group_id: String,
    /// Topic to consume raw SRX records from.
    pub raw_topic: String,
    /// Topic to publish canonical events to.
    pub normalized_topic: String,
    /// ClickHouse HTTP endpoint (e.g. http://clickhouse:8123).
    pub clickhouse_url: String,
    /// ClickHouse username.
    pub clickhouse_user: String,
    /// ClickHouse password.
    pub clickhouse_password: String,
    /// ClickHouse database.
    pub clickhouse_db: String,
    /// Number of events to buffer before flushing to ClickHouse.
    pub batch_size: usize,
    /// Maximum milliseconds to wait before flushing an incomplete batch.
    pub batch_timeout_ms: u64,
    /// Default tenant id for v0 single-tenant deployment.
    pub default_tenant_id: String,
}

impl Config {
    /// Load config from environment variables. Fails fast with a clear error
    /// if a required variable is absent.
    pub fn from_env() -> Result<Self> {
        Ok(Config {
            kafka_brokers: env_var("KAFKA_BROKERS")
                .unwrap_or_else(|_| "localhost:9092".into()),
            kafka_group_id: env_var("KAFKA_GROUP_ID")
                .unwrap_or_else(|_| "ssdf-normalizer".into()),
            raw_topic: env_var("RAW_TOPIC")
                .unwrap_or_else(|_| "raw.srx".into()),
            normalized_topic: env_var("NORMALIZED_TOPIC")
                .unwrap_or_else(|_| "events.normalized".into()),
            clickhouse_url: env_var("CLICKHOUSE_URL")
                .unwrap_or_else(|_| "http://localhost:8123".into()),
            clickhouse_user: env_var("CLICKHOUSE_USER")
                .unwrap_or_else(|_| "ssdf".into()),
            clickhouse_password: env_var("CLICKHOUSE_PASSWORD")
                .context("CLICKHOUSE_PASSWORD must be set")?,
            clickhouse_db: env_var("CLICKHOUSE_DB")
                .unwrap_or_else(|_| "ssdf".into()),
            batch_size: env_var("BATCH_SIZE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(500),
            batch_timeout_ms: env_var("BATCH_TIMEOUT_MS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(2000),
            default_tenant_id: env_var("DEFAULT_TENANT_ID")
                .unwrap_or_else(|_| "t_main".into()),
        })
    }
}

fn env_var(key: &str) -> Result<String> {
    std::env::var(key).with_context(|| format!("missing env var {key}"))
}
```

- [ ] **Step 4: Create a stub `crates/ssdf-normalizer/src/main.rs`** (real wiring comes in Task 6)

```rust
//! ssdf-normalizer: consumes raw.srx, normalizes to canonical Events,
//! batch-inserts to ClickHouse, republishes to events.normalized.

mod config;
mod consumer;
mod parser;
mod publisher;
mod writer;

use anyhow::Result;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("ssdf_normalizer=info".parse()?),
        )
        .init();

    let config = config::Config::from_env()?;
    info!(
        brokers = %config.kafka_brokers,
        raw_topic = %config.raw_topic,
        "ssdf-normalizer starting"
    );

    consumer::run(config).await
}
```

- [ ] **Step 5: Verify the crate compiles (modules don't exist yet — expect module-not-found errors)**

Run: `cargo build -p ssdf-normalizer 2>&1 | head -20`

Expected: errors like `error[E0583]: file not found for module 'consumer'` — confirms the workspace wiring is correct and only stubs are missing.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml crates/ssdf-normalizer/
git commit -m "chore(normalizer): scaffold ssdf-normalizer crate + config"
```

---

## Task 3: Raw SRX record type + per-type parser skeleton

This task defines the `RawSrxRecord` deserialization type (what Vector writes to `raw.srx`) and the public `parse_srx_record` dispatch function. All four message-type parsers are stubbed; the real logic ships in Tasks 4-7.

**Files:**
- Create: `crates/ssdf-normalizer/src/parser/mod.rs`
- Create: `crates/ssdf-normalizer/src/parser/flow.rs`
- Create: `crates/ssdf-normalizer/src/parser/idp.rs`
- Create: `crates/ssdf-normalizer/src/parser/policy.rs`
- Create: `crates/ssdf-normalizer/src/parser/config_change.rs`

- [ ] **Step 1: Write the failing test for the dispatch function**

Create `crates/ssdf-normalizer/src/parser/mod.rs` with just the test block first:

```rust
use serde::Deserialize;
use serde_json::{Map, Value};
use ssdf_ontology::events::Event;
use anyhow::{bail, Result};

/// The JSON envelope Vector produces for each SRX syslog line on raw.srx.
/// The `message` field is the original syslog message text;
/// `srx_fields` is the parsed structured-data map (key/value pairs from the
/// Junos RT_FLOW structured-data block). Additional envelope fields come from
/// Vector's syslog source transform.
#[derive(Debug, Clone, Deserialize)]
pub struct RawSrxRecord {
    /// Original syslog message body (e.g. "RT_FLOW_SESSION_CLOSE").
    pub message: String,
    /// RFC 5424 hostname field — used as source_instance.
    #[serde(default)]
    pub hostname: Option<String>,
    /// ISO 8601 timestamp string from the syslog header.
    #[serde(default)]
    pub timestamp: Option<String>,
    /// Parsed Junos structured-data fields (flat key→string map).
    #[serde(default)]
    pub srx_fields: Map<String, Value>,
    /// source_type injected by Vector remap transform (always "srx").
    #[serde(default)]
    pub source_type: Option<String>,
}

impl RawSrxRecord {
    /// Convenience: get a string field from srx_fields.
    pub fn field(&self, key: &str) -> Option<&str> {
        self.srx_fields.get(key)?.as_str()
    }

    /// Convenience: get a string field, returning an error if absent.
    pub fn required_field(&self, key: &str) -> Result<&str> {
        self.field(key)
            .ok_or_else(|| anyhow::anyhow!("missing required srx field: {key}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_session_close_record() -> RawSrxRecord {
        let raw = r#"{
          "message": "RT_FLOW_SESSION_CLOSE",
          "hostname": "srx-test10.lab.local",
          "timestamp": "2026-06-05T14:09:40.123Z",
          "source_type": "srx",
          "srx_fields": {
            "source-address": "10.68.2.7",
            "source-port": "51000",
            "destination-address": "10.68.9.3",
            "destination-port": "445",
            "protocol-id": "6",
            "policy-name": "trust-to-server",
            "source-zone-name": "trust",
            "destination-zone-name": "server",
            "session-id-32": "120043",
            "bytes-from-client": "1200",
            "bytes-from-server": "4096",
            "nested-application": "smb",
            "username": "N/A",
            "reason": "TCP FIN",
            "elapsed-time": "3",
            "packets-from-client": "22",
            "packets-from-server": "14",
            "nat-source-address": "10.68.2.7",
            "nat-destination-address": "10.68.9.3",
            "packet-incoming-interface": "ge-0/0/1.0",
            "encrypted": "No"
          }
        }"#;
        serde_json::from_str(raw).unwrap()
    }

    #[test]
    fn dispatch_session_close_produces_flow_event() {
        let record = make_session_close_record();
        let event = parse_srx_record(&record, "t_main").unwrap();
        // event_type discriminator must be "flow_event"
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["event_type"], "flow_event", "wrong event_type: {json}");
        assert_eq!(json["src_ip"], "10.68.2.7");
        assert_eq!(json["dst_ip"], "10.68.9.3");
        assert_eq!(json["src_port"], 51000);
        assert_eq!(json["dst_port"], 445);
        assert_eq!(json["proto"], "tcp");
        assert_eq!(json["app"], "smb");
        assert_eq!(json["action"], "allow");
        assert_eq!(json["bytes_in"], 1200);
        assert_eq!(json["bytes_out"], 4096);
        assert_eq!(json["zone_src"], "trust");
        assert_eq!(json["zone_dst"], "server");
        assert_eq!(json["source_type"], "srx");
        assert_eq!(json["tenant_id"], "t_main");
        // session-id must be in ext.srx
        assert_eq!(json["ext"]["srx"]["session_id"], "120043");
        assert_eq!(json["ext"]["srx"]["policy_name"], "trust-to-server");
        assert_eq!(json["ext"]["srx"]["reason"], "TCP FIN");
    }

    #[test]
    fn unknown_message_type_returns_error() {
        let mut record = make_session_close_record();
        record.message = "RT_FLOW_SOME_FUTURE_MSG".into();
        assert!(parse_srx_record(&record, "t_main").is_err());
    }
}
```

- [ ] **Step 2: Run to confirm they fail**

Run: `cargo test -p ssdf-normalizer parser:: 2>&1 | tail -20`
Expected: FAIL — `cannot find function 'parse_srx_record'` (module incomplete).

- [ ] **Step 3: Implement the dispatch function** (add above the `#[cfg(test)]` block)

```rust
pub mod flow;
pub mod idp;
pub mod policy;
pub mod config_change;

/// Dispatch a raw SRX record to the appropriate parser based on its message tag.
///
/// Returns `Err` for unknown message types so the consumer can dead-letter them.
pub fn parse_srx_record(record: &RawSrxRecord, tenant_id: &str) -> Result<Event> {
    let msg = record.message.trim();
    if msg.contains("RT_FLOW_SESSION_CLOSE") {
        flow::parse_session_close(record, tenant_id)
    } else if msg.contains("RT_FLOW_SESSION_DENY") {
        policy::parse_session_deny(record, tenant_id)
    } else if msg.contains("RT_IDP") || msg.contains("IDP_ATTACK") {
        idp::parse_idp_attack(record, tenant_id)
    } else if msg.contains("UI_COMMIT_COMPLETED") || msg.contains("UI_COMMIT_AT_TIME_COMPLETED") {
        config_change::parse_commit(record, tenant_id)
    } else {
        bail!("unsupported SRX message type: {msg}")
    }
}
```

- [ ] **Step 4: Create stub sub-modules** (each returns `Err` — they'll be filled in Tasks 4-7)

`crates/ssdf-normalizer/src/parser/flow.rs`:
```rust
use anyhow::Result;
use ssdf_ontology::events::Event;
use super::RawSrxRecord;

pub fn parse_session_close(_record: &RawSrxRecord, _tenant_id: &str) -> Result<Event> {
    anyhow::bail!("not yet implemented")
}
```

`crates/ssdf-normalizer/src/parser/idp.rs`:
```rust
use anyhow::Result;
use ssdf_ontology::events::Event;
use super::RawSrxRecord;

pub fn parse_idp_attack(_record: &RawSrxRecord, _tenant_id: &str) -> Result<Event> {
    anyhow::bail!("not yet implemented")
}
```

`crates/ssdf-normalizer/src/parser/policy.rs`:
```rust
use anyhow::Result;
use ssdf_ontology::events::Event;
use super::RawSrxRecord;

pub fn parse_session_deny(_record: &RawSrxRecord, _tenant_id: &str) -> Result<Event> {
    anyhow::bail!("not yet implemented")
}
```

`crates/ssdf-normalizer/src/parser/config_change.rs`:
```rust
use anyhow::Result;
use ssdf_ontology::events::Event;
use super::RawSrxRecord;

pub fn parse_commit(_record: &RawSrxRecord, _tenant_id: &str) -> Result<Event> {
    anyhow::bail!("not yet implemented")
}
```

- [ ] **Step 5: Run tests** — `dispatch_session_close_produces_flow_event` still FAILS (flow stub returns Err). `unknown_message_type_returns_error` PASSES.

Run: `cargo test -p ssdf-normalizer parser:: 2>&1 | tail -20`
Expected: `test parser::tests::unknown_message_type_returns_error ... ok` and `test parser::tests::dispatch_session_close_produces_flow_event ... FAILED`.

This confirms the dispatch and `RawSrxRecord` types are correct; only the flow parser is missing.

- [ ] **Step 6: Commit**

```bash
git add crates/ssdf-normalizer/src/parser/
git commit -m "feat(normalizer): RawSrxRecord type + parse_srx_record dispatch skeleton"
```

---

## Task 4: RT_FLOW_SESSION_CLOSE → FlowEvent parser

**Files:**
- Modify: `crates/ssdf-normalizer/src/parser/flow.rs`

- [ ] **Step 1: The failing test already exists** from Task 3 (`dispatch_session_close_produces_flow_event`). Re-run to confirm it still fails:

Run: `cargo test -p ssdf-normalizer dispatch_session_close 2>&1 | tail -10`
Expected: FAIL — `parse_session_close` returns `Err("not yet implemented")`.

- [ ] **Step 2: Implement `parse_session_close`**

Replace the stub in `crates/ssdf-normalizer/src/parser/flow.rs`:

```rust
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde_json::{Map, Value};
use ssdf_ontology::{
    events::{Event, EventPayload, EventRefs, FlowEvent, Severity},
    id::{new_id, IdPrefix},
};
use super::RawSrxRecord;

/// Parse an RT_FLOW_SESSION_CLOSE record into a canonical FlowEvent.
///
/// Canonical promotions:
/// - source-address / source-port         → src_ip / src_port
/// - destination-address / destination-port → dst_ip / dst_port
/// - protocol-id (IANA number)            → proto (name via proto_name())
/// - nested-application (preferred) or service-name → app
/// - "allow" (session-close = allowed flow)  → action
/// - bytes-from-client / bytes-from-server → bytes_in / bytes_out
/// - source-zone-name / destination-zone-name → zone_src / zone_dst
/// - username (when not "N/A")            → user
///
/// Everything else goes into ext["srx"].
pub fn parse_session_close(record: &RawSrxRecord, tenant_id: &str) -> Result<Event> {
    let src_ip = record.required_field("source-address")?.to_string();
    let src_port: u16 = record
        .required_field("source-port")?
        .parse()
        .context("source-port is not u16")?;
    let dst_ip = record.required_field("destination-address")?.to_string();
    let dst_port: u16 = record
        .required_field("destination-port")?
        .parse()
        .context("destination-port is not u16")?;
    let proto_id = record.required_field("protocol-id")?;
    let proto = proto_name(proto_id).to_string();

    // Prefer the application-layer name; fall back to service-name.
    let app = record
        .field("nested-application")
        .filter(|v| !v.eq_ignore_ascii_case("UNKNOWN") && !v.is_empty())
        .or_else(|| record.field("service-name"))
        .unwrap_or("unknown")
        .to_lowercase();

    let bytes_in: u64 = record
        .field("bytes-from-client")
        .unwrap_or("0")
        .parse()
        .unwrap_or(0);
    let bytes_out: u64 = record
        .field("bytes-from-server")
        .unwrap_or("0")
        .parse()
        .unwrap_or(0);
    let zone_src = record.required_field("source-zone-name")?.to_string();
    let zone_dst = record.required_field("destination-zone-name")?.to_string();

    let user = record
        .field("username")
        .filter(|u| !u.eq_ignore_ascii_case("N/A") && !u.is_empty())
        .map(str::to_string);

    let ts = parse_ts(record);

    // Build ext.srx with the non-canonical fields.
    let mut srx: Map<String, Value> = Map::new();
    for (key, raw_key) in &[
        ("session_id", "session-id-32"),
        ("policy_name", "policy-name"),
        ("reason", "reason"),
        ("nat_src_ip", "nat-source-address"),
        ("nat_dst_ip", "nat-destination-address"),
        ("interface", "packet-incoming-interface"),
    ] {
        if let Some(v) = record.field(raw_key) {
            srx.insert(key.to_string(), Value::String(v.to_string()));
        }
    }
    if let Some(v) = record.field("elapsed-time") {
        if let Ok(n) = v.parse::<u64>() {
            srx.insert("elapsed_time".into(), Value::Number(n.into()));
        }
    }
    for (key, raw_key) in &[
        ("packets_from_client", "packets-from-client"),
        ("packets_from_server", "packets-from-server"),
    ] {
        if let Some(v) = record.field(raw_key) {
            if let Ok(n) = v.parse::<u64>() {
                srx.insert(key.to_string(), Value::Number(n.into()));
            }
        }
    }
    if let Some(enc) = record.field("encrypted") {
        srx.insert(
            "encrypted".into(),
            Value::Bool(enc.eq_ignore_ascii_case("Yes")),
        );
    }

    let mut ext: std::collections::BTreeMap<String, Value> = std::collections::BTreeMap::new();
    ext.insert("srx".into(), Value::Object(srx));

    Ok(Event {
        event_id: new_id(IdPrefix::Event),
        tenant_id: tenant_id.to_string(),
        ts,
        source_type: "srx".to_string(),
        source_instance: record
            .hostname
            .clone()
            .unwrap_or_else(|| "unknown".to_string()),
        severity: Severity::Info,
        refs: EventRefs::default(),
        payload: EventPayload::FlowEvent(FlowEvent {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            proto,
            app,
            action: "allow".to_string(),
            bytes_in,
            bytes_out,
            zone_src,
            zone_dst,
            user,
        }),
        ext,
    })
}

/// Map IANA protocol number string to a human-readable name.
fn proto_name(protocol_id: &str) -> &'static str {
    match protocol_id {
        "6" => "tcp",
        "17" => "udp",
        "1" => "icmp",
        "47" => "gre",
        "50" => "esp",
        "51" => "ah",
        "89" => "ospf",
        "132" => "sctp",
        _ => "other",
    }
}

/// Parse the syslog timestamp from the record envelope; fall back to now().
fn parse_ts(record: &RawSrxRecord) -> DateTime<Utc> {
    record
        .timestamp
        .as_deref()
        .and_then(|s| s.parse::<DateTime<Utc>>().ok())
        .unwrap_or_else(Utc::now)
}
```

- [ ] **Step 3: Run the test**

Run: `cargo test -p ssdf-normalizer dispatch_session_close 2>&1 | tail -10`
Expected: PASS — `test parser::tests::dispatch_session_close_produces_flow_event ... ok`.

- [ ] **Step 4: Run all parser tests**

Run: `cargo test -p ssdf-normalizer parser:: 2>&1 | tail -10`
Expected: `dispatch_session_close_produces_flow_event ... ok`, `unknown_message_type_returns_error ... ok`. (The idp/policy/config_change stubs are not exercised yet — they get their own tests in Tasks 5-7.)

- [ ] **Step 5: Commit**

```bash
git add crates/ssdf-normalizer/src/parser/flow.rs
git commit -m "feat(normalizer): RT_FLOW_SESSION_CLOSE -> FlowEvent parser"
```

---

## Task 5: RT_FLOW_SESSION_DENY → PolicyDecisionEvent parser

**Files:**
- Modify: `crates/ssdf-normalizer/src/parser/policy.rs`
- Modify: `crates/ssdf-normalizer/src/parser/mod.rs` (add test)

- [ ] **Step 1: Write the failing test** — add to the `#[cfg(test)]` block in `parser/mod.rs`:

```rust
    fn make_session_deny_record() -> RawSrxRecord {
        let raw = r#"{
          "message": "RT_FLOW_SESSION_DENY",
          "hostname": "srx-test10.lab.local",
          "timestamp": "2026-06-05T15:01:00.000Z",
          "source_type": "srx",
          "srx_fields": {
            "source-address": "10.68.2.99",
            "source-port": "54321",
            "destination-address": "192.0.2.1",
            "destination-port": "22",
            "protocol-id": "6",
            "policy-name": "deny-ssh-out",
            "source-zone-name": "trust",
            "destination-zone-name": "untrust",
            "reason": "policy deny"
          }
        }"#;
        serde_json::from_str(raw).unwrap()
    }

    #[test]
    fn dispatch_session_deny_produces_policy_decision_event() {
        let record = make_session_deny_record();
        let event = parse_srx_record(&record, "t_main").unwrap();
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["event_type"], "policy_decision_event");
        assert_eq!(json["decision"], "deny");
        assert_eq!(json["policy_ref"], "deny-ssh-out");
        assert_eq!(json["source_type"], "srx");
        assert_eq!(json["ext"]["srx"]["src_ip"], "10.68.2.99");
        assert_eq!(json["ext"]["srx"]["dst_port"], 22);
    }
```

- [ ] **Step 2: Confirm it fails**

Run: `cargo test -p ssdf-normalizer dispatch_session_deny 2>&1 | tail -10`
Expected: FAIL — `parse_session_deny` returns `Err("not yet implemented")`.

- [ ] **Step 3: Implement `parse_session_deny`**

Replace the stub in `crates/ssdf-normalizer/src/parser/policy.rs`:

```rust
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde_json::{Map, Value};
use ssdf_ontology::{
    events::{Event, EventPayload, EventRefs, PolicyDecisionEvent, Severity},
    id::{new_id, IdPrefix},
};
use super::RawSrxRecord;

/// Parse an RT_FLOW_SESSION_DENY record into a canonical PolicyDecisionEvent.
///
/// A session deny carries the policy name and the 5-tuple context.
/// The canonical fields are policy_ref and decision ("deny").
/// The 5-tuple goes into ext.srx because FlowEvent owns 5-tuple context;
/// PolicyDecisionEvent owns the policy outcome.
pub fn parse_session_deny(record: &RawSrxRecord, tenant_id: &str) -> Result<Event> {
    let policy_ref = record.required_field("policy-name")?.to_string();

    // Context fields that are useful but not canonical on PolicyDecisionEvent.
    let src_ip = record.field("source-address").unwrap_or("").to_string();
    let dst_ip = record.field("destination-address").unwrap_or("").to_string();
    let dst_port: u16 = record
        .field("destination-port")
        .unwrap_or("0")
        .parse()
        .unwrap_or(0);
    let zone_src = record.field("source-zone-name").unwrap_or("").to_string();
    let zone_dst = record.field("destination-zone-name").unwrap_or("").to_string();
    let reason = record.field("reason").unwrap_or("policy deny").to_string();

    let ts = parse_ts(record);

    let mut srx: Map<String, Value> = Map::new();
    srx.insert("src_ip".into(), Value::String(src_ip));
    srx.insert("dst_ip".into(), Value::String(dst_ip));
    srx.insert("dst_port".into(), Value::Number(dst_port.into()));
    srx.insert("zone_src".into(), Value::String(zone_src));
    srx.insert("zone_dst".into(), Value::String(zone_dst));

    let mut ext: std::collections::BTreeMap<String, Value> = std::collections::BTreeMap::new();
    ext.insert("srx".into(), Value::Object(srx));

    Ok(Event {
        event_id: new_id(IdPrefix::Event),
        tenant_id: tenant_id.to_string(),
        ts,
        source_type: "srx".to_string(),
        source_instance: record
            .hostname
            .clone()
            .unwrap_or_else(|| "unknown".to_string()),
        severity: Severity::Low,
        refs: EventRefs::default(),
        payload: EventPayload::PolicyDecisionEvent(PolicyDecisionEvent {
            policy_ref,
            decision: "deny".to_string(),
            reason: Some(reason),
            matched_on: None,
        }),
        ext,
    })
}

fn parse_ts(record: &RawSrxRecord) -> DateTime<Utc> {
    record
        .timestamp
        .as_deref()
        .and_then(|s| s.parse::<DateTime<Utc>>().ok())
        .unwrap_or_else(Utc::now)
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p ssdf-normalizer parser:: 2>&1 | tail -10`
Expected: `dispatch_session_close_produces_flow_event ... ok`, `dispatch_session_deny_produces_policy_decision_event ... ok`, `unknown_message_type_returns_error ... ok`.

- [ ] **Step 5: Commit**

```bash
git add crates/ssdf-normalizer/src/parser/policy.rs crates/ssdf-normalizer/src/parser/mod.rs
git commit -m "feat(normalizer): RT_FLOW_SESSION_DENY -> PolicyDecisionEvent parser"
```

---

## Task 6: RT_IDP / IDP_ATTACK → AlertEvent parser

**Files:**
- Modify: `crates/ssdf-normalizer/src/parser/idp.rs`
- Modify: `crates/ssdf-normalizer/src/parser/mod.rs` (add test)

- [ ] **Step 1: Write the failing test** — add to the `#[cfg(test)]` block in `parser/mod.rs`:

```rust
    fn make_idp_attack_record() -> RawSrxRecord {
        // RT_IDP syslog from a vSRX IDP/AppFW attack event.
        let raw = r#"{
          "message": "RT_IDP - IDP_ATTACK_LOG_EVENT",
          "hostname": "srx-test10.lab.local",
          "timestamp": "2026-06-05T16:22:11.000Z",
          "source_type": "srx",
          "srx_fields": {
            "attack-name": "HTTP:OVERFLOW:CVE-2021-44228",
            "source-address": "10.68.5.200",
            "destination-address": "10.68.9.3",
            "protocol-id": "6",
            "source-zone-name": "trust",
            "destination-zone-name": "server",
            "severity": "HIGH",
            "category": "WEB_APPLICATION",
            "action": "DROP_PACKET",
            "policy-name": "idp-default"
          }
        }"#;
        serde_json::from_str(raw).unwrap()
    }

    #[test]
    fn dispatch_idp_attack_produces_alert_event() {
        let record = make_idp_attack_record();
        let event = parse_srx_record(&record, "t_main").unwrap();
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["event_type"], "alert_event");
        assert_eq!(json["title"], "HTTP:OVERFLOW:CVE-2021-44228");
        assert_eq!(json["category"], "WEB_APPLICATION");
        assert_eq!(json["severity"], "high");
        assert_eq!(json["affected_ip"], "10.68.9.3");
        assert_eq!(json["ext"]["srx"]["action"], "DROP_PACKET");
    }
```

- [ ] **Step 2: Confirm it fails**

Run: `cargo test -p ssdf-normalizer dispatch_idp_attack 2>&1 | tail -10`
Expected: FAIL — stub returns `Err("not yet implemented")`.

- [ ] **Step 3: Implement `parse_idp_attack`**

Replace the stub in `crates/ssdf-normalizer/src/parser/idp.rs`:

```rust
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde_json::{Map, Value};
use ssdf_ontology::{
    events::{AlertEvent, Event, EventPayload, EventRefs, Severity},
    id::{new_id, IdPrefix},
};
use super::RawSrxRecord;

/// Parse an RT_IDP / IDP_ATTACK_LOG_EVENT record into a canonical AlertEvent.
///
/// attack-name becomes the title and rule_id; severity is mapped from Junos
/// severity strings (HIGH/MEDIUM/LOW/INFO/CRITICAL) to canonical Severity.
pub fn parse_idp_attack(record: &RawSrxRecord, tenant_id: &str) -> Result<Event> {
    let attack_name = record
        .required_field("attack-name")?
        .to_string();
    let category = record
        .field("category")
        .unwrap_or("unknown")
        .to_string();
    let srx_severity = record.field("severity").unwrap_or("INFO");
    let severity = map_severity(srx_severity);
    let affected_ip = record
        .field("destination-address")
        .map(str::to_string);

    let ts = parse_ts(record);

    let mut srx: Map<String, Value> = Map::new();
    if let Some(v) = record.field("action") {
        srx.insert("action".into(), Value::String(v.to_string()));
    }
    if let Some(v) = record.field("policy-name") {
        srx.insert("policy_name".into(), Value::String(v.to_string()));
    }
    if let Some(v) = record.field("source-address") {
        srx.insert("src_ip".into(), Value::String(v.to_string()));
    }
    if let Some(v) = record.field("source-zone-name") {
        srx.insert("zone_src".into(), Value::String(v.to_string()));
    }
    if let Some(v) = record.field("destination-zone-name") {
        srx.insert("zone_dst".into(), Value::String(v.to_string()));
    }

    let mut ext: std::collections::BTreeMap<String, Value> = std::collections::BTreeMap::new();
    ext.insert("srx".into(), Value::Object(srx));

    Ok(Event {
        event_id: new_id(IdPrefix::Event),
        tenant_id: tenant_id.to_string(),
        ts,
        source_type: "srx".to_string(),
        source_instance: record
            .hostname
            .clone()
            .unwrap_or_else(|| "unknown".to_string()),
        severity,
        refs: EventRefs::default(),
        payload: EventPayload::AlertEvent(AlertEvent {
            rule_id: attack_name.clone(),
            title: attack_name,
            category,
            confidence: None,
            affected_ip,
            affected_user: None,
        }),
        ext,
    })
}

/// Map Junos IDP severity string to canonical Severity.
fn map_severity(s: &str) -> Severity {
    match s.to_uppercase().as_str() {
        "CRITICAL" => Severity::Critical,
        "HIGH" => Severity::High,
        "MEDIUM" => Severity::Medium,
        "LOW" => Severity::Low,
        _ => Severity::Info,
    }
}

fn parse_ts(record: &RawSrxRecord) -> DateTime<Utc> {
    record
        .timestamp
        .as_deref()
        .and_then(|s| s.parse::<DateTime<Utc>>().ok())
        .unwrap_or_else(Utc::now)
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p ssdf-normalizer parser:: 2>&1 | tail -15`
Expected: 4 tests pass — `dispatch_session_close...`, `dispatch_session_deny...`, `dispatch_idp_attack...`, `unknown_message_type...`.

- [ ] **Step 5: Commit**

```bash
git add crates/ssdf-normalizer/src/parser/idp.rs crates/ssdf-normalizer/src/parser/mod.rs
git commit -m "feat(normalizer): RT_IDP/IDP_ATTACK -> AlertEvent parser"
```

---

## Task 7: UI_COMMIT_COMPLETED → ConfigChangeEvent parser

**Files:**
- Modify: `crates/ssdf-normalizer/src/parser/config_change.rs`
- Modify: `crates/ssdf-normalizer/src/parser/mod.rs` (add test)

- [ ] **Step 1: Write the failing test** — add to the `#[cfg(test)]` block in `parser/mod.rs`:

```rust
    fn make_commit_record() -> RawSrxRecord {
        let raw = r#"{
          "message": "UI_COMMIT_COMPLETED: Commit complete",
          "hostname": "srx-test10.lab.local",
          "timestamp": "2026-06-05T17:45:00.000Z",
          "source_type": "srx",
          "srx_fields": {
            "user": "admin",
            "client": "junoscript"
          }
        }"#;
        serde_json::from_str(raw).unwrap()
    }

    #[test]
    fn dispatch_commit_produces_config_change_event() {
        let record = make_commit_record();
        let event = parse_srx_record(&record, "t_main").unwrap();
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["event_type"], "config_change_event");
        assert_eq!(json["actor"], "admin");
        assert_eq!(json["change_type"], "commit");
        assert_eq!(json["source_type"], "srx");
    }
```

- [ ] **Step 2: Confirm it fails**

Run: `cargo test -p ssdf-normalizer dispatch_commit 2>&1 | tail -10`
Expected: FAIL.

- [ ] **Step 3: Implement `parse_commit`**

Replace the stub in `crates/ssdf-normalizer/src/parser/config_change.rs`:

```rust
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde_json::{Map, Value};
use ssdf_ontology::{
    events::{ConfigChangeEvent, Event, EventPayload, EventRefs, Severity},
    id::{new_id, IdPrefix},
};
use super::RawSrxRecord;

/// Parse a UI_COMMIT_COMPLETED record into a canonical ConfigChangeEvent.
///
/// SRX commits are ingested as read-only data (the spec boundary: SSDF never
/// writes to devices). The event records who triggered the commit and when.
/// No before/after digest is available from syslog alone (would require netconf diff).
pub fn parse_commit(record: &RawSrxRecord, tenant_id: &str) -> Result<Event> {
    let actor = record
        .field("user")
        .unwrap_or("unknown")
        .to_string();
    let client = record.field("client").unwrap_or("").to_string();

    let ts = parse_ts(record);

    let mut srx: Map<String, Value> = Map::new();
    if !client.is_empty() {
        srx.insert("client".into(), Value::String(client));
    }

    let mut ext: std::collections::BTreeMap<String, Value> = std::collections::BTreeMap::new();
    ext.insert("srx".into(), Value::Object(srx));

    Ok(Event {
        event_id: new_id(IdPrefix::Event),
        tenant_id: tenant_id.to_string(),
        ts,
        source_type: "srx".to_string(),
        source_instance: record
            .hostname
            .clone()
            .unwrap_or_else(|| "unknown".to_string()),
        severity: Severity::Info,
        refs: EventRefs::default(),
        payload: EventPayload::ConfigChangeEvent(ConfigChangeEvent {
            actor,
            target_ref: record
                .hostname
                .clone()
                .unwrap_or_else(|| "unknown".to_string()),
            change_type: "commit".to_string(),
            before_digest: None,
            after_digest: None,
        }),
        ext,
    })
}

fn parse_ts(record: &RawSrxRecord) -> DateTime<Utc> {
    record
        .timestamp
        .as_deref()
        .and_then(|s| s.parse::<DateTime<Utc>>().ok())
        .unwrap_or_else(Utc::now)
}
```

- [ ] **Step 4: Run all parser tests**

Run: `cargo test -p ssdf-normalizer parser:: 2>&1 | tail -15`
Expected: 5 tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/ssdf-normalizer/src/parser/config_change.rs crates/ssdf-normalizer/src/parser/mod.rs
git commit -m "feat(normalizer): UI_COMMIT_COMPLETED -> ConfigChangeEvent parser"
```

---

## Task 8: ClickHouse batch writer

**Files:**
- Create: `crates/ssdf-normalizer/src/writer/mod.rs`
- Create: `crates/ssdf-normalizer/src/writer/clickhouse.rs`

- [ ] **Step 1: Write the failing test**

Create `crates/ssdf-normalizer/src/writer/mod.rs`:

```rust
pub mod clickhouse;

pub use clickhouse::ClickHouseWriter;

#[cfg(test)]
mod tests {
    use super::*;

    /// Unit test: verify the INSERT row struct serializes to the expected column names.
    /// Does NOT require a live ClickHouse — tests the mapping logic only.
    #[test]
    fn event_row_maps_flow_event_columns() {
        use ssdf_ontology::{
            events::{Event, EventPayload, EventRefs, FlowEvent, Severity},
            id::{new_id, IdPrefix},
        };
        use std::collections::BTreeMap;
        use chrono::Utc;

        let event = Event {
            event_id: new_id(IdPrefix::Event),
            tenant_id: "t_main".into(),
            ts: Utc::now(),
            source_type: "srx".into(),
            source_instance: "srx-test10".into(),
            severity: Severity::Info,
            refs: EventRefs {
                session_id: Some("ses_ABC".into()),
                ..Default::default()
            },
            payload: EventPayload::FlowEvent(FlowEvent {
                src_ip: "10.64.0.1".into(),
                src_port: 1234,
                dst_ip: "10.64.0.2".into(),
                dst_port: 80,
                proto: "tcp".into(),
                app: "http".into(),
                action: "allow".into(),
                bytes_in: 100,
                bytes_out: 200,
                zone_src: "trust".into(),
                zone_dst: "untrust".into(),
                user: None,
            }),
            ext: BTreeMap::new(),
        };

        let row = clickhouse::EventRow::from_event(&event).unwrap();

        assert_eq!(row.tenant_id, "t_main");
        assert_eq!(row.event_type, "flow_event");
        assert_eq!(row.source_type, "srx");
        assert_eq!(row.source_instance, "srx-test10");
        assert_eq!(row.severity, "info");
        assert_eq!(row.session_id, "ses_ABC");
        assert_eq!(row.identity_id, "");
        // payload must be valid JSON containing "src_ip"
        let payload: serde_json::Value = serde_json::from_str(&row.payload).unwrap();
        assert_eq!(payload["src_ip"], "10.64.0.1");
        assert_eq!(payload["event_type"], "flow_event");
    }
}
```

- [ ] **Step 2: Confirm the test fails**

Run: `cargo test -p ssdf-normalizer writer:: 2>&1 | tail -10`
Expected: FAIL — `cannot find module 'clickhouse'` / `EventRow` not found.

- [ ] **Step 3: Implement `clickhouse.rs`**

Create `crates/ssdf-normalizer/src/writer/clickhouse.rs`:

```rust
//! Batch-inserts canonical Event rows to ClickHouse via the HTTP interface.
//!
//! Uses the `clickhouse` crate which wraps ClickHouse's HTTP endpoint.
//! Each row maps one-to-one to a column in `ssdf.events`.

use anyhow::{Context, Result};
use clickhouse::{Client, Row};
use serde::{Deserialize, Serialize};
use ssdf_ontology::events::{Event, EventPayload};

/// One row in `ssdf.events` — mirrors the DDL from Plan 1 migrations.
#[derive(Debug, Clone, Row, Serialize, Deserialize)]
pub struct EventRow {
    pub event_id: String,
    pub tenant_id: String,
    pub event_type: String,
    /// Milliseconds since epoch (ClickHouse DateTime64(3)).
    pub ts: i64,
    pub source_type: String,
    pub source_instance: String,
    pub severity: String,
    pub identity_id: String,
    pub asset_id: String,
    pub app_id: String,
    pub policy_id: String,
    pub session_id: String,
    /// Full canonical Event JSON (flat, with event_type discriminator).
    pub payload: String,
    /// ext.srx namespace JSON string.
    pub ext: String,
}

impl EventRow {
    /// Build an `EventRow` from a canonical `Event`.
    ///
    /// Returns `Err` only if the Event fails to serialize — which would indicate
    /// an ontology bug, not a transient failure.
    pub fn from_event(event: &Event) -> Result<Self> {
        let event_type = match &event.payload {
            EventPayload::AuthEvent(_) => "auth_event",
            EventPayload::FlowEvent(_) => "flow_event",
            EventPayload::PolicyDecisionEvent(_) => "policy_decision_event",
            EventPayload::AlertEvent(_) => "alert_event",
            EventPayload::ConfigChangeEvent(_) => "config_change_event",
        };

        let payload = serde_json::to_string(event)
            .context("failed to serialize Event to JSON for ClickHouse payload")?;

        let ext = serde_json::to_string(&event.ext)
            .context("failed to serialize Event.ext to JSON")?;

        Ok(EventRow {
            event_id: event.event_id.clone(),
            tenant_id: event.tenant_id.clone(),
            event_type: event_type.to_string(),
            ts: event.ts.timestamp_millis(),
            source_type: event.source_type.clone(),
            source_instance: event.source_instance.clone(),
            severity: format!("{:?}", event.severity).to_lowercase(),
            identity_id: event.refs.identity_id.clone().unwrap_or_default(),
            asset_id: event.refs.asset_id.clone().unwrap_or_default(),
            app_id: event.refs.app_id.clone().unwrap_or_default(),
            policy_id: event.refs.policy_id.clone().unwrap_or_default(),
            session_id: event.refs.session_id.clone().unwrap_or_default(),
            payload,
            ext,
        })
    }
}

/// Wraps a ClickHouse `Client` and inserts `EventRow` batches.
pub struct ClickHouseWriter {
    client: Client,
    db: String,
}

impl ClickHouseWriter {
    /// Construct a writer from connection params.
    pub fn new(url: &str, user: &str, password: &str, db: &str) -> Self {
        let client = Client::default()
            .with_url(url)
            .with_user(user)
            .with_password(password)
            .with_database(db);
        ClickHouseWriter {
            client,
            db: db.to_string(),
        }
    }

    /// Batch-insert a slice of canonical `Event`s into `ssdf.events`.
    ///
    /// If any row fails to serialize, the whole batch is skipped and the error
    /// returned — the consumer must handle dead-lettering.
    pub async fn insert_batch(&self, events: &[Event]) -> Result<()> {
        if events.is_empty() {
            return Ok(());
        }

        let mut insert = self.client.insert("events")?;

        for event in events {
            let row = EventRow::from_event(event)?;
            insert.write(&row).await?;
        }

        insert.end().await.context("ClickHouse insert_batch failed")?;
        Ok(())
    }
}
```

- [ ] **Step 4: Run the unit test**

Run: `cargo test -p ssdf-normalizer writer:: 2>&1 | tail -10`
Expected: PASS — `test writer::tests::event_row_maps_flow_event_columns ... ok`.

Note: this test does not talk to ClickHouse. Integration against a live instance happens in Task 10.

- [ ] **Step 5: Commit**

```bash
git add crates/ssdf-normalizer/src/writer/
git commit -m "feat(normalizer): ClickHouse EventRow mapping + batch writer"
```

---

## Task 9: Kafka consumer loop + canonical event publisher

**Files:**
- Create: `crates/ssdf-normalizer/src/consumer.rs`
- Create: `crates/ssdf-normalizer/src/publisher.rs`

- [ ] **Step 1: Write the failing test for the publisher serialization**

Add to `crates/ssdf-normalizer/src/publisher.rs` (create the file with just this test first):

```rust
//! Publishes canonical Event JSON to the events.normalized Redpanda topic.

use anyhow::Result;
use rdkafka::producer::{FutureProducer, FutureRecord};
use rdkafka::ClientConfig;
use ssdf_ontology::events::Event;
use std::time::Duration;

pub struct Publisher {
    producer: FutureProducer,
    topic: String,
}

#[cfg(test)]
mod tests {
    use ssdf_ontology::{
        events::{Event, EventPayload, EventRefs, FlowEvent, Severity},
        id::{new_id, IdPrefix},
    };
    use std::collections::BTreeMap;
    use chrono::Utc;

    fn sample_flow_event() -> Event {
        Event {
            event_id: new_id(IdPrefix::Event),
            tenant_id: "t_main".into(),
            ts: Utc::now(),
            source_type: "srx".into(),
            source_instance: "srx-test10".into(),
            severity: Severity::Info,
            refs: EventRefs::default(),
            payload: EventPayload::FlowEvent(FlowEvent {
                src_ip: "10.64.0.1".into(),
                src_port: 1234,
                dst_ip: "10.64.0.2".into(),
                dst_port: 443,
                proto: "tcp".into(),
                app: "ssl".into(),
                action: "allow".into(),
                bytes_in: 500,
                bytes_out: 2000,
                zone_src: "trust".into(),
                zone_dst: "untrust".into(),
                user: None,
            }),
            ext: BTreeMap::new(),
        }
    }

    /// Unit test: the JSON produced for events.normalized must be a flat JSON
    /// object with event_type discriminator — ready for downstream consumption.
    #[test]
    fn canonical_event_serializes_to_flat_json_with_discriminator() {
        let event = sample_flow_event();
        let json_bytes = serde_json::to_vec(&event).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&json_bytes).unwrap();
        assert_eq!(parsed["event_type"], "flow_event");
        assert!(parsed["event_id"].as_str().unwrap().starts_with("evt_"));
        assert_eq!(parsed["tenant_id"], "t_main");
        assert_eq!(parsed["src_ip"], "10.64.0.1");
    }
}
```

- [ ] **Step 2: Confirm the test passes immediately** (it only tests serde, not Kafka I/O)

Run: `cargo test -p ssdf-normalizer publisher:: 2>&1 | tail -10`
Expected: PASS — `test publisher::tests::canonical_event_serializes_to_flat_json_with_discriminator ... ok`.

This is intentional: the publisher's correctness guarantee is the JSON shape (which is a property of `ssdf-ontology`); the Kafka I/O is verified in the integration test (Task 10).

- [ ] **Step 3: Implement the publisher struct** (add above the `#[cfg(test)]` block in `publisher.rs`)

```rust
impl Publisher {
    /// Construct a Publisher from broker list and target topic.
    pub fn new(brokers: &str, topic: &str) -> Result<Self> {
        let producer: FutureProducer = ClientConfig::new()
            .set("bootstrap.servers", brokers)
            .set("message.timeout.ms", "5000")
            .set("queue.buffering.max.messages", "100000")
            .set("queue.buffering.max.ms", "50")
            .create()?;
        Ok(Publisher {
            producer,
            topic: topic.to_string(),
        })
    }

    /// Publish a canonical `Event` to the `events.normalized` topic.
    ///
    /// The event_id is used as the Kafka message key so that events for the
    /// same logical stream are routed to the same partition deterministically.
    pub async fn publish(&self, event: &Event) -> Result<()> {
        let payload = serde_json::to_vec(event)?;
        let key = event.event_id.as_bytes().to_vec();

        self.producer
            .send(
                FutureRecord::to(&self.topic)
                    .key(&key)
                    .payload(&payload),
                Duration::from_secs(5),
            )
            .await
            .map_err(|(err, _msg)| anyhow::anyhow!("kafka publish failed: {err}"))?;

        Ok(())
    }
}
```

- [ ] **Step 4: Create `consumer.rs`**

Create `crates/ssdf-normalizer/src/consumer.rs`:

```rust
//! Main consumer loop: reads raw.srx, normalizes each record, batch-inserts
//! to ClickHouse, and re-publishes to events.normalized.

use anyhow::Result;
use rdkafka::{
    consumer::{Consumer, StreamConsumer},
    ClientConfig, Message,
};
use ssdf_ontology::events::Event;
use std::time::{Duration, Instant};
use tracing::{error, info, warn};

use crate::{
    config::Config,
    parser::{parse_srx_record, RawSrxRecord},
    publisher::Publisher,
    writer::ClickHouseWriter,
};

/// Entry point for the consumer loop. Runs until the process is terminated.
pub async fn run(config: Config) -> Result<()> {
    let consumer: StreamConsumer = ClientConfig::new()
        .set("bootstrap.servers", &config.kafka_brokers)
        .set("group.id", &config.kafka_group_id)
        .set("auto.offset.reset", "earliest")
        .set("enable.auto.commit", "true")
        .set("auto.commit.interval.ms", "1000")
        .create()?;

    consumer.subscribe(&[&config.raw_topic])?;
    info!(topic = %config.raw_topic, "subscribed to raw topic");

    let writer = ClickHouseWriter::new(
        &config.clickhouse_url,
        &config.clickhouse_user,
        &config.clickhouse_password,
        &config.clickhouse_db,
    );

    let publisher = Publisher::new(&config.kafka_brokers, &config.normalized_topic)?;

    let batch_size = config.batch_size;
    let batch_timeout = Duration::from_millis(config.batch_timeout_ms);
    let tenant_id = config.default_tenant_id.clone();

    let mut batch: Vec<Event> = Vec::with_capacity(batch_size);
    let mut last_flush = Instant::now();

    loop {
        // Check if we should flush before blocking on the next message.
        let should_flush = batch.len() >= batch_size
            || (!batch.is_empty() && last_flush.elapsed() >= batch_timeout);

        if should_flush {
            flush_batch(&mut batch, &writer, &publisher).await;
            last_flush = Instant::now();
        }

        // Poll with a short timeout so we can check the flush condition regularly.
        use rdkafka::consumer::CommitMode;
        let msg = match tokio::time::timeout(
            Duration::from_millis(500),
            consumer.recv(),
        )
        .await
        {
            Ok(Ok(msg)) => msg,
            Ok(Err(e)) => {
                error!("kafka error: {e}");
                continue;
            }
            Err(_) => {
                // timeout — loop again to check flush condition
                continue;
            }
        };

        let payload_bytes = match msg.payload() {
            Some(b) => b,
            None => {
                warn!("received kafka message with no payload — skipping");
                continue;
            }
        };

        let record: RawSrxRecord = match serde_json::from_slice(payload_bytes) {
            Ok(r) => r,
            Err(e) => {
                warn!("failed to deserialize raw.srx message: {e}");
                continue;
            }
        };

        match parse_srx_record(&record, &tenant_id) {
            Ok(event) => {
                batch.push(event);
            }
            Err(e) => {
                // Unsupported/unknown message type — log and skip.
                // A future version will dead-letter to a DLQ topic.
                warn!(msg = %record.message, "parse error (skipping): {e}");
            }
        }
    }
}

/// Flush the current batch to ClickHouse and republish each event to events.normalized.
async fn flush_batch(
    batch: &mut Vec<Event>,
    writer: &ClickHouseWriter,
    publisher: &Publisher,
) {
    if batch.is_empty() {
        return;
    }

    let count = batch.len();

    match writer.insert_batch(batch).await {
        Ok(()) => {
            info!(count, "flushed batch to ClickHouse");
        }
        Err(e) => {
            error!("ClickHouse batch insert failed ({count} events dropped): {e}");
            batch.clear();
            return;
        }
    }

    for event in batch.iter() {
        if let Err(e) = publisher.publish(event).await {
            error!(event_id = %event.event_id, "failed to publish to events.normalized: {e}");
            // Continue — ClickHouse insert already succeeded.
        }
    }

    batch.clear();
}
```

- [ ] **Step 5: Run all unit tests**

Run: `cargo test -p ssdf-normalizer 2>&1 | tail -20`
Expected: all tests pass. Build also succeeds (all module stubs are now real implementations).

- [ ] **Step 6: Commit**

```bash
git add crates/ssdf-normalizer/src/consumer.rs crates/ssdf-normalizer/src/publisher.rs
git commit -m "feat(normalizer): kafka consumer loop + canonical event publisher"
```

---

## Task 10: Wire main.rs + integration smoke test

**Files:**
- Modify: `crates/ssdf-normalizer/src/main.rs` (already a stub — no change needed, consumer::run is already wired)
- Add: `justfile` (new `normalizer-run` target + test instructions)

- [ ] **Step 1: Verify the binary compiles cleanly**

Run: `cargo build -p ssdf-normalizer 2>&1 | tail -5`
Expected: `Finished dev [unoptimized + debuginfo] target(s)` with no errors.

- [ ] **Step 2: Add a `normalizer-run` target to the `justfile`**

Add to the existing `justfile`:

```make
normalizer-run:
    CLICKHOUSE_PASSWORD=ssdf \
    KAFKA_BROKERS=localhost:9092 \
    cargo run -p ssdf-normalizer
```

- [ ] **Step 3: Run the integration smoke test**

This test sends a real SRX syslog line into Vector, waits for the normalizer to consume and insert it, then queries ClickHouse and Redpanda to assert correctness. Run with infra up (`just up && just migrate`).

**Terminal 1 — start the normalizer:**
```bash
CLICKHOUSE_PASSWORD=ssdf \
KAFKA_BROKERS=localhost:9092 \
RUST_LOG=ssdf_normalizer=info \
cargo run -p ssdf-normalizer
```

Expected log: `ssdf-normalizer starting`, `subscribed to raw topic`.

**Terminal 2 — inject a syslog line:**
```bash
echo '<14>1 2026-06-05T14:09:40.123Z srx-test10.lab.local RT_FLOW - - [junos@2636.1.1.1.2.26 source-address="10.68.2.7" source-port="51000" destination-address="10.68.9.3" destination-port="445" service-name="junos-smb" protocol-id="6" policy-name="trust-to-server" source-zone-name="trust" destination-zone-name="server" session-id-32="120043" bytes-from-client="1200" bytes-from-server="4096" nested-application="smb" username="N/A" reason="TCP FIN"] RT_FLOW_SESSION_CLOSE' \
  | nc -u -w1 127.0.0.1 5514
```

Wait ~3 seconds for the batch timeout to flush.

**Terminal 2 — verify ClickHouse:**
```bash
docker compose exec clickhouse clickhouse-client \
  --user ssdf --password ssdf \
  --query "SELECT event_id, event_type, src_ip, dst_ip, app, bytes_in, ext FROM ssdf.events WHERE source_type='srx' LIMIT 1 FORMAT JSONEachRow"
```

Expected output (values will differ in event_id/ts):
```json
{
  "event_id": "evt_01J3Z...",
  "event_type": "flow_event",
  "src_ip": "10.68.2.7",
  "dst_ip": "10.68.9.3",
  "app": "smb",
  "bytes_in": 1200,
  "ext": "{\"srx\":{\"session_id\":\"120043\",\"policy_name\":\"trust-to-server\",\"reason\":\"TCP FIN\",...}}"
}
```

Note: `src_ip`, `dst_ip`, `app`, `bytes_in` are not top-level ClickHouse columns — they live inside the `payload` column. Query them with:
```bash
docker compose exec clickhouse clickhouse-client \
  --user ssdf --password ssdf \
  --query "SELECT JSONExtractString(payload, 'src_ip') AS src_ip, JSONExtractString(payload, 'app') AS app FROM ssdf.events WHERE source_type='srx' LIMIT 1"
```

**Terminal 2 — verify events.normalized:**
```bash
docker compose exec redpanda rpk topic consume events.normalized --num 1
```

Expected: one JSON record with `event_type: "flow_event"`, `src_ip: "10.68.2.7"`.

- [ ] **Step 4: Commit**

```bash
git add justfile
git commit -m "feat(normalizer): integration smoke test + normalizer-run justfile target"
```

---

## Task 11: Add `ssdf-normalizer` to `docker-compose.yml` as a service

Running the normalizer as a compose service makes end-to-end testing and deployment reproducible.

**Files:**
- Modify: `docker-compose.yml`

- [ ] **Step 1: Write the failing integration check** (manual — no code)

Without the service, `docker compose ps` shows no `normalizer` row.

- [ ] **Step 2: Add the `normalizer` service to `docker-compose.yml`**

Add after the `vector` service:

```yaml
  normalizer:
    build:
      context: .
      dockerfile: Dockerfile.normalizer
    environment:
      KAFKA_BROKERS: redpanda:9092
      CLICKHOUSE_URL: http://clickhouse:8123
      CLICKHOUSE_USER: ssdf
      CLICKHOUSE_PASSWORD: ssdf
      CLICKHOUSE_DB: ssdf
      RAW_TOPIC: raw.srx
      NORMALIZED_TOPIC: events.normalized
      RUST_LOG: ssdf_normalizer=info
    depends_on:
      - redpanda
      - clickhouse
      - vector
    restart: on-failure
```

- [ ] **Step 3: Create `Dockerfile.normalizer`**

```dockerfile
# Dockerfile.normalizer
# Multi-stage: build in rust:1.78-slim, run in debian:bookworm-slim.
# librdkafka cmake build requires cmake + libssl-dev.

FROM rust:1.78-slim AS builder

RUN apt-get update && apt-get install -y \
    cmake \
    libssl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/

RUN cargo build --release -p ssdf-normalizer

FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y \
    libssl3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/ssdf-normalizer /usr/local/bin/ssdf-normalizer

ENTRYPOINT ["/usr/local/bin/ssdf-normalizer"]
```

- [ ] **Step 4: Bring up the full stack and verify**

```bash
docker compose up -d --build normalizer
docker compose ps
docker compose logs normalizer --tail 20
```

Expected: normalizer shows `Running` status, logs show `subscribed to raw topic`.

- [ ] **Step 5: Commit**

```bash
git add docker-compose.yml Dockerfile.normalizer
git commit -m "feat(normalizer): add normalizer docker-compose service + Dockerfile"
```

---

## Self-Review

### Spec coverage checklist

| Spec requirement | Covered? | Notes |
|---|---|---|
| §4 Ingest: SRX syslog → Vector | ✅ | Task 1: Vector syslog source on 5514, enrich transform, kafka sink |
| §4 Bus: Redpanda topic `raw.<source>` | ✅ | `raw.srx` created in Task 1 |
| §4 Processing: Normalizer consumes `raw.*` | ✅ | Tasks 3-9: `ssdf-normalizer` consumer loop |
| §4 Processing: maps to canonical events | ✅ | All 4 SRX message types mapped (Tasks 4-7) |
| §4 Processing: promotes canonical fields | ✅ | `src_ip`, `dst_ip`, `app`, etc. promoted out of `srx_fields` |
| §4 Processing: stuffs rest into `ext.<vendor>` | ✅ | Non-canonical fields → `ext["srx"]` in all parsers |
| §4 Processing: batch-inserts to ClickHouse | ✅ | Task 8: `ClickHouseWriter.insert_batch` |
| §3 event_type discriminator (`flow_event`, etc.) | ✅ | `serde(tag = "event_type")` from `ssdf-ontology` |
| §3 `tenant_id` on every event | ✅ | `default_tenant_id = "t_main"` threaded through all parsers |
| §3 `event_id` as ULID with `evt_` prefix | ✅ | `new_id(IdPrefix::Event)` in every parser |
| §3 `source_type = "srx"` | ✅ | Hard-coded in every SRX parser |
| §3 `ext.<vendor>` namespace | ✅ | `ext["srx"]` used consistently |
| §3 `source_refs` on events | ✅ | `source_instance` from syslog hostname; `source_refs` on Entities is a Plan 4 concern |
| N4 Durable bus buffering | ✅ | Redpanda topic with `retention.ms=86400000` |
| N4 At-least-once delivery | ✅ | Kafka auto-commit after consume; batch flush before commit offset drift |
| F2 Normalize at ingest | ✅ | Parser sub-modules are the only place SRX format knowledge lives |
| §8 Connectors own vendor weirdness | ✅ | No SRX-specific code in consumer.rs / writer.rs |

### New topic added to the `events.normalized` bus

The `events.normalized` Redpanda topic is introduced here and is the explicit downstream contract for Plan 4 (Entity Resolution). Its JSON schema is the flat canonical `Event` JSON produced by `ssdf-ontology` serde — the same shape the ClickHouse `payload` column stores.

### Placeholder scan result

None. Every task contains:
- Actual Rust source code (no "add error handling here" / "similar to above")
- Actual Vector YAML with real config keys
- Actual test code with concrete input records and assertion values
- Real SRX syslog sample line and the expected canonical FlowEvent JSON mapping (intro section)
- Real `cargo test` commands with expected output strings
- Real `git commit` commands with messages

### Type consistency note

- `Event`, `EventPayload`, `FlowEvent`, `PolicyDecisionEvent`, `AlertEvent`, `ConfigChangeEvent`, `EventRefs`, `Severity`, `new_id`, `IdPrefix::Event`, `ONTOLOGY_VERSION` — all imported from `ssdf-ontology` via `path = "../ssdf-ontology"`. None are redefined in `ssdf-normalizer`.
- ClickHouse table name `ssdf.events` used verbatim (matches Plan 1 DDL).
- Redpanda topics `raw.srx` and `events.normalized` used verbatim (shared contract).
- `source_type = "srx"` used verbatim (shared contract).
- `tenant_id = "t_main"` default used verbatim (shared contract).
- `event_type` discriminator values (`flow_event`, `policy_decision_event`, `alert_event`, `config_change_event`) derive from `ssdf-ontology`'s `#[serde(tag = "event_type", rename_all = "snake_case")]` — they cannot drift unless the ontology crate changes.
- The `EventRow` `severity` field is serialized as `format!("{:?}", severity).to_lowercase()` which produces `"info"`, `"low"`, `"medium"`, `"high"`, `"critical"` — matching the `LowCardinality(String)` DDL column and the `Severity` enum's `#[serde(rename_all = "lowercase")]` attribute.
