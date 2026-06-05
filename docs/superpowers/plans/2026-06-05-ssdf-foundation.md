# SSDF Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up the SSDF monorepo with a typed canonical-ontology Rust crate and the dual-store infra (ClickHouse, Neo4j, Postgres, Redpanda, MinIO) plus its schema, so every later subsystem builds on a shared, tested foundation.

**Architecture:** A Cargo workspace holds Rust crates; `ssdf-ontology` is the shared library defining global IDs, the 5 canonical event types, and the 8 entity types with serde JSON. Infra runs via `docker-compose`; storage schemas are plain SQL/Cypher DDL applied by a `just` task and checked by a verification script.

**Tech Stack:** Rust (edition 2021), `ulid`, `serde`, `serde_json`, `chrono`; Docker Compose (Redpanda, ClickHouse 24.x, Neo4j 5 Community, Postgres 16, MinIO); `just` task runner.

**Spec:** `docs/superpowers/specs/2026-06-05-ssdf-data-fabric-design.md` (§3 Ontology, §4 Data Plane).

---

## File Structure

```
SSDF/
├── Cargo.toml                         # workspace root
├── justfile                           # dev tasks (up/down/migrate/verify/test)
├── docker-compose.yml                 # Redpanda, ClickHouse, Neo4j, Postgres, MinIO
├── crates/
│   └── ssdf-ontology/
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs                 # module wiring + re-exports
│           ├── id.rs                  # global ID minting + parsing
│           ├── events.rs              # Event envelope + 5 event payloads
│           ├── entities.rs            # Entity envelope + 8 entity bodies
│           └── version.rs             # ONTOLOGY_VERSION constant
├── migrations/
│   ├── clickhouse/001_events.sql      # events + audit tables
│   ├── postgres/001_config.sql        # sources, resolution_keys, sovereignty_policy
│   └── neo4j/001_constraints.cypher   # uniqueness constraints per entity label
└── scripts/
    └── verify_schema.sh               # applies DDL + asserts objects exist
```

Each ontology module has one responsibility (IDs, events, entities, version). DDL is split by store. The verify script is the integration test for the infra/schema task.

---

## Task 1: Workspace scaffold

**Files:**
- Create: `Cargo.toml`
- Create: `crates/ssdf-ontology/Cargo.toml`
- Create: `crates/ssdf-ontology/src/lib.rs`

- [ ] **Step 1: Create the workspace root `Cargo.toml`**

```toml
[workspace]
resolver = "2"
members = ["crates/ssdf-ontology"]

[workspace.package]
edition = "2021"
license = "Apache-2.0"

[workspace.dependencies]
ulid = "1"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
chrono = { version = "0.4", features = ["serde"] }
```

- [ ] **Step 2: Create the crate `Cargo.toml`**

```toml
[package]
name = "ssdf-ontology"
version = "0.1.0"
edition.workspace = true
license.workspace = true

[dependencies]
ulid.workspace = true
serde.workspace = true
serde_json.workspace = true
chrono.workspace = true
```

- [ ] **Step 3: Create a placeholder `src/lib.rs` so the crate compiles**

```rust
//! SSDF canonical ontology: global IDs, events, and entities.
```

- [ ] **Step 4: Verify the workspace builds**

Run: `cargo build`
Expected: compiles cleanly — `Compiling ssdf-ontology v0.1.0` then `Finished`.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml crates/ssdf-ontology/Cargo.toml crates/ssdf-ontology/src/lib.rs
git commit -m "chore: scaffold cargo workspace + ssdf-ontology crate"
```

---

## Task 2: Global IDs (`id.rs`)

Type-prefixed ULIDs: `idn_<ULID>`, `ast_`, `app_`, `seg_`, `pol_`, `ses_`, `alr_`, `inc_`, plus `evt_` (events) and `src_` (sources).

**Files:**
- Create: `crates/ssdf-ontology/src/id.rs`
- Modify: `crates/ssdf-ontology/src/lib.rs`

- [ ] **Step 1: Write the failing tests**

Create `crates/ssdf-ontology/src/id.rs`:

```rust
use std::fmt;
use ulid::Ulid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdPrefix {
    Identity,
    Asset,
    Application,
    NetworkSegment,
    PolicyObject,
    Session,
    Alert,
    Incident,
    Event,
    Source,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_id_has_prefix() {
        let id = new_id(IdPrefix::Identity);
        assert!(id.starts_with("idn_"), "got {id}");
    }

    #[test]
    fn parse_roundtrips_prefix() {
        let id = new_id(IdPrefix::Asset);
        let (prefix, _ulid) = parse_id(&id).expect("should parse");
        assert_eq!(prefix, IdPrefix::Asset);
    }

    #[test]
    fn ids_are_unique() {
        assert_ne!(new_id(IdPrefix::Event), new_id(IdPrefix::Event));
    }

    #[test]
    fn rejects_bad_ids() {
        assert!(parse_id("nope").is_err());
        assert!(parse_id("zzz_01ARZ3NDEKTSV4RRFFQ69G5FAV").is_err());
        assert!(parse_id("idn_not-a-ulid").is_err());
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p ssdf-ontology id::`
Expected: FAIL — `cannot find function 'new_id'` / `parse_id`.

- [ ] **Step 3: Implement the minimal code**

Add above the `#[cfg(test)]` block in `crates/ssdf-ontology/src/id.rs`:

```rust
impl IdPrefix {
    pub fn as_str(self) -> &'static str {
        match self {
            IdPrefix::Identity => "idn",
            IdPrefix::Asset => "ast",
            IdPrefix::Application => "app",
            IdPrefix::NetworkSegment => "seg",
            IdPrefix::PolicyObject => "pol",
            IdPrefix::Session => "ses",
            IdPrefix::Alert => "alr",
            IdPrefix::Incident => "inc",
            IdPrefix::Event => "evt",
            IdPrefix::Source => "src",
        }
    }

    pub fn from_code(code: &str) -> Option<IdPrefix> {
        Some(match code {
            "idn" => IdPrefix::Identity,
            "ast" => IdPrefix::Asset,
            "app" => IdPrefix::Application,
            "seg" => IdPrefix::NetworkSegment,
            "pol" => IdPrefix::PolicyObject,
            "ses" => IdPrefix::Session,
            "alr" => IdPrefix::Alert,
            "inc" => IdPrefix::Incident,
            "evt" => IdPrefix::Event,
            "src" => IdPrefix::Source,
            _ => return None,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct IdParseError(pub String);

impl fmt::Display for IdParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid ssdf id: {}", self.0)
    }
}

impl std::error::Error for IdParseError {}

/// Mint a new globally-unique, type-prefixed, lexicographically-sortable id.
pub fn new_id(prefix: IdPrefix) -> String {
    format!("{}_{}", prefix.as_str(), Ulid::new())
}

/// Parse an id into its prefix and ULID, validating both.
pub fn parse_id(s: &str) -> Result<(IdPrefix, Ulid), IdParseError> {
    let (code, rest) = s.split_once('_').ok_or_else(|| IdParseError(s.to_string()))?;
    let prefix = IdPrefix::from_code(code).ok_or_else(|| IdParseError(s.to_string()))?;
    let ulid = Ulid::from_string(rest).map_err(|_| IdParseError(s.to_string()))?;
    Ok((prefix, ulid))
}
```

Wire the module in `crates/ssdf-ontology/src/lib.rs`:

```rust
//! SSDF canonical ontology: global IDs, events, and entities.

pub mod id;

pub use id::{new_id, parse_id, IdParseError, IdPrefix};
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p ssdf-ontology id::`
Expected: PASS — 4 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/ssdf-ontology/src/id.rs crates/ssdf-ontology/src/lib.rs
git commit -m "feat(ontology): type-prefixed ULID global ids"
```

---

## Task 3: Event types (`events.rs`)

The `Event` envelope (shared fields) carries one of 5 internally-tagged payloads. JSON is flat with an `event_type` discriminator.

**Files:**
- Create: `crates/ssdf-ontology/src/events.rs`
- Modify: `crates/ssdf-ontology/src/lib.rs`

- [ ] **Step 1: Write the failing tests**

Create `crates/ssdf-ontology/src/events.rs`:

```rust
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct EventRefs {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub identity_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub asset_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub app_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub policy_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub session_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_flow() -> Event {
        Event {
            event_id: "evt_01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
            tenant_id: "t_main".into(),
            ts: "2026-06-05T14:09:40Z".parse::<DateTime<Utc>>().unwrap(),
            source_type: "srx".into(),
            source_instance: "srx-test10".into(),
            severity: Severity::Info,
            refs: EventRefs {
                session_id: Some("ses_01ARZ3NDEKTSV4RRFFQ69G5FB0".into()),
                ..Default::default()
            },
            payload: EventPayload::FlowEvent(FlowEvent {
                src_ip: "10.68.2.7".into(),
                src_port: 51000,
                dst_ip: "10.68.9.3".into(),
                dst_port: 445,
                proto: "tcp".into(),
                app: "smb".into(),
                action: "allow".into(),
                bytes_in: 1200,
                bytes_out: 4096,
                zone_src: "trust".into(),
                zone_dst: "server".into(),
                user: None,
            }),
            ext: BTreeMap::new(),
        }
    }

    #[test]
    fn flow_event_roundtrips() {
        let event = sample_flow();
        let json = serde_json::to_string(&event).unwrap();
        let back: Event = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    #[test]
    fn flow_event_has_discriminator() {
        let json = serde_json::to_value(sample_flow()).unwrap();
        assert_eq!(json["event_type"], "flow_event");
        assert_eq!(json["dst_port"], 445);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p ssdf-ontology events::`
Expected: FAIL — `cannot find type 'Event'` / `EventPayload` / `FlowEvent`.

- [ ] **Step 3: Implement the minimal code**

Add above the `#[cfg(test)]` block in `crates/ssdf-ontology/src/events.rs`:

```rust
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Event {
    pub event_id: String,
    pub tenant_id: String,
    pub ts: DateTime<Utc>,
    pub source_type: String,
    pub source_instance: String,
    pub severity: Severity,
    #[serde(default)]
    pub refs: EventRefs,
    #[serde(flatten)]
    pub payload: EventPayload,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub ext: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event_type", rename_all = "snake_case")]
pub enum EventPayload {
    AuthEvent(AuthEvent),
    FlowEvent(FlowEvent),
    PolicyDecisionEvent(PolicyDecisionEvent),
    AlertEvent(AlertEvent),
    ConfigChangeEvent(ConfigChangeEvent),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthEvent {
    pub actor: String,
    pub outcome: String,
    pub mfa: bool,
    pub auth_method: String,
    pub src_ip: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub geo: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub risk: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FlowEvent {
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub proto: String,
    pub app: String,
    pub action: String,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub zone_src: String,
    pub zone_dst: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub user: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyDecisionEvent {
    pub policy_ref: String,
    pub decision: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub matched_on: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AlertEvent {
    pub rule_id: String,
    pub title: String,
    pub category: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub confidence: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub affected_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub affected_user: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConfigChangeEvent {
    pub actor: String,
    pub target_ref: String,
    pub change_type: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub before_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub after_digest: Option<String>,
}
```

Add to `crates/ssdf-ontology/src/lib.rs`:

```rust
pub mod events;

pub use events::{
    AlertEvent, AuthEvent, ConfigChangeEvent, Event, EventPayload, EventRefs, FlowEvent,
    PolicyDecisionEvent, Severity,
};
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p ssdf-ontology events::`
Expected: PASS — 2 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/ssdf-ontology/src/events.rs crates/ssdf-ontology/src/lib.rs
git commit -m "feat(ontology): canonical event types with tagged payloads"
```

---

## Task 4: Entity types + ontology version (`entities.rs`, `version.rs`)

The `Entity` envelope carries one of 8 internally-tagged bodies (`kind` discriminator). Minimal but faithful field sets per spec §3.

**Files:**
- Create: `crates/ssdf-ontology/src/entities.rs`
- Create: `crates/ssdf-ontology/src/version.rs`
- Modify: `crates/ssdf-ontology/src/lib.rs`

- [ ] **Step 1: Write the failing tests**

Create `crates/ssdf-ontology/src/entities.rs`:

```rust
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SourceRef {
    pub source_type: String,
    pub source_instance: String,
    pub source_id: String,
    pub observed_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_identity() -> Entity {
        Entity {
            id: "idn_01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
            tenant_id: "t_main".into(),
            first_seen: "2026-06-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap(),
            last_seen: "2026-06-05T14:02:11Z".parse::<DateTime<Utc>>().unwrap(),
            source_refs: vec![SourceRef {
                source_type: "okta".into(),
                source_instance: "okta-main".into(),
                source_id: "00u123".into(),
                observed_at: "2026-06-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap(),
            }],
            body: EntityBody::Identity(IdentityBody {
                display_name: "Alice Example".into(),
                kind: "user".into(),
                primary_email: Some("alice@example.com".into()),
                status: "active".into(),
                risk_score: Some(12),
                groups: vec!["admins".into()],
            }),
            ext: BTreeMap::new(),
            labels: BTreeMap::new(),
        }
    }

    #[test]
    fn identity_roundtrips() {
        let entity = sample_identity();
        let json = serde_json::to_string(&entity).unwrap();
        let back: Entity = serde_json::from_str(&json).unwrap();
        assert_eq!(entity, back);
    }

    #[test]
    fn identity_has_kind_discriminator() {
        let json = serde_json::to_value(sample_identity()).unwrap();
        assert_eq!(json["kind"], "identity");
        assert_eq!(json["display_name"], "Alice Example");
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p ssdf-ontology entities::`
Expected: FAIL — `cannot find type 'Entity'` / `EntityBody` / `IdentityBody`.

- [ ] **Step 3: Implement the minimal code**

Add above the `#[cfg(test)]` block in `crates/ssdf-ontology/src/entities.rs`:

```rust
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Entity {
    pub id: String,
    pub tenant_id: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    #[serde(default)]
    pub source_refs: Vec<SourceRef>,
    #[serde(flatten)]
    pub body: EntityBody,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub ext: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EntityBody {
    Identity(IdentityBody),
    Asset(AssetBody),
    Application(ApplicationBody),
    NetworkSegment(NetworkSegmentBody),
    PolicyObject(PolicyObjectBody),
    Session(SessionBody),
    Alert(AlertBody),
    Incident(IncidentBody),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IdentityBody {
    pub display_name: String,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub primary_email: Option<String>,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub risk_score: Option<i32>,
    #[serde(default)]
    pub groups: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssetBody {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub ips: Vec<String>,
    #[serde(default)]
    pub macs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub os: Option<String>,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub criticality: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub exposure: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApplicationBody {
    pub name: String,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub app_id: Option<String>,
    #[serde(default)]
    pub dst_ports: Vec<u16>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub category: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetworkSegmentBody {
    pub name: String,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub cidr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub trust_level: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyObjectBody {
    pub name: String,
    pub kind: String,
    pub action: String,
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub rule_index: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub device_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionBody {
    pub kind: String,
    pub start: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub end: Option<DateTime<Utc>>,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub identity_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub app_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub verdict: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AlertBody {
    pub title: String,
    pub severity: String,
    pub category: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub confidence: Option<f32>,
    #[serde(default)]
    pub affected_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IncidentBody {
    pub title: String,
    pub severity: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub alert_refs: Vec<String>,
}
```

Create `crates/ssdf-ontology/src/version.rs`:

```rust
/// Semantic version of the canonical ontology. Bump on any breaking field change.
pub const ONTOLOGY_VERSION: &str = "1.0.0";
```

Add to `crates/ssdf-ontology/src/lib.rs`:

```rust
pub mod entities;
pub mod version;

pub use entities::{
    AlertBody, ApplicationBody, AssetBody, Entity, EntityBody, IdentityBody, IncidentBody,
    NetworkSegmentBody, PolicyObjectBody, SessionBody, SourceRef,
};
pub use version::ONTOLOGY_VERSION;
```

- [ ] **Step 4: Run all crate tests to verify they pass**

Run: `cargo test -p ssdf-ontology`
Expected: PASS — all tests from Tasks 2-4 green (8 total).

- [ ] **Step 5: Commit**

```bash
git add crates/ssdf-ontology/src/entities.rs crates/ssdf-ontology/src/version.rs crates/ssdf-ontology/src/lib.rs
git commit -m "feat(ontology): canonical entity types + ontology version"
```

---

## Task 5: Infra docker-compose + justfile

**Files:**
- Create: `docker-compose.yml`
- Create: `justfile`

- [ ] **Step 1: Create `docker-compose.yml`**

```yaml
name: ssdf
services:
  redpanda:
    image: redpandadata/redpanda:v24.2.7
    command:
      - redpanda start
      - --smp 1
      - --overprovisioned
      - --kafka-addr PLAINTEXT://0.0.0.0:9092
      - --advertise-kafka-addr PLAINTEXT://localhost:9092
    ports: ["9092:9092"]

  clickhouse:
    image: clickhouse/clickhouse-server:24.8
    environment:
      CLICKHOUSE_DB: ssdf
      CLICKHOUSE_USER: ssdf
      CLICKHOUSE_PASSWORD: ssdf
    ports: ["8123:8123", "9000:9000"]
    ulimits:
      nofile: { soft: 262144, hard: 262144 }

  neo4j:
    image: neo4j:5.23-community
    environment:
      NEO4J_AUTH: neo4j/ssdfssdf
    ports: ["7474:7474", "7687:7687"]

  postgres:
    image: postgres:16
    environment:
      POSTGRES_DB: ssdf
      POSTGRES_USER: ssdf
      POSTGRES_PASSWORD: ssdf
    ports: ["5432:5432"]

  minio:
    image: minio/minio:RELEASE.2024-08-17T01-24-54Z
    command: server /data --console-address ":9001"
    environment:
      MINIO_ROOT_USER: ssdf
      MINIO_ROOT_PASSWORD: ssdfssdf
    ports: ["9002:9000", "9001:9001"]
```

- [ ] **Step 2: Create `justfile`**

```make
set shell := ["bash", "-uc"]

up:
    docker compose up -d

down:
    docker compose down -v

test:
    cargo test

migrate:
    bash scripts/verify_schema.sh apply

verify:
    bash scripts/verify_schema.sh verify
```

- [ ] **Step 3: Bring the stack up**

Run: `just up`
Expected: all 5 services reach `Started`. Confirm with `docker compose ps` — every service `running`.

- [ ] **Step 4: Commit**

```bash
git add docker-compose.yml justfile
git commit -m "chore: docker-compose infra (redpanda, clickhouse, neo4j, postgres, minio) + justfile"
```

---

## Task 6: Storage schema DDL + verification

**Files:**
- Create: `migrations/clickhouse/001_events.sql`
- Create: `migrations/postgres/001_config.sql`
- Create: `migrations/neo4j/001_constraints.cypher`
- Create: `scripts/verify_schema.sh`

- [ ] **Step 1: Create the ClickHouse DDL** `migrations/clickhouse/001_events.sql`

```sql
CREATE DATABASE IF NOT EXISTS ssdf;

CREATE TABLE IF NOT EXISTS ssdf.events
(
    event_id        String,
    tenant_id       LowCardinality(String),
    event_type      LowCardinality(String),
    ts              DateTime64(3, 'UTC'),
    source_type     LowCardinality(String),
    source_instance LowCardinality(String),
    severity        LowCardinality(String),
    identity_id     String DEFAULT '',
    asset_id        String DEFAULT '',
    app_id          String DEFAULT '',
    policy_id       String DEFAULT '',
    session_id      String DEFAULT '',
    payload         String,
    ext             String DEFAULT '{}'
)
ENGINE = MergeTree
PARTITION BY (tenant_id, toDate(ts))
ORDER BY (tenant_id, event_type, ts, event_id)
TTL toDateTime(ts) + INTERVAL 30 DAY;

CREATE TABLE IF NOT EXISTS ssdf.audit
(
    ts                   DateTime64(3, 'UTC'),
    request_id           String,
    tenant_id            LowCardinality(String),
    caller               String,
    tier                 LowCardinality(String),
    server               LowCardinality(String),
    tool                 String,
    args_digest          String,
    datasets_touched     Array(String),
    sovereignty_decision LowCardinality(String),
    rows_returned        UInt32,
    redactions_applied   Array(String),
    latency_ms           UInt32,
    outcome              LowCardinality(String)
)
ENGINE = MergeTree
ORDER BY (ts, request_id);
```

- [ ] **Step 2: Create the Postgres DDL** `migrations/postgres/001_config.sql`

```sql
CREATE TABLE IF NOT EXISTS sources (
    id         text PRIMARY KEY,
    type       text NOT NULL,
    name       text NOT NULL,
    tenant_id  text NOT NULL,
    connection jsonb NOT NULL DEFAULT '{}',
    secret_ref text,
    status     text NOT NULL DEFAULT 'pending',
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS resolution_keys (
    tenant_id   text NOT NULL,
    kind        text NOT NULL,
    natural_key text NOT NULL,
    global_id   text NOT NULL,
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, kind, natural_key)
);

CREATE TABLE IF NOT EXISTS sovereignty_policy (
    id         bigserial PRIMARY KEY,
    version    int NOT NULL,
    document   jsonb NOT NULL,
    active     boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now()
);
```

- [ ] **Step 3: Create the Neo4j constraints** `migrations/neo4j/001_constraints.cypher`

```cypher
CREATE CONSTRAINT identity_id IF NOT EXISTS FOR (n:Identity) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT asset_id IF NOT EXISTS FOR (n:Asset) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT application_id IF NOT EXISTS FOR (n:Application) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT segment_id IF NOT EXISTS FOR (n:NetworkSegment) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT policy_id IF NOT EXISTS FOR (n:PolicyObject) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT session_id IF NOT EXISTS FOR (n:Session) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT alert_id IF NOT EXISTS FOR (n:Alert) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT incident_id IF NOT EXISTS FOR (n:Incident) REQUIRE n.id IS UNIQUE;
```

- [ ] **Step 4: Create the verification script** `scripts/verify_schema.sh`

```bash
#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-verify}"

ch() { docker compose exec -T clickhouse clickhouse-client --user ssdf --password ssdf "$@"; }
pg() { docker compose exec -T postgres psql -U ssdf -d ssdf -v ON_ERROR_STOP=1 "$@"; }
cy() { docker compose exec -T neo4j cypher-shell -u neo4j -p ssdfssdf "$@"; }

if [[ "$MODE" == "apply" ]]; then
  ch --multiquery < migrations/clickhouse/001_events.sql
  pg < migrations/postgres/001_config.sql
  cy < migrations/neo4j/001_constraints.cypher
  echo "APPLIED"
  exit 0
fi

# verify
EVENTS=$(ch --query "EXISTS TABLE ssdf.events")
AUDIT=$(ch --query "EXISTS TABLE ssdf.audit")
SOURCES=$(pg -tAc "SELECT to_regclass('public.sources') IS NOT NULL")
CONSTRAINTS=$(cy --format plain "SHOW CONSTRAINTS YIELD name RETURN count(*) AS c" | tail -n1 | tr -d '[:space:]')

echo "events=$EVENTS audit=$AUDIT sources=$SOURCES constraints=$CONSTRAINTS"
[[ "$EVENTS" == "1" && "$AUDIT" == "1" && "$SOURCES" == "t" && "$CONSTRAINTS" -ge "8" ]] \
  && echo "OK" || { echo "SCHEMA VERIFY FAILED"; exit 1; }
```

- [ ] **Step 5: Apply and verify the schema**

Run: `chmod +x scripts/verify_schema.sh && just migrate && just verify`
Expected: ends with `events=1 audit=1 sources=t constraints=8` then `OK`.

- [ ] **Step 6: Commit**

```bash
git add migrations scripts/verify_schema.sh
git commit -m "feat(storage): clickhouse/postgres/neo4j schema + verify script"
```

---

## Self-Review

**Spec coverage (foundation slice):**
- §3 two-layer model → `Event`/`Entity` envelopes (Tasks 3-4). ✅
- §3 8 entities + 5 events → all present (Tasks 3-4). ✅
- §3 type-prefixed ULID global IDs → `id.rs` (Task 2). ✅
- §3 vendor extensions (`ext`) → `ext` map on `Event` + `Entity`. ✅
- §3 `source_refs` provenance → `SourceRef` on `Entity`. ✅
- §3 ontology versioning (N7) → `ONTOLOGY_VERSION` (Task 4). ✅
- §4 dual store + bus + cold → docker-compose (Task 5). ✅
- §4 ClickHouse partition/TTL, Postgres config/resolution/policy, Neo4j constraints → migrations (Task 6). ✅
- Out of foundation scope (later plans): Vector/normalizer (Plan 2), connectors (Plan 3), resolution logic (Plan 4), services (Plan 5), MCP/sovereignty (Plan 6). Tracked in the plan sequence.

**Placeholder scan:** none — every step has concrete code/commands.

**Type consistency:** `IdPrefix` codes match across `as_str`/`from_code`; `EventPayload`/`EntityBody` variant names match their body structs; `lib.rs` re-exports match defined type names; `event_type`/`kind` discriminators match the DDL `event_type` column and Neo4j labels.

**Note on entity `Session` envelope:** spec lists `src_ref`/`dst_ref`/`bytes` on Session; v0 `SessionBody` omits these (network endpoints are carried on `FlowEvent`; notable-session enrichment lands in Plan 4). Intentional minimal-v0 scoping, not a gap.
