# SSDF Entity Resolution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the `ssdf-resolver` Rust binary that consumes canonical events from the `events.normalized` Redpanda topic, resolves natural keys to stable global IDs (deterministic, recorded in Postgres `resolution_keys`), upserts Entity nodes + relationships into Neo4j over Bolt, materializes only *notable* Sessions while rolling routine flows into `Asset -TALKS_TO-> Asset|Application` aggregate edges, and emits auditable, reversible merge/resolution events.

**Architecture:** The crate is split into PURE decision logic (natural-key extraction, deterministic global-id assignment, notable-session classification, TALKS_TO rollup) that is unit-testable with zero I/O, and two thin I/O adapters behind traits — a Postgres `KeyStore` and a Neo4j `GraphWriter` — so the core is tested against in-memory fakes. A `main.rs` Kafka consume loop wires real adapters around the pure core; merge/resolution decisions are emitted as `ResolutionEvent`s (reversible) to the `events.resolution` topic and persisted via the keystore.

**Tech Stack:** Rust (edition 2021), `tokio`, `rdkafka` (Kafka/Redpanda consumer + producer), `sqlx` (Postgres, `runtime-tokio`), `neo4rs` (Neo4j Bolt), `serde`/`serde_json`, `chrono`, `ssdf-ontology` (path dep — `Event`, `EventPayload`, `Entity`, `EntityBody`, `SourceRef`, `new_id`, `IdPrefix`).

**Spec:** `docs/superpowers/specs/2026-06-05-ssdf-data-fabric-design.md` (§3 Ontology — entities, relationships, natural keys, scaling rule, IDs & extensions; §4 Processing/Storage). Builds on `docs/superpowers/plans/2026-06-05-ssdf-foundation.md` (Plan 1 — `ssdf-ontology` crate, Neo4j constraints, Postgres `resolution_keys`).

---

## File Structure

```
SSDF/
├── Cargo.toml                              # workspace root — add ssdf-resolver to members
└── crates/
    └── ssdf-resolver/
        ├── Cargo.toml                      # binary crate manifest + deps
        └── src/
            ├── main.rs                     # tokio entrypoint: Kafka consume loop wiring real adapters
            ├── lib.rs                      # module wiring + re-exports (so tests import the crate)
            ├── keys.rs                     # PURE: natural-key extraction from an Event (per entity kind)
            ├── resolve.rs                  # PURE: KeyStore-trait-driven global-id assignment + merge decisions
            ├── notable.rs                  # PURE: notable-session decision + TALKS_TO rollup decision
            ├── plan.rs                     # PURE: turn one Event into a GraphPlan (entities+edges to write)
            ├── keystore.rs                 # KeyStore trait + Postgres impl + in-memory fake (test cfg)
            ├── graph.rs                    # GraphWriter trait + Neo4j Bolt impl + recording fake (test cfg)
            ├── events.rs                   # ResolutionEvent type (reversible merge/resolution audit record)
            └── tests/
                ├── identity_resolution.rs  # integration-of-pure-units: Identity resolve + idempotent re-resolve
                ├── asset_resolution.rs     # Asset resolve by ip+window vs hostname
                ├── notable_rules.rs        # auth always notable; allowed short flow → rollup; denied → notable
                └── reverse_merge.rs        # merge then reverse, asserting keystore + emitted events
```

Responsibilities (one line each):
- `keys.rs` — natural-key extraction: maps an `Event` to a list of `NaturalKey { kind, key }` candidates, no I/O.
- `resolve.rs` — global-id assignment: given a `NaturalKey` and a `KeyStore`, return an existing or freshly-minted global id; produce `MergeDecision`s.
- `notable.rs` — notable-session + rollup rules: pure predicates over `Event`/`FlowEvent`/`AuthEvent` returning `SessionDisposition`.
- `plan.rs` — composes `keys` + `resolve` + `notable` into a `GraphPlan` (entity upserts + edge upserts + rollup increments).
- `keystore.rs` — `KeyStore` async trait (`lookup`, `assign`, `record_merge`, `reverse_merge`); Postgres impl + `InMemoryKeyStore` fake.
- `graph.rs` — `GraphWriter` async trait (`upsert_entity`, `upsert_edge`, `bump_talks_to`); Neo4j impl + `RecordingGraphWriter` fake.
- `events.rs` — `ResolutionEvent` (kind: `resolved`/`merged`/`merge_reversed`) carrying before/after ids for reversibility + audit.
- `plan.rs`/`main.rs` — `main.rs` is the only file that touches Kafka/Postgres/Neo4j over the network; everything it calls is pure or trait-bounded.

---

## Task 1: Crate scaffold + workspace wiring

**Files:**
- Modify: `Cargo.toml` (workspace root — add member + shared deps)
- Create: `crates/ssdf-resolver/Cargo.toml`
- Create: `crates/ssdf-resolver/src/lib.rs`
- Create: `crates/ssdf-resolver/src/main.rs`

- [ ] **Step 1: Add the crate to the workspace + declare shared deps**

Edit the root `Cargo.toml`. Change the `members` line and append the new workspace deps:

```toml
[workspace]
resolver = "2"
members = ["crates/ssdf-ontology", "crates/ssdf-resolver"]

[workspace.package]
edition = "2021"
license = "Apache-2.0"

[workspace.dependencies]
ulid = "1"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
chrono = { version = "0.4", features = ["serde"] }
tokio = { version = "1", features = ["macros", "rt-multi-thread", "signal"] }
rdkafka = { version = "0.36", features = ["cmake-build", "tokio"] }
sqlx = { version = "0.8", default-features = false, features = ["runtime-tokio", "postgres", "macros", "chrono"] }
neo4rs = "0.8"
anyhow = "1"
ssdf-ontology = { path = "crates/ssdf-ontology" }
```

- [ ] **Step 2: Create `crates/ssdf-resolver/Cargo.toml`**

```toml
[package]
name = "ssdf-resolver"
version = "0.1.0"
edition.workspace = true
license.workspace = true

[[bin]]
name = "ssdf-resolver"
path = "src/main.rs"

[lib]
name = "ssdf_resolver"
path = "src/lib.rs"

[dependencies]
ssdf-ontology.workspace = true
serde.workspace = true
serde_json.workspace = true
chrono.workspace = true
tokio.workspace = true
rdkafka.workspace = true
sqlx.workspace = true
neo4rs.workspace = true
anyhow.workspace = true
```

- [ ] **Step 3: Create a placeholder `src/lib.rs`**

```rust
//! SSDF entity resolution: natural-key extraction, deterministic global-id
//! assignment, notable-session classification, and graph projection.
```

- [ ] **Step 4: Create a placeholder `src/main.rs` so the binary compiles**

```rust
fn main() {
    println!("ssdf-resolver: not yet wired");
}
```

- [ ] **Step 5: Verify the workspace builds**

Run: `cargo build -p ssdf-resolver`
Expected: compiles cleanly — ends with `Finished`. (First build compiles `rdkafka`/`sqlx`/`neo4rs`; this is slow but should succeed. If `cmake`/`libsasl2` is missing, install build deps first: `sudo apt-get install -y cmake libsasl2-dev`.)

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml crates/ssdf-resolver/Cargo.toml crates/ssdf-resolver/src/lib.rs crates/ssdf-resolver/src/main.rs
git commit -m "chore(resolver): scaffold ssdf-resolver binary crate"
```

---

## Task 2: Natural-key extraction (`keys.rs`)

Per spec §3, each event yields candidate natural keys: Identity → `email:<addr>` or `okta_user:<id>`; Asset → `hostname:<h>`, `mac:<m>`, `wazuh_agent:<id>`, or `ip:<addr>@<window>` (time bucketed); Application → `okta_app:<id>`, `fwapp:<id>`, or `dstipport:<ip>:<port>`. Extraction is PURE — it reads an `Event` and returns ordered `NaturalKey` candidates (most-specific first).

**Files:**
- Create: `crates/ssdf-resolver/src/keys.rs`
- Modify: `crates/ssdf-resolver/src/lib.rs`

- [ ] **Step 1: Write the failing tests**

Create `crates/ssdf-resolver/src/keys.rs`:

```rust
use chrono::{DateTime, Timelike, Utc};
use ssdf_ontology::{AuthEvent, Event, EventPayload, FlowEvent};

/// The entity kind a natural key resolves to. String value is the `kind`
/// column written to Postgres `resolution_keys` and matches the ontology
/// snake_case discriminator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntityKind {
    Identity,
    Asset,
    Application,
}

impl EntityKind {
    pub fn as_str(self) -> &'static str {
        match self {
            EntityKind::Identity => "identity",
            EntityKind::Asset => "asset",
            EntityKind::Application => "application",
        }
    }
}

/// A deterministic natural key: `(kind, key)` is unique within a tenant and
/// maps to exactly one global id in `resolution_keys`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NaturalKey {
    pub kind: EntityKind,
    pub key: String,
}

/// Time-window bucket (hour granularity) used to scope ip-based asset keys so a
/// recycled DHCP lease in a later window resolves to a distinct asset.
pub fn ip_window(ts: DateTime<Utc>) -> String {
    ts.format("%Y%m%dT%H").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use std::collections::BTreeMap;

    fn auth(actor: &str, user_ext: Option<(&str, &str)>) -> Event {
        let mut ext = BTreeMap::new();
        if let Some((k, v)) = user_ext {
            ext.insert(k.to_string(), serde_json::json!(v));
        }
        Event {
            event_id: "evt_01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
            tenant_id: "t_main".into(),
            ts: Utc.with_ymd_and_hms(2026, 6, 5, 14, 9, 40).unwrap(),
            source_type: "okta".into(),
            source_instance: "okta-main".into(),
            severity: ssdf_ontology::Severity::Info,
            refs: Default::default(),
            payload: EventPayload::AuthEvent(AuthEvent {
                actor: actor.into(),
                outcome: "success".into(),
                mfa: true,
                auth_method: "password".into(),
                src_ip: "10.68.2.7".into(),
                geo: None,
                risk: None,
            }),
            ext,
        }
    }

    fn flow(src_ip: &str, dst_ip: &str, dst_port: u16, user: Option<&str>) -> Event {
        Event {
            event_id: "evt_01ARZ3NDEKTSV4RRFFQ69G5FB1".into(),
            tenant_id: "t_main".into(),
            ts: Utc.with_ymd_and_hms(2026, 6, 5, 14, 9, 40).unwrap(),
            source_type: "srx".into(),
            source_instance: "srx-test10".into(),
            severity: ssdf_ontology::Severity::Info,
            refs: Default::default(),
            payload: EventPayload::FlowEvent(FlowEvent {
                src_ip: src_ip.into(),
                src_port: 51000,
                dst_ip: dst_ip.into(),
                dst_port,
                proto: "tcp".into(),
                app: "smb".into(),
                action: "allow".into(),
                bytes_in: 1200,
                bytes_out: 4096,
                zone_src: "trust".into(),
                zone_dst: "server".into(),
                user: user.map(|u| u.into()),
            }),
            ext: BTreeMap::new(),
        }
    }

    #[test]
    fn identity_key_prefers_okta_user_id() {
        let event = auth("alice@example.com", Some(("okta_user_id", "00u123")));
        let keys = identity_keys(&event);
        assert_eq!(
            keys[0],
            NaturalKey { kind: EntityKind::Identity, key: "okta_user:00u123".into() }
        );
        assert_eq!(
            keys[1],
            NaturalKey { kind: EntityKind::Identity, key: "email:alice@example.com".into() }
        );
    }

    #[test]
    fn identity_key_falls_back_to_email() {
        let event = auth("alice@example.com", None);
        let keys = identity_keys(&event);
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].key, "email:alice@example.com");
    }

    #[test]
    fn identity_email_is_lowercased() {
        let event = auth("Alice@Example.COM", None);
        let keys = identity_keys(&event);
        assert_eq!(keys[0].key, "email:alice@example.com");
    }

    #[test]
    fn asset_key_prefers_hostname_then_ip_window() {
        let mut event = flow("10.68.2.7", "10.68.9.3", 445, None);
        event.ext.insert("src_hostname".into(), serde_json::json!("WS-ALICE"));
        let keys = asset_src_keys(&event);
        assert_eq!(keys[0], NaturalKey { kind: EntityKind::Asset, key: "hostname:ws-alice".into() });
        assert_eq!(
            keys[1],
            NaturalKey { kind: EntityKind::Asset, key: "ip:10.68.2.7@20260605T14".into() }
        );
    }

    #[test]
    fn asset_key_ip_only_when_no_hostname() {
        let event = flow("10.68.2.7", "10.68.9.3", 445, None);
        let keys = asset_src_keys(&event);
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].key, "ip:10.68.2.7@20260605T14");
    }

    #[test]
    fn application_key_is_dst_ip_port() {
        let event = flow("10.68.2.7", "10.68.9.3", 445, None);
        let keys = application_keys(&event);
        assert_eq!(
            keys[0],
            NaturalKey { kind: EntityKind::Application, key: "dstipport:10.68.9.3:445".into() }
        );
    }

    #[test]
    fn ip_window_buckets_by_hour() {
        let ts = Utc.with_ymd_and_hms(2026, 6, 5, 14, 59, 59).unwrap();
        assert_eq!(ip_window(ts), "20260605T14");
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p ssdf-resolver keys::`
Expected: FAIL — `cannot find function 'identity_keys'` / `asset_src_keys` / `application_keys`.

- [ ] **Step 3: Implement the minimal code**

Add above the `#[cfg(test)]` block in `crates/ssdf-resolver/src/keys.rs`:

```rust
fn ext_str(event: &Event, field: &str) -> Option<String> {
    event.ext.get(field).and_then(|v| v.as_str()).map(|s| s.to_string())
}

/// Identity natural keys, most-specific first: okta_user_id (if present in
/// ext), then the lowercased actor email.
pub fn identity_keys(event: &Event) -> Vec<NaturalKey> {
    let EventPayload::AuthEvent(auth) = &event.payload else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if let Some(uid) = ext_str(event, "okta_user_id") {
        out.push(NaturalKey { kind: EntityKind::Identity, key: format!("okta_user:{uid}") });
    }
    if auth.actor.contains('@') {
        out.push(NaturalKey {
            kind: EntityKind::Identity,
            key: format!("email:{}", auth.actor.to_lowercase()),
        });
    }
    out
}

fn flow(event: &Event) -> Option<&FlowEvent> {
    match &event.payload {
        EventPayload::FlowEvent(flow) => Some(flow),
        _ => None,
    }
}

/// Asset natural keys for the flow SOURCE, most-specific first: hostname (ext
/// `src_hostname`, lowercased), mac (ext `src_mac`), wazuh_agent (ext
/// `wazuh_agent_id`), then `ip:<src_ip>@<hour-window>`.
pub fn asset_src_keys(event: &Event) -> Vec<NaturalKey> {
    let Some(flow) = flow(event) else { return Vec::new() };
    let mut out = Vec::new();
    if let Some(h) = ext_str(event, "src_hostname") {
        out.push(NaturalKey { kind: EntityKind::Asset, key: format!("hostname:{}", h.to_lowercase()) });
    }
    if let Some(m) = ext_str(event, "src_mac") {
        out.push(NaturalKey { kind: EntityKind::Asset, key: format!("mac:{}", m.to_lowercase()) });
    }
    if let Some(a) = ext_str(event, "wazuh_agent_id") {
        out.push(NaturalKey { kind: EntityKind::Asset, key: format!("wazuh_agent:{a}") });
    }
    out.push(NaturalKey {
        kind: EntityKind::Asset,
        key: format!("ip:{}@{}", flow.src_ip, ip_window(event.ts)),
    });
    out
}

/// Asset natural keys for the flow DESTINATION (server side): ip+window only in
/// v0 (servers are stable; hostname enrichment lands later).
pub fn asset_dst_keys(event: &Event) -> Vec<NaturalKey> {
    let Some(flow) = flow(event) else { return Vec::new() };
    vec![NaturalKey {
        kind: EntityKind::Asset,
        key: format!("ip:{}@{}", flow.dst_ip, ip_window(event.ts)),
    }]
}

/// Application natural keys: fw app-id (ext `fw_app_id`), okta_app_id (ext
/// `okta_app_id`), then `(dst_ip,port)`.
pub fn application_keys(event: &Event) -> Vec<NaturalKey> {
    let Some(flow) = flow(event) else { return Vec::new() };
    let mut out = Vec::new();
    if let Some(id) = ext_str(event, "fw_app_id") {
        out.push(NaturalKey { kind: EntityKind::Application, key: format!("fwapp:{id}") });
    }
    if let Some(id) = ext_str(event, "okta_app_id") {
        out.push(NaturalKey { kind: EntityKind::Application, key: format!("okta_app:{id}") });
    }
    out.push(NaturalKey {
        kind: EntityKind::Application,
        key: format!("dstipport:{}:{}", flow.dst_ip, flow.dst_port),
    });
    out
}
```

Wire the module in `crates/ssdf-resolver/src/lib.rs`:

```rust
//! SSDF entity resolution: natural-key extraction, deterministic global-id
//! assignment, notable-session classification, and graph projection.

pub mod keys;

pub use keys::{
    application_keys, asset_dst_keys, asset_src_keys, identity_keys, ip_window, EntityKind,
    NaturalKey,
};
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p ssdf-resolver keys::`
Expected: PASS — 7 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/ssdf-resolver/src/keys.rs crates/ssdf-resolver/src/lib.rs
git commit -m "feat(resolver): pure natural-key extraction per entity kind"
```

---

## Task 3: Reversible resolution events (`events.rs`)

Per spec §3, "conflicts/merges are recorded as events (auditable, reversible)". A `ResolutionEvent` is the audit record + the reversibility mechanism: a `merged` event captures both the surviving and absorbed global ids plus the natural keys re-pointed, so a `merge_reversed` event can restore them. These are PURE serde types (no I/O).

**Files:**
- Create: `crates/ssdf-resolver/src/events.rs`
- Modify: `crates/ssdf-resolver/src/lib.rs`

- [ ] **Step 1: Write the failing tests**

Create `crates/ssdf-resolver/src/events.rs`:

```rust
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// What a ResolutionEvent records. snake_case in JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionKind {
    /// A natural key was first bound to a (possibly new) global id.
    Resolved,
    /// Two global ids were merged: `survivor_id` absorbs `absorbed_id`.
    Merged,
    /// A prior merge was undone, restoring `absorbed_id`.
    MergeReversed,
}

/// Auditable, reversible record of a resolution decision. Emitted to the
/// `events.resolution` topic and the audit trail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolutionEvent {
    pub resolution_id: String,
    pub tenant_id: String,
    pub kind: ResolutionKind,
    pub entity_kind: String,
    pub ts: DateTime<Utc>,
    /// The surviving / assigned global id.
    pub survivor_id: String,
    /// Present for `merged` / `merge_reversed`: the id absorbed (or restored).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub absorbed_id: Option<String>,
    /// Natural keys re-pointed by this event (so a reverse can restore them).
    #[serde(default)]
    pub repointed_keys: Vec<String>,
    /// The triggering source event id, for provenance.
    pub source_event_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn sample_merge() -> ResolutionEvent {
        ResolutionEvent {
            resolution_id: "evt_01ARZ3NDEKTSV4RRFFQ69G5FC0".into(),
            tenant_id: "t_main".into(),
            kind: ResolutionKind::Merged,
            entity_kind: "identity".into(),
            ts: Utc.with_ymd_and_hms(2026, 6, 5, 14, 9, 40).unwrap(),
            survivor_id: "idn_01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
            absorbed_id: Some("idn_01ARZ3NDEKTSV4RRFFQ69G5FB9".into()),
            repointed_keys: vec!["email:alice@example.com".into()],
            source_event_id: "evt_01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
        }
    }

    #[test]
    fn merge_event_roundtrips() {
        let event = sample_merge();
        let json = serde_json::to_string(&event).unwrap();
        let back: ResolutionEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    #[test]
    fn kind_serializes_snake_case() {
        let json = serde_json::to_value(sample_merge()).unwrap();
        assert_eq!(json["kind"], "merged");
        assert_eq!(json["survivor_id"], "idn_01ARZ3NDEKTSV4RRFFQ69G5FAV");
    }

    #[test]
    fn reverse_of_merge_restores_absorbed() {
        let merge = sample_merge();
        let reverse = reverse_event(
            &merge,
            "evt_01ARZ3NDEKTSV4RRFFQ69G5FD0".into(),
            Utc.with_ymd_and_hms(2026, 6, 5, 15, 0, 0).unwrap(),
        );
        assert_eq!(reverse.kind, ResolutionKind::MergeReversed);
        // The absorbed id becomes the thing restored; repointed keys are the
        // same set that were moved.
        assert_eq!(reverse.absorbed_id, merge.absorbed_id);
        assert_eq!(reverse.survivor_id, merge.survivor_id);
        assert_eq!(reverse.repointed_keys, merge.repointed_keys);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p ssdf-resolver events::`
Expected: FAIL — `cannot find function 'reverse_event'`.

- [ ] **Step 3: Implement the minimal code**

Add above the `#[cfg(test)]` block in `crates/ssdf-resolver/src/events.rs`:

```rust
/// Build the inverse of a `Merged` event: a `MergeReversed` carrying the same
/// survivor/absorbed/keys so a `KeyStore::reverse_merge` can restore the prior
/// natural-key bindings. Panics-free; callers pass a fresh id + ts.
pub fn reverse_event(merged: &ResolutionEvent, resolution_id: String, ts: DateTime<Utc>) -> ResolutionEvent {
    ResolutionEvent {
        resolution_id,
        tenant_id: merged.tenant_id.clone(),
        kind: ResolutionKind::MergeReversed,
        entity_kind: merged.entity_kind.clone(),
        ts,
        survivor_id: merged.survivor_id.clone(),
        absorbed_id: merged.absorbed_id.clone(),
        repointed_keys: merged.repointed_keys.clone(),
        source_event_id: merged.source_event_id.clone(),
    }
}
```

Add to `crates/ssdf-resolver/src/lib.rs`:

```rust
pub mod events;

pub use events::{reverse_event, ResolutionEvent, ResolutionKind};
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p ssdf-resolver events::`
Expected: PASS — 3 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/ssdf-resolver/src/events.rs crates/ssdf-resolver/src/lib.rs
git commit -m "feat(resolver): reversible ResolutionEvent audit record"
```

---

## Task 4: KeyStore trait + in-memory fake (`keystore.rs`)

The `KeyStore` is the only thing that knows about Postgres `resolution_keys`. The trait keeps resolution logic testable. Postgres impl uses `sqlx`. An `InMemoryKeyStore` fake backs all pure-logic tests. The trait is `async` (sqlx is async); fakes implement it trivially.

**Files:**
- Create: `crates/ssdf-resolver/src/keystore.rs`
- Modify: `crates/ssdf-resolver/src/lib.rs`

- [ ] **Step 1: Write the failing tests**

Create `crates/ssdf-resolver/src/keystore.rs`:

```rust
use crate::keys::NaturalKey;
use anyhow::Result;
use std::collections::HashMap;
use std::sync::Mutex;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::EntityKind;

    fn key(k: &str) -> NaturalKey {
        NaturalKey { kind: EntityKind::Identity, key: k.into() }
    }

    #[tokio::test]
    async fn assign_then_lookup_returns_same_id() {
        let store = InMemoryKeyStore::new();
        let id = store.assign("t_main", &key("email:alice@example.com"), "idn_NEW1").await.unwrap();
        assert_eq!(id, "idn_NEW1");
        let found = store.lookup("t_main", &key("email:alice@example.com")).await.unwrap();
        assert_eq!(found, Some("idn_NEW1".into()));
    }

    #[tokio::test]
    async fn assign_is_idempotent_keeps_first_id() {
        let store = InMemoryKeyStore::new();
        let first = store.assign("t_main", &key("email:bob@example.com"), "idn_FIRST").await.unwrap();
        // A second assign with a DIFFERENT candidate id must NOT overwrite.
        let second = store.assign("t_main", &key("email:bob@example.com"), "idn_SECOND").await.unwrap();
        assert_eq!(first, "idn_FIRST");
        assert_eq!(second, "idn_FIRST");
    }

    #[tokio::test]
    async fn lookup_missing_is_none() {
        let store = InMemoryKeyStore::new();
        assert_eq!(store.lookup("t_main", &key("email:nobody@x.com")).await.unwrap(), None);
    }

    #[tokio::test]
    async fn tenant_scoping_isolates_keys() {
        let store = InMemoryKeyStore::new();
        store.assign("t_main", &key("email:a@x.com"), "idn_MAIN").await.unwrap();
        assert_eq!(store.lookup("t_other", &key("email:a@x.com")).await.unwrap(), None);
    }

    #[tokio::test]
    async fn record_merge_repoints_keys_then_reverse_restores() {
        let store = InMemoryKeyStore::new();
        // Two identities discovered independently.
        store.assign("t_main", &key("email:alice@example.com"), "idn_A").await.unwrap();
        store.assign("t_main", &key("okta_user:00u123"), "idn_B").await.unwrap();
        // Merge B into A: repoint okta_user key onto survivor idn_A.
        store
            .record_merge("t_main", "idn_A", "idn_B", &[key("okta_user:00u123")])
            .await
            .unwrap();
        assert_eq!(
            store.lookup("t_main", &key("okta_user:00u123")).await.unwrap(),
            Some("idn_A".into())
        );
        // Reverse: okta_user key points back at idn_B.
        store
            .reverse_merge("t_main", "idn_A", "idn_B", &[key("okta_user:00u123")])
            .await
            .unwrap();
        assert_eq!(
            store.lookup("t_main", &key("okta_user:00u123")).await.unwrap(),
            Some("idn_B".into())
        );
        // idn_A's own key is untouched.
        assert_eq!(
            store.lookup("t_main", &key("email:alice@example.com")).await.unwrap(),
            Some("idn_A".into())
        );
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p ssdf-resolver keystore::`
Expected: FAIL — `cannot find type 'InMemoryKeyStore'`, `trait KeyStore` not found.

- [ ] **Step 3: Implement the trait + fake**

Add above the `#[cfg(test)]` block in `crates/ssdf-resolver/src/keystore.rs`:

```rust
/// Maps natural keys to stable global ids inside `resolution_keys`, and records
/// reversible merges. Async because the production impl is sqlx/Postgres.
#[allow(async_fn_in_trait)]
pub trait KeyStore {
    /// Return the global id currently bound to `(tenant, key)`, if any.
    async fn lookup(&self, tenant_id: &str, key: &NaturalKey) -> Result<Option<String>>;

    /// Bind `(tenant, key)` to a global id. If already bound, the EXISTING id
    /// wins (idempotent) and is returned; `candidate_id` is used only if the
    /// key is new. This is the determinism guarantee.
    async fn assign(&self, tenant_id: &str, key: &NaturalKey, candidate_id: &str) -> Result<String>;

    /// Re-point `keys` from `absorbed_id` onto `survivor_id` (a merge).
    async fn record_merge(
        &self,
        tenant_id: &str,
        survivor_id: &str,
        absorbed_id: &str,
        keys: &[NaturalKey],
    ) -> Result<()>;

    /// Re-point `keys` from `survivor_id` back onto `absorbed_id` (reverse a merge).
    async fn reverse_merge(
        &self,
        tenant_id: &str,
        survivor_id: &str,
        absorbed_id: &str,
        keys: &[NaturalKey],
    ) -> Result<()>;
}

/// In-memory `KeyStore` for unit tests. Keyed by `(tenant, kind, key)`.
#[derive(Default)]
pub struct InMemoryKeyStore {
    map: Mutex<HashMap<(String, String, String), String>>,
}

impl InMemoryKeyStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn k(tenant_id: &str, key: &NaturalKey) -> (String, String, String) {
        (tenant_id.to_string(), key.kind.as_str().to_string(), key.key.clone())
    }
}

impl KeyStore for InMemoryKeyStore {
    async fn lookup(&self, tenant_id: &str, key: &NaturalKey) -> Result<Option<String>> {
        Ok(self.map.lock().unwrap().get(&Self::k(tenant_id, key)).cloned())
    }

    async fn assign(&self, tenant_id: &str, key: &NaturalKey, candidate_id: &str) -> Result<String> {
        let mut map = self.map.lock().unwrap();
        let entry = map.entry(Self::k(tenant_id, key)).or_insert_with(|| candidate_id.to_string());
        Ok(entry.clone())
    }

    async fn record_merge(
        &self,
        tenant_id: &str,
        survivor_id: &str,
        _absorbed_id: &str,
        keys: &[NaturalKey],
    ) -> Result<()> {
        let mut map = self.map.lock().unwrap();
        for key in keys {
            map.insert(Self::k(tenant_id, key), survivor_id.to_string());
        }
        Ok(())
    }

    async fn reverse_merge(
        &self,
        tenant_id: &str,
        _survivor_id: &str,
        absorbed_id: &str,
        keys: &[NaturalKey],
    ) -> Result<()> {
        let mut map = self.map.lock().unwrap();
        for key in keys {
            map.insert(Self::k(tenant_id, key), absorbed_id.to_string());
        }
        Ok(())
    }
}
```

Add to `crates/ssdf-resolver/src/lib.rs`:

```rust
pub mod keystore;

pub use keystore::{InMemoryKeyStore, KeyStore};
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p ssdf-resolver keystore::`
Expected: PASS — 5 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/ssdf-resolver/src/keystore.rs crates/ssdf-resolver/src/lib.rs
git commit -m "feat(resolver): KeyStore trait + idempotent in-memory fake"
```

---

## Task 5: Deterministic global-id assignment (`resolve.rs`)

`resolve.rs` walks a key's candidate list (most-specific first), returns the first already-bound global id, else mints one for the most-specific key. Critically it ALSO binds every other candidate key to the chosen id so future events keyed differently resolve to the same entity — and when two different already-bound ids collide across candidates it emits a `MergeDecision` (survivor = the first/most-specific match). This is where reversibility originates. Logic is generic over `KeyStore`; tests use `InMemoryKeyStore`.

**Files:**
- Create: `crates/ssdf-resolver/src/resolve.rs`
- Modify: `crates/ssdf-resolver/src/lib.rs`

- [ ] **Step 1: Write the failing tests**

Create `crates/ssdf-resolver/src/resolve.rs`:

```rust
use crate::keys::{EntityKind, NaturalKey};
use crate::keystore::KeyStore;
use anyhow::Result;
use ssdf_ontology::{new_id, IdPrefix};

/// Outcome of resolving one ordered candidate list to a single global id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolution {
    pub global_id: String,
    /// Set when two pre-existing ids collided and were merged into `global_id`.
    pub merge: Option<MergeDecision>,
}

/// A reversible merge: `survivor_id` absorbs `absorbed_id`; `repointed_keys`
/// are the keys moved onto the survivor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeDecision {
    pub survivor_id: String,
    pub absorbed_id: String,
    pub repointed_keys: Vec<NaturalKey>,
}

fn prefix_for(kind: EntityKind) -> IdPrefix {
    match kind {
        EntityKind::Identity => IdPrefix::Identity,
        EntityKind::Asset => IdPrefix::Asset,
        EntityKind::Application => IdPrefix::Application,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::InMemoryKeyStore;

    fn ident(k: &str) -> NaturalKey {
        NaturalKey { kind: EntityKind::Identity, key: k.into() }
    }

    #[tokio::test]
    async fn first_resolution_mints_and_binds_all_candidates() {
        let store = InMemoryKeyStore::new();
        let candidates = vec![ident("okta_user:00u123"), ident("email:alice@example.com")];
        let res = resolve(&store, "t_main", EntityKind::Identity, &candidates).await.unwrap();
        assert!(res.global_id.starts_with("idn_"), "got {}", res.global_id);
        assert!(res.merge.is_none());
        // BOTH candidate keys now resolve to the same id.
        assert_eq!(
            store.lookup("t_main", &ident("okta_user:00u123")).await.unwrap(),
            Some(res.global_id.clone())
        );
        assert_eq!(
            store.lookup("t_main", &ident("email:alice@example.com")).await.unwrap(),
            Some(res.global_id.clone())
        );
    }

    #[tokio::test]
    async fn re_resolution_is_idempotent_same_id() {
        let store = InMemoryKeyStore::new();
        let candidates = vec![ident("email:alice@example.com")];
        let first = resolve(&store, "t_main", EntityKind::Identity, &candidates).await.unwrap();
        let second = resolve(&store, "t_main", EntityKind::Identity, &candidates).await.unwrap();
        assert_eq!(first.global_id, second.global_id);
        assert!(second.merge.is_none());
    }

    #[tokio::test]
    async fn colliding_bound_ids_produce_reversible_merge() {
        let store = InMemoryKeyStore::new();
        // Two events seen separately bound distinct ids to distinct keys.
        store.assign("t_main", &ident("okta_user:00u123"), "idn_OKTA").await.unwrap();
        store.assign("t_main", &ident("email:alice@example.com"), "idn_EMAIL").await.unwrap();
        // Now one event carries BOTH keys → collision → merge.
        let candidates = vec![ident("okta_user:00u123"), ident("email:alice@example.com")];
        let res = resolve(&store, "t_main", EntityKind::Identity, &candidates).await.unwrap();
        // Survivor is the most-specific (first) match.
        assert_eq!(res.global_id, "idn_OKTA");
        let merge = res.merge.expect("collision should merge");
        assert_eq!(merge.survivor_id, "idn_OKTA");
        assert_eq!(merge.absorbed_id, "idn_EMAIL");
        assert_eq!(merge.repointed_keys, vec![ident("email:alice@example.com")]);
        // After merge the email key now resolves to the survivor.
        assert_eq!(
            store.lookup("t_main", &ident("email:alice@example.com")).await.unwrap(),
            Some("idn_OKTA".into())
        );
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p ssdf-resolver resolve::`
Expected: FAIL — `cannot find function 'resolve'`.

- [ ] **Step 3: Implement the minimal code**

Add above the `#[cfg(test)]` block in `crates/ssdf-resolver/src/resolve.rs`:

```rust
/// Resolve an ordered (most-specific-first) candidate key list to ONE global id.
///
/// Determinism rules:
/// 1. The first candidate already bound to an id wins as the survivor.
/// 2. If no candidate is bound, mint a fresh id for the most-specific candidate.
/// 3. Every unbound candidate is then bound to the survivor (so future events
///    keyed differently converge).
/// 4. Any OTHER candidate bound to a DIFFERENT id is merged into the survivor
///    (reversible MergeDecision returned).
pub async fn resolve<S: KeyStore>(
    store: &S,
    tenant_id: &str,
    kind: EntityKind,
    candidates: &[NaturalKey],
) -> Result<Resolution> {
    debug_assert!(!candidates.is_empty(), "resolve requires >=1 candidate");

    // Look up every candidate's current binding.
    let mut bound: Vec<(usize, String)> = Vec::new();
    for (idx, key) in candidates.iter().enumerate() {
        if let Some(id) = store.lookup(tenant_id, key).await? {
            bound.push((idx, id));
        }
    }

    // Pick survivor: first bound id in candidate order, else mint for candidate[0].
    let survivor_id = match bound.first() {
        Some((_, id)) => id.clone(),
        None => store.assign(tenant_id, &candidates[0], &new_id(prefix_for(kind))).await?,
    };

    // Bind any unbound candidates to the survivor.
    for key in candidates {
        store.assign(tenant_id, key, &survivor_id).await?;
    }

    // Detect collisions: candidates bound to a DIFFERENT id than the survivor.
    let mut repointed_keys = Vec::new();
    let mut absorbed_id: Option<String> = None;
    for (idx, id) in &bound {
        if id != &survivor_id {
            absorbed_id = Some(id.clone());
            repointed_keys.push(candidates[*idx].clone());
        }
    }

    let merge = match absorbed_id {
        Some(absorbed) => {
            store
                .record_merge(tenant_id, &survivor_id, &absorbed, &repointed_keys)
                .await?;
            Some(MergeDecision {
                survivor_id: survivor_id.clone(),
                absorbed_id: absorbed,
                repointed_keys,
            })
        }
        None => None,
    };

    Ok(Resolution { global_id: survivor_id, merge })
}
```

Add to `crates/ssdf-resolver/src/lib.rs`:

```rust
pub mod resolve;

pub use resolve::{resolve, MergeDecision, Resolution};
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p ssdf-resolver resolve::`
Expected: PASS — 3 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/ssdf-resolver/src/resolve.rs crates/ssdf-resolver/src/lib.rs
git commit -m "feat(resolver): deterministic global-id assignment with reversible merge"
```

---

## Task 6: Notable-session + TALKS_TO rollup decision (`notable.rs`)

This is the spec's critical scaling rule (§3): auth sessions are ALWAYS notable; network flows are notable only when long-lived, denied, or alert-linked; routine allowed flows roll up into `Asset -TALKS_TO-> Asset|Application` aggregate edges. PURE — reads an `Event` and returns a `SessionDisposition`.

**Files:**
- Create: `crates/ssdf-resolver/src/notable.rs`
- Modify: `crates/ssdf-resolver/src/lib.rs`

- [ ] **Step 1: Write the failing tests**

Create `crates/ssdf-resolver/src/notable.rs`:

```rust
use ssdf_ontology::{Event, EventPayload};

/// Seconds above which a network flow counts as long-lived (→ notable).
pub const LONG_LIVED_SECS: u64 = 300;

/// What to do with the session implied by an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionDisposition {
    /// Materialize a Session graph node.
    Notable(NotableReason),
    /// Do NOT create a node; fold into an Asset-TALKS_TO aggregate edge.
    Rollup,
    /// Event implies no session (e.g. a standalone config change).
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotableReason {
    Auth,
    Denied,
    LongLived,
    AlertLinked,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use ssdf_ontology::{AuthEvent, FlowEvent, Severity};
    use std::collections::BTreeMap;

    fn base_flow() -> FlowEvent {
        FlowEvent {
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
        }
    }

    fn flow_event(flow: FlowEvent, ext: BTreeMap<String, serde_json::Value>) -> Event {
        Event {
            event_id: "evt_01ARZ3NDEKTSV4RRFFQ69G5FB1".into(),
            tenant_id: "t_main".into(),
            ts: Utc.with_ymd_and_hms(2026, 6, 5, 14, 9, 40).unwrap(),
            source_type: "srx".into(),
            source_instance: "srx-test10".into(),
            severity: Severity::Info,
            refs: Default::default(),
            payload: EventPayload::FlowEvent(flow),
            ext,
        }
    }

    fn auth_event() -> Event {
        Event {
            event_id: "evt_01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
            tenant_id: "t_main".into(),
            ts: Utc.with_ymd_and_hms(2026, 6, 5, 14, 9, 40).unwrap(),
            source_type: "okta".into(),
            source_instance: "okta-main".into(),
            severity: Severity::Info,
            refs: Default::default(),
            payload: EventPayload::AuthEvent(AuthEvent {
                actor: "alice@example.com".into(),
                outcome: "success".into(),
                mfa: true,
                auth_method: "password".into(),
                src_ip: "10.68.2.7".into(),
                geo: None,
                risk: None,
            }),
            ext: BTreeMap::new(),
        }
    }

    #[test]
    fn auth_is_always_notable() {
        assert_eq!(
            disposition(&auth_event()),
            SessionDisposition::Notable(NotableReason::Auth)
        );
    }

    #[test]
    fn allowed_short_flow_rolls_up() {
        let event = flow_event(base_flow(), BTreeMap::new());
        assert_eq!(disposition(&event), SessionDisposition::Rollup);
    }

    #[test]
    fn denied_flow_is_notable() {
        let mut flow = base_flow();
        flow.action = "deny".into();
        let event = flow_event(flow, BTreeMap::new());
        assert_eq!(
            disposition(&event),
            SessionDisposition::Notable(NotableReason::Denied)
        );
    }

    #[test]
    fn long_lived_flow_is_notable() {
        let mut ext = BTreeMap::new();
        ext.insert("duration_secs".into(), serde_json::json!(600));
        let event = flow_event(base_flow(), ext);
        assert_eq!(
            disposition(&event),
            SessionDisposition::Notable(NotableReason::LongLived)
        );
    }

    #[test]
    fn alert_linked_flow_is_notable() {
        let mut ext = BTreeMap::new();
        ext.insert("alert_ref".into(), serde_json::json!("alr_01ARZ3NDEKTSV4RRFFQ69G5FE0"));
        let event = flow_event(base_flow(), ext);
        assert_eq!(
            disposition(&event),
            SessionDisposition::Notable(NotableReason::AlertLinked)
        );
    }

    #[test]
    fn non_session_event_is_none() {
        use ssdf_ontology::ConfigChangeEvent;
        let event = Event {
            event_id: "evt_01ARZ3NDEKTSV4RRFFQ69G5FC9".into(),
            tenant_id: "t_main".into(),
            ts: Utc.with_ymd_and_hms(2026, 6, 5, 14, 9, 40).unwrap(),
            source_type: "srx".into(),
            source_instance: "srx-test10".into(),
            severity: Severity::Info,
            refs: Default::default(),
            payload: EventPayload::ConfigChangeEvent(ConfigChangeEvent {
                actor: "admin".into(),
                target_ref: "pol_x".into(),
                change_type: "commit".into(),
                before_digest: None,
                after_digest: None,
            }),
            ext: BTreeMap::new(),
        };
        assert_eq!(disposition(&event), SessionDisposition::None);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p ssdf-resolver notable::`
Expected: FAIL — `cannot find function 'disposition'`.

- [ ] **Step 3: Implement the minimal code**

Add above the `#[cfg(test)]` block in `crates/ssdf-resolver/src/notable.rs`:

```rust
fn ext_u64(event: &Event, field: &str) -> Option<u64> {
    event.ext.get(field).and_then(|v| v.as_u64())
}

fn has_ext(event: &Event, field: &str) -> bool {
    event.ext.get(field).map(|v| !v.is_null()).unwrap_or(false)
}

/// Classify the session implied by an event per the spec scaling rule:
/// auth = always notable; network flow = notable iff denied, long-lived, or
/// alert-linked, else rollup; anything else = no session.
pub fn disposition(event: &Event) -> SessionDisposition {
    match &event.payload {
        EventPayload::AuthEvent(_) => SessionDisposition::Notable(NotableReason::Auth),
        EventPayload::FlowEvent(flow) => {
            let denied = matches!(flow.action.as_str(), "deny" | "drop" | "reject");
            if denied {
                return SessionDisposition::Notable(NotableReason::Denied);
            }
            if has_ext(event, "alert_ref") {
                return SessionDisposition::Notable(NotableReason::AlertLinked);
            }
            if ext_u64(event, "duration_secs").map(|d| d >= LONG_LIVED_SECS).unwrap_or(false) {
                return SessionDisposition::Notable(NotableReason::LongLived);
            }
            SessionDisposition::Rollup
        }
        _ => SessionDisposition::None,
    }
}
```

Add to `crates/ssdf-resolver/src/lib.rs`:

```rust
pub mod notable;

pub use notable::{disposition, NotableReason, SessionDisposition, LONG_LIVED_SECS};
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p ssdf-resolver notable::`
Expected: PASS — 6 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/ssdf-resolver/src/notable.rs crates/ssdf-resolver/src/lib.rs
git commit -m "feat(resolver): notable-session + TALKS_TO rollup classification"
```

---

## Task 7: GraphWriter trait + recording fake (`graph.rs`)

`GraphWriter` is the only thing that talks Bolt to Neo4j. The trait keeps plan-execution testable. A `RecordingGraphWriter` fake captures every call so plan tests assert exact upserts/edges/rollups without a live database. The relationship set is the spec §3 edge list, encoded as a typed `EdgeType`.

**Files:**
- Create: `crates/ssdf-resolver/src/graph.rs`
- Modify: `crates/ssdf-resolver/src/lib.rs`

- [ ] **Step 1: Write the failing tests**

Create `crates/ssdf-resolver/src/graph.rs`:

```rust
use anyhow::Result;
use ssdf_ontology::Entity;
use std::sync::Mutex;

/// Graph edge types — the spec §3 relationship set plus the aggregate TALKS_TO.
/// `as_str` is the Neo4j relationship type written in Cypher.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeType {
    AuthenticatesAs,
    Uses,
    Accesses,
    Involves,
    MemberOfSegment,
    GovernedBy,
    Governs,
    Generates,
    Affects,
    Includes,
    TalksTo,
}

impl EdgeType {
    pub fn as_str(self) -> &'static str {
        match self {
            EdgeType::AuthenticatesAs => "AUTHENTICATES_AS",
            EdgeType::Uses => "USES",
            EdgeType::Accesses => "ACCESSES",
            EdgeType::Involves => "INVOLVES",
            EdgeType::MemberOfSegment => "MEMBER_OF_SEGMENT",
            EdgeType::GovernedBy => "GOVERNED_BY",
            EdgeType::Governs => "GOVERNS",
            EdgeType::Generates => "GENERATES",
            EdgeType::Affects => "AFFECTS",
            EdgeType::Includes => "INCLUDES",
            EdgeType::TalksTo => "TALKS_TO",
        }
    }
}

/// One directed edge to upsert: `(from_id)-[rel]->(to_id)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Edge {
    pub from_id: String,
    pub rel: EdgeType,
    pub to_id: String,
}

/// Writes entities + relationships into the graph (Neo4j in prod). Scoped by
/// tenant_id in every Cypher statement.
#[allow(async_fn_in_trait)]
pub trait GraphWriter {
    /// MERGE an entity node by `id` (within tenant), setting its properties.
    async fn upsert_entity(&self, tenant_id: &str, entity: &Entity) -> Result<()>;

    /// MERGE a relationship between two existing nodes (within tenant).
    async fn upsert_edge(&self, tenant_id: &str, edge: &Edge) -> Result<()>;

    /// Increment an aggregate Asset-TALKS_TO->(Asset|Application) edge's
    /// counters (count, bytes) and refresh `last_seen`.
    async fn bump_talks_to(
        &self,
        tenant_id: &str,
        from_asset_id: &str,
        to_id: &str,
        bytes: u64,
    ) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn recording_writer_captures_edges_and_rollups() {
        let writer = RecordingGraphWriter::new();
        writer
            .upsert_edge(
                "t_main",
                &Edge { from_id: "idn_A".into(), rel: EdgeType::Uses, to_id: "ast_B".into() },
            )
            .await
            .unwrap();
        writer.bump_talks_to("t_main", "ast_B", "app_C", 4096).await.unwrap();

        assert_eq!(writer.edges(), vec![Edge {
            from_id: "idn_A".into(),
            rel: EdgeType::Uses,
            to_id: "ast_B".into(),
        }]);
        assert_eq!(writer.rollups(), vec![("ast_B".into(), "app_C".into(), 4096u64)]);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p ssdf-resolver graph::`
Expected: FAIL — `cannot find type 'RecordingGraphWriter'`.

- [ ] **Step 3: Implement the trait fake**

Add above the `#[cfg(test)]` block in `crates/ssdf-resolver/src/graph.rs`:

```rust
/// In-memory `GraphWriter` for tests: records every call.
#[derive(Default)]
pub struct RecordingGraphWriter {
    entities: Mutex<Vec<(String, Entity)>>,
    edges: Mutex<Vec<Edge>>,
    rollups: Mutex<Vec<(String, String, u64)>>,
}

impl RecordingGraphWriter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn entities(&self) -> Vec<(String, Entity)> {
        self.entities.lock().unwrap().clone()
    }

    pub fn edges(&self) -> Vec<Edge> {
        self.edges.lock().unwrap().clone()
    }

    pub fn rollups(&self) -> Vec<(String, String, u64)> {
        self.rollups.lock().unwrap().clone()
    }
}

impl GraphWriter for RecordingGraphWriter {
    async fn upsert_entity(&self, tenant_id: &str, entity: &Entity) -> Result<()> {
        self.entities.lock().unwrap().push((tenant_id.to_string(), entity.clone()));
        Ok(())
    }

    async fn upsert_edge(&self, _tenant_id: &str, edge: &Edge) -> Result<()> {
        self.edges.lock().unwrap().push(edge.clone());
        Ok(())
    }

    async fn bump_talks_to(
        &self,
        _tenant_id: &str,
        from_asset_id: &str,
        to_id: &str,
        bytes: u64,
    ) -> Result<()> {
        self.rollups.lock().unwrap().push((from_asset_id.to_string(), to_id.to_string(), bytes));
        Ok(())
    }
}
```

Add to `crates/ssdf-resolver/src/lib.rs`:

```rust
pub mod graph;

pub use graph::{Edge, EdgeType, GraphWriter, RecordingGraphWriter};
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p ssdf-resolver graph::`
Expected: PASS — 1 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/ssdf-resolver/src/graph.rs crates/ssdf-resolver/src/lib.rs
git commit -m "feat(resolver): GraphWriter trait + recording fake with typed edges"
```

---

## Task 8: Event → graph projection (`plan.rs`)

`project_event` is the composition root for the pure pipeline: extract keys → resolve to global ids → classify the session → build entity upserts + the spec's edges, OR a TALKS_TO rollup for routine flows. It calls `KeyStore` + `GraphWriter` (so it's tested with the two fakes) and returns any `ResolutionEvent`s that must be emitted. This is where the scaling rule is enforced end-to-end: a routine allowed flow produces ZERO Session nodes and one `bump_talks_to`; a denied/auth flow produces a Session node + relationships.

**Files:**
- Create: `crates/ssdf-resolver/src/plan.rs`
- Modify: `crates/ssdf-resolver/src/lib.rs`

- [ ] **Step 1: Write the failing tests**

Create `crates/ssdf-resolver/src/plan.rs`:

```rust
use crate::events::{ResolutionEvent, ResolutionKind};
use crate::graph::{Edge, EdgeType, GraphWriter};
use crate::keys::{
    application_keys, asset_dst_keys, asset_src_keys, identity_keys, EntityKind, NaturalKey,
};
use crate::keystore::KeyStore;
use crate::notable::{disposition, SessionDisposition};
use crate::resolve::resolve;
use anyhow::Result;
use chrono::Utc;
use ssdf_ontology::{
    new_id, ApplicationBody, AssetBody, Entity, EntityBody, EventPayload, IdPrefix, IdentityBody,
    SessionBody, SourceRef,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::RecordingGraphWriter;
    use crate::keystore::InMemoryKeyStore;
    use chrono::TimeZone;
    use ssdf_ontology::{AuthEvent, Event, FlowEvent, Severity};
    use std::collections::BTreeMap;

    fn allowed_flow() -> Event {
        Event {
            event_id: "evt_FLOW1".into(),
            tenant_id: "t_main".into(),
            ts: Utc.with_ymd_and_hms(2026, 6, 5, 14, 9, 40).unwrap(),
            source_type: "srx".into(),
            source_instance: "srx-test10".into(),
            severity: Severity::Info,
            refs: Default::default(),
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

    fn auth_ok() -> Event {
        Event {
            event_id: "evt_AUTH1".into(),
            tenant_id: "t_main".into(),
            ts: Utc.with_ymd_and_hms(2026, 6, 5, 14, 9, 40).unwrap(),
            source_type: "okta".into(),
            source_instance: "okta-main".into(),
            severity: Severity::Info,
            refs: Default::default(),
            payload: EventPayload::AuthEvent(AuthEvent {
                actor: "alice@example.com".into(),
                outcome: "success".into(),
                mfa: true,
                auth_method: "password".into(),
                src_ip: "10.68.2.7".into(),
                geo: None,
                risk: None,
            }),
            ext: BTreeMap::new(),
        }
    }

    #[tokio::test]
    async fn allowed_flow_rolls_up_no_session_node() {
        let store = InMemoryKeyStore::new();
        let writer = RecordingGraphWriter::new();
        let emitted = project_event(&store, &writer, &allowed_flow()).await.unwrap();
        // Two Asset nodes (src + dst) + one Application node upserted; NO Session.
        let kinds: Vec<String> = writer
            .entities()
            .iter()
            .map(|(_, e)| serde_json::to_value(&e.body).unwrap()["kind"].as_str().unwrap().to_string())
            .collect();
        assert!(!kinds.contains(&"session".to_string()), "routine flow must not make a Session node");
        assert!(kinds.contains(&"asset".to_string()));
        // Exactly one TALKS_TO rollup with the flow's total bytes (in+out).
        assert_eq!(writer.rollups().len(), 1);
        assert_eq!(writer.rollups()[0].2, 1200 + 4096);
        // No edges for a pure rollup.
        assert!(writer.edges().is_empty());
        assert!(emitted.iter().all(|e| e.kind == ResolutionKind::Resolved || e.kind == ResolutionKind::Merged));
    }

    #[tokio::test]
    async fn denied_flow_creates_session_and_involves_edges() {
        let store = InMemoryKeyStore::new();
        let writer = RecordingGraphWriter::new();
        let mut event = allowed_flow();
        if let EventPayload::FlowEvent(flow) = &mut event.payload {
            flow.action = "deny".into();
        }
        project_event(&store, &writer, &event).await.unwrap();
        let kinds: Vec<String> = writer
            .entities()
            .iter()
            .map(|(_, e)| serde_json::to_value(&e.body).unwrap()["kind"].as_str().unwrap().to_string())
            .collect();
        assert!(kinds.contains(&"session".to_string()), "denied flow must make a Session node");
        // Session-INVOLVES->Asset for both src + dst.
        let involves: Vec<&Edge> = writer.edges().iter().filter(|e| e.rel == EdgeType::Involves).collect();
        assert_eq!(involves.len(), 2);
        // No rollup for a notable flow.
        assert!(writer.rollups().is_empty());
    }

    #[tokio::test]
    async fn auth_creates_session_and_authenticates_edge() {
        let store = InMemoryKeyStore::new();
        let writer = RecordingGraphWriter::new();
        project_event(&store, &writer, &auth_ok()).await.unwrap();
        let kinds: Vec<String> = writer
            .entities()
            .iter()
            .map(|(_, e)| serde_json::to_value(&e.body).unwrap()["kind"].as_str().unwrap().to_string())
            .collect();
        assert!(kinds.contains(&"identity".to_string()));
        assert!(kinds.contains(&"session".to_string()));
        let auth_edges: Vec<&Edge> = writer
            .edges()
            .iter()
            .filter(|e| e.rel == EdgeType::AuthenticatesAs)
            .collect();
        assert_eq!(auth_edges.len(), 1, "Identity-AUTHENTICATES_AS->Session");
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p ssdf-resolver plan::`
Expected: FAIL — `cannot find function 'project_event'`.

- [ ] **Step 3: Implement the minimal code**

Add above the `#[cfg(test)]` block in `crates/ssdf-resolver/src/plan.rs`:

```rust
fn source_ref(event: &ssdf_ontology::Event) -> SourceRef {
    SourceRef {
        source_type: event.source_type.clone(),
        source_instance: event.source_instance.clone(),
        source_id: event.event_id.clone(),
        observed_at: event.ts,
    }
}

/// Resolve one candidate list to a global id, upsert a minimal entity body for
/// it, and return the id. Emits a ResolutionEvent (resolved/merged).
async fn resolve_and_upsert<S: KeyStore, G: GraphWriter>(
    store: &S,
    writer: &G,
    event: &ssdf_ontology::Event,
    kind: EntityKind,
    candidates: &[NaturalKey],
    body: impl FnOnce() -> EntityBody,
    emitted: &mut Vec<ResolutionEvent>,
) -> Result<String> {
    let resolution = resolve(store, &event.tenant_id, kind, candidates).await?;
    let entity = Entity {
        id: resolution.global_id.clone(),
        tenant_id: event.tenant_id.clone(),
        first_seen: event.ts,
        last_seen: event.ts,
        source_refs: vec![source_ref(event)],
        body: body(),
        ext: Default::default(),
        labels: Default::default(),
    };
    writer.upsert_entity(&event.tenant_id, &entity).await?;

    match resolution.merge {
        Some(merge) => emitted.push(ResolutionEvent {
            resolution_id: new_id(IdPrefix::Event),
            tenant_id: event.tenant_id.clone(),
            kind: ResolutionKind::Merged,
            entity_kind: kind.as_str().to_string(),
            ts: Utc::now(),
            survivor_id: merge.survivor_id,
            absorbed_id: Some(merge.absorbed_id),
            repointed_keys: merge.repointed_keys.into_iter().map(|k| k.key).collect(),
            source_event_id: event.event_id.clone(),
        }),
        None => emitted.push(ResolutionEvent {
            resolution_id: new_id(IdPrefix::Event),
            tenant_id: event.tenant_id.clone(),
            kind: ResolutionKind::Resolved,
            entity_kind: kind.as_str().to_string(),
            ts: Utc::now(),
            survivor_id: resolution.global_id.clone(),
            absorbed_id: None,
            repointed_keys: Vec::new(),
            source_event_id: event.event_id.clone(),
        }),
    }
    Ok(resolution.global_id)
}

fn session_entity(event: &ssdf_ontology::Event, kind: &str, identity_ref: Option<String>) -> Entity {
    Entity {
        id: new_id(IdPrefix::Session),
        tenant_id: event.tenant_id.clone(),
        first_seen: event.ts,
        last_seen: event.ts,
        source_refs: vec![source_ref(event)],
        body: EntityBody::Session(SessionBody {
            kind: kind.to_string(),
            start: event.ts,
            end: None,
            state: "observed".to_string(),
            identity_ref,
            app_ref: None,
            verdict: None,
        }),
        ext: Default::default(),
        labels: Default::default(),
    }
}

/// Project one canonical event into graph writes. Enforces the scaling rule:
/// routine allowed flows roll up into Asset-TALKS_TO edges (no Session node);
/// notable flows + all auth events materialize a Session node + relationships.
pub async fn project_event<S: KeyStore, G: GraphWriter>(
    store: &S,
    writer: &G,
    event: &ssdf_ontology::Event,
) -> Result<Vec<ResolutionEvent>> {
    let mut emitted = Vec::new();
    let tenant = event.tenant_id.clone();

    match &event.payload {
        EventPayload::FlowEvent(flow) => {
            let src_id = resolve_and_upsert(
                store, writer, event, EntityKind::Asset, &asset_src_keys(event),
                || EntityBody::Asset(AssetBody {
                    hostname: None, ips: vec![flow.src_ip.clone()], macs: vec![],
                    os: None, kind: "host".into(), criticality: None, exposure: None,
                }),
                &mut emitted,
            ).await?;
            let dst_id = resolve_and_upsert(
                store, writer, event, EntityKind::Asset, &asset_dst_keys(event),
                || EntityBody::Asset(AssetBody {
                    hostname: None, ips: vec![flow.dst_ip.clone()], macs: vec![],
                    os: None, kind: "host".into(), criticality: None, exposure: None,
                }),
                &mut emitted,
            ).await?;
            let app_id = resolve_and_upsert(
                store, writer, event, EntityKind::Application, &application_keys(event),
                || EntityBody::Application(ApplicationBody {
                    name: flow.app.clone(), kind: "service".into(), app_id: None,
                    dst_ports: vec![flow.dst_port], category: None,
                }),
                &mut emitted,
            ).await?;

            match disposition(event) {
                SessionDisposition::Rollup => {
                    // Scaling rule: routine flow → aggregate edge only.
                    writer.bump_talks_to(&tenant, &src_id, &app_id, flow.bytes_in + flow.bytes_out).await?;
                }
                SessionDisposition::Notable(_) => {
                    let session = session_entity(event, "network-flow", None);
                    let session_id = session.id.clone();
                    writer.upsert_entity(&tenant, &session).await?;
                    writer.upsert_edge(&tenant, &Edge { from_id: session_id.clone(), rel: EdgeType::Involves, to_id: src_id }).await?;
                    writer.upsert_edge(&tenant, &Edge { from_id: session_id.clone(), rel: EdgeType::Involves, to_id: dst_id }).await?;
                    writer.upsert_edge(&tenant, &Edge { from_id: session_id, rel: EdgeType::Accesses, to_id: app_id }).await?;
                }
                SessionDisposition::None => {}
            }
        }
        EventPayload::AuthEvent(_) => {
            let identity_id = resolve_and_upsert(
                store, writer, event, EntityKind::Identity, &identity_keys(event),
                || EntityBody::Identity(IdentityBody {
                    display_name: identity_display(event),
                    kind: "user".into(), primary_email: identity_email(event),
                    status: "active".into(), risk_score: None, groups: vec![],
                }),
                &mut emitted,
            ).await?;
            // Auth is always notable → Session node + AUTHENTICATES_AS edge.
            let session = session_entity(event, "auth", Some(identity_id.clone()));
            let session_id = session.id.clone();
            writer.upsert_entity(&tenant, &session).await?;
            writer.upsert_edge(&tenant, &Edge { from_id: identity_id, rel: EdgeType::AuthenticatesAs, to_id: session_id }).await?;
        }
        _ => {}
    }

    Ok(emitted)
}

fn identity_email(event: &ssdf_ontology::Event) -> Option<String> {
    match &event.payload {
        EventPayload::AuthEvent(a) if a.actor.contains('@') => Some(a.actor.to_lowercase()),
        _ => None,
    }
}

fn identity_display(event: &ssdf_ontology::Event) -> String {
    match &event.payload {
        EventPayload::AuthEvent(a) => a.actor.clone(),
        _ => "unknown".into(),
    }
}
```

Add to `crates/ssdf-resolver/src/lib.rs`:

```rust
pub mod plan;

pub use plan::project_event;
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p ssdf-resolver plan::`
Expected: PASS — 3 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/ssdf-resolver/src/plan.rs crates/ssdf-resolver/src/lib.rs
git commit -m "feat(resolver): event->graph projection enforcing the scaling rule"
```

---

## Task 9: Postgres KeyStore + Neo4j GraphWriter (real impls)

Real adapters behind the traits already proven. These are wired into `main.rs`. They are exercised by a `#[ignore]`-by-default integration test that runs only when the Plan-1 docker-compose stack is up (`just up && just migrate`).

**Files:**
- Modify: `crates/ssdf-resolver/src/keystore.rs` (add `PgKeyStore`)
- Modify: `crates/ssdf-resolver/src/graph.rs` (add `Neo4jGraphWriter`)
- Modify: `crates/ssdf-resolver/src/lib.rs`

- [ ] **Step 1: Write the failing (ignored) integration test for `PgKeyStore`**

Append inside the existing `#[cfg(test)] mod tests` in `crates/ssdf-resolver/src/keystore.rs`:

```rust
    // Requires: `just up && just migrate` (Plan 1 stack). Run with:
    // `cargo test -p ssdf-resolver keystore::tests::pg_ -- --ignored`
    #[tokio::test]
    #[ignore]
    async fn pg_assign_then_lookup_roundtrips() {
        let url = "postgres://ssdf:ssdf@localhost:5432/ssdf";
        let store = PgKeyStore::connect(url).await.unwrap();
        let key = NaturalKey { kind: EntityKind::Identity, key: format!("email:it-{}@x.com", ulid_now()) };
        let id = store.assign("t_main", &key, "idn_PGTEST").await.unwrap();
        assert_eq!(id, "idn_PGTEST");
        assert_eq!(store.lookup("t_main", &key).await.unwrap(), Some("idn_PGTEST".into()));
    }

    fn ulid_now() -> String {
        // unique-enough suffix to avoid cross-run key collisions
        format!("{}", chrono::Utc::now().timestamp_nanos_opt().unwrap())
    }
```

- [ ] **Step 2: Run it to confirm the type is missing**

Run: `cargo test -p ssdf-resolver keystore::`
Expected: FAIL to COMPILE — `cannot find type 'PgKeyStore'`.

- [ ] **Step 3: Implement `PgKeyStore`**

Add to `crates/ssdf-resolver/src/keystore.rs` (above the test module), and `use sqlx::postgres::PgPoolOptions;` at the top:

```rust
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

/// Postgres-backed `KeyStore` over the Plan-1 `resolution_keys` table.
pub struct PgKeyStore {
    pool: PgPool,
}

impl PgKeyStore {
    pub async fn connect(url: &str) -> Result<Self> {
        let pool = PgPoolOptions::new().max_connections(5).connect(url).await?;
        Ok(Self { pool })
    }
}

impl KeyStore for PgKeyStore {
    async fn lookup(&self, tenant_id: &str, key: &NaturalKey) -> Result<Option<String>> {
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT global_id FROM resolution_keys \
             WHERE tenant_id = $1 AND kind = $2 AND natural_key = $3",
        )
        .bind(tenant_id)
        .bind(key.kind.as_str())
        .bind(&key.key)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| r.0))
    }

    async fn assign(&self, tenant_id: &str, key: &NaturalKey, candidate_id: &str) -> Result<String> {
        // ON CONFLICT DO NOTHING preserves the existing id (idempotent); then
        // read back the winning id.
        sqlx::query(
            "INSERT INTO resolution_keys (tenant_id, kind, natural_key, global_id) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (tenant_id, kind, natural_key) DO NOTHING",
        )
        .bind(tenant_id)
        .bind(key.kind.as_str())
        .bind(&key.key)
        .bind(candidate_id)
        .execute(&self.pool)
        .await?;
        let id = self
            .lookup(tenant_id, key)
            .await?
            .expect("row exists after insert/conflict");
        Ok(id)
    }

    async fn record_merge(
        &self,
        tenant_id: &str,
        survivor_id: &str,
        _absorbed_id: &str,
        keys: &[NaturalKey],
    ) -> Result<()> {
        for key in keys {
            sqlx::query(
                "UPDATE resolution_keys SET global_id = $4, updated_at = now() \
                 WHERE tenant_id = $1 AND kind = $2 AND natural_key = $3",
            )
            .bind(tenant_id)
            .bind(key.kind.as_str())
            .bind(&key.key)
            .bind(survivor_id)
            .execute(&self.pool)
            .await?;
        }
        Ok(())
    }

    async fn reverse_merge(
        &self,
        tenant_id: &str,
        _survivor_id: &str,
        absorbed_id: &str,
        keys: &[NaturalKey],
    ) -> Result<()> {
        for key in keys {
            sqlx::query(
                "UPDATE resolution_keys SET global_id = $4, updated_at = now() \
                 WHERE tenant_id = $1 AND kind = $2 AND natural_key = $3",
            )
            .bind(tenant_id)
            .bind(key.kind.as_str())
            .bind(&key.key)
            .bind(absorbed_id)
            .execute(&self.pool)
            .await?;
        }
        Ok(())
    }
}
```

Re-export in `crates/ssdf-resolver/src/lib.rs`:

```rust
pub use keystore::{InMemoryKeyStore, KeyStore, PgKeyStore};
```

- [ ] **Step 4: Verify it compiles + the ignored test passes against a live stack**

Run: `cargo test -p ssdf-resolver keystore::` (compiles + runs the in-memory tests)
Expected: PASS — 5 passed; 1 ignored.
Then, with `just up && just migrate` from Plan 1 running:
Run: `cargo test -p ssdf-resolver keystore::tests::pg_ -- --ignored`
Expected: PASS — 1 passed.

- [ ] **Step 5: Implement `Neo4jGraphWriter`**

Add to `crates/ssdf-resolver/src/graph.rs` (above the test module), with `use neo4rs::{query, Graph};` and `use ssdf_ontology::Entity;` at the top:

```rust
use neo4rs::{query, Graph};

/// Neo4j Bolt-backed `GraphWriter`. The node label is the entity `kind`
/// (capitalized) matching the Plan-1 uniqueness constraints.
pub struct Neo4jGraphWriter {
    graph: Graph,
}

impl Neo4jGraphWriter {
    pub async fn connect(uri: &str, user: &str, pass: &str) -> Result<Self> {
        let graph = Graph::new(uri, user, pass).await?;
        Ok(Self { graph })
    }
}

fn label_for(entity: &Entity) -> &'static str {
    match &entity.body {
        ssdf_ontology::EntityBody::Identity(_) => "Identity",
        ssdf_ontology::EntityBody::Asset(_) => "Asset",
        ssdf_ontology::EntityBody::Application(_) => "Application",
        ssdf_ontology::EntityBody::NetworkSegment(_) => "NetworkSegment",
        ssdf_ontology::EntityBody::PolicyObject(_) => "PolicyObject",
        ssdf_ontology::EntityBody::Session(_) => "Session",
        ssdf_ontology::EntityBody::Alert(_) => "Alert",
        ssdf_ontology::EntityBody::Incident(_) => "Incident",
    }
}

impl GraphWriter for Neo4jGraphWriter {
    async fn upsert_entity(&self, tenant_id: &str, entity: &Entity) -> Result<()> {
        let label = label_for(entity);
        // MERGE on (id, tenant_id); store the canonical JSON as `props` for the
        // graph service to read back. Labels are static, so format is safe.
        let cypher = format!(
            "MERGE (n:{label} {{id: $id, tenant_id: $tenant}}) \
             SET n.props = $props, n.last_seen = $last_seen \
             ON CREATE SET n.first_seen = $first_seen"
        );
        let props = serde_json::to_string(entity)?;
        self.graph
            .run(
                query(&cypher)
                    .param("id", entity.id.as_str())
                    .param("tenant", tenant_id)
                    .param("props", props)
                    .param("first_seen", entity.first_seen.to_rfc3339())
                    .param("last_seen", entity.last_seen.to_rfc3339()),
            )
            .await?;
        Ok(())
    }

    async fn upsert_edge(&self, tenant_id: &str, edge: &Edge) -> Result<()> {
        let cypher = format!(
            "MATCH (a {{id: $from, tenant_id: $tenant}}), (b {{id: $to, tenant_id: $tenant}}) \
             MERGE (a)-[r:{}]->(b)",
            edge.rel.as_str()
        );
        self.graph
            .run(
                query(&cypher)
                    .param("from", edge.from_id.as_str())
                    .param("to", edge.to_id.as_str())
                    .param("tenant", tenant_id),
            )
            .await?;
        Ok(())
    }

    async fn bump_talks_to(
        &self,
        tenant_id: &str,
        from_asset_id: &str,
        to_id: &str,
        bytes: u64,
    ) -> Result<()> {
        let cypher = "MATCH (a {id: $from, tenant_id: $tenant}), (b {id: $to, tenant_id: $tenant}) \
                      MERGE (a)-[r:TALKS_TO]->(b) \
                      ON CREATE SET r.flow_count = 1, r.bytes = $bytes \
                      ON MATCH SET r.flow_count = r.flow_count + 1, r.bytes = r.bytes + $bytes";
        self.graph
            .run(
                query(cypher)
                    .param("from", from_asset_id)
                    .param("to", to_id)
                    .param("tenant", tenant_id)
                    .param("bytes", bytes as i64),
            )
            .await?;
        Ok(())
    }
}
```

Re-export in `crates/ssdf-resolver/src/lib.rs`:

```rust
pub use graph::{Edge, EdgeType, GraphWriter, Neo4jGraphWriter, RecordingGraphWriter};
```

- [ ] **Step 6: Verify it compiles**

Run: `cargo build -p ssdf-resolver`
Expected: compiles cleanly — `Finished`.

- [ ] **Step 7: Commit**

```bash
git add crates/ssdf-resolver/src/keystore.rs crates/ssdf-resolver/src/graph.rs crates/ssdf-resolver/src/lib.rs
git commit -m "feat(resolver): Postgres KeyStore + Neo4j Bolt GraphWriter impls"
```

---

## Task 10: Kafka consume loop (`main.rs`)

`main.rs` is the only networked file: it consumes canonical Event JSON from `events.normalized`, runs `project_event`, and produces emitted `ResolutionEvent`s to `events.resolution`. Config via env. A `#[ignore]` end-to-end test seeds one event and asserts a node appears; routine local CI relies on the pure tests above.

**Files:**
- Modify: `crates/ssdf-resolver/src/main.rs`

- [ ] **Step 1: Write the consume loop**

Replace `crates/ssdf-resolver/src/main.rs`:

```rust
use anyhow::{Context, Result};
use rdkafka::config::ClientConfig;
use rdkafka::consumer::{Consumer, StreamConsumer};
use rdkafka::producer::{FutureProducer, FutureRecord};
use rdkafka::Message;
use ssdf_ontology::Event;
use ssdf_resolver::{project_event, Neo4jGraphWriter, PgKeyStore};
use std::time::Duration;

/// Topic the normalizer (Plan 2) writes canonical events to.
const TOPIC_IN: &str = "events.normalized";
/// Topic resolution/merge audit events are emitted to.
const TOPIC_OUT: &str = "events.resolution";

fn env(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

#[tokio::main]
async fn main() -> Result<()> {
    let brokers = env("SSDF_KAFKA_BROKERS", "localhost:9092");
    let pg_url = env("SSDF_PG_URL", "postgres://ssdf:ssdf@localhost:5432/ssdf");
    let neo4j_uri = env("SSDF_NEO4J_URI", "neo4j://localhost:7687");
    let neo4j_user = env("SSDF_NEO4J_USER", "neo4j");
    let neo4j_pass = env("SSDF_NEO4J_PASS", "ssdfssdf");

    let store = PgKeyStore::connect(&pg_url).await.context("connect postgres")?;
    let writer = Neo4jGraphWriter::connect(&neo4j_uri, &neo4j_user, &neo4j_pass)
        .await
        .context("connect neo4j")?;

    let consumer: StreamConsumer = ClientConfig::new()
        .set("group.id", "ssdf-resolver")
        .set("bootstrap.servers", &brokers)
        .set("enable.auto.commit", "true")
        .set("auto.offset.reset", "earliest")
        .create()
        .context("create consumer")?;
    consumer.subscribe(&[TOPIC_IN]).context("subscribe")?;

    let producer: FutureProducer = ClientConfig::new()
        .set("bootstrap.servers", &brokers)
        .create()
        .context("create producer")?;

    eprintln!("ssdf-resolver: consuming {TOPIC_IN} -> graph; emitting {TOPIC_OUT}");

    loop {
        let msg = match consumer.recv().await {
            Ok(msg) => msg,
            Err(err) => {
                eprintln!("kafka recv error: {err}");
                continue;
            }
        };
        let Some(payload) = msg.payload() else { continue };
        let event: Event = match serde_json::from_slice(payload) {
            Ok(event) => event,
            Err(err) => {
                eprintln!("skip unparseable event: {err}");
                continue;
            }
        };

        match project_event(&store, &writer, &event).await {
            Ok(resolutions) => {
                for res in resolutions {
                    let body = serde_json::to_vec(&res).expect("serialize resolution event");
                    let key = res.survivor_id.clone();
                    let record = FutureRecord::to(TOPIC_OUT).payload(&body).key(&key);
                    if let Err((err, _)) = producer.send(record, Duration::from_secs(5)).await {
                        eprintln!("emit resolution event failed: {err}");
                    }
                }
            }
            Err(err) => eprintln!("project_event failed for {}: {err}", event.event_id),
        }
    }
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cargo build -p ssdf-resolver`
Expected: compiles cleanly — `Finished`.

- [ ] **Step 3: Smoke-run against the live stack (manual)**

With Plan-1 stack up + topics created (`rpk topic create events.normalized events.resolution` via the redpanda container), run the binary and produce one canonical FlowEvent JSON to `events.normalized`:

Run: `cargo run -p ssdf-resolver`
Expected: logs `consuming events.normalized -> graph`. After producing a sample event, a `Asset`/`Application` node + `TALKS_TO` edge appears in Neo4j (verify via `cypher-shell`).

- [ ] **Step 4: Commit**

```bash
git add crates/ssdf-resolver/src/main.rs
git commit -m "feat(resolver): kafka consume loop wiring real Postgres + Neo4j adapters"
```

---

## Task 11: End-to-end integration tests (`tests/`)

These `tests/*.rs` files exercise the full pure pipeline (`project_event` + `resolve` + reversal) through the public crate API using the two in-memory fakes — the acceptance gate for the four required scenarios. They live in `crates/ssdf-resolver/tests/`.

**Files:**
- Create: `crates/ssdf-resolver/tests/identity_resolution.rs`
- Create: `crates/ssdf-resolver/tests/asset_resolution.rs`
- Create: `crates/ssdf-resolver/tests/notable_rules.rs`
- Create: `crates/ssdf-resolver/tests/reverse_merge.rs`

- [ ] **Step 1: Write `tests/identity_resolution.rs` (resolve + idempotent re-resolve)**

```rust
use ssdf_resolver::{project_event, InMemoryKeyStore, RecordingGraphWriter};
use ssdf_ontology::{AuthEvent, Event, EventPayload, Severity};
use chrono::{TimeZone, Utc};
use std::collections::BTreeMap;

fn auth_event(event_id: &str) -> Event {
    let mut ext = BTreeMap::new();
    ext.insert("okta_user_id".into(), serde_json::json!("00u123"));
    Event {
        event_id: event_id.into(),
        tenant_id: "t_main".into(),
        ts: Utc.with_ymd_and_hms(2026, 6, 5, 14, 9, 40).unwrap(),
        source_type: "okta".into(),
        source_instance: "okta-main".into(),
        severity: Severity::Info,
        refs: Default::default(),
        payload: EventPayload::AuthEvent(AuthEvent {
            actor: "Alice@Example.com".into(),
            outcome: "success".into(),
            mfa: true,
            auth_method: "password".into(),
            src_ip: "10.68.2.7".into(),
            geo: None,
            risk: None,
        }),
        ext,
    }
}

#[tokio::test]
async fn identity_resolves_to_stable_id_and_reresolution_is_idempotent() {
    let store = InMemoryKeyStore::new();
    let writer = RecordingGraphWriter::new();

    project_event(&store, &writer, &auth_event("evt_1")).await.unwrap();
    let first_id = store.lookup("t_main", &ssdf_resolver::NaturalKey {
        kind: ssdf_resolver::EntityKind::Identity,
        key: "okta_user:00u123".into(),
    }).await.unwrap().unwrap();
    assert!(first_id.starts_with("idn_"));

    // A second auth event with the same okta_user_id + email must resolve to
    // the SAME identity id (idempotent).
    project_event(&store, &writer, &auth_event("evt_2")).await.unwrap();
    let second_id = store.lookup("t_main", &ssdf_resolver::NaturalKey {
        kind: ssdf_resolver::EntityKind::Identity,
        key: "email:alice@example.com".into(),
    }).await.unwrap().unwrap();
    assert_eq!(first_id, second_id, "re-resolution must be idempotent");
}
```

- [ ] **Step 2: Write `tests/asset_resolution.rs` (ip+window vs hostname)**

```rust
use ssdf_resolver::{project_event, EntityKind, InMemoryKeyStore, NaturalKey, RecordingGraphWriter};
use ssdf_ontology::{Event, EventPayload, FlowEvent, Severity};
use chrono::{TimeZone, Utc};
use std::collections::BTreeMap;

fn flow(event_id: &str, src_hostname: Option<&str>) -> Event {
    let mut ext = BTreeMap::new();
    if let Some(h) = src_hostname {
        ext.insert("src_hostname".into(), serde_json::json!(h));
    }
    Event {
        event_id: event_id.into(),
        tenant_id: "t_main".into(),
        ts: Utc.with_ymd_and_hms(2026, 6, 5, 14, 9, 40).unwrap(),
        source_type: "srx".into(),
        source_instance: "srx-test10".into(),
        severity: Severity::Info,
        refs: Default::default(),
        payload: EventPayload::FlowEvent(FlowEvent {
            src_ip: "10.68.2.7".into(), src_port: 51000,
            dst_ip: "10.68.9.3".into(), dst_port: 445,
            proto: "tcp".into(), app: "smb".into(), action: "allow".into(),
            bytes_in: 1200, bytes_out: 4096,
            zone_src: "trust".into(), zone_dst: "server".into(), user: None,
        }),
        ext,
    }
}

#[tokio::test]
async fn asset_resolved_by_ip_window_then_unified_by_hostname() {
    let store = InMemoryKeyStore::new();
    let writer = RecordingGraphWriter::new();

    // First flow has no hostname → resolves by ip+window.
    project_event(&store, &writer, &flow("evt_1", None)).await.unwrap();
    let ip_id = store.lookup("t_main", &NaturalKey {
        kind: EntityKind::Asset, key: "ip:10.68.2.7@20260605T14".into(),
    }).await.unwrap().unwrap();
    assert!(ip_id.starts_with("ast_"));

    // Second flow (same hour, same ip) now carries a hostname → both keys bind
    // to the SAME asset (hostname is more specific but converges on the ip id).
    project_event(&store, &writer, &flow("evt_2", Some("WS-ALICE"))).await.unwrap();
    let host_id = store.lookup("t_main", &NaturalKey {
        kind: EntityKind::Asset, key: "hostname:ws-alice".into(),
    }).await.unwrap().unwrap();
    let ip_id_again = store.lookup("t_main", &NaturalKey {
        kind: EntityKind::Asset, key: "ip:10.68.2.7@20260605T14".into(),
    }).await.unwrap().unwrap();
    // hostname key is newly minted as survivor; ip key was already bound, so the
    // ip-bound id is the survivor and the hostname key converges on it.
    assert_eq!(host_id, ip_id_again);
    assert_eq!(host_id, ip_id, "same machine resolves to one asset across keys");
}
```

- [ ] **Step 3: Write `tests/notable_rules.rs` (auth notable; allowed short → rollup; denied → notable)**

```rust
use ssdf_resolver::{project_event, InMemoryKeyStore, RecordingGraphWriter};
use ssdf_ontology::{AuthEvent, Event, EventPayload, FlowEvent, Severity};
use chrono::{TimeZone, Utc};
use std::collections::BTreeMap;

fn ts() -> chrono::DateTime<Utc> { Utc.with_ymd_and_hms(2026, 6, 5, 14, 9, 40).unwrap() }

fn flow(action: &str) -> Event {
    Event {
        event_id: "evt_f".into(), tenant_id: "t_main".into(), ts: ts(),
        source_type: "srx".into(), source_instance: "srx-test10".into(),
        severity: Severity::Info, refs: Default::default(),
        payload: EventPayload::FlowEvent(FlowEvent {
            src_ip: "10.68.2.7".into(), src_port: 51000,
            dst_ip: "10.68.9.3".into(), dst_port: 445,
            proto: "tcp".into(), app: "smb".into(), action: action.into(),
            bytes_in: 1200, bytes_out: 4096,
            zone_src: "trust".into(), zone_dst: "server".into(), user: None,
        }),
        ext: BTreeMap::new(),
    }
}

fn auth() -> Event {
    Event {
        event_id: "evt_a".into(), tenant_id: "t_main".into(), ts: ts(),
        source_type: "okta".into(), source_instance: "okta-main".into(),
        severity: Severity::Info, refs: Default::default(),
        payload: EventPayload::AuthEvent(AuthEvent {
            actor: "alice@example.com".into(), outcome: "success".into(), mfa: true,
            auth_method: "password".into(), src_ip: "10.68.2.7".into(), geo: None, risk: None,
        }),
        ext: BTreeMap::new(),
    }
}

fn session_count(writer: &RecordingGraphWriter) -> usize {
    writer.entities().iter().filter(|(_, e)| {
        serde_json::to_value(&e.body).unwrap()["kind"] == "session"
    }).count()
}

#[tokio::test]
async fn auth_always_makes_a_session() {
    let store = InMemoryKeyStore::new();
    let writer = RecordingGraphWriter::new();
    project_event(&store, &writer, &auth()).await.unwrap();
    assert_eq!(session_count(&writer), 1);
    assert!(writer.rollups().is_empty());
}

#[tokio::test]
async fn allowed_short_flow_rolls_up_no_session() {
    let store = InMemoryKeyStore::new();
    let writer = RecordingGraphWriter::new();
    project_event(&store, &writer, &flow("allow")).await.unwrap();
    assert_eq!(session_count(&writer), 0, "routine flow must not create a Session node");
    assert_eq!(writer.rollups().len(), 1, "routine flow folds into a TALKS_TO edge");
}

#[tokio::test]
async fn denied_flow_makes_a_session() {
    let store = InMemoryKeyStore::new();
    let writer = RecordingGraphWriter::new();
    project_event(&store, &writer, &flow("deny")).await.unwrap();
    assert_eq!(session_count(&writer), 1);
    assert!(writer.rollups().is_empty(), "notable flow does not roll up");
}
```

- [ ] **Step 4: Write `tests/reverse_merge.rs` (merge then reverse is auditable + restores keys)**

```rust
use ssdf_resolver::{
    resolve, reverse_event, EntityKind, InMemoryKeyStore, KeyStore, NaturalKey, ResolutionEvent,
    ResolutionKind,
};
use chrono::{TimeZone, Utc};

fn ident(key: &str) -> NaturalKey {
    NaturalKey { kind: EntityKind::Identity, key: key.into() }
}

#[tokio::test]
async fn merge_is_recorded_and_reversible() {
    let store = InMemoryKeyStore::new();
    // Two identities seen separately.
    store.assign("t_main", &ident("okta_user:00u123"), "idn_OKTA").await.unwrap();
    store.assign("t_main", &ident("email:alice@example.com"), "idn_EMAIL").await.unwrap();

    // An event carrying both keys triggers a merge (survivor = okta, the
    // most-specific match).
    let candidates = vec![ident("okta_user:00u123"), ident("email:alice@example.com")];
    let resolution = resolve(&store, "t_main", EntityKind::Identity, &candidates).await.unwrap();
    let merge = resolution.merge.expect("collision merges");
    assert_eq!(merge.survivor_id, "idn_OKTA");
    assert_eq!(merge.absorbed_id, "idn_EMAIL");
    // Post-merge: email key points at the survivor.
    assert_eq!(
        store.lookup("t_main", &ident("email:alice@example.com")).await.unwrap(),
        Some("idn_OKTA".into())
    );

    // Build the auditable merge event, then its reverse, and apply the reverse.
    let merge_event = ResolutionEvent {
        resolution_id: "evt_MERGE".into(),
        tenant_id: "t_main".into(),
        kind: ResolutionKind::Merged,
        entity_kind: "identity".into(),
        ts: Utc.with_ymd_and_hms(2026, 6, 5, 14, 9, 40).unwrap(),
        survivor_id: merge.survivor_id.clone(),
        absorbed_id: Some(merge.absorbed_id.clone()),
        repointed_keys: merge.repointed_keys.iter().map(|k| k.key.clone()).collect(),
        source_event_id: "evt_TRIGGER".into(),
    };
    let reversal = reverse_event(
        &merge_event,
        "evt_REVERSE".into(),
        Utc.with_ymd_and_hms(2026, 6, 5, 15, 0, 0).unwrap(),
    );
    assert_eq!(reversal.kind, ResolutionKind::MergeReversed);

    store
        .reverse_merge("t_main", &merge.survivor_id, &merge.absorbed_id, &merge.repointed_keys)
        .await
        .unwrap();

    // After reversal, the email key is restored to its original id.
    assert_eq!(
        store.lookup("t_main", &ident("email:alice@example.com")).await.unwrap(),
        Some("idn_EMAIL".into())
    );
    // The survivor's own key is untouched.
    assert_eq!(
        store.lookup("t_main", &ident("okta_user:00u123")).await.unwrap(),
        Some("idn_OKTA".into())
    );
}
```

- [ ] **Step 5: Run all integration tests**

Run: `cargo test -p ssdf-resolver --test identity_resolution --test asset_resolution --test notable_rules --test reverse_merge`
Expected: PASS — 1 + 1 + 3 + 1 = 6 integration tests pass.

Then run the full suite:
Run: `cargo test -p ssdf-resolver`
Expected: PASS — all unit + integration tests green (in-memory tests run; Postgres `pg_` test ignored).

- [ ] **Step 6: Commit**

```bash
git add crates/ssdf-resolver/tests/
git commit -m "test(resolver): end-to-end identity/asset/notable/reverse-merge integration tests"
```

---

## Self-Review

**Spec coverage:**
- §3 entity resolution natural keys (Identity email/UPN/okta_user_id; Asset ip+window/hostname/mac/wazuh_agent_id; Application okta_app_id/fw app-id/(dst_ip,port)) → `keys.rs` (Task 2). ✅
- §3 deterministic v0 resolution (no ML) → `resolve.rs` walks ordered candidates, first-match-wins, mints type-prefixed ULID via `new_id`/`IdPrefix` (Task 5). ✅
- §3 natural-key → global-id map in Postgres `resolution_keys` → `PgKeyStore` over the exact Plan-1 table/columns `(tenant_id, kind, natural_key, global_id, updated_at)` (Task 9). ✅
- §3 **scaling rule** (raw flows stay events; Session node only when notable; auth always; network when long-lived/denied/alert-linked; routine → `Asset -TALKS_TO-> Asset|Application`) → `notable.rs` + `plan.rs`; proven by `notable_rules.rs` (allowed short flow → 0 sessions + 1 rollup; denied/auth → 1 session) (Tasks 6, 8, 11). ✅
- §3 relationships → `EdgeType` covers AUTHENTICATES_AS, USES, ACCESSES, INVOLVES, MEMBER_OF_SEGMENT, GOVERNED_BY, GOVERNS, GENERATES, AFFECTS, INCLUDES, TALKS_TO (Task 7); `plan.rs` emits AUTHENTICATES_AS (auth), INVOLVES (notable flow src+dst), ACCESSES (notable flow → app), TALKS_TO (rollup). The remaining edge types are defined/typed and writable via `upsert_edge` for later connectors (Wazuh Alerts, PolicyObjects, Segments) — present but lighter per the v0 must-have ("Identity + Asset at minimum; the rest lighter but present"). ✅
- §3 merges recorded as events + **reversible** → `ResolutionEvent` (`merged`/`merge_reversed`) + `reverse_event` + `KeyStore::record_merge`/`reverse_merge`; proven by `reverse_merge.rs` restoring the absorbed id (Tasks 3, 5, 9, 11). ✅
- §3 source IDs never overwritten → every upserted entity carries a `SourceRef` from the event (`plan.rs`). ✅
- §3 type-prefixed global IDs → `IdPrefix::{Identity,Asset,Application,Session}` via `new_id` (Tasks 5, 8). ✅
- §4 Processing — Entity Resolution consumes normalized events, maintains key map in Postgres, upserts entities/relationships into Neo4j, emits merge events → `main.rs` consume loop on `events.normalized`, emit `events.resolution` (Task 10). ✅
- §4 Storage — Postgres resolution keyspace + Neo4j entities/relationships over Bolt, swappable behind a `GraphService`-style interface → `KeyStore`/`GraphWriter` traits keep both engines swappable (Tasks 4, 7, 9). ✅
- §8 v0 must-have — entity resolution for Identity + Asset → both fully covered with dedicated integration tests; tenant_id plumbed in every Cypher + Postgres statement; defaults to `t_main`. ✅
- §8 pitfall "raw flows stay events, never graph nodes" → enforced + tested as the central scaling rule. ✅
- §8 defer — probabilistic/ML matching is explicitly NOT implemented (deterministic only). ✅

**Placeholder scan:** none. Every step has concrete Rust code, concrete event fixtures, and exact `cargo`/`git` commands with expected FAIL/PASS counts. No TODO/TBD/"add error handling"/"similar to Task N".

**Type consistency (verbatim against `ssdf-ontology` + infra names):**
- ssdf-ontology types used exactly as defined in Plan 1: `Event`, `EventPayload::{AuthEvent,FlowEvent,ConfigChangeEvent}`, `AuthEvent`, `FlowEvent` (fields `src_ip/src_port/dst_ip/dst_port/proto/app/action/bytes_in/bytes_out/zone_src/zone_dst/user`), `ConfigChangeEvent` (fields `actor/target_ref/change_type/before_digest/after_digest`), `Severity`, `EventRefs` (via `refs: Default::default()`), `Entity` (`id/tenant_id/first_seen/last_seen/source_refs/body/ext/labels`), `EntityBody::{Identity,Asset,Application,NetworkSegment,PolicyObject,Session,Alert,Incident}`, `IdentityBody` (`display_name/kind/primary_email/status/risk_score/groups`), `AssetBody` (`hostname/ips/macs/os/kind/criticality/exposure`), `ApplicationBody` (`name/kind/app_id/dst_ports/category`), `SessionBody` (`kind/start/end/state/identity_ref/app_ref/verdict` — matches Plan-1's reduced v0 shape; no `src_ref`/`dst_ref`/`bytes`, consistent with Plan-1's note), `SourceRef` (`source_type/source_instance/source_id/observed_at`), `new_id`, `IdPrefix::{Identity,Asset,Application,Session,Event}`. Entity JSON is FLAT with snake_case `kind` discriminator — tests assert `["kind"] == "session"/"asset"/"identity"` accordingly. ✅
- Infra names verbatim: input topic `events.normalized`; output topic `events.resolution`; Postgres table `resolution_keys` with columns `(tenant_id, kind, natural_key, global_id, updated_at)` and PK `(tenant_id, kind, natural_key)` from Plan 1; Neo4j labels `Identity/Asset/Application/NetworkSegment/PolicyObject/Session/Alert/Incident` match Plan-1 uniqueness constraints; default `tenant_id = "t_main"`. ✅
- Internal naming consistent across tasks: `EntityKind::as_str()` returns the same snake_case (`identity`/`asset`/`application`) written to the `kind` column and read by `KeyStore`; `EdgeType::as_str()` relationship names match the spec edge list; trait method names (`lookup`/`assign`/`record_merge`/`reverse_merge`, `upsert_entity`/`upsert_edge`/`bump_talks_to`) are identical in trait defs, fakes, real impls, and call sites in `plan.rs`/`main.rs`. ✅

**Open assumption to double-check:** the `ext` field names the normalizer (Plan 2) will populate — `okta_user_id`, `src_hostname`, `src_mac`, `wazuh_agent_id`, `fw_app_id`, `okta_app_id`, `duration_secs`, `alert_ref`. These are this resolver's expected enrichment keys; they must match what Plan 2's normalizer actually emits. If Plan 2 names them differently, align `keys.rs`/`notable.rs` accessors to those exact keys.
