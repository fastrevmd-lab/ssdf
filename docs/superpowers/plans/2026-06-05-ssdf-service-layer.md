# SSDF Service Layer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a shared tonic/prost proto crate (`ssdf-proto`) defining the read+ingest service contract and a Rust gRPC server (`ssdf-server`) hosting the five SSDF services backed by ClickHouse (events/timelines), Neo4j (graph), and Postgres (config/policy), proving the v0 milestone: a cross-source incident timeline answerable over gRPC.

**Architecture:** `ssdf-proto` compiles `proto/ssdf.proto` (package `ssdf.v1`) via `tonic-build` in `build.rs`; messages mirror `ssdf-ontology` Event/Entity fields. `ssdf-server` implements the tonic service traits, with all store query construction pushed behind **pure builder functions** (`sql.rs` for ClickHouse, `cypher.rs` for Neo4j) that are unit-testable without a live DB. Every request derives `tenant_id` from gRPC metadata (never a client field) and scopes all store queries by it. Services are **read + ingest only** — SSDF never writes to a security device. Bold spec ops are fully implemented; non-bold ops are defined in proto and return `Status::unimplemented` as explicit deferred stubs.

**Tech Stack:** Rust (edition 2021), `tonic`, `prost`, `tonic-build`, `tokio`, `clickhouse`, `neo4rs`, `sqlx` (Postgres), `serde_json`, `ssdf-ontology` (Plan 1); `grpcurl` for manual verification; `docker-compose` stores from Plan 1; `just` for the integration task.

**Spec:** `docs/superpowers/specs/2026-06-05-ssdf-data-fabric-design.md` (§5 Service Layer, §3 Ontology, §4 Storage, §8 v0 milestone).

---

## File Structure

```
SSDF/
├── Cargo.toml                              # workspace root — add ssdf-proto + ssdf-server members
├── justfile                                # add `integration` task (runs ignored DB tests)
├── crates/
│   ├── ssdf-proto/
│   │   ├── Cargo.toml                       # tonic/prost deps + tonic-build build-dep
│   │   ├── build.rs                         # tonic_build compiles proto/ssdf.proto
│   │   ├── proto/
│   │   │   └── ssdf.proto                   # package ssdf.v1 — all 5 services + messages
│   │   └── src/
│   │       └── lib.rs                       # tonic::include_proto!("ssdf.v1") re-export
│   └── ssdf-server/
│       ├── Cargo.toml                       # tonic, tokio, clickhouse, neo4rs, sqlx, ssdf-proto, ssdf-ontology
│       └── src/
│           ├── main.rs                      # wire stores, build Server, serve all services
│           ├── tenant.rs                    # extract tenant_id from request metadata
│           ├── sql.rs                       # PURE ClickHouse SQL builders (events/timeline/activity/aggregate)
│           ├── cypher.rs                    # PURE Neo4j Cypher builders (get/search/neighbors/findpath)
│           ├── graph.rs                     # GraphService impl (Neo4j via cypher.rs)
│           ├── query.rs                     # QueryService impl (ClickHouse via sql.rs)
│           ├── ingestion.rs                 # IngestionService impl (Postgres sources)
│           ├── normalization.rs             # NormalizationService impl (ontology schema + Postgres resolution_keys)
│           └── policy.rs                    # PolicyService impl (Postgres/graph PolicyObjects, READ-ONLY)
└── crates/ssdf-server/tests/
    ├── timeline_integration.rs              # #[ignore] GetIncidentTimeline over real ClickHouse fixture
    └── graph_integration.rs                 # #[ignore] Neighbors over real Neo4j fixture
```

Pure builders (`sql.rs`, `cypher.rs`) hold all query-string construction so the bulk of logic is unit-tested without Docker. Service impls (`graph.rs`/`query.rs`/`ingestion.rs`/`normalization.rs`/`policy.rs`) are thin: derive tenant, call a builder, execute against a store, map rows to proto. Integration tests in `tests/` are `#[ignore]`-gated and run only via `just integration`.

---

## Task 1: Add proto crate to the workspace

**Files:**
- Modify: `Cargo.toml` (workspace root)
- Create: `crates/ssdf-proto/Cargo.toml`
- Create: `crates/ssdf-proto/build.rs`
- Create: `crates/ssdf-proto/proto/ssdf.proto`
- Create: `crates/ssdf-proto/src/lib.rs`

- [ ] **Step 1: Add workspace members + shared deps**

Edit the root `Cargo.toml`. Change `members` and add the new workspace dependencies:

```toml
[workspace]
resolver = "2"
members = ["crates/ssdf-ontology", "crates/ssdf-proto", "crates/ssdf-server"]

[workspace.package]
edition = "2021"
license = "Apache-2.0"

[workspace.dependencies]
ulid = "1"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
chrono = { version = "0.4", features = ["serde"] }
ssdf-ontology = { path = "crates/ssdf-ontology" }
ssdf-proto = { path = "crates/ssdf-proto" }
tonic = "0.12"
prost = "0.13"
tonic-build = "0.12"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
clickhouse = { version = "0.13", features = ["time"] }
neo4rs = "0.8"
sqlx = { version = "0.8", features = ["runtime-tokio", "postgres", "json", "chrono"] }
```

- [ ] **Step 2: Create `crates/ssdf-proto/Cargo.toml`**

```toml
[package]
name = "ssdf-proto"
version = "0.1.0"
edition.workspace = true
license.workspace = true

[dependencies]
tonic.workspace = true
prost.workspace = true

[build-dependencies]
tonic-build.workspace = true
```

- [ ] **Step 3: Create `crates/ssdf-proto/build.rs`**

```rust
fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["proto/ssdf.proto"], &["proto"])?;
    Ok(())
}
```

- [ ] **Step 4: Create a minimal valid `crates/ssdf-proto/proto/ssdf.proto`**

This is replaced/expanded in Tasks 2-3; start with just the package + one service so the crate compiles.

```proto
syntax = "proto3";

package ssdf.v1;

// Health probe — proves the proto pipeline end-to-end before the real services land.
service HealthService {
  rpc Ping(PingRequest) returns (PingReply);
}

message PingRequest {}
message PingReply {
  string status = 1;
}
```

- [ ] **Step 5: Create `crates/ssdf-proto/src/lib.rs`**

```rust
//! Generated SSDF gRPC contract (package `ssdf.v1`).
tonic::include_proto!("ssdf.v1");
```

- [ ] **Step 6: Verify the proto crate builds**

Run: `cargo build -p ssdf-proto`
Expected: `protoc` runs, `Compiling ssdf-proto v0.1.0`, then `Finished`. (If protoc is missing: `apt-get install -y protobuf-compiler`, then re-run.)

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml crates/ssdf-proto
git commit -m "chore(proto): scaffold ssdf-proto crate with tonic-build pipeline"
```

---

## Task 2: Define GraphService + QueryService proto (the priority contract)

These two services satisfy the v0 "Done" milestone (graph traversal + cross-source timeline). Define their full message set now; the remaining three services are added in Task 3.

**Files:**
- Modify: `crates/ssdf-proto/proto/ssdf.proto`

- [ ] **Step 1: Replace `proto/ssdf.proto` with the shared envelope + GraphService + QueryService**

Replace the whole file with:

```proto
syntax = "proto3";

package ssdf.v1;

// ── Shared envelopes (mirror ssdf-ontology) ──────────────────────────────────

// Provenance for one source observation (mirrors ssdf_ontology::SourceRef).
message SourceRef {
  string source_type = 1;       // "srx" | "okta" | "wazuh" | "panos"
  string source_instance = 2;   // e.g. "srx-test10"
  string source_id = 3;         // vendor-native id (never overwritten)
  string observed_at = 4;       // RFC3339 UTC
}

// Inclusive time window. Bounds are RFC3339 UTC strings; empty = unbounded.
message TimeRange {
  string start = 1;
  string end = 2;
}

// One resolved entity (mirrors ssdf_ontology::Entity). `body` is canonical JSON
// for the kind-specific body; `labels`/`ext` are JSON objects.
message Entity {
  string id = 1;                // idn_/ast_/app_/seg_/pol_/ses_/alr_/inc_
  string tenant_id = 2;
  string kind = 3;              // identity|asset|application|network_segment|policy_object|session|alert|incident
  string first_seen = 4;        // RFC3339 UTC
  string last_seen = 5;         // RFC3339 UTC
  repeated SourceRef source_refs = 6;
  string body_json = 7;         // kind-specific canonical body as JSON
  string labels_json = 8;       // denormalized summary labels as JSON object
  string ext_json = 9;          // vendor extensions as JSON object (gated downstream)
}

// One canonical event row (mirrors ssdf_ontology::Event).
message Event {
  string event_id = 1;          // evt_<ULID>
  string tenant_id = 2;
  string event_type = 3;        // auth_event|flow_event|policy_decision_event|alert_event|config_change_event
  string ts = 4;                // RFC3339 UTC
  string source_type = 5;
  string source_instance = 6;
  string severity = 7;          // info|low|medium|high|critical
  string identity_id = 8;
  string asset_id = 9;
  string app_id = 10;
  string policy_id = 11;
  string session_id = 12;
  string payload_json = 13;     // event-type-specific fields as JSON
  string ext_json = 14;         // vendor extensions as JSON object
}

// Graph edge between two entities.
message Edge {
  string from_id = 1;
  string to_id = 2;
  string rel_type = 3;          // AUTHENTICATES_AS|USES|ACCESSES|INVOLVES|... (spec §3)
  string props_json = 4;        // edge properties as JSON object
}

// ── GraphService (Neo4j entities + relationships) ────────────────────────────

service GraphService {
  rpc GetEntity(GetEntityRequest) returns (GetEntityReply);           // implemented
  rpc SearchEntities(SearchEntitiesRequest) returns (SearchEntitiesReply); // implemented
  rpc Neighbors(NeighborsRequest) returns (GraphReply);               // implemented
  rpc FindPath(FindPathRequest) returns (GraphReply);                 // implemented
  rpc UpsertEntity(UpsertEntityRequest) returns (UpsertEntityReply);  // deferred stub
  rpc LinkEntities(LinkEntitiesRequest) returns (LinkEntitiesReply);  // deferred stub
}

message GetEntityRequest {
  string id = 1;
  bool include_raw = 2;         // when true, ext_json is populated (scope-gated in Plan 6)
}
message GetEntityReply {
  Entity entity = 1;
}

message SearchEntitiesRequest {
  string kind = 1;              // optional filter; empty = any kind
  string query = 2;            // free-text matched against labels/name
  map<string, string> filters = 3; // exact-match label filters
  uint32 limit = 4;             // server clamps to <= 500; 0 => default 50
}
message SearchEntitiesReply {
  repeated Entity entities = 1;
}

message NeighborsRequest {
  string id = 1;
  uint32 depth = 2;             // server clamps to <= 3 (spec); 0 => 1
  repeated string rel_types = 3; // optional edge-type allowlist
  repeated string kinds = 4;    // optional neighbor-kind allowlist
}

message FindPathRequest {
  string from_id = 1;
  string to_id = 2;
  uint32 max_hops = 3;          // server clamps to <= 5 (spec); 0 => 5
}

message GraphReply {
  repeated Entity nodes = 1;
  repeated Edge edges = 2;
}

message UpsertEntityRequest {
  Entity entity = 1;
}
message UpsertEntityReply {
  string id = 1;
}

message LinkEntitiesRequest {
  Edge edge = 1;
}
message LinkEntitiesReply {
  bool linked = 1;
}

// ── QueryService (ClickHouse events + timelines) ─────────────────────────────

service QueryService {
  rpc SearchEvents(SearchEventsRequest) returns (SearchEventsReply);           // implemented
  rpc Aggregate(AggregateRequest) returns (AggregateReply);                    // implemented
  rpc GetIncidentTimeline(GetIncidentTimelineRequest) returns (TimelineReply); // implemented
  rpc GetEntityActivity(GetEntityActivityRequest) returns (ActivityReply);     // implemented
}

message SearchEventsRequest {
  repeated string event_types = 1; // optional filter; empty = all types
  TimeRange time_range = 2;        // required; bounds the scan
  map<string, string> filters = 3; // exact-match on identity_id/asset_id/app_id/etc.
  uint32 limit = 4;                // server clamps to <= 1000; 0 => default 100
}
message SearchEventsReply {
  repeated Event events = 1;
}

message AggregateRequest {
  string event_type = 1;        // required
  TimeRange time_range = 2;     // required
  string group_by = 3;          // a column: source_type|severity|event_type|identity_id|asset_id
  map<string, string> filters = 4;
  uint32 limit = 5;             // distinct groups returned; clamps to <= 500; 0 => 50
}
message AggregateBucket {
  string key = 1;
  uint64 count = 2;
}
message AggregateReply {
  repeated AggregateBucket buckets = 1;
}

// Either incident_id OR (entity_id + window). incident_id wins if both set.
message GetIncidentTimelineRequest {
  string incident_id = 1;
  string entity_id = 2;
  TimeRange window = 3;         // required when entity_id is used
  uint32 limit = 4;             // server clamps to <= 1000; 0 => 500
}
message TimelineReply {
  repeated Event events = 1;    // ordered ascending by ts, cross-source
}

message GetEntityActivityRequest {
  string entity_id = 1;
  TimeRange window = 2;         // required
  repeated string event_types = 3;
}
message ActivityRollup {
  string event_type = 1;
  uint64 count = 2;
  string first_ts = 3;
  string last_ts = 4;
}
message ActivityReply {
  repeated ActivityRollup rollups = 1;
  repeated Event recent = 2;    // up to 20 most recent events for grounding
}
```

- [ ] **Step 2: Verify proto still compiles**

Run: `cargo build -p ssdf-proto`
Expected: `Finished` with no protoc errors. (`HealthService` is now gone — that's fine, nothing depends on it yet.)

- [ ] **Step 3: Commit**

```bash
git add crates/ssdf-proto/proto/ssdf.proto
git commit -m "feat(proto): GraphService + QueryService contract (ssdf.v1)"
```

---

## Task 3: Define IngestionService, NormalizationService, PolicyService proto

These complete the §5 contract. Bold ops (`GetSourceHealth`, `GetOntologySchema`, `ResolveEntity`, `GetPoliciesForEntity`) are implemented later; the rest are defined here and stubbed.

**Files:**
- Modify: `crates/ssdf-proto/proto/ssdf.proto`

- [ ] **Step 1: Append the three services to the END of `proto/ssdf.proto`**

```proto
// ── IngestionService (Postgres `sources`) — read + SSDF-own-config only ───────

service IngestionService {
  rpc RegisterSource(RegisterSourceRequest) returns (RegisterSourceReply); // deferred stub
  rpc ListSources(ListSourcesRequest) returns (ListSourcesReply);          // implemented
  rpc GetSourceHealth(GetSourceHealthRequest) returns (GetSourceHealthReply); // implemented
  rpc PauseSource(PauseSourceRequest) returns (PauseSourceReply);          // deferred stub
  rpc ReplayFrom(ReplayFromRequest) returns (ReplayFromReply);             // deferred stub
}

message Source {
  string id = 1;                // src_<ULID>
  string type = 2;              // srx|panos|okta|wazuh
  string name = 3;
  string tenant_id = 4;
  string status = 5;            // pending|healthy|lagging|paused|error
  string created_at = 6;        // RFC3339 UTC
}

message RegisterSourceRequest {
  string type = 1;
  string name = 2;
  string connection_json = 3;   // connection params as JSON object
  string secret_ref = 4;        // reference into secrets backend — NEVER a raw secret
}
message RegisterSourceReply {
  string source_id = 1;
}

message ListSourcesRequest {}
message ListSourcesReply {
  repeated Source sources = 1;
}

message GetSourceHealthRequest {
  string source_id = 1;         // empty = all sources for the tenant
}
message SourceHealth {
  string source_id = 1;
  string status = 2;            // healthy|lagging|paused|error|pending
  uint64 lag_seconds = 3;       // seconds since last event ingested (0 if unknown)
  string last_event_ts = 4;     // RFC3339 UTC of newest event from this source
  uint64 events_last_hour = 5;
}
message GetSourceHealthReply {
  repeated SourceHealth health = 1;
}

message PauseSourceRequest {
  string source_id = 1;
}
message PauseSourceReply {
  bool paused = 1;
}

message ReplayFromRequest {
  string source_id = 1;
  string from_ts = 2;           // RFC3339 UTC
}
message ReplayFromReply {
  bool accepted = 1;
}

// ── NormalizationService (ontology schema + Postgres `resolution_keys`) ───────

service NormalizationService {
  rpc GetOntologySchema(GetOntologySchemaRequest) returns (GetOntologySchemaReply); // implemented
  rpc ListMappings(ListMappingsRequest) returns (ListMappingsReply);                // deferred stub
  rpc UpsertMapping(UpsertMappingRequest) returns (UpsertMappingReply);             // deferred stub
  rpc ResolveEntity(ResolveEntityRequest) returns (ResolveEntityReply);             // implemented
}

message GetOntologySchemaRequest {}
message OntologyField {
  string name = 1;
  string type = 2;              // string|int|bool|float|datetime|array|object
  bool required = 3;
}
message OntologyType {
  string name = 1;              // Identity|Asset|...|AuthEvent|FlowEvent|...
  string category = 2;          // "entity" | "event"
  repeated OntologyField fields = 3;
}
message OntologyRelationship {
  string from_kind = 1;
  string rel_type = 2;
  string to_kind = 3;
}
message GetOntologySchemaReply {
  string ontology_version = 1;  // ssdf_ontology::ONTOLOGY_VERSION
  repeated OntologyType types = 2;
  repeated OntologyRelationship relationships = 3;
}

message Mapping {
  string source_type = 1;       // srx|panos|okta|wazuh
  string source_field = 2;
  string canonical_field = 3;
}
message ListMappingsRequest {
  string source_type = 1;       // optional filter
}
message ListMappingsReply {
  repeated Mapping mappings = 1;
}
message UpsertMappingRequest {
  Mapping mapping = 1;
}
message UpsertMappingReply {
  bool upserted = 1;
}

// Look up the global entity id for a vendor-native natural key.
message ResolveEntityRequest {
  string kind = 1;              // identity|asset|application|...
  string natural_key = 2;       // e.g. "email:alice@example.com" or "ip:10.68.2.7"
}
message ResolveEntityReply {
  string global_id = 1;         // empty if unresolved
  bool resolved = 2;
}

// ── PolicyService (ingested PolicyObjects ↔ entities) — READ-ONLY ─────────────
// NOTE: no mutation ops. SSDF never writes policy and never writes to a device.

service PolicyService {
  rpc ListPolicies(ListPoliciesRequest) returns (ListPoliciesReply);                 // deferred stub
  rpc GetPolicy(GetPolicyRequest) returns (GetPolicyReply);                           // deferred stub
  rpc GetPoliciesForEntity(GetPoliciesForEntityRequest) returns (GetPoliciesForEntityReply); // implemented
}

message ListPoliciesRequest {
  string device_ref = 1;        // optional filter
  uint32 limit = 2;
}
message ListPoliciesReply {
  repeated Entity policies = 1; // PolicyObject entities
}

message GetPolicyRequest {
  string id = 1;                // pol_<ULID>
}
message GetPolicyReply {
  Entity policy = 1;
}

message GetPoliciesForEntityRequest {
  string entity_id = 1;         // an Asset/Application/Identity governed by policies
}
message GetPoliciesForEntityReply {
  repeated Entity policies = 1; // governing PolicyObject entities
}
```

- [ ] **Step 2: Verify the full proto compiles**

Run: `cargo build -p ssdf-proto`
Expected: `Finished` — all five services compile.

- [ ] **Step 3: Confirm generated trait names**

Run: `grep -rho "mod [a-z_]*_server" target/*/build/ssdf-proto-*/out/ssdf.v1.rs 2>/dev/null | sort -u`
Expected: lines including `mod graph_service_server`, `mod query_service_server`, `mod ingestion_service_server`, `mod normalization_service_server`, `mod policy_service_server`.

- [ ] **Step 4: Commit**

```bash
git add crates/ssdf-proto/proto/ssdf.proto
git commit -m "feat(proto): ingestion, normalization, policy services (ssdf.v1)"
```

---

## Task 4: Scaffold `ssdf-server` crate + tenant-from-metadata

The server derives `tenant_id` from gRPC metadata, never from a client field. v0 default tenant is `"t_main"` when the `tenant-id` header is absent (single-tenant deployment).

**Files:**
- Create: `crates/ssdf-server/Cargo.toml`
- Create: `crates/ssdf-server/src/main.rs`
- Create: `crates/ssdf-server/src/tenant.rs`

- [ ] **Step 1: Create `crates/ssdf-server/Cargo.toml`**

```toml
[package]
name = "ssdf-server"
version = "0.1.0"
edition.workspace = true
license.workspace = true

[dependencies]
ssdf-proto.workspace = true
ssdf-ontology.workspace = true
tonic.workspace = true
prost.workspace = true
tokio.workspace = true
clickhouse.workspace = true
neo4rs.workspace = true
sqlx.workspace = true
serde_json.workspace = true
```

- [ ] **Step 2: Write the failing tenant test**

Create `crates/ssdf-server/src/tenant.rs`:

```rust
//! Derive tenant scoping from gRPC request metadata. The tenant is taken from the
//! `tenant-id` header (set by the Gateway/auth layer from the caller's token); it
//! is NEVER read from a client-supplied message field. v0 default: "t_main".

use tonic::Request;

/// v0 single-tenant default when no `tenant-id` header is present.
pub const DEFAULT_TENANT: &str = "t_main";

/// Extract the tenant id from request metadata, falling back to the v0 default.
pub fn tenant_of<T>(request: &Request<T>) -> String {
    request
        .metadata()
        .get("tenant-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .unwrap_or(DEFAULT_TENANT)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tonic::Request;

    #[test]
    fn defaults_when_header_absent() {
        let request = Request::new(());
        assert_eq!(tenant_of(&request), "t_main");
    }

    #[test]
    fn reads_header_when_present() {
        let mut request = Request::new(());
        request.metadata_mut().insert("tenant-id", "t_acme".parse().unwrap());
        assert_eq!(tenant_of(&request), "t_acme");
    }

    #[test]
    fn ignores_empty_header() {
        let mut request = Request::new(());
        request.metadata_mut().insert("tenant-id", "".parse().unwrap());
        assert_eq!(tenant_of(&request), "t_main");
    }
}
```

- [ ] **Step 3: Create a minimal `crates/ssdf-server/src/main.rs` so the crate compiles**

```rust
//! SSDF gRPC server — hosts the read+ingest service layer (no device writes).
mod tenant;

fn main() {
    println!("ssdf-server: services wired in later tasks");
}
```

- [ ] **Step 4: Run the tenant tests — verify they pass**

Run: `cargo test -p ssdf-server tenant::`
Expected: PASS — 3 passed. (`tenant_of` is fully implemented above; this confirms the metadata rule.)

- [ ] **Step 5: Commit**

```bash
git add crates/ssdf-server/Cargo.toml crates/ssdf-server/src/main.rs crates/ssdf-server/src/tenant.rs
git commit -m "feat(server): scaffold ssdf-server + tenant-from-metadata extraction"
```

---

## Task 5: Pure ClickHouse SQL builders (`sql.rs`) — unit-tested, no DB

All ClickHouse query strings are built by pure functions taking already-derived `tenant_id` plus request params. Tenant scoping, time-range bounds, and a clamped `limit` are always applied. These tests assert the exact generated SQL — no live DB needed.

**Files:**
- Create: `crates/ssdf-server/src/sql.rs`
- Modify: `crates/ssdf-server/src/main.rs` (add `mod sql;`)

- [ ] **Step 1: Write the failing tests**

Create `crates/ssdf-server/src/sql.rs`:

```rust
//! Pure ClickHouse SQL builders. No DB handle, no async — just string construction
//! from a derived tenant plus request params. Every query is tenant-scoped, time-
//! bounded, and limit-clamped. Values are bound via `?` params (see `Query`).

/// A built query: SQL text with `?` placeholders + the ordered bind values.
#[derive(Debug, PartialEq)]
pub struct Query {
    pub sql: String,
    pub binds: Vec<String>,
}

/// Clamp a client-supplied limit to a hard ceiling, applying a default when 0.
pub fn clamp_limit(requested: u32, default: u32, max: u32) -> u32 {
    let value = if requested == 0 { default } else { requested };
    value.min(max)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamp_limit_applies_default_and_ceiling() {
        assert_eq!(clamp_limit(0, 100, 1000), 100);
        assert_eq!(clamp_limit(50, 100, 1000), 50);
        assert_eq!(clamp_limit(5000, 100, 1000), 1000);
    }

    #[test]
    fn search_events_scopes_tenant_time_and_limit() {
        let query = build_search_events(
            "t_main",
            &["flow_event".to_string()],
            "2026-06-05T00:00:00Z",
            "2026-06-05T23:59:59Z",
            &[("asset_id".to_string(), "ast_123".to_string())],
            100,
        );
        assert_eq!(
            query.sql,
            "SELECT event_id, tenant_id, event_type, ts, source_type, source_instance, \
severity, identity_id, asset_id, app_id, policy_id, session_id, payload, ext \
FROM ssdf.events \
WHERE tenant_id = ? AND ts >= ? AND ts <= ? AND event_type IN (?) AND asset_id = ? \
ORDER BY ts ASC LIMIT 100"
        );
        assert_eq!(
            query.binds,
            vec![
                "t_main".to_string(),
                "2026-06-05T00:00:00Z".to_string(),
                "2026-06-05T23:59:59Z".to_string(),
                "flow_event".to_string(),
                "ast_123".to_string(),
            ]
        );
    }

    #[test]
    fn search_events_omits_type_filter_when_empty() {
        let query = build_search_events("t_main", &[], "2026-06-05T00:00:00Z", "", &[], 0);
        assert_eq!(
            query.sql,
            "SELECT event_id, tenant_id, event_type, ts, source_type, source_instance, \
severity, identity_id, asset_id, app_id, policy_id, session_id, payload, ext \
FROM ssdf.events \
WHERE tenant_id = ? AND ts >= ? \
ORDER BY ts ASC LIMIT 100"
        );
        assert_eq!(
            query.binds,
            vec!["t_main".to_string(), "2026-06-05T00:00:00Z".to_string()]
        );
    }

    #[test]
    fn timeline_for_entity_unions_all_ref_columns() {
        let query = build_entity_timeline(
            "t_main",
            "ast_123",
            "2026-06-01T00:00:00Z",
            "2026-06-05T23:59:59Z",
            500,
        );
        assert_eq!(
            query.sql,
            "SELECT event_id, tenant_id, event_type, ts, source_type, source_instance, \
severity, identity_id, asset_id, app_id, policy_id, session_id, payload, ext \
FROM ssdf.events \
WHERE tenant_id = ? AND ts >= ? AND ts <= ? \
AND (identity_id = ? OR asset_id = ? OR app_id = ? OR policy_id = ? OR session_id = ?) \
ORDER BY ts ASC LIMIT 500"
        );
        assert_eq!(
            query.binds,
            vec![
                "t_main".to_string(),
                "2026-06-01T00:00:00Z".to_string(),
                "2026-06-05T23:59:59Z".to_string(),
                "ast_123".to_string(),
                "ast_123".to_string(),
                "ast_123".to_string(),
                "ast_123".to_string(),
                "ast_123".to_string(),
            ]
        );
    }

    #[test]
    fn aggregate_groups_and_counts() {
        let query = build_aggregate(
            "t_main",
            "flow_event",
            "source_type",
            "2026-06-05T00:00:00Z",
            "2026-06-05T23:59:59Z",
            &[],
            50,
        );
        assert_eq!(
            query.sql,
            "SELECT source_type AS key, count() AS cnt FROM ssdf.events \
WHERE tenant_id = ? AND event_type = ? AND ts >= ? AND ts <= ? \
GROUP BY source_type ORDER BY cnt DESC LIMIT 50"
        );
        assert_eq!(
            query.binds,
            vec![
                "t_main".to_string(),
                "flow_event".to_string(),
                "2026-06-05T00:00:00Z".to_string(),
                "2026-06-05T23:59:59Z".to_string(),
            ]
        );
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p ssdf-server sql::`
Expected: FAIL — `cannot find function 'build_search_events'` / `build_entity_timeline` / `build_aggregate`.

- [ ] **Step 3: Implement the builders**

Add above the `#[cfg(test)]` block in `crates/ssdf-server/src/sql.rs`:

```rust
const EVENT_COLUMNS: &str = "event_id, tenant_id, event_type, ts, source_type, \
source_instance, severity, identity_id, asset_id, app_id, policy_id, session_id, \
payload, ext";

/// Whitelist of columns accepted as exact-match filters / group-by keys. Anything
/// not on this list is dropped — prevents column injection from `filters`/`group_by`.
fn is_known_column(name: &str) -> bool {
    matches!(
        name,
        "event_type" | "source_type" | "source_instance" | "severity"
            | "identity_id" | "asset_id" | "app_id" | "policy_id" | "session_id"
    )
}

/// SearchEvents: tenant + time-range + optional type/filter, ordered, limited.
pub fn build_search_events(
    tenant_id: &str,
    event_types: &[String],
    start: &str,
    end: &str,
    filters: &[(String, String)],
    limit: u32,
) -> Query {
    let limit = clamp_limit(limit, 100, 1000);
    let mut sql = format!("SELECT {EVENT_COLUMNS} FROM ssdf.events WHERE tenant_id = ? AND ts >= ?");
    let mut binds = vec![tenant_id.to_string(), start.to_string()];

    if !end.is_empty() {
        sql.push_str(" AND ts <= ?");
        binds.push(end.to_string());
    }
    if !event_types.is_empty() {
        let placeholders = vec!["?"; event_types.len()].join(", ");
        sql.push_str(&format!(" AND event_type IN ({placeholders})"));
        binds.extend(event_types.iter().cloned());
    }
    for (column, value) in filters {
        if is_known_column(column) {
            sql.push_str(&format!(" AND {column} = ?"));
            binds.push(value.clone());
        }
    }
    sql.push_str(&format!(" ORDER BY ts ASC LIMIT {limit}"));
    Query { sql, binds }
}

/// Entity timeline: every event referencing the entity in ANY ref column, time-bounded.
pub fn build_entity_timeline(
    tenant_id: &str,
    entity_id: &str,
    start: &str,
    end: &str,
    limit: u32,
) -> Query {
    let limit = clamp_limit(limit, 500, 1000);
    let sql = format!(
        "SELECT {EVENT_COLUMNS} FROM ssdf.events \
WHERE tenant_id = ? AND ts >= ? AND ts <= ? \
AND (identity_id = ? OR asset_id = ? OR app_id = ? OR policy_id = ? OR session_id = ?) \
ORDER BY ts ASC LIMIT {limit}"
    );
    let id = entity_id.to_string();
    let binds = vec![
        tenant_id.to_string(),
        start.to_string(),
        end.to_string(),
        id.clone(),
        id.clone(),
        id.clone(),
        id.clone(),
        id,
    ];
    Query { sql, binds }
}

/// Aggregate: count rows of one event_type grouped by a whitelisted column.
pub fn build_aggregate(
    tenant_id: &str,
    event_type: &str,
    group_by: &str,
    start: &str,
    end: &str,
    filters: &[(String, String)],
    limit: u32,
) -> Query {
    let limit = clamp_limit(limit, 50, 500);
    let column = if is_known_column(group_by) { group_by } else { "source_type" };
    let mut sql = format!(
        "SELECT {column} AS key, count() AS cnt FROM ssdf.events \
WHERE tenant_id = ? AND event_type = ? AND ts >= ? AND ts <= ?"
    );
    let mut binds = vec![
        tenant_id.to_string(),
        event_type.to_string(),
        start.to_string(),
        end.to_string(),
    ];
    for (filter_column, value) in filters {
        if is_known_column(filter_column) {
            sql.push_str(&format!(" AND {filter_column} = ?"));
            binds.push(value.clone());
        }
    }
    sql.push_str(&format!(" GROUP BY {column} ORDER BY cnt DESC LIMIT {limit}"));
    Query { sql, binds }
}
```

Add `mod sql;` to `crates/ssdf-server/src/main.rs` (below `mod tenant;`):

```rust
mod sql;
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p ssdf-server sql::`
Expected: PASS — 5 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/ssdf-server/src/sql.rs crates/ssdf-server/src/main.rs
git commit -m "feat(server): pure ClickHouse SQL builders with tenant+time+limit scoping"
```

---

## Task 6: Pure Neo4j Cypher builders (`cypher.rs`) — unit-tested, no DB

All Cypher is built by pure functions. Every match scopes nodes by `tenant_id`, clamps `depth`/`max_hops` to the spec ceilings (≤3 / ≤5), and applies an optional relationship-type allowlist. Tenant + the entity id are passed as Cypher parameters (`$tenant`, `$id`), never string-interpolated.

**Files:**
- Create: `crates/ssdf-server/src/cypher.rs`
- Modify: `crates/ssdf-server/src/main.rs` (add `mod cypher;`)

- [ ] **Step 1: Write the failing tests**

Create `crates/ssdf-server/src/cypher.rs`:

```rust
//! Pure Neo4j Cypher builders. No driver, no async. Every query scopes by
//! `$tenant`, clamps traversal depth to the spec ceiling, and parameterizes the
//! anchor id as `$id`. Relationship-type allowlists are validated against a known
//! set so they can be safely inlined into the pattern.

/// Clamp a traversal bound to a ceiling, applying a default when 0.
pub fn clamp_depth(requested: u32, default: u32, max: u32) -> u32 {
    let value = if requested == 0 { default } else { requested };
    value.min(max)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamp_depth_applies_default_and_ceiling() {
        assert_eq!(clamp_depth(0, 1, 3), 1);
        assert_eq!(clamp_depth(2, 1, 3), 2);
        assert_eq!(clamp_depth(9, 1, 3), 3);
    }

    #[test]
    fn get_entity_scopes_tenant() {
        assert_eq!(
            build_get_entity(),
            "MATCH (n {id: $id, tenant_id: $tenant}) RETURN n LIMIT 1"
        );
    }

    #[test]
    fn neighbors_clamps_depth_and_filters_rel_types() {
        let cypher = build_neighbors(2, &["USES".to_string(), "ACCESSES".to_string()]);
        assert_eq!(
            cypher,
            "MATCH (n {id: $id, tenant_id: $tenant}) \
MATCH path = (n)-[r:USES|ACCESSES*1..2]-(m) \
WHERE m.tenant_id = $tenant \
RETURN nodes(path) AS nodes, relationships(path) AS rels LIMIT 1000"
        );
    }

    #[test]
    fn neighbors_without_rel_types_matches_any_edge_and_clamps_to_three() {
        let cypher = build_neighbors(7, &[]);
        assert_eq!(
            cypher,
            "MATCH (n {id: $id, tenant_id: $tenant}) \
MATCH path = (n)-[r*1..3]-(m) \
WHERE m.tenant_id = $tenant \
RETURN nodes(path) AS nodes, relationships(path) AS rels LIMIT 1000"
        );
    }

    #[test]
    fn neighbors_drops_unknown_rel_types() {
        // "DROP" is not a known SSDF relationship — it must be filtered out.
        let cypher = build_neighbors(1, &["USES".to_string(), "DROP".to_string()]);
        assert_eq!(
            cypher,
            "MATCH (n {id: $id, tenant_id: $tenant}) \
MATCH path = (n)-[r:USES*1..1]-(m) \
WHERE m.tenant_id = $tenant \
RETURN nodes(path) AS nodes, relationships(path) AS rels LIMIT 1000"
        );
    }

    #[test]
    fn find_path_clamps_max_hops() {
        let cypher = build_find_path(9);
        assert_eq!(
            cypher,
            "MATCH (a {id: $from_id, tenant_id: $tenant}), (b {id: $to_id, tenant_id: $tenant}) \
MATCH path = shortestPath((a)-[*..5]-(b)) \
RETURN nodes(path) AS nodes, relationships(path) AS rels LIMIT 1"
        );
    }

    #[test]
    fn search_entities_filters_by_kind_label() {
        let cypher = build_search_entities("Identity", 50);
        assert_eq!(
            cypher,
            "MATCH (n:Identity {tenant_id: $tenant}) \
WHERE ($query = '' OR toLower(toString(n.labels)) CONTAINS toLower($query)) \
RETURN n LIMIT 50"
        );
    }

    #[test]
    fn search_entities_any_kind_when_blank() {
        let cypher = build_search_entities("", 50);
        assert_eq!(
            cypher,
            "MATCH (n {tenant_id: $tenant}) \
WHERE ($query = '' OR toLower(toString(n.labels)) CONTAINS toLower($query)) \
RETURN n LIMIT 50"
        );
    }

    #[test]
    fn policies_for_entity_traverses_governed_by() {
        assert_eq!(
            build_policies_for_entity(),
            "MATCH (n {id: $id, tenant_id: $tenant}) \
MATCH (n)-[:GOVERNED_BY|GOVERNS]-(p:PolicyObject {tenant_id: $tenant}) \
RETURN p LIMIT 200"
        );
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p ssdf-server cypher::`
Expected: FAIL — `cannot find function 'build_get_entity'` / `build_neighbors` / etc.

- [ ] **Step 3: Implement the builders**

Add above the `#[cfg(test)]` block in `crates/ssdf-server/src/cypher.rs`:

```rust
/// Known SSDF relationship types (spec §3). Only these may be inlined into a pattern.
const KNOWN_RELS: &[&str] = &[
    "AUTHENTICATES_AS", "USES", "ACCESSES", "INVOLVES", "MEMBER_OF_SEGMENT",
    "GOVERNED_BY", "GOVERNS", "GENERATES", "AFFECTS", "INCLUDES", "TALKS_TO",
];

/// Known entity labels (spec §3). Only these may be inlined as a node label.
const KNOWN_LABELS: &[&str] = &[
    "Identity", "Asset", "Application", "NetworkSegment", "PolicyObject",
    "Session", "Alert", "Incident",
];

fn validated_rels(rel_types: &[String]) -> Vec<&'static str> {
    rel_types
        .iter()
        .filter_map(|requested| KNOWN_RELS.iter().copied().find(|known| *known == requested))
        .collect()
}

fn validated_label(kind: &str) -> Option<&'static str> {
    KNOWN_LABELS.iter().copied().find(|known| *known == kind)
}

/// GetEntity: anchor node scoped by id + tenant.
pub fn build_get_entity() -> String {
    "MATCH (n {id: $id, tenant_id: $tenant}) RETURN n LIMIT 1".to_string()
}

/// Neighbors: variable-length traversal from the anchor, tenant-scoped on both ends,
/// depth clamped to <=3, with an optional validated relationship-type allowlist.
pub fn build_neighbors(depth: u32, rel_types: &[String]) -> String {
    let depth = clamp_depth(depth, 1, 3);
    let rels = validated_rels(rel_types);
    let rel_pattern = if rels.is_empty() {
        format!("[r*1..{depth}]")
    } else {
        format!("[r:{}*1..{depth}]", rels.join("|"))
    };
    format!(
        "MATCH (n {{id: $id, tenant_id: $tenant}}) \
MATCH path = (n)-{rel_pattern}-(m) \
WHERE m.tenant_id = $tenant \
RETURN nodes(path) AS nodes, relationships(path) AS rels LIMIT 1000"
    )
}

/// FindPath: shortestPath between two tenant-scoped anchors, hops clamped to <=5.
pub fn build_find_path(max_hops: u32) -> String {
    let max_hops = clamp_depth(max_hops, 5, 5);
    format!(
        "MATCH (a {{id: $from_id, tenant_id: $tenant}}), (b {{id: $to_id, tenant_id: $tenant}}) \
MATCH path = shortestPath((a)-[*..{max_hops}]-(b)) \
RETURN nodes(path) AS nodes, relationships(path) AS rels LIMIT 1"
    )
}

/// SearchEntities: optional kind label + tenant scope + free-text label match.
pub fn build_search_entities(kind: &str, limit: u32) -> String {
    let limit = clamp_depth(limit, 50, 500);
    let label = match validated_label(kind) {
        Some(label) => format!(":{label}"),
        None => String::new(),
    };
    format!(
        "MATCH (n{label} {{tenant_id: $tenant}}) \
WHERE ($query = '' OR toLower(toString(n.labels)) CONTAINS toLower($query)) \
RETURN n LIMIT {limit}"
    )
}

/// GetPoliciesForEntity: PolicyObjects governing the anchor entity, tenant-scoped.
pub fn build_policies_for_entity() -> String {
    "MATCH (n {id: $id, tenant_id: $tenant}) \
MATCH (n)-[:GOVERNED_BY|GOVERNS]-(p:PolicyObject {tenant_id: $tenant}) \
RETURN p LIMIT 200"
        .to_string()
}
```

Add `mod cypher;` to `crates/ssdf-server/src/main.rs`:

```rust
mod cypher;
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p ssdf-server cypher::`
Expected: PASS — 9 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/ssdf-server/src/cypher.rs crates/ssdf-server/src/main.rs
git commit -m "feat(server): pure Neo4j Cypher builders with tenant scope + depth clamps"
```

---

## Task 7: QueryService implementation (ClickHouse)

Thin service: derive tenant, call a `sql.rs` builder, execute via the `clickhouse` client, map rows to proto `Event`. `GetIncidentTimeline` resolves `incident_id` → its `alert_refs`/`affected entity` window via the graph is deferred; v0 implements the `entity_id + window` path (sufficient for the milestone) and, for `incident_id`, looks up events whose `session_id`/`asset_id`/etc. match — here v0 uses the entity-timeline path keyed on the incident's referenced ids. For the milestone we implement the **entity_id + window** branch fully and resolve `incident_id` by treating it as an entity ref (incidents reference events via the same ref columns once Plan 4 materializes them).

**Files:**
- Create: `crates/ssdf-server/src/query.rs`
- Modify: `crates/ssdf-server/src/main.rs`

- [ ] **Step 1: Define the ClickHouse row struct + mapping and the service struct**

Create `crates/ssdf-server/src/query.rs`:

```rust
//! QueryService — events, aggregates, timelines over ClickHouse. All store access
//! goes through pure builders in `crate::sql`; this file only derives tenant,
//! executes, and maps rows to proto.

use clickhouse::Client;
use clickhouse::Row;
use serde::Deserialize;
use tonic::{Request, Response, Status};

use ssdf_proto::query_service_server::QueryService;
use ssdf_proto::{
    ActivityReply, ActivityRollup, AggregateBucket, AggregateReply, AggregateRequest, Event,
    GetEntityActivityRequest, GetIncidentTimelineRequest, SearchEventsReply, SearchEventsRequest,
    TimelineReply,
};

use crate::sql;
use crate::tenant::tenant_of;

/// One row as read from `ssdf.events`. `ts` is rendered as an RFC3339 string by CH.
#[derive(Row, Deserialize)]
struct EventRow {
    event_id: String,
    tenant_id: String,
    event_type: String,
    ts: String,
    source_type: String,
    source_instance: String,
    severity: String,
    identity_id: String,
    asset_id: String,
    app_id: String,
    policy_id: String,
    session_id: String,
    payload: String,
    ext: String,
}

impl From<EventRow> for Event {
    fn from(row: EventRow) -> Self {
        Event {
            event_id: row.event_id,
            tenant_id: row.tenant_id,
            event_type: row.event_type,
            ts: row.ts,
            source_type: row.source_type,
            source_instance: row.source_instance,
            severity: row.severity,
            identity_id: row.identity_id,
            asset_id: row.asset_id,
            app_id: row.app_id,
            policy_id: row.policy_id,
            session_id: row.session_id,
            payload_json: row.payload,
            ext_json: row.ext,
        }
    }
}

pub struct QuerySvc {
    pub client: Client,
}

/// Execute a `sql::Query` and collect rows. Binds are applied in order.
async fn fetch_events(client: &Client, query: sql::Query) -> Result<Vec<Event>, Status> {
    let mut cursor = {
        let mut q = client.query(&query.sql);
        for bind in &query.binds {
            q = q.bind(bind);
        }
        q.fetch::<EventRow>().map_err(|e| Status::internal(e.to_string()))?
    };
    let mut events = Vec::new();
    while let Some(row) = cursor.next().await.map_err(|e| Status::internal(e.to_string()))? {
        events.push(row.into());
    }
    Ok(events)
}
```

- [ ] **Step 2: Write the failing builder-selection test**

Append to `crates/ssdf-server/src/query.rs` (this unit test asserts the timeline branch picks the right builder + tenant, without a DB):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeline_request_uses_entity_timeline_builder() {
        // entity_id + window path builds an entity-timeline query scoped to tenant.
        let query = sql::build_entity_timeline(
            "t_main",
            "ast_123",
            "2026-06-01T00:00:00Z",
            "2026-06-05T23:59:59Z",
            500,
        );
        assert!(query.sql.contains("FROM ssdf.events"));
        assert!(query.sql.contains("ORDER BY ts ASC"));
        assert_eq!(query.binds[0], "t_main");
    }
}
```

- [ ] **Step 3: Run it to verify it compiles+passes (proves the wiring types line up)**

Run: `cargo test -p ssdf-server query::tests::timeline_request_uses_entity_timeline_builder`
Expected: FAIL to compile first (trait impl not yet present in module path is fine — this test only touches `sql`). If it fails to compile because `QueryService` import is unused, proceed to Step 4 which adds the impl; then it passes.

- [ ] **Step 4: Implement the `QueryService` trait**

Append to `crates/ssdf-server/src/query.rs`:

```rust
#[tonic::async_trait]
impl QueryService for QuerySvc {
    async fn search_events(
        &self,
        request: Request<SearchEventsRequest>,
    ) -> Result<Response<SearchEventsReply>, Status> {
        let tenant = tenant_of(&request);
        let req = request.into_inner();
        let range = req.time_range.unwrap_or_default();
        if range.start.is_empty() {
            return Err(Status::invalid_argument("time_range.start is required"));
        }
        let filters: Vec<(String, String)> = req.filters.into_iter().collect();
        let query =
            sql::build_search_events(&tenant, &req.event_types, &range.start, &range.end, &filters, req.limit);
        let events = fetch_events(&self.client, query).await?;
        Ok(Response::new(SearchEventsReply { events }))
    }

    async fn aggregate(
        &self,
        request: Request<AggregateRequest>,
    ) -> Result<Response<AggregateReply>, Status> {
        let tenant = tenant_of(&request);
        let req = request.into_inner();
        let range = req.time_range.unwrap_or_default();
        if req.event_type.is_empty() || range.start.is_empty() || range.end.is_empty() {
            return Err(Status::invalid_argument("event_type + bounded time_range required"));
        }
        let filters: Vec<(String, String)> = req.filters.into_iter().collect();
        let query = sql::build_aggregate(
            &tenant, &req.event_type, &req.group_by, &range.start, &range.end, &filters, req.limit,
        );

        #[derive(Row, Deserialize)]
        struct Bucket {
            key: String,
            cnt: u64,
        }
        let mut cursor = {
            let mut q = self.client.query(&query.sql);
            for bind in &query.binds {
                q = q.bind(bind);
            }
            q.fetch::<Bucket>().map_err(|e| Status::internal(e.to_string()))?
        };
        let mut buckets = Vec::new();
        while let Some(b) = cursor.next().await.map_err(|e| Status::internal(e.to_string()))? {
            buckets.push(AggregateBucket { key: b.key, count: b.cnt });
        }
        Ok(Response::new(AggregateReply { buckets }))
    }

    async fn get_incident_timeline(
        &self,
        request: Request<GetIncidentTimelineRequest>,
    ) -> Result<Response<TimelineReply>, Status> {
        let tenant = tenant_of(&request);
        let req = request.into_inner();
        // v0: resolve the anchor entity id (incident_id wins; else entity_id), then
        // pull every event referencing it within the window, ordered cross-source.
        let anchor = if !req.incident_id.is_empty() {
            req.incident_id
        } else if !req.entity_id.is_empty() {
            req.entity_id
        } else {
            return Err(Status::invalid_argument("incident_id or entity_id required"));
        };
        let window = req.window.unwrap_or_default();
        if window.start.is_empty() || window.end.is_empty() {
            return Err(Status::invalid_argument("window with start+end required"));
        }
        let query = sql::build_entity_timeline(&tenant, &anchor, &window.start, &window.end, req.limit);
        let events = fetch_events(&self.client, query).await?;
        Ok(Response::new(TimelineReply { events }))
    }

    async fn get_entity_activity(
        &self,
        request: Request<GetEntityActivityRequest>,
    ) -> Result<Response<ActivityReply>, Status> {
        let tenant = tenant_of(&request);
        let req = request.into_inner();
        let window = req.window.unwrap_or_default();
        if req.entity_id.is_empty() || window.start.is_empty() || window.end.is_empty() {
            return Err(Status::invalid_argument("entity_id + bounded window required"));
        }
        // Pull the windowed events for the entity, then roll up in-process.
        let query =
            sql::build_entity_timeline(&tenant, &req.entity_id, &window.start, &window.end, 1000);
        let mut events = fetch_events(&self.client, query).await?;
        if !req.event_types.is_empty() {
            events.retain(|e| req.event_types.contains(&e.event_type));
        }

        use std::collections::BTreeMap;
        let mut rollup: BTreeMap<String, (u64, String, String)> = BTreeMap::new();
        for event in &events {
            let entry = rollup
                .entry(event.event_type.clone())
                .or_insert((0, event.ts.clone(), event.ts.clone()));
            entry.0 += 1;
            if event.ts < entry.1 {
                entry.1 = event.ts.clone();
            }
            if event.ts > entry.2 {
                entry.2 = event.ts.clone();
            }
        }
        let rollups = rollup
            .into_iter()
            .map(|(event_type, (count, first_ts, last_ts))| ActivityRollup {
                event_type,
                count,
                first_ts,
                last_ts,
            })
            .collect();
        let recent: Vec<Event> = events.into_iter().rev().take(20).collect();
        Ok(Response::new(ActivityReply { rollups, recent }))
    }
}
```

Add `mod query;` to `crates/ssdf-server/src/main.rs`:

```rust
mod query;
```

- [ ] **Step 5: Run the query unit test + build the crate**

Run: `cargo test -p ssdf-server query:: && cargo build -p ssdf-server`
Expected: PASS — 1 passed; crate builds (the timeline branch type-checks against the trait).

- [ ] **Step 6: Commit**

```bash
git add crates/ssdf-server/src/query.rs crates/ssdf-server/src/main.rs
git commit -m "feat(server): QueryService over ClickHouse (search/aggregate/timeline/activity)"
```

---

## Task 8: GraphService implementation (Neo4j)

Thin service: derive tenant, call a `cypher.rs` builder, run via `neo4rs`, map nodes/edges to proto. `GetEntity`, `SearchEntities`, `Neighbors`, `FindPath` are implemented; `UpsertEntity`, `LinkEntities` are deferred stubs returning `Status::unimplemented` (entity writes are owned by the Plan 4 resolver, not this read service).

**Files:**
- Create: `crates/ssdf-server/src/graph.rs`
- Modify: `crates/ssdf-server/src/main.rs`

- [ ] **Step 1: Implement node→proto mapping + the service struct**

Create `crates/ssdf-server/src/graph.rs`:

```rust
//! GraphService — entities + relationships over Neo4j. All Cypher comes from
//! `crate::cypher`; this file derives tenant, binds params, runs, and maps to proto.
//! Writes (UpsertEntity/LinkEntities) are deferred stubs — the Plan 4 resolver owns
//! entity writes; this is a read service.

use neo4rs::{Graph, Node, query};
use tonic::{Request, Response, Status};

use ssdf_proto::graph_service_server::GraphService;
use ssdf_proto::{
    Edge, Entity, FindPathRequest, GetEntityReply, GetEntityRequest, GraphReply,
    LinkEntitiesReply, LinkEntitiesRequest, NeighborsRequest, SearchEntitiesReply,
    SearchEntitiesRequest, SourceRef, UpsertEntityReply, UpsertEntityRequest,
};

use crate::cypher;
use crate::tenant::tenant_of;

pub struct GraphSvc {
    pub graph: Graph,
}

/// Map a Neo4j node to a proto `Entity`. Missing optional props default to "".
/// `include_raw` gates `ext_json` (full gating enforced by the Plan 6 Guard).
fn node_to_entity(node: &Node, include_raw: bool) -> Entity {
    let get = |key: &str| node.get::<String>(key).unwrap_or_default();
    let labels: Vec<String> = node.labels().iter().map(|s| s.to_string()).collect();
    let kind = labels.first().cloned().unwrap_or_default().to_lowercase();
    let source_refs = node
        .get::<String>("source_refs")
        .ok()
        .and_then(|raw| serde_json::from_str::<Vec<SourceRefJson>>(&raw).ok())
        .unwrap_or_default()
        .into_iter()
        .map(Into::into)
        .collect();
    Entity {
        id: get("id"),
        tenant_id: get("tenant_id"),
        kind,
        first_seen: get("first_seen"),
        last_seen: get("last_seen"),
        source_refs,
        body_json: get("body"),
        labels_json: get("labels"),
        ext_json: if include_raw { get("ext") } else { String::new() },
    }
}

#[derive(serde::Deserialize)]
struct SourceRefJson {
    source_type: String,
    source_instance: String,
    source_id: String,
    observed_at: String,
}

impl From<SourceRefJson> for SourceRef {
    fn from(value: SourceRefJson) -> Self {
        SourceRef {
            source_type: value.source_type,
            source_instance: value.source_instance,
            source_id: value.source_id,
            observed_at: value.observed_at,
        }
    }
}
```

- [ ] **Step 2: Write a failing unit test for node mapping**

Append to `crates/ssdf-server/src/graph.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_ref_json_maps_to_proto() {
        let json = r#"{"source_type":"okta","source_instance":"okta-main","source_id":"00u1","observed_at":"2026-06-01T00:00:00Z"}"#;
        let parsed: SourceRefJson = serde_json::from_str(json).unwrap();
        let proto: SourceRef = parsed.into();
        assert_eq!(proto.source_type, "okta");
        assert_eq!(proto.source_id, "00u1");
    }
}
```

- [ ] **Step 3: Run it to verify it fails to compile (impl not present yet)**

Run: `cargo test -p ssdf-server graph::`
Expected: FAIL to compile — `GraphService` imported but not implemented (unused import / trait not satisfied when registered in main). The unit test itself will pass once the module compiles; proceed to Step 4 to add the trait impl.

- [ ] **Step 4: Implement the `GraphService` trait**

Append to `crates/ssdf-server/src/graph.rs`:

```rust
#[tonic::async_trait]
impl GraphService for GraphSvc {
    async fn get_entity(
        &self,
        request: Request<GetEntityRequest>,
    ) -> Result<Response<GetEntityReply>, Status> {
        let tenant = tenant_of(&request);
        let req = request.into_inner();
        let cypher = cypher::build_get_entity();
        let mut result = self
            .graph
            .execute(query(&cypher).param("id", req.id).param("tenant", tenant))
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        let row = result
            .next()
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| Status::not_found("entity not found"))?;
        let node: Node = row.get("n").map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(GetEntityReply {
            entity: Some(node_to_entity(&node, req.include_raw)),
        }))
    }

    async fn search_entities(
        &self,
        request: Request<SearchEntitiesRequest>,
    ) -> Result<Response<SearchEntitiesReply>, Status> {
        let tenant = tenant_of(&request);
        let req = request.into_inner();
        let cypher = cypher::build_search_entities(&req.kind, req.limit);
        let mut result = self
            .graph
            .execute(query(&cypher).param("tenant", tenant).param("query", req.query))
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        let mut entities = Vec::new();
        while let Some(row) = result.next().await.map_err(|e| Status::internal(e.to_string()))? {
            let node: Node = row.get("n").map_err(|e| Status::internal(e.to_string()))?;
            entities.push(node_to_entity(&node, false));
        }
        Ok(Response::new(SearchEntitiesReply { entities }))
    }

    async fn neighbors(
        &self,
        request: Request<NeighborsRequest>,
    ) -> Result<Response<GraphReply>, Status> {
        let tenant = tenant_of(&request);
        let req = request.into_inner();
        let cypher = cypher::build_neighbors(req.depth, &req.rel_types);
        let mut result = self
            .graph
            .execute(query(&cypher).param("id", req.id).param("tenant", tenant))
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        collect_graph(&mut result, &req.kinds).await
    }

    async fn find_path(
        &self,
        request: Request<FindPathRequest>,
    ) -> Result<Response<GraphReply>, Status> {
        let tenant = tenant_of(&request);
        let req = request.into_inner();
        let cypher = cypher::build_find_path(req.max_hops);
        let mut result = self
            .graph
            .execute(
                query(&cypher)
                    .param("from_id", req.from_id)
                    .param("to_id", req.to_id)
                    .param("tenant", tenant),
            )
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        collect_graph(&mut result, &[]).await
    }

    // ── Deferred stubs (entity writes are owned by the Plan 4 resolver) ──────────
    async fn upsert_entity(
        &self,
        _request: Request<UpsertEntityRequest>,
    ) -> Result<Response<UpsertEntityReply>, Status> {
        Err(Status::unimplemented(
            "UpsertEntity is owned by the entity-resolution pipeline (Plan 4), not the read service",
        ))
    }

    async fn link_entities(
        &self,
        _request: Request<LinkEntitiesRequest>,
    ) -> Result<Response<LinkEntitiesReply>, Status> {
        Err(Status::unimplemented(
            "LinkEntities is owned by the entity-resolution pipeline (Plan 4), not the read service",
        ))
    }
}

/// Collect a path-returning result (`nodes`, `rels`) into a `GraphReply`, optionally
/// filtering nodes to an allowlist of kinds.
async fn collect_graph(
    result: &mut neo4rs::RowStream,
    kinds: &[String],
) -> Result<Response<GraphReply>, Status> {
    use std::collections::BTreeMap;
    let mut nodes: BTreeMap<String, Entity> = BTreeMap::new();
    let mut edges: Vec<Edge> = Vec::new();

    while let Some(row) = result.next().await.map_err(|e| Status::internal(e.to_string()))? {
        if let Ok(path_nodes) = row.get::<Vec<Node>>("nodes") {
            for node in &path_nodes {
                let entity = node_to_entity(node, false);
                if kinds.is_empty() || kinds.contains(&entity.kind) {
                    nodes.insert(entity.id.clone(), entity);
                }
            }
        }
        if let Ok(rels) = row.get::<Vec<neo4rs::Relation>>("rels") {
            for rel in &rels {
                edges.push(Edge {
                    from_id: rel.get::<String>("from_id").unwrap_or_default(),
                    to_id: rel.get::<String>("to_id").unwrap_or_default(),
                    rel_type: rel.typ().to_string(),
                    props_json: rel.get::<String>("props").unwrap_or_default(),
                });
            }
        }
    }
    Ok(Response::new(GraphReply {
        nodes: nodes.into_values().collect(),
        edges,
    }))
}
```

Add `mod graph;` to `crates/ssdf-server/src/main.rs`:

```rust
mod graph;
```

- [ ] **Step 5: Run graph unit test + build**

Run: `cargo test -p ssdf-server graph:: && cargo build -p ssdf-server`
Expected: PASS — 1 passed; crate builds with the full GraphService trait satisfied.

- [ ] **Step 6: Commit**

```bash
git add crates/ssdf-server/src/graph.rs crates/ssdf-server/src/main.rs
git commit -m "feat(server): GraphService over Neo4j (get/search/neighbors/findpath; write stubs)"
```

---

## Task 9: IngestionService (Postgres + ClickHouse health)

Implements `ListSources` (Postgres `sources`) and `GetSourceHealth` (joins source list with ClickHouse last-event lag). `RegisterSource`, `PauseSource`, `ReplayFrom` are deferred stubs (write/lifecycle ops land with the Plan 6 admin MCP).

**Files:**
- Create: `crates/ssdf-server/src/ingestion.rs`
- Modify: `crates/ssdf-server/src/main.rs`

- [ ] **Step 1: Implement the service**

Create `crates/ssdf-server/src/ingestion.rs`:

```rust
//! IngestionService — source config (Postgres `sources`) + ingest health
//! (ClickHouse lag). Read + SSDF-own-config only; never writes to a device.
//! Lifecycle writes (Register/Pause/Replay) are deferred stubs (Plan 6 admin MCP).

use clickhouse::{Client, Row};
use serde::Deserialize;
use sqlx::PgPool;
use tonic::{Request, Response, Status};

use ssdf_proto::ingestion_service_server::IngestionService;
use ssdf_proto::{
    GetSourceHealthReply, GetSourceHealthRequest, ListSourcesReply, ListSourcesRequest,
    PauseSourceReply, PauseSourceRequest, RegisterSourceReply, RegisterSourceRequest,
    ReplayFromReply, ReplayFromRequest, Source, SourceHealth,
};

use crate::tenant::tenant_of;

pub struct IngestionSvc {
    pub pg: PgPool,
    pub ch: Client,
}

#[tonic::async_trait]
impl IngestionService for IngestionSvc {
    async fn list_sources(
        &self,
        request: Request<ListSourcesRequest>,
    ) -> Result<Response<ListSourcesReply>, Status> {
        let tenant = tenant_of(&request);
        let rows = sqlx::query_as::<_, (String, String, String, String, String, chrono::DateTime<chrono::Utc>)>(
            "SELECT id, type, name, tenant_id, status, created_at FROM sources WHERE tenant_id = $1 ORDER BY created_at",
        )
        .bind(&tenant)
        .fetch_all(&self.pg)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;
        let sources = rows
            .into_iter()
            .map(|(id, ty, name, tenant_id, status, created_at)| Source {
                id,
                r#type: ty,
                name,
                tenant_id,
                status,
                created_at: created_at.to_rfc3339(),
            })
            .collect();
        Ok(Response::new(ListSourcesReply { sources }))
    }

    async fn get_source_health(
        &self,
        request: Request<GetSourceHealthRequest>,
    ) -> Result<Response<GetSourceHealthReply>, Status> {
        let tenant = tenant_of(&request);
        let req = request.into_inner();
        // Per-source ingest lag from ClickHouse, scoped by tenant. We key on
        // source_instance == source name (Plan 3 connectors stamp it on events).
        #[derive(Row, Deserialize)]
        struct LagRow {
            source_instance: String,
            last_ts: String,
            lag_seconds: u64,
            events_last_hour: u64,
        }
        let mut sql = String::from(
            "SELECT source_instance, toString(max(ts)) AS last_ts, \
toUInt64(dateDiff('second', max(ts), now())) AS lag_seconds, \
toUInt64(countIf(ts >= now() - INTERVAL 1 HOUR)) AS events_last_hour \
FROM ssdf.events WHERE tenant_id = ?",
        );
        if !req.source_id.is_empty() {
            sql.push_str(" AND source_instance = ?");
        }
        sql.push_str(" GROUP BY source_instance");

        let mut q = self.ch.query(&sql).bind(&tenant);
        if !req.source_id.is_empty() {
            q = q.bind(&req.source_id);
        }
        let mut cursor = q.fetch::<LagRow>().map_err(|e| Status::internal(e.to_string()))?;
        let mut health = Vec::new();
        while let Some(row) = cursor.next().await.map_err(|e| Status::internal(e.to_string()))? {
            let status = if row.lag_seconds <= 300 {
                "healthy"
            } else {
                "lagging"
            };
            health.push(SourceHealth {
                source_id: row.source_instance,
                status: status.to_string(),
                lag_seconds: row.lag_seconds,
                last_event_ts: row.last_ts,
                events_last_hour: row.events_last_hour,
            });
        }
        Ok(Response::new(GetSourceHealthReply { health }))
    }

    // ── Deferred stubs (lifecycle writes land with Plan 6 admin MCP) ─────────────
    async fn register_source(
        &self,
        _request: Request<RegisterSourceRequest>,
    ) -> Result<Response<RegisterSourceReply>, Status> {
        Err(Status::unimplemented("RegisterSource lands with the admin MCP (Plan 6)"))
    }
    async fn pause_source(
        &self,
        _request: Request<PauseSourceRequest>,
    ) -> Result<Response<PauseSourceReply>, Status> {
        Err(Status::unimplemented("PauseSource lands with the admin MCP (Plan 6)"))
    }
    async fn replay_from(
        &self,
        _request: Request<ReplayFromRequest>,
    ) -> Result<Response<ReplayFromReply>, Status> {
        Err(Status::unimplemented("ReplayFrom lands with the admin MCP (Plan 6)"))
    }
}
```

Add `mod ingestion;` to `crates/ssdf-server/src/main.rs`.

- [ ] **Step 2: Build**

Run: `cargo build -p ssdf-server`
Expected: `Finished` — IngestionService trait satisfied.

- [ ] **Step 3: Commit**

```bash
git add crates/ssdf-server/src/ingestion.rs crates/ssdf-server/src/main.rs
git commit -m "feat(server): IngestionService list/health (register/pause/replay stubbed)"
```

---

## Task 10: NormalizationService (ontology schema + entity resolution)

Implements `GetOntologySchema` (returns ontology types/fields/relationships + `ONTOLOGY_VERSION` from `ssdf-ontology`) and `ResolveEntity` (Postgres `resolution_keys` lookup). `ListMappings`, `UpsertMapping` are deferred stubs.

**Files:**
- Create: `crates/ssdf-server/src/normalization.rs`
- Modify: `crates/ssdf-server/src/main.rs`

- [ ] **Step 1: Write the failing schema test**

Create `crates/ssdf-server/src/normalization.rs`:

```rust
//! NormalizationService — ontology schema (from `ssdf-ontology`) + entity
//! resolution (Postgres `resolution_keys`). Mapping CRUD is a deferred stub.

use sqlx::PgPool;
use tonic::{Request, Response, Status};

use ssdf_ontology::ONTOLOGY_VERSION;
use ssdf_proto::normalization_service_server::NormalizationService;
use ssdf_proto::{
    GetOntologySchemaReply, GetOntologySchemaRequest, ListMappingsReply, ListMappingsRequest,
    OntologyField, OntologyRelationship, OntologyType, ResolveEntityReply, ResolveEntityRequest,
    UpsertMappingReply, UpsertMappingRequest,
};

use crate::tenant::tenant_of;

/// Static description of the canonical ontology surface (entities + events +
/// relationships). Mirrors `ssdf-ontology` field sets (spec §3); the version is
/// taken from the crate constant so schema + version never drift.
pub fn ontology_schema() -> GetOntologySchemaReply {
    let field = |name: &str, ty: &str, required: bool| OntologyField {
        name: name.to_string(),
        type: ty.to_string(),
        required,
    };
    let rel = |from: &str, rel: &str, to: &str| OntologyRelationship {
        from_kind: from.to_string(),
        rel_type: rel.to_string(),
        to_kind: to.to_string(),
    };
    let types = vec![
        OntologyType {
            name: "Identity".into(),
            category: "entity".into(),
            fields: vec![
                field("display_name", "string", true),
                field("kind", "string", true),
                field("primary_email", "string", false),
                field("status", "string", true),
                field("risk_score", "int", false),
                field("groups", "array", false),
            ],
        },
        OntologyType {
            name: "Asset".into(),
            category: "entity".into(),
            fields: vec![
                field("hostname", "string", false),
                field("ips", "array", false),
                field("macs", "array", false),
                field("os", "string", false),
                field("kind", "string", true),
                field("criticality", "string", false),
                field("exposure", "string", false),
            ],
        },
        OntologyType {
            name: "FlowEvent".into(),
            category: "event".into(),
            fields: vec![
                field("src_ip", "string", true),
                field("dst_ip", "string", true),
                field("dst_port", "int", true),
                field("proto", "string", true),
                field("action", "string", true),
            ],
        },
        OntologyType {
            name: "AuthEvent".into(),
            category: "event".into(),
            fields: vec![
                field("actor", "string", true),
                field("outcome", "string", true),
                field("mfa", "bool", true),
                field("src_ip", "string", true),
            ],
        },
    ];
    let relationships = vec![
        rel("Identity", "AUTHENTICATES_AS", "Session"),
        rel("Identity", "USES", "Asset"),
        rel("Session", "ACCESSES", "Application"),
        rel("Session", "INVOLVES", "Asset"),
        rel("Asset", "MEMBER_OF_SEGMENT", "NetworkSegment"),
        rel("Session", "GOVERNED_BY", "PolicyObject"),
        rel("PolicyObject", "GOVERNS", "Application"),
        rel("Session", "GENERATES", "Alert"),
        rel("Alert", "AFFECTS", "Asset"),
        rel("Incident", "INCLUDES", "Alert"),
    ];
    GetOntologySchemaReply {
        ontology_version: ONTOLOGY_VERSION.to_string(),
        types,
        relationships,
    }
}

pub struct NormalizationSvc {
    pub pg: PgPool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_carries_version_and_core_types() {
        let schema = ontology_schema();
        assert_eq!(schema.ontology_version, ONTOLOGY_VERSION);
        assert!(schema.types.iter().any(|t| t.name == "Identity" && t.category == "entity"));
        assert!(schema.types.iter().any(|t| t.name == "FlowEvent" && t.category == "event"));
        assert!(schema
            .relationships
            .iter()
            .any(|r| r.from_kind == "Identity" && r.rel_type == "USES" && r.to_kind == "Asset"));
    }
}
```

- [ ] **Step 2: Run the schema unit test**

Run: `cargo test -p ssdf-server normalization::tests::schema_carries_version_and_core_types`
Expected: PASS — 1 passed (no DB needed; pure schema function).

- [ ] **Step 3: Implement the trait**

Append to `crates/ssdf-server/src/normalization.rs`:

```rust
#[tonic::async_trait]
impl NormalizationService for NormalizationSvc {
    async fn get_ontology_schema(
        &self,
        _request: Request<GetOntologySchemaRequest>,
    ) -> Result<Response<GetOntologySchemaReply>, Status> {
        Ok(Response::new(ontology_schema()))
    }

    async fn resolve_entity(
        &self,
        request: Request<ResolveEntityRequest>,
    ) -> Result<Response<ResolveEntityReply>, Status> {
        let tenant = tenant_of(&request);
        let req = request.into_inner();
        if req.kind.is_empty() || req.natural_key.is_empty() {
            return Err(Status::invalid_argument("kind + natural_key required"));
        }
        let row = sqlx::query_as::<_, (String,)>(
            "SELECT global_id FROM resolution_keys WHERE tenant_id = $1 AND kind = $2 AND natural_key = $3",
        )
        .bind(&tenant)
        .bind(&req.kind)
        .bind(&req.natural_key)
        .fetch_optional(&self.pg)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;
        match row {
            Some((global_id,)) => Ok(Response::new(ResolveEntityReply { global_id, resolved: true })),
            None => Ok(Response::new(ResolveEntityReply {
                global_id: String::new(),
                resolved: false,
            })),
        }
    }

    // ── Deferred stubs (mapping CRUD lands with the normalizer admin surface) ────
    async fn list_mappings(
        &self,
        _request: Request<ListMappingsRequest>,
    ) -> Result<Response<ListMappingsReply>, Status> {
        Err(Status::unimplemented("ListMappings is deferred (normalizer admin surface)"))
    }
    async fn upsert_mapping(
        &self,
        _request: Request<UpsertMappingRequest>,
    ) -> Result<Response<UpsertMappingReply>, Status> {
        Err(Status::unimplemented("UpsertMapping is deferred (normalizer admin surface)"))
    }
}
```

Add `mod normalization;` to `crates/ssdf-server/src/main.rs`.

- [ ] **Step 4: Run tests + build**

Run: `cargo test -p ssdf-server normalization:: && cargo build -p ssdf-server`
Expected: PASS — 1 passed; crate builds.

- [ ] **Step 5: Commit**

```bash
git add crates/ssdf-server/src/normalization.rs crates/ssdf-server/src/main.rs
git commit -m "feat(server): NormalizationService schema + resolve (mappings stubbed)"
```

---

## Task 11: PolicyService (read-only) — `GetPoliciesForEntity`

READ-ONLY: no policy mutation, no device writes. Implements `GetPoliciesForEntity` (Neo4j traversal to governing `PolicyObject`s). `ListPolicies`, `GetPolicy` are deferred stubs.

**Files:**
- Create: `crates/ssdf-server/src/policy.rs`
- Modify: `crates/ssdf-server/src/main.rs`

- [ ] **Step 1: Implement the service**

Create `crates/ssdf-server/src/policy.rs`:

```rust
//! PolicyService — ingested PolicyObjects ↔ entities. READ-ONLY: no policy
//! mutation, no device writes. GetPoliciesForEntity traverses the graph to the
//! PolicyObjects governing an entity. List/Get are deferred stubs.

use neo4rs::{Graph, Node, query};
use tonic::{Request, Response, Status};

use ssdf_proto::policy_service_server::PolicyService;
use ssdf_proto::{
    GetPoliciesForEntityReply, GetPoliciesForEntityRequest, GetPolicyReply, GetPolicyRequest,
    ListPoliciesReply, ListPoliciesRequest,
};

use crate::cypher;
use crate::graph::node_to_entity;
use crate::tenant::tenant_of;

pub struct PolicySvc {
    pub graph: Graph,
}

#[tonic::async_trait]
impl PolicyService for PolicySvc {
    async fn get_policies_for_entity(
        &self,
        request: Request<GetPoliciesForEntityRequest>,
    ) -> Result<Response<GetPoliciesForEntityReply>, Status> {
        let tenant = tenant_of(&request);
        let req = request.into_inner();
        if req.entity_id.is_empty() {
            return Err(Status::invalid_argument("entity_id required"));
        }
        let cypher = cypher::build_policies_for_entity();
        let mut result = self
            .graph
            .execute(query(&cypher).param("id", req.entity_id).param("tenant", tenant))
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        let mut policies = Vec::new();
        while let Some(row) = result.next().await.map_err(|e| Status::internal(e.to_string()))? {
            let node: Node = row.get("p").map_err(|e| Status::internal(e.to_string()))?;
            policies.push(node_to_entity(&node, false));
        }
        Ok(Response::new(GetPoliciesForEntityReply { policies }))
    }

    // ── Deferred stubs ──────────────────────────────────────────────────────────
    async fn list_policies(
        &self,
        _request: Request<ListPoliciesRequest>,
    ) -> Result<Response<ListPoliciesReply>, Status> {
        Err(Status::unimplemented("ListPolicies is deferred (v0.1 PolicyService)"))
    }
    async fn get_policy(
        &self,
        _request: Request<GetPolicyRequest>,
    ) -> Result<Response<GetPolicyReply>, Status> {
        Err(Status::unimplemented("GetPolicy is deferred (v0.1 PolicyService)"))
    }
}
```

In `crates/ssdf-server/src/graph.rs`, change `fn node_to_entity` to `pub(crate) fn node_to_entity` so `policy.rs` can reuse it. Add `mod policy;` to `main.rs`.

- [ ] **Step 2: Build**

Run: `cargo build -p ssdf-server`
Expected: `Finished` — PolicyService trait satisfied, `node_to_entity` shared.

- [ ] **Step 3: Commit**

```bash
git add crates/ssdf-server/src/policy.rs crates/ssdf-server/src/graph.rs crates/ssdf-server/src/main.rs
git commit -m "feat(server): PolicyService read-only GetPoliciesForEntity (list/get stubbed)"
```

---

## Task 12: Wire `main.rs` — connect stores, serve all five services

**Files:**
- Modify: `crates/ssdf-server/src/main.rs`

- [ ] **Step 1: Replace `main.rs` with the full server wiring**

```rust
//! SSDF gRPC server — hosts the read+ingest service layer (no device writes).
//! Reflection-free, plaintext for v0 (mTLS + Gateway/Sovereignty Guard land in Plan 6).

mod cypher;
mod graph;
mod ingestion;
mod normalization;
mod policy;
mod query;
mod sql;
mod tenant;

use clickhouse::Client as ClickHouseClient;
use neo4rs::Graph;
use sqlx::postgres::PgPoolOptions;
use std::env;
use tonic::transport::Server;

use ssdf_proto::graph_service_server::GraphServiceServer;
use ssdf_proto::ingestion_service_server::IngestionServiceServer;
use ssdf_proto::normalization_service_server::NormalizationServiceServer;
use ssdf_proto::policy_service_server::PolicyServiceServer;
use ssdf_proto::query_service_server::QueryServiceServer;

use crate::graph::GraphSvc;
use crate::ingestion::IngestionSvc;
use crate::normalization::NormalizationSvc;
use crate::policy::PolicySvc;
use crate::query::QuerySvc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = env::var("SSDF_GRPC_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:50051".to_string())
        .parse()?;

    let ch_url = env::var("CLICKHOUSE_URL").unwrap_or_else(|_| "http://localhost:8123".to_string());
    let clickhouse = ClickHouseClient::default()
        .with_url(&ch_url)
        .with_user(env::var("CLICKHOUSE_USER").unwrap_or_else(|_| "ssdf".to_string()))
        .with_password(env::var("CLICKHOUSE_PASSWORD").unwrap_or_else(|_| "ssdf".to_string()))
        .with_database("ssdf");

    let neo4j_uri = env::var("NEO4J_URI").unwrap_or_else(|_| "neo4j://localhost:7687".to_string());
    let neo4j = Graph::new(
        &neo4j_uri,
        env::var("NEO4J_USER").unwrap_or_else(|_| "neo4j".to_string()),
        env::var("NEO4J_PASSWORD").unwrap_or_else(|_| "ssdfssdf".to_string()),
    )
    .await?;

    let pg_url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://ssdf:ssdf@localhost:5432/ssdf".to_string());
    let pg = PgPoolOptions::new().max_connections(8).connect(&pg_url).await?;

    let graph_svc = GraphSvc { graph: neo4j.clone() };
    let query_svc = QuerySvc { client: clickhouse.clone() };
    let ingestion_svc = IngestionSvc { pg: pg.clone(), ch: clickhouse.clone() };
    let normalization_svc = NormalizationSvc { pg: pg.clone() };
    let policy_svc = PolicySvc { graph: neo4j.clone() };

    println!("ssdf-server listening on {addr}");
    Server::builder()
        .add_service(GraphServiceServer::new(graph_svc))
        .add_service(QueryServiceServer::new(query_svc))
        .add_service(IngestionServiceServer::new(ingestion_svc))
        .add_service(NormalizationServiceServer::new(normalization_svc))
        .add_service(PolicyServiceServer::new(policy_svc))
        .serve(addr)
        .await?;
    Ok(())
}
```

- [ ] **Step 2: Build the full server**

Run: `cargo build -p ssdf-server`
Expected: `Finished` — all five `*Server` wrappers construct and serve.

- [ ] **Step 3: Smoke-test against live stores (Plan 1 infra up + schema applied)**

Bring up infra and seed one event so health/schema calls return data:

```bash
just up && just migrate
docker compose exec -T clickhouse clickhouse-client --user ssdf --password ssdf --query \
"INSERT INTO ssdf.events (event_id, tenant_id, event_type, ts, source_type, source_instance, severity, asset_id, payload) VALUES \
('evt_seed','t_main','flow_event',now(),'srx','srx-test10','info','ast_123','{}')"
```

Run the server in the background, then call `GetOntologySchema` (no DB) via grpcurl:

```bash
cargo run -p ssdf-server &
grpcurl -plaintext -proto crates/ssdf-proto/proto/ssdf.proto -import-path crates/ssdf-proto/proto \
  -H 'tenant-id: t_main' localhost:50051 ssdf.v1.NormalizationService/GetOntologySchema
```

Expected: JSON with `"ontologyVersion": "1.0.0"` and a `types` array including `Identity` and `FlowEvent`.

- [ ] **Step 4: Verify a deferred stub returns Unimplemented**

```bash
grpcurl -plaintext -proto crates/ssdf-proto/proto/ssdf.proto -import-path crates/ssdf-proto/proto \
  -H 'tenant-id: t_main' -d '{"id":"pol_x"}' localhost:50051 ssdf.v1.PolicyService/GetPolicy
```

Expected: `ERROR: Code: Unimplemented` with message `GetPolicy is deferred (v0.1 PolicyService)`. Stop the server: `kill %1`.

- [ ] **Step 5: Commit**

```bash
git add crates/ssdf-server/src/main.rs
git commit -m "feat(server): wire stores + serve all five gRPC services"
```

---

## Task 13: Integration tests — GetIncidentTimeline + Neighbors (DB-gated)

These exercise real stores via Plan 1 docker-compose, seed a tiny fixture, and assert behavior. They are `#[ignore]`d so `cargo test` stays DB-free; `just integration` runs them.

**Files:**
- Create: `crates/ssdf-server/tests/timeline_integration.rs`
- Create: `crates/ssdf-server/tests/graph_integration.rs`
- Modify: `justfile`

- [ ] **Step 1: Add a `[dev-dependencies]` block to `crates/ssdf-server/Cargo.toml`**

```toml
[dev-dependencies]
tokio = { workspace = true }
clickhouse = { workspace = true }
neo4rs = { workspace = true }
```

- [ ] **Step 2: Write the timeline integration test**

Create `crates/ssdf-server/tests/timeline_integration.rs`:

```rust
//! Integration: cross-source incident timeline over a real ClickHouse instance.
//! Gated behind #[ignore]; run via `just integration` with Plan 1 infra up + migrated.
//! Proves the v0 "Done" milestone: a cross-source timeline is answerable via gRPC.

use clickhouse::Client;
use tonic::Request;

use ssdf_proto::query_service_server::QueryService;
use ssdf_proto::{GetIncidentTimelineRequest, TimeRange};

fn ch() -> Client {
    Client::default()
        .with_url(std::env::var("CLICKHOUSE_URL").unwrap_or_else(|_| "http://localhost:8123".into()))
        .with_user("ssdf")
        .with_password("ssdf")
        .with_database("ssdf")
}

async fn seed(client: &Client) {
    // Two sources (okta auth + srx flow) referencing the same asset, out of ts order.
    client
        .query(
            "INSERT INTO ssdf.events \
(event_id, tenant_id, event_type, ts, source_type, source_instance, severity, asset_id, payload) VALUES \
('evt_b','t_main','flow_event','2026-06-05 10:05:00','srx','srx-test10','info','ast_it','{}'), \
('evt_a','t_main','auth_event','2026-06-05 10:00:00','okta','okta-main','info','ast_it','{}')",
        )
        .execute()
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires live ClickHouse (just integration)"]
async fn incident_timeline_returns_ordered_cross_source_events() {
    let client = ch();
    seed(&client).await;
    let svc = ssdf_server_test_support::query_svc(client);

    let mut request = Request::new(GetIncidentTimelineRequest {
        incident_id: String::new(),
        entity_id: "ast_it".into(),
        window: Some(TimeRange {
            start: "2026-06-05T00:00:00Z".into(),
            end: "2026-06-05T23:59:59Z".into(),
        }),
        limit: 0,
    });
    request.metadata_mut().insert("tenant-id", "t_main".parse().unwrap());

    let reply = svc.get_incident_timeline(request).await.unwrap().into_inner();
    let types: Vec<_> = reply.events.iter().map(|e| e.event_type.clone()).collect();
    // Ascending by ts: auth_event (10:00) before flow_event (10:05), across two sources.
    assert_eq!(types, vec!["auth_event", "flow_event"]);
    let sources: Vec<_> = reply.events.iter().map(|e| e.source_type.clone()).collect();
    assert_eq!(sources, vec!["okta", "srx"]);
}
```

- [ ] **Step 3: Expose a tiny test-support constructor**

Because `QuerySvc` lives in a binary crate, add a thin library target so tests can build the service. Add to `crates/ssdf-server/Cargo.toml`:

```toml
[lib]
name = "ssdf_server_test_support"
path = "src/test_support.rs"
```

Create `crates/ssdf-server/src/test_support.rs`:

```rust
//! Minimal re-export surface so integration tests can construct services.
//! Mirrors the binary's modules; kept tiny on purpose.
#[path = "tenant.rs"]
pub mod tenant;
#[path = "sql.rs"]
pub mod sql;
#[path = "cypher.rs"]
pub mod cypher;
#[path = "query.rs"]
pub mod query;
#[path = "graph.rs"]
pub mod graph;

use clickhouse::Client;
use neo4rs::Graph;

/// Construct a `QuerySvc` for integration tests.
pub fn query_svc(client: Client) -> query::QuerySvc {
    query::QuerySvc { client }
}

/// Construct a `GraphSvc` for integration tests.
pub fn graph_svc(graph: Graph) -> graph::GraphSvc {
    graph::GraphSvc { graph }
}
```

In `query.rs` and `graph.rs`, change `use crate::sql;` / `use crate::cypher;` / `use crate::tenant::tenant_of;` to `use crate::{sql, cypher, tenant::tenant_of};` style only if the binary and lib share the same crate root — since both the `[lib]` and `[[bin]]` compile from the same crate, `crate::` resolves in both. (No code change needed if modules are declared in both roots; `main.rs` already declares them.)

- [ ] **Step 4: Write the graph integration test**

Create `crates/ssdf-server/tests/graph_integration.rs`:

```rust
//! Integration: Neighbors over a real Neo4j instance. Gated behind #[ignore].

use neo4rs::{Graph, query};
use tonic::Request;

use ssdf_proto::graph_service_server::GraphService;
use ssdf_proto::NeighborsRequest;

async fn neo() -> Graph {
    Graph::new(
        std::env::var("NEO4J_URI").unwrap_or_else(|_| "neo4j://localhost:7687".into()),
        "neo4j",
        "ssdfssdf",
    )
    .await
    .unwrap()
}

async fn seed(graph: &Graph) {
    graph
        .run(query(
            "MERGE (a:Identity {id:'idn_it', tenant_id:'t_main', labels:'{\"name\":\"alice\"}'}) \
MERGE (b:Asset {id:'ast_it', tenant_id:'t_main', labels:'{\"hostname\":\"box\"}'}) \
MERGE (a)-[:USES {from_id:'idn_it', to_id:'ast_it'}]->(b)",
        ))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires live Neo4j (just integration)"]
async fn neighbors_returns_used_asset_with_tenant_scope() {
    let graph = neo().await;
    seed(&graph).await;
    let svc = ssdf_server_test_support::graph_svc(graph);

    let mut request = Request::new(NeighborsRequest {
        id: "idn_it".into(),
        depth: 1,
        rel_types: vec!["USES".into()],
        kinds: vec![],
    });
    request.metadata_mut().insert("tenant-id", "t_main".parse().unwrap());

    let reply = svc.neighbors(request).await.unwrap().into_inner();
    assert!(reply.nodes.iter().any(|n| n.id == "ast_it" && n.kind == "asset"));
    assert!(reply.edges.iter().any(|e| e.rel_type == "USES"));
}
```

- [ ] **Step 5: Add the `integration` task to `justfile`**

```make
integration:
    cargo test -p ssdf-server -- --ignored
```

- [ ] **Step 6: Run the integration tests against live infra**

Run: `just up && just migrate && just integration`
Expected: PASS — `incident_timeline_returns_ordered_cross_source_events` and `neighbors_returns_used_asset_with_tenant_scope` both pass (2 ignored tests now run green).

- [ ] **Step 7: Confirm the default test run still skips DB tests**

Run: `cargo test -p ssdf-server`
Expected: all pure unit tests pass; the two integration tests report `ignored`.

- [ ] **Step 8: Commit**

```bash
git add crates/ssdf-server/Cargo.toml crates/ssdf-server/src/test_support.rs crates/ssdf-server/tests justfile
git commit -m "test(server): DB-gated integration for GetIncidentTimeline + Neighbors"
```

---

## Self-Review

**Spec coverage — every §5 operation accounted for (implemented vs explicit stub):**

| Service | Operation | Status | Where |
|---|---|---|---|
| IngestionService | RegisterSource | stub (`Unimplemented`, Plan 6 admin MCP) | Task 9 |
| IngestionService | ListSources | **implemented** (Postgres `sources`) | Task 9 |
| IngestionService | **GetSourceHealth** | **implemented** (ClickHouse lag) | Task 9 |
| IngestionService | PauseSource | stub (`Unimplemented`) | Task 9 |
| IngestionService | ReplayFrom | stub (`Unimplemented`) | Task 9 |
| NormalizationService | **GetOntologySchema** | **implemented** (ontology + `ONTOLOGY_VERSION`) | Task 10 |
| NormalizationService | ListMappings | stub (`Unimplemented`) | Task 10 |
| NormalizationService | UpsertMapping | stub (`Unimplemented`) | Task 10 |
| NormalizationService | **ResolveEntity** | **implemented** (Postgres `resolution_keys`) | Task 10 |
| GraphService | **GetEntity** | **implemented** (Neo4j) | Task 8 |
| GraphService | **SearchEntities** | **implemented** (Neo4j) | Task 8 |
| GraphService | **Neighbors** | **implemented** (Neo4j, depth-clamped) | Task 8 |
| GraphService | **FindPath** | **implemented** (Neo4j shortestPath) | Task 8 |
| GraphService | UpsertEntity | stub (`Unimplemented`, Plan 4 resolver owns writes) | Task 8 |
| GraphService | LinkEntities | stub (`Unimplemented`, Plan 4 resolver owns writes) | Task 8 |
| QueryService | **SearchEvents** | **implemented** (ClickHouse) | Task 7 |
| QueryService | **Aggregate** | **implemented** (ClickHouse) | Task 7 |
| QueryService | **GetIncidentTimeline** | **implemented** (ClickHouse, milestone) | Task 7 + Task 13 |
| QueryService | **GetEntityActivity** | **implemented** (ClickHouse + in-proc rollup) | Task 7 |
| PolicyService | ListPolicies | stub (`Unimplemented`) | Task 11 |
| PolicyService | GetPolicy | stub (`Unimplemented`) | Task 11 |
| PolicyService | **GetPoliciesForEntity** | **implemented** (Neo4j, read-only) | Task 11 |

All 21 §5 operations are defined in proto (Tasks 2-3). All 11 bold/agent-relevant ops are fully implemented. The 10 non-bold ops are explicit `Status::unimplemented` stubs with reasons. **PolicyService has no mutation op and no device-write path** — read-only boundary honored. The v0 "Done = cross-source incident timeline answerable via gRPC" milestone is satisfied by `GetIncidentTimeline` (Task 7) and proven by the integration test (Task 13).

**Other spec sections:**
- §5 multi-tenancy (tenant from metadata, never client field) → `tenant.rs` (Task 4), used by every service; integration tests set the header. ✅
- §5 read + ingest only, never a device write → no service exposes a device-write op; UpsertEntity/LinkEntities (graph writes, not device writes) are stubbed to the resolver. ✅
- §5 Gateway + Sovereignty Guard → explicitly out of scope here; `main.rs` comment + `include_raw` seam flag the Plan 6 dependency. ✅
- §4 storage (ClickHouse `ssdf.events`, Neo4j labels/rels, Postgres `sources`/`resolution_keys`) → queried verbatim. ✅
- §3 ontology reuse → `GetOntologySchema` returns `ssdf_ontology::ONTOLOGY_VERSION`; proto Event/Entity mirror ontology fields. ✅
- §8 v0 milestone → Task 13 integration test asserts ordered cross-source timeline. ✅

**Placeholder scan:** No `TODO`/`TBD`/"implement later"/"add error handling" left. Every code step shows full code; every stub shows the real `Status::unimplemented(...)` body; every command has expected output. Deferred ops are intentional, labeled stubs (not placeholders) and are listed above.

**Type consistency:**
- proto package is `ssdf.v1` everywhere (proto, `include_proto!`, grpcurl paths `ssdf.v1.<Service>/<Op>`).
- Generated server modules referenced match tonic-build output: `graph_service_server::GraphServiceServer`, `query_service_server::QueryServiceServer`, `ingestion_service_server::IngestionServiceServer`, `normalization_service_server::NormalizationServiceServer`, `policy_service_server::PolicyServiceServer` (verified in Task 3 Step 3).
- Tenant rule: `tenant_of(&request)` reads the `tenant-id` metadata header, defaults `t_main`; never reads a tenant field from a message. Applied in all five service impls.
- Store/table names verbatim: ClickHouse `ssdf.events`; Postgres `sources` / `resolution_keys`; Neo4j labels `Identity`/`Asset`/`PolicyObject` and rels `USES`/`GOVERNED_BY`/`GOVERNS` (match Plan 1 DDL + spec §3).
- `ssdf-ontology` reuse: `ONTOLOGY_VERSION` imported in `normalization.rs`; proto `Event`/`Entity` field names mirror `ssdf_ontology::Event`/`Entity`.
- Builder names are stable across tasks: `build_search_events`/`build_entity_timeline`/`build_aggregate`/`clamp_limit` (sql.rs) and `build_get_entity`/`build_neighbors`/`build_find_path`/`build_search_entities`/`build_policies_for_entity`/`clamp_depth` (cypher.rs) — referenced identically in service impls and tests.
- `node_to_entity` is `pub(crate)` (Task 11) so both `graph.rs` and `policy.rs` use one mapping.

**One assumption to double-check:** `GetIncidentTimeline`'s `incident_id` branch (Task 7) treats the incident id as an entity ref matched against the event ref columns — this works only once Plan 4 materializes Incident nodes and stamps the incident/anchor id onto related events' ref columns. The `entity_id + window` branch (which the milestone integration test exercises) is fully self-contained and needs no such assumption. Confirm Plan 4's resolver writes the incident anchor id into events' ref columns; if instead incidents reference alerts via graph edges, the `incident_id` branch should first resolve the incident's `affected_refs` via GraphService and then union those into the timeline query.
