# SSDF — Sovereign Security Data Fabric — Design Spec (v0)

- **Date:** 2026-06-05
- **Status:** Approved design (pre-implementation)
- **Authors:** mharman + Claude
- **Scope of this spec:** the minimal v0 backend — ingest, normalize, store, query, correlate, and expose read-only MCP tools.

---

## 1. Overview & Scope

SSDF is a **sovereign, AI-native security data lake**. It ingests telemetry and
control-plane *records* from multiple security products, normalizes them into a canonical
ontology, stores them in a dual data plane (columnar events + graph entities), and exposes
that data to multiple LLMs through **read-only MCP tools**.

### In scope
- Ingest, normalize, store, query, and **correlate** security data.
- A canonical ontology spanning identity, network, endpoint, and policy data.
- A read-only service layer wrapped by MCP tools for LLM/agent consumption.
- Data-sovereignty and data-minimization controls for local vs frontier LLM access.

### Explicitly OUT of scope (hard boundary)
- **SSDF never manages, configures, or writes back to any security product** (SRX,
  PAN-OS, Okta, Wazuh, etc.). No "apply change," no "propose policy change" execution.
- Acting on SSDF insights (changing a firewall, disabling an Okta user) is a **separate
  project**, handled by separate management tooling (e.g. junos-mcp / panos-mcp) that may
  consume SSDF as read-only context. SSDF's responsibility ends at serving data.
- No UI / dashboards. The MCP tool surface is the product.

### Principles
- **AI-native:** schemas/APIs/tools designed for LLM/agent workflows, not humans.
- **Sovereign:** all raw data + sensitive context stays on-prem/private; swappable storage
  and LLM backends; no public-cloud-only critical path.
- **Minimal & tight:** smallest component set that works; no speculative complexity.
- **Extensible:** new products plug in via a connector + `ext.<vendor>` namespace without
  redesigning the core.

---

## 2. Requirements

### Functional
- **F1 Ingest** — receive/pull telemetry + control-plane records per source: streaming/syslog
  for SRX & PAN-OS; API-poll + webhooks for Okta & Wazuh.
- **F2 Normalize** — map each source to the canonical ontology; preserve original fields as
  vendor extensions (`ext.<vendor>`).
- **F3 Entity resolution** — resolve identities & assets across sources to stable global IDs
  (source IDs retained); merges are reversible.
- **F4 Store (dual)** — events → columnar (ClickHouse); entities + relationships → graph (Neo4j).
- **F5 Query** — time-ranged/filtered event search, graph traversal (neighborhoods/paths),
  cross-source incident timelines.
- **F6 Service API** — bounded-context services, each wrappable 1:1 by MCP tools.
- **F7 Extensibility** — add a connector + extend ontology via vendor extensions without core redesign.

### Non-functional
- **N1 Sovereignty** — raw data + sensitive context stays on-prem; no public-cloud-only critical path.
- **N2 Performance** — sustain ~tens of thousands events/sec ingest; interactive query latency for agents.
- **N3 Scalability** — horizontally scalable ingest + storage.
- **N4 Resilience** — durable bus buffering; at-least-once delivery into stores.
- **N5 Auditability** — every service/tool call + data access logged immutably.
- **N6 Tenancy-ready** — `tenant_id` on core records + APIs (single tenant deployed in v0).
- **N7 Schema evolution** — ontology + event schemas explicitly versioned.

### AI / LLM-specific
- **A1 AI-native surface** — agent-oriented operations; outputs shaped for LLM consumption.
- **A2 MCP boundaries** — each operation maps to a typed MCP tool.
- **A3 Data minimization** — tools return least data necessary; raw payloads gated.
- **A4 Local vs frontier tiering** — local tools get full detail; frontier tools get
  summary/aggregate/redacted views.
- **A5 Policy-gated egress** — a sovereignty policy is consulted before any data crosses the boundary.
- **A6 Multi-LLM** — model-agnostic; no single provider load-bearing.
- **A7 Provenance** — tool outputs carry source IDs + timestamps for grounding/citation.

### v0 decisions
- **First sources / build order:** SRX → Okta → Wazuh (proves identity↔network↔endpoint
  correlation) → PAN-OS (proves multi-vendor NGFW).
- **Storage:** dual-store from day one.
- **Tenancy:** single-tenant, workspace-ready schema.
- **LLM runtime:** local-first; frontier access gated through redaction/sovereignty.
- **MCP direction:** LLM → SSDF (read/query) only. Vendor-control direction is a separate project.

---

## 3. Canonical Ontology

### Two-layer model
- **Events** = immutable facts, stored columnar (ClickHouse). The input-of-record.
- **Entities** = resolved current-state projection, stored in the graph (Neo4j), built/updated
  **from** events. Keeps raw fidelity (sovereignty) while giving agents a clean graph.

### Entities (8)
Shared envelope on every entity: `id` (global) · `tenant_id` · `first_seen` · `last_seen` ·
`source_refs[]` · `ext{}` · `labels{}` (denormalized summary).

| Entity | Key canonical fields | Natural keys (resolution) |
|---|---|---|
| **Identity** | `display_name`, `kind`(user/service/device), `primary_email`, `status`, `risk_score`, `groups[]` | email/UPN, okta_user_id |
| **Asset** | `hostname`, `ips[]`, `macs[]`, `os`, `kind`, `criticality`, `exposure` | ip+time-window, hostname, mac, wazuh_agent_id |
| **Application** | `name`, `kind`(saas/internal/service), `app_id`, `dst_ports[]`, `category` | okta_app_id, fw app-id, (dst_ip,port) |
| **NetworkSegment** | `name`, `kind`(zone/vlan/subnet), `cidr`, `trust_level` | fw zone name, cidr |
| **PolicyObject** | `name`, `kind`(fw-rule/okta-policy), `action`, `enabled`, `rule_index`, `device_ref` | vendor rule UUID/name + device |
| **Session** | `kind`(network-flow/auth), `start`, `end`, `state`, `src_ref`, `dst_ref`, `identity_ref`, `app_ref`, `bytes`, `verdict` | 5-tuple+time (network), okta session_id (auth) |
| **Alert** | `title`, `severity`, `category`, `status`, `confidence`, `affected_refs[]` | source alert id |
| **Incident** | `title`, `severity`, `status`, `summary`, `alert_refs[]`, `timeline[]` | SSDF-minted |

### Relationships (graph edges)
`Identity -AUTHENTICATES_AS-> Session` · `Identity -USES-> Asset` ·
`Session -ACCESSES-> Application` · `Session -INVOLVES-> Asset` (src/dst) ·
`Asset -MEMBER_OF_SEGMENT-> NetworkSegment` · `Session -GOVERNED_BY-> PolicyObject` ·
`PolicyObject -GOVERNS-> Application` · `Session -GENERATES-> Alert` ·
`Alert -AFFECTS-> Asset|Identity` · `Incident -INCLUDES-> Alert`.

### Events (5)
Shared envelope: `event_id`(ULID) · `tenant_id` · `event_type` · `ts` · `source_type` ·
`source_instance` · `severity` · resolved refs (`identity_id`,`asset_id`,`app_id`,`policy_id`,`session_id`) · `ext{}`.

| Event | Distinct fields | Emitted by |
|---|---|---|
| **AuthEvent** | `actor`, `outcome`, `mfa`, `auth_method`, `src_ip`, `geo`, `risk` | Okta |
| **FlowEvent** | `src_ip/port`, `dst_ip/port`, `proto`, `app`, `action`, `bytes_in/out`, `zone_src/dst`, `user` | SRX, PAN-OS |
| **PolicyDecisionEvent** | `policy_ref`, `decision`, `reason`, `matched_on` | SRX/PAN policy match, Okta policy eval |
| **AlertEvent** | `rule_id`, `title`, `category`, `confidence`, `affected_ip/user` | Wazuh, FW IPS/threat, Okta risk |
| **ConfigChangeEvent** | `actor`, `target_ref`, `change_type`, `before/after` digest | FW commits, Okta admin changes (ingested as data only) |

### Scaling rule (critical)
Raw firewall flows do **not** each become graph nodes. Every `FlowEvent` lives in ClickHouse
and references entities directly. A `Session` **node** is materialized only when *notable*
(auth sessions always; network sessions when long-lived, denied, or alert-linked). Routine
flows roll up into aggregated `Asset -TALKS_TO-> Asset|Application` edges.

### IDs & extensions
- **Global IDs:** SSDF-minted type-prefixed ULIDs — `idn_`, `ast_`, `app_`, `seg_`, `pol_`,
  `ses_`, `alr_`, `inc_`.
- **Source IDs:** never overwritten — `source_refs[] = {source_type, source_instance, source_id, observed_at}`.
- **Resolution:** Entity Resolution maps natural keys → global id; conflicts/merges are
  recorded as events (auditable, reversible).
- **Vendor extensions:** canonical fields promoted; everything else under namespaced `ext`
  (`ext.srx.*`, `ext.panos.*`, `ext.okta.*`, `ext.wazuh.*`).

---

## 4. Data Plane

### Ingest
- **SRX / PAN-OS** → structured **syslog** into **Vector** (parse vendor formats) → Redpanda.
- **Okta** → Python connector: System Log API polling (cursor) + event hooks (webhook).
- **Wazuh** → Python connector pulling from the Wazuh indexer/API (agentless).

### Bus
**Redpanda** (Kafka API, single binary, no ZooKeeper/JVM). Topics `raw.<source>`. Durable
buffering (N4); horizontally scalable consumers (N3).

### Processing (Rust)
- **Normalizer** — consumes `raw.*`, maps to canonical events, promotes canonical fields,
  stuffs the rest into `ext.<vendor>`, batch-inserts events to ClickHouse.
- **Entity Resolution** — consumes normalized events, maintains natural-key→global-id map
  in Postgres, upserts entities/relationships into Neo4j, emits auditable merge events.

### Storage
- **ClickHouse** — events + audit. Partition by `(tenant, toDate(ts))`; TTL tiers: hot 30d →
  compress → cold to MinIO → drop per retention policy.
- **Neo4j (Community)** — entities + relationships. Single node is sufficient (graph holds
  only current state + notable sessions). Tenancy via `tenant_id` property scoping in Cypher.
- **Postgres** — source/tenant config, sovereignty policy, resolution keyspace.
- **MinIO** — on-prem S3 cold tier.

### Graph engine note
Neo4j Community is GPLv3, but SSDF talks to it over the **Bolt network protocol** (separate
process) using Apache-licensed drivers — no copyleft reaches SSDF code. Community = single
node, no native multi-DB/RBAC; acceptable given the small graph and `tenant_id` scoping.
`GraphService` is an interface so the engine stays swappable.

---

## 5. Service Layer

Rust services exposing **gRPC** (tonic). A single **API Gateway** is the front door for the
Python MCP layer: it handles authN/Z, injects tenant context, and runs the Sovereignty Guard
on every response. All services are **read + ingest only**.

| Service | Owns | Key operations (agent-relevant in bold) |
|---|---|---|
| **IngestionService** | source config, connector lifecycle, offsets | `RegisterSource`, `ListSources`, **`GetSourceHealth`**, `PauseSource`, `ReplayFrom` |
| **NormalizationService** | mappings, ontology version, entity resolution | **`GetOntologySchema`**, `ListMappings`, `UpsertMapping`, **`ResolveEntity`** |
| **GraphService** | entities + relationships (Neo4j) | **`GetEntity`**, **`SearchEntities`**, **`Neighbors`**, **`FindPath`**, `UpsertEntity`, `LinkEntities` |
| **QueryService** | events, metrics, timelines (ClickHouse + graph labels) | **`SearchEvents`**, **`Aggregate`**, **`GetIncidentTimeline`**, **`GetEntityActivity`** |
| **PolicyService** | ingested policies ↔ entities (read-only) | `ListPolicies`, `GetPolicy`, **`GetPoliciesForEntity`** |

### Multi-tenancy
Every gRPC call carries `tenant_id` in request metadata (derived from token, never
client-supplied). Services scope all store queries by `tenant_id`.

### AuthN / AuthZ
- Service↔service: mTLS, internal CA.
- MCP layer→Gateway: per-agent service accounts, OAuth2 client-credentials tokens with
  fine-grained scopes (`events:read`, `graph:read`, `policy:read`, `raw:read`, `config:write`).
- Local-LLM accounts get broad scopes incl. `raw:read`; frontier-LLM accounts get a
  restricted set (no `raw:read`).

---

## 6. MCP Tools

All read-only, **LLM → SSDF**. Delivered as **two MCP servers** over the same backend.

### Catalog
| Tool | Input | Output (LLM-shaped) | Tier |
|---|---|---|---|
| `get_ontology_schema` | – | entity/event types, fields, relationships | both |
| `search_entities` | `kind?`, `query`, `filters{}`, `limit` | `[{id, kind, name, key_labels{}, last_seen}]` | both (masked on frontier) |
| `get_entity` | `id`, `include_raw?` | canonical + `source_refs[]` (+`ext` w/ `raw:read`) | local |
| `get_entity_neighbors` | `id`, `depth≤3`, `rel_types?`, `kinds?` | `{nodes[], edges[]}` | local |
| `find_path` | `from_id`, `to_id`, `max_hops≤5` | ordered `{nodes[], edges[]}` | local |
| `search_events` | `event_types?`, `time_range`, `filters{}`, `limit` | flat rows + provenance | local |
| `get_incident_timeline` | `incident_id` \| `entity_id`+`window` | ordered events + provenance | both (frontier summarized) |
| `get_entity_activity` | `entity_id`, `window`, `event_types?` | activity rollup + recent refs | both (frontier aggregates) |
| `get_policies_for_entity` | `entity_id` | governing PolicyObjects | local |
| `get_source_health` | – | per-source ingest status/lag | both |

### Output shape
Every result item carries `provenance {source, source_id, tenant_id}` and timestamps (A7).
Default outputs are summaries + IDs; raw payloads (`ext.*`) require `raw:read` + explicit
`include_raw`. All tools are `limit`- and `time_range`-bounded.

### Two-server enforcement
- **`ssdf-local-mcp`** (sovereign local models): full tool set, raw access via scope, unmasked.
- **`ssdf-frontier-mcp`** (Claude/GPT): subset of tools, redacted output, **no raw/row-level
  tools in its catalog** — a frontier model physically cannot invoke them. The Sovereignty
  Guard applies per-dataset flags on top.

---

## 7. Sovereignty & Safety Controls

### Egress classes (most-restrictive-wins)
`never_leave` (deny at frontier) · `summary_only` · `mask_identities` · `redact_fields` · `open`.
Rules match on `source`, `kind`, `category` (e.g. `raw_payload`), `tenant_id`, `labels`.

### Guard flow
MCP call → token→tier+scopes → service fetches data → **tag data** → **match sovereignty
rules** → compute **most-restrictive action** for tier → transform response → **audit record**.

### Config model
Declarative YAML loaded into Postgres (`sovereignty_policy`, versioned, hot-reloadable).
**Frontier default = `never_leave` (deny-by-default / allow-list).** Local default = `open`
but audited. Raw payloads = `never_leave`. Datasets are opted *in* for frontier use per rule.

```yaml
defaults:
  local:    open
  frontier: never_leave
rules:
  - match: { category: raw_payload }
    frontier: never_leave
  - match: { kind: Identity }
    frontier: mask_identities
  - match: { source: wazuh, kind: Alert }
    frontier: summary_only
tenant_overrides:
  t_main:
    - match: { kind: Asset, labels: { criticality: crown_jewel } }
      frontier: never_leave
```

### Audit model
Append-only `audit` table in ClickHouse (long TTL, tier-able to MinIO WORM):
`ts · request_id · tenant_id · caller · tier · server · tool · args_digest(hash) ·
datasets_touched[] · sovereignty_decision · rows_returned · redactions_applied[] ·
latency_ms · outcome`. `args_digest` is a hash (audit log is not itself a leak vector).
Optional hash-chain for tamper-evidence (v0.2).

### Other guards
Per-tier rate limits + result caps; deny-by-default for unclassified datasets at frontier;
query-cost ceiling; (v0.1) optional PII/secret scan on free-text summaries before frontier egress.

---

## 8. v0 Implementation Plan

### Stack
Rust (Vector, Normalizer, Entity Resolution, gRPC services) · Python (Okta/Wazuh connectors,
two MCP servers, multi-LLM layer) · ClickHouse · Neo4j Community · Postgres · Redpanda · MinIO.

### Milestones
- **v0 — read path proven (SRX → Okta → Wazuh):** Vector + connectors → Redpanda → Normalizer
  + Entity Resolution → ClickHouse + Neo4j + Postgres. GraphService + QueryService (gRPC).
  Ontology v1. Audit table. Single tenant.
  **Done =** a cross-source incident timeline is answerable via gRPC (no MCP yet).
- **v0.1 — MCP + sovereignty + PAN-OS:** both MCP servers; Sovereignty Guard + policy YAML;
  PolicyService + Ingestion/Normalization APIs; add PAN-OS connector.
  **Done =** a local LLM answers questions over the fabric; frontier gets safe summaries.
- **v0.2 — multi-LLM + hardening:** model-agnostic agent layer; entity-resolution merge review;
  hash-chained audit; MinIO cold tiering + retention TTLs.
  **Done =** agents correlate identity+network+endpoint with provenance, sovereignty enforced.

### Must-have (v0) vs defer
| Must-have | Defer |
|---|---|
| Ontology v1 + versioning | Full MITRE ATT&CK mapping |
| 3 connectors, at-least-once into stores | Auto-scaling / multi-node Neo4j |
| Dual store + basic search/timeline | Advanced graph (SmartGraph-style) features |
| `tenant_id` plumbed everywhere | Actual multi-tenant deployment |
| Entity resolution for Identity + Asset | Probabilistic/ML entity matching |
| Audit table | Hash-chain tamper-evidence |

### Pitfalls / keep-clean abstractions
- Raw flows stay events, never graph nodes (biggest scaling trap).
- Version ontology + event schema from day one (changes ripple to all three stores + MCP output).
- `GraphService`/`QueryService` behind interfaces — keep Neo4j/ClickHouse swappable.
- Entity-resolution merges must be reversible (recorded as events).
- Sovereignty Guard is the single egress chokepoint — no service may return data to the MCP
  layer bypassing it.
- Connectors own all vendor weirdness; no vendor conditionals leak into services/tools.

---

## 9. Open Questions / Future
- Embeddings/semantic search (pgvector or ClickHouse ANN) for entity/event similarity — not v0.
- Probabilistic entity resolution — v0 uses deterministic natural keys.
- Additional sources (SASE) follow the same connector + `ext.<vendor>` pattern post-v0.
