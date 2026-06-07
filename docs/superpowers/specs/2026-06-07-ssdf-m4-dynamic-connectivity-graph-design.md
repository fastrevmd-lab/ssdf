# SSDF M4 — Dynamic Connectivity Graph Design

**Date:** 2026-06-07
**Status:** Draft design
**Milestone:** M4, following M1 SRX → Vector → ClickHouse, M2 read-only MCP query layer, and the completed M3 milestone

## Goal

Add an evidence-backed **Dynamic Connectivity Graph** to SSDF so a security admin/operator or
LLM agent can ask contextual questions such as:

- "What does this asset talk to?"
- "Which rule governed this traffic?"
- "Is this rule still used?"
- "What new connectivity appeared compared with last week?"
- "What is the trend in connections, bytes, denies, or unique peers for this rule/asset/zone?"
- "What would a human need to know before changing or removing this rule?"

M4 should turn the M1 event stream into compact, time-windowed **connectivity memory + metrics**
without making SSDF a firewall manager, SIEM, XDR, SASE console, or NSPM workflow platform.

## Product boundary

SSDF remains **read-only**.

In scope:

- Observed connectivity from telemetry that already landed in `ssdf.events`.
- Time-windowed rollups for asset/rule/zone/application context.
- Read-only MCP tools that return graph-shaped, LLM-sized answers with provenance.
- Evidence links back to ClickHouse event IDs/time windows.

Out of scope for M4:

- Applying firewall/SASE/XDR changes.
- Rule recertification workflow, approvals, or ticketing.
- Full policy simulation / "can reach" claims based only on config.
- Neo4j or a dedicated graph database.
- Every raw flow becoming a graph node.

Design rule: M4 answers **"what was observed?"** and **"what changed over time?"**. It must not
claim **"this can reach that"** unless that reachability was observed in telemetry.

## Architecture

M4 deliberately stays close to the existing M1/M2 footprint:

```text
SRX / later NGFW logs
      │
      ▼
Vector ECS normalization
      │
      ▼
ClickHouse ssdf.events  ──► ssdf.connectivity_edges_hourly
      │                         ▲
      │                         │ materialized view or scheduled rollup
      ▼                         │
ssdf-mcp-query ────────────────┘
      │
      ▼
LLM agents / security operators
```

### Why ClickHouse-first

The simplified v0 spec intentionally deferred Neo4j and broader entity resolution. M4 should not
reverse that decision. A dynamic connectivity graph can be represented as aggregate **edges** in
ClickHouse first:

- `src_ip` / `dst_ip` / `dst_port` / `transport` / `rule_name` / ingress+egress zone form the edge key.
- Hourly buckets make trend and baseline queries cheap.
- Raw events stay in `ssdf.events` for evidence and drill-down.
- A future `GraphStore` can project the same edge records into Postgres-as-graph or Neo4j later.

This gives operator value now while preserving the later graph-store seam.

## Data model

### New table: `ssdf.connectivity_edges_hourly`

One row per observed connectivity edge per hour.

Recommended columns:

| Column | Type | Purpose |
|---|---|---|
| `bucket_start` | `DateTime('UTC')` | Hour bucket. |
| `tenant_id` | `LowCardinality(String)` | Tenant scope. |
| `event_provider` | `LowCardinality(String)` | `juniper`, later `panw`, etc. |
| `source_ip` | `IPv4` | Observed source. Nulls should be filtered out of this rollup. |
| `destination_ip` | `IPv4` | Observed destination. Nulls should be filtered out of this rollup. |
| `destination_port` | `UInt16` | Observed destination port, `0` if absent/unknown. |
| `network_transport` | `LowCardinality(String)` | `tcp`, `udp`, `icmp`, etc. |
| `rule_name` | `String` | Matched rule if present; empty string means unknown. |
| `observer_ingress_zone` | `LowCardinality(String)` | Source/ingress zone. |
| `observer_egress_zone` | `LowCardinality(String)` | Destination/egress zone. |
| `allowed_count` | `UInt64` | Count of allowed/close/create style events. |
| `denied_count` | `UInt64` | Count of deny events. |
| `flow_count` | `UInt64` | Total observed flow events in bucket. |
| `bytes_total` | `UInt64` | Sum of `network_bytes` where present. |
| `first_seen` | `DateTime64(3, 'UTC')` | First event timestamp in bucket. |
| `last_seen` | `DateTime64(3, 'UTC')` | Last event timestamp in bucket. |
| `sample_event_ids` | `Array(String)` | Small capped sample for provenance/drill-down. |

Implementation may use a ClickHouse materialized view, refreshable view, or scheduled rollup
script. The implementation plan should choose the smallest reliable option for the deployed
ClickHouse version.

### Derived edge identity

MCP responses should expose a stable `edge_key` derived from:

```text
tenant_id|provider|source_ip|destination_ip|destination_port|transport|rule_name|ingress_zone|egress_zone
```

The edge key is for query correlation only; it is not a permanent global ID yet.

## MCP tool additions

M4 extends the existing `ssdf-mcp-query` server rather than adding a second server.

### 1. `get_connectivity_for_ip`

```text
get_connectivity_for_ip(ip, direction="both", since?, until?, limit=50)
```

Returns top observed peers for an IP over a time window:

- peer IPs and ports
- rules involved
- zones involved
- allowed/denied counts
- bytes
- first/last seen
- sample event IDs

### 2. `get_policy_usage`

```text
get_policy_usage(rule_name, since?, until?, group_by="peer"|"port"|"zone"|"hour", limit=50)
```

Answers whether a rule is used and how:

- last seen
- hit/flow count
- allow/deny count
- top source/destination pairs
- top destination ports
- bytes trend
- evidence samples

### 3. `get_connectivity_trend`

```text
get_connectivity_trend(subject_type="ip"|"rule"|"zone", subject, metric="flows"|"bytes"|"denies"|"unique_peers", since?, until?, granularity="hour")
```

Returns a compact time series suitable for an LLM to summarize.

### 4. `find_new_connectivity`

```text
find_new_connectivity(ip?, rule_name?, baseline_since, baseline_until, compare_since, compare_until, limit=50)
```

Compares two windows and returns edges present in the compare window but absent from baseline.
This is the key "what changed?" operator tool.

### 5. `explain_observed_connectivity`

```text
explain_observed_connectivity(src_ip, dst_ip, dst_port?, since?, until?)
```

Returns an evidence-backed explanation:

- whether the path was observed
- first/last seen
- allowed vs denied counts
- rule(s) observed governing the traffic
- zones
- sample event IDs
- caveat: "observed telemetry only; not a full configured reachability simulation"

## LLM response shape

All M4 tools should return bounded JSON with:

```json
{
  "subject": "...",
  "window": {"since": "...", "until": "..."},
  "summary": "short human-readable statement",
  "rows": [],
  "row_count": 0,
  "truncated": false,
  "provenance": {
    "source_table": "ssdf.connectivity_edges_hourly",
    "raw_table": "ssdf.events",
    "sample_event_ids": []
  },
  "caveats": []
}
```

Caveats are mandatory when a tool could be mistaken for policy simulation. Example:

```text
This result is based on observed flow telemetry only. Absence of observed traffic does not prove
that policy denies the path.
```

## Acceptance criteria

M4 is done when an LLM agent can answer these with real data via MCP:

1. "Show what 10.64.0.5 talked to in the last 24 hours."
2. "Show usage and last hit for rule `trust-to-untrust-default` in the last 7 days."
3. "Trend denied flows for this rule by hour."
4. "What new destinations did this source talk to today compared with the previous 7 days?"
5. "Explain observed connectivity from A to B on port 443 and cite sample event IDs."

All tools must remain read-only and must enforce the same limit/time-window discipline as M2.

## Testing strategy

- Unit tests for SQL builders: grouping, filters, time bounds, limits, and no string interpolation.
- Unit tests for edge-key generation and response shaping.
- Guard tests ensuring M4 queries only read `ssdf.connectivity_edges_hourly` and `ssdf.events`.
- Integration tests against live ClickHouse when `CH_HOST`/credentials are provided.
- A fixture test that inserts small synthetic events into a temporary table or test database and verifies rollup output.

## Future phases unlocked by M4

M4 is the observed-connectivity foundation. Later phases can add:

- **Configured connectivity graph** from firewall config snapshots and policy objects.
- **Policy-vs-observed comparison**: configured access that is never used, observed traffic with unknown rule, broad rules with narrow actual use.
- **Entity resolution**: IPs mapped to assets, users, apps, and segments once the entity layer arrives.
- **GraphStore projection**: Postgres-as-graph first; Neo4j only if path traversal becomes load-bearing.
- **Multi-vendor graph**: PAN-OS, Fortinet, SASE/DEM, UniFi, Proxmox, identity and endpoint sources.

## Positioning note

This is the SSDF wedge against the market: not a full NSPM suite, not XDR, not SASE DEM, and not
a new UI. M4 provides **sovereign, MCP-native connectivity memory and metrics** so agents and
operators can reason from evidence before a separate vendor MCP performs any authorized action.
