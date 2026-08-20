# SSDF `fabric_status` — source and resolver liveness

**Date:** 2026-08-19
**Status:** approved, pending implementation plan

## Problem

Every defect found during the 2026-08-19 outage investigation shared one
signature: **it failed silently.** A renamed vendor MCP tool, a changed response
envelope, a missing required argument, an unreachable device, a truncated
payload, an IPv6 address in an IPv4 column — each produced no error anyone saw.
`run_collectors` catches at collector granularity, so a dead vendor integration
looks identical to a healthy one from outside.

Concretely, and all true simultaneously on the morning of 2026-08-19:

- the topo, policy and health collectors had been failing for four days
- `ssdf.entities(source='configured')` had been empty that whole time, while the
  policy resolver ran hourly, exited 0, and logged `0 entities, 0 edges upserted`
- UniFi had produced **zero events for 30+ days**
- the UniFi topology collector had never once succeeded since a tool-signature
  change, though UniFi *health* telemetry flowed the entire time

None of this was visible without hand-querying ClickHouse.

`ingest_status` (M14d) is the only liveness surface and does not help here. It
keys on `observer_hostname`, which covers exactly two of four providers:

| provider | events with observer_hostname | without |
|---|---|---|
| juniper | 183,391 | 375 |
| paloalto | 46,843 | 0 |
| proxmox | 0 | 24,841 |
| unifi | absent from the 7d window entirely | — |

`proxmox` is structurally invisible: that field is deliberately blank for it,
being the firewall-provenance field. `unifi` disappeared from the derived
expected set once it went quiet. Resolvers have no recorded state at all — no
heartbeat table, nothing in ClickHouse.

## Decisions

Five decisions, each taken deliberately over a plausible alternative.

### 1. Hybrid expected set

Declared for sources and resolvers; derived (as today) for the device fleet.

A set derived from observations cannot, by construction, miss a thing that was
never observed. UniFi's silence was undetectable for exactly that reason —
nothing was present to go stale. Sources and resolvers are a handful of entries
that change perhaps twice a year and where *absence is the entire signal*, so
they are declared. The 24-device fleet churns constantly and is where derivation
earns its keep, so it stays derived and `ingest_status` keeps working unchanged.

### 2. Resolver liveness is output-derived, not a heartbeat

Each resolver is measured by whether its characteristic output advanced.

A heartbeat table would have reported the policy resolver **healthy** for four
days: it ran on schedule, exited 0, and finished. Output-derived freshness flags
it stale immediately, because `entities(source='configured')` stopped advancing.
The failure mode actually encountered is invisible to the mechanism that looks
more rigorous. A crashed resolver is caught by both, so output-derived strictly
dominates for this failure class, at zero instrumentation cost, and it reports on
history predating the tool.

What this loses — distinguishing "did not run" from "ran and produced nothing" —
does not change the operator's next action, which is `journalctl -u <unit>`
either way.

### 3. A new `fabric_status` tool; `ingest_status` untouched

`ingest_status` keeps its name, contract and per-device detail. `fabric_status`
answers "is anything broken?" and includes devices only as a roll-up count.

Extending `ingest_status` additively was tempting — one call, no new surface —
but M12 established that tool naming drives agent routing, and no LLM asked "is
the topology resolver working?" will reach for a tool called `ingest_status`.
Renaming or aliasing churns a contract that four committed eval scorecards bind
to (`required_tools: [ingest_status]`).

The overlap risk of two tools is real and is contained by purpose, not data: one
answers "what is broken", the other "tell me about the devices". `fabric_status`
is a strict superset for the first question, so an agent asking it is never
falsely reassured.

### 4. Each source declares the signal that proves it alive

Not every source should be producing events. UniFi IPS detections are rare and
behavioural by design; proxmox emits only on login or task activity. A naive
"hours since last event" makes those permanently noisy, and a tool that cries
wolf is worse than no tool — it trains the operator to ignore the one time it is
right.

So a manifest entry names the observable that proves liveness, which is not
always `ssdf.events`. UniFi is checked against `health_metrics(provider='unifi')`
— the collector polls every five minutes regardless of whether a threat fires.
"No detections this month" then reads healthy, while a broken integration reads
stale. These are different questions and deserve different signals.

### 5. The manifest lives in code

A module, not a JSON file on the guest.

The manifest *is* the assertion about what should exist. An unversioned file
editable without review and invisible to CI is precisely the artifact that drifts
out of sync with reality and then quietly lies — the same failure class this tool
exists to catch, and the same one that produced a stale `.codex/config.toml` and
pre-M14 device keys in the ENV templates. Budgets in code get a diff, a test and
a reviewer.

The repo idiom of a code default plus optional file override
(`MCP_CLASSIFICATION_FILE`, `MCP_TOKENS_FILE`) can be added later if retuning
proves frequent. Starting with it is speculative.

## Design

### Modules

- `fabric_manifest.py` — the `Subject` declaration and the manifest itself
- `fabric_tools.py` — `FabricTools.fabric_status()`

This mirrors the existing split where `liveness_tools.py` holds a tool and
`classification.py` holds a declaration.

### Subject

```python
@dataclass(frozen=True)
class Subject:
    name: str             # "unifi", "ssdf-policy"
    kind: str             # "source" | "resolver"
    table: str            # "ssdf.health_metrics"
    ts_column: str        # "timestamp"
    filter_column: str | None
    filter_value: str | None
    budget_hours: float
    note: str             # why THIS signal and THIS budget
```

`note` is required, not decorative: an entry whose reasoning is not written down
cannot be reviewed later, and these budgets are judgement calls.

A single builder renders any entry to
`SELECT max({ts}) ... WHERE {col} = {value:String}` with the value **bound as a
parameter**. Table, timestamp and filter column names come only from the frozen
manifest and are never caller-supplied, so the tool exposes no injection surface.
`hours_since` is computed in SQL via `dateDiff`, following the M14d finding that
clickhouse-connect returns tz-aware datetimes that break naive subtraction.

### Manifest

| subject | kind | table | ts_column | filter | budget |
|---|---|---|---|---|---|
| juniper | source | `ssdf.events` | `timestamp` | `event_provider='juniper'` | 1h |
| paloalto | source | `ssdf.events` | `timestamp` | `event_provider='paloalto'` | 1h |
| proxmox | source | `ssdf.events` | `timestamp` | `event_provider='proxmox'` | 24h |
| unifi | source | `ssdf.health_metrics` | `timestamp` | `provider='unifi'` | 0.5h |
| ssdf-topo | resolver | `ssdf.topo_observations` | `observed_at` | — | 0.25h |
| ssdf-entity | resolver | `ssdf.entity_edges` | `last_seen` | — | 0.25h |
| ssdf-policy | resolver | `ssdf.entities` | `last_seen` | `source='configured'` | 2h |
| ssdf-health | resolver | `ssdf.health_metrics` | `timestamp` | — | 0.25h |
| ssdf-public-metrics | resolver | `ssdf_public.metric_timeseries` | `inserted_at` | — | 0.25h |

Budgets derive from deployed cadence: the four 5-minute timers get 0.25h,
`ssdf-policy` is hourly so gets 2h, event sources get 1h, and proxmox gets 24h
because idle is correct. `ssdf_ro` already holds SELECT on
`ssdf_public.metric_timeseries`, so no grant change is required.

#### Write time, not data time

`ts_column` must be the time the row was **written**, not the time the data
describes. Several candidate tables carry both, and picking the wrong one
produces a permanent false alarm. Measured on the live fabric while every
resolver was running normally:

| table | column | age | verdict |
|---|---|---|---|
| `ssdf_public.metric_timeseries` | `bucket_start` | 0.49h | **wrong** — the aggregation window lags by design, so a 0.25h budget reads stale while the resolver is healthy |
| `ssdf_public.metric_timeseries` | `inserted_at` | 0.06h | correct |

`ssdf.entity_edges` was checked for the same hazard and is safe: `last_seen`
looked event-derived from its name, but measured 0.07h old while flow events were
near zero, which proves the entity resolver stamps it at write time. That was
verified rather than assumed, because the lab's traffic generators are
deliberately stopped and an event-derived column would have been hours stale.

Adding a subject means checking this explicitly. If a table offers only a
data-time column, it is not a valid liveness signal for a resolver.

### Response

```json
{
  "healthy": false,
  "checked_at": "2026-08-19T23:00:00.000+00:00",
  "subjects": [
    {"name": "ssdf-policy", "kind": "resolver",
     "signal": "ssdf.entities(source=configured)",
     "last_seen": "2026-08-15T18:00:00.000Z", "hours_since": 97.3,
     "budget_hours": 2, "stale": true, "note": "..."}
  ],
  "devices": {"total": 24, "fresh": 3, "stale": 21},
  "summary": {"total": 9, "stale": 1, "fresh": 8}
}
```

`healthy` is true only when no subject is stale and no subject errored. Subjects
sort stale-first so the answer to "what is broken" is the top of the list.

### Failure handling

Two rules, both direct lessons from the outage.

**Never observed is stale, not absent.** A subject whose signal returns no rows
gets `last_seen: null, hours_since: null, stale: true`. UniFi went unnoticed for
30 days precisely because nothing was there to age.

**Per-subject errors appear in the response.** If one subject's query fails, the
others still return and that subject comes back with an `error` field, and
`healthy` is false. Catching an error and continuing silently is what hid every
bug on 2026-08-19; that pattern is not being rebuilt inside the tool meant to
detect it.

### Classification

`security_log`. The response exposes device names, provider inventory and
infrastructure shape, so it is sovereign-only and must never register on the
public tier.

## Testing

Unit, with a stubbed store — no live ClickHouse:

- fresh below budget, stale above, and the boundary
- never-observed subject → `stale: true`, `last_seen: null`
- one failing subject surfaced with `error` while others still return
- `healthy` false when any subject is stale, and when any subject errored
- subjects sorted stale-first
- `fabric_status` is classed non-shareable and absent from a public-tier build
- **manifest coverage**: every ingest provider and every deployed resolver unit
  has an entry, so adding a source without declaring it fails CI

## Out of scope

- Alerting, notification or scheduled evaluation. This is an on-demand MCP tool;
  a consumer that polls it is a separate concern.
- A public-tier or de-identified variant.
- Replacing or deprecating `ingest_status`.
- Instrumenting resolvers with a heartbeat (decision 2).
- Distinguishing "resolver did not run" from "ran and produced nothing".

## Risks

- **Budgets are judgement calls** and will be wrong somewhere. Mitigated by
  keeping them in reviewed code with a written `note`, and by the manifest
  coverage test making omissions loud rather than silent.
- **A signal can go stale for a reason unrelated to the subject.** If ClickHouse
  itself is down every subject reads stale at once, which is arguably correct but
  reads as nine failures rather than one. Accepted; the summary makes a
  total blackout self-evident.
- **The manifest can still drift** if a source is added and not declared. The
  coverage test is the guard, and it is the reason that test is not optional.
