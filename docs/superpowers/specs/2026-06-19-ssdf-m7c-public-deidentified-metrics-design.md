# SSDF M7c — Public De-identified Metrics Tier (design)

**Date:** 2026-06-19
**Status:** Design of record for M7c. Supersedes the M7b assumption that the public tier
should expose anonymized *topology*. The public tier pivots to a **de-identified
metrics/time-series surface for predictive analysis**.
**Family:** extends the M7a (classification) / M7b (public split) public-tier line.
**Depends on:** M7a/M7b (classification, `ssdf_public` grant hard-floor), the existing
`ssdf.events` fabric. **Feeds-on (future):** M13 operational-health telemetry ingest.

---

## 1. Motivation & boundary

### Why a public tier at all
The sovereign/local LLMs already answer factual questions ("how many firewalls", "does a
path exist") easily. The **only** reason to involve a *public* (frontier) LLM is heavier
**predictive reasoning** on the data — *"look at the trend and tell me when this becomes a
problem."* The public tier exists to hand a powerful model a **useful-but-non-sensitive**
view of the fabric and get prediction back.

### What changed from M7b
M7b shipped the public tier exposing the **topology graph** (`graph_nodes`/`graph_edges`).
Two problems, both discovered while aligning the data-classification policy with the
operator's intent (2026-06-19):

1. **Wrong purpose.** Topology is near-useless for predictive analysis; the predictive
   signal lives in the *numbers over time*, not the graph shape.
2. **Leaks sovereign data.** The operator's policy: device/firewall **names** are not
   sensitive, but **MAC, IP, VLAN, switch port, VMID, and physical link layout are
   sovereign** ("no public LLM should be able to figure out the topology"). The M7b public
   surface exposes all of those via `SELECT *` over the graph tables.

### Classification policy (operator intent, 2026-06-19)
- **Sovereign (never public, even aggregate):** real IP/MAC/VLAN/port/VMID, physical link
  layout, firewall **rules** + rule **results** (allow/deny outcomes), IPS/Suricata
  detections + signature detail, security **posture**, and hardware **specs** (RAM size,
  CPU model, link speed).
- **Shareable (public OK):** device/firewall/host **names**; de-identified **volume/activity
  metrics over time**; operational **utilization/trend** signals (utilization %, error-rate,
  flap counts) — explicitly distinct from the hardware specs they derive from.
- **Middle tier — exposed as normalized trend indices only:** deny/block rate, IPS detection
  volume (ratio-to-baseline, no absolute counts, no per-rule/per-signature breakdown).

The de-identification boundary — keyed pseudonymization + identifier-stripping + bucketing —
is computed **sovereign-side** and structurally enforced at the grant floor.

### Out of scope (M7c)
- Operational-health *ingest* (memory/CPU/interface/flap telemetry). That data is **not in
  the fabric today** — it is **M13**, a separate prerequisite ingest series. M7c builds an
  **extensible measure catalog** so M13's signals slot in with no redesign, but M7c ships
  only the measures derivable from today's `ssdf.events` (flows, IPS, Proxmox audit).
- No write/management capability (SSDF stays read-only).
- LLM-judge / runner changes (eval harness boundary unchanged).

---

## 2. Architecture & data flow

One direction only; the public process never holds sovereign credentials.

```
ssdf.events (sovereign, raw)
        │  reads raw, de-identifies + aggregates
        ▼
public-metrics resolver  (ct109, 4th role, ~5-min timer)
        ├──► ssdf_public.metric_timeseries   (aggregate series; no entity dimension)
        ├──► ssdf_public.entity_series        (per-SURROGATE series; top-N entities only)
        └──► ssdf.pseudonym_map               (SOVEREIGN-only: real ↔ surrogate, keyed)

public LLM ─► ssdf-mcp-public (ct113) ─ metric_timeseries / top_series /
                                          entity_metric_timeseries ─► reads ssdf_public.* ONLY
operator   ─► ssdf-mcp-query  (ct106) ─ reidentify(surrogate) ─► reads ssdf.pseudonym_map
```

### New components
- **`public-metrics` resolver** — new `services/public-metrics/` (or a 4th role mirroring
  topo/entity/policy). Runs on **ct109** on a ~5-min systemd timer
  (`ssdf-public-metrics.timer` → oneshot service). Reads `ssdf.events`; writes the three
  tables below. Writes as a dedicated CH user `ssdf_pubmetrics` (SELECT on `ssdf.events`;
  INSERT on the two `ssdf_public.*` metric tables + `ssdf.pseudonym_map`).
- **`ssdf_public.metric_timeseries`** (physical table, populated by the resolver — NOT a
  view over base): `(bucket_start DateTime, metric LowCardinality(String),
  dim LowCardinality(String), value Float64, tenant_id LowCardinality(String))`. System-wide
  aggregate series; `dim` carries only de-identified dimensions (e.g. `''` for system-total).
- **`ssdf_public.entity_series`** (physical table): `(bucket_start DateTime,
  surrogate String, metric LowCardinality(String), value Float64,
  tenant_id LowCardinality(String))`. Per-entity series keyed by **surrogate only**, written
  **only for the top-N busiest surrogates** per window (bounds inventory disclosure).
- **`ssdf.pseudonym_map`** (sovereign): `(kind LowCardinality(String), real_value String,
  surrogate String, key_version UInt16, first_seen DateTime64(3,'UTC'),
  last_seen DateTime64(3,'UTC'))`, `ReplacingMergeTree(last_seen)` ordered by
  `(kind, real_value, key_version)`. Read **only** by the sovereign `reidentify` tool.

### Grants (extends the M7b hard-floor — 008's model)
- `ssdf_public` (the public reader) gets **SELECT on `ssdf_public.metric_timeseries` and
  `ssdf_public.entity_series` only**. No base `ssdf.*`, no `ssdf.pseudonym_map`.
- `ssdf_ro` (the sovereign reader on ct106) gets **SELECT on `ssdf.pseudonym_map`** so
  `reidentify` can resolve surrogates. This grant is **never** given to `ssdf_public`.
- The M7b definer views (`ssdf_public.graph_nodes`/`graph_edges`) are left in place but no
  longer granted to / registered by the public tier (topology goes sovereign — §5).
- Net: a full dump of everything the public reader can name yields **surrogates + numbers**,
  never a real identifier, rule, detection, or spec.

---

## 3. Pseudonymization, the keyed map, and re-identification

### Key
A single sovereign secret `PUBLIC_PSEUDONYM_KEY` (random 128-bit), held **only** on the
ct109 resolver (`/etc/ssdf-public-metrics/ENV.local`, mode 600 via systemd
`LoadCredential=`, matching the P1 DynamicUser pattern). It never touches ClickHouse DDL and
never reaches ct106 or ct113.

### Surrogate computation (resolver, Python)
```
surrogate = prefix[kind] + hex(sipHash64Keyed(PUBLIC_PSEUDONYM_KEY, kind + ":" + real_value))[:10]
```
Per-kind prefixes so the model can reason by type without learning identity:
`h_` host, `fw_` firewall, `seg_` segment/VLAN, `p_` port, `vm_` VMID.

Properties:
- **Consistent** — same real value → same surrogate every run, so per-entity series stay
  continuous and relational structure (`h_3f9a` over time) survives.
- **Irreversible** — keyed one-way hash; surrogate→real is infeasible without the key. The
  IP input space is small, but the public side **cannot recompute** the hash without the
  key, so it cannot be brute-forced from public data.
- **Collision-safe** — the resolver upserts each `(kind, real_value) → surrogate` into
  `ssdf.pseudonym_map`; if it ever observes a surrogate already bound to a *different*
  `real_value` (same `key_version`), it lengthens the hex slice and re-records. The map is
  authoritative.

### Re-identification
Sovereign-only **`reidentify(surrogate)`** on ct106 (class `identity`) reads
`ssdf.pseudonym_map` and returns the real value(s) + `kind`. Audited like every sovereign
tool. Operator flow: public model flags `h_3f9a` → operator runs `reidentify` on the
sovereign side → real host/IP.

### Key rotation
Rotating the key remaps all surrogates (per-entity series continuity resets). The
`key_version` column keeps surrogates minted under an old key re-identifiable after
rotation. Rotation is expected to be rare; documented in the onboarding runbook.

---

## 4. Measure catalog

The catalog is **extensible** (a declarative list the resolver iterates); M13 health signals
append to it without redesign. M7c ships only measures derivable from today's `ssdf.events`.

### Tier 1 — shareable volume/activity (ship now)
| Metric id | Source | Aggregate (`metric_timeseries`) | Per-entity (`entity_series`) |
|---|---|---|---|
| `bytes` | `sum(network_bytes)` | system total per bucket | per surrogate-host, top-N |
| `flows` | `count()` | system total per bucket | per surrogate-host, top-N |
| `connections` | distinct 5-tuple count | system total per bucket | per surrogate-host, top-N |

### Tier 2 — normalized stance indices (ship now, ratio-to-baseline only)
| Metric id | Source | Form |
|---|---|---|
| `deny_rate_index` | `event_action` deny/block fraction | value = current-bucket deny-rate ÷ trailing-30-day baseline deny-rate; **no absolute counts**, no per-rule breakdown |
| `ips_volume_index` | UniFi IPS detection count | value = current-bucket detection rate ÷ 30-day baseline; no per-signature breakdown |

### Tier 3 — operational health (catalog placeholders, **gated on M13 ingest**)
`mem_util_pct`, `cpu_util_pct`, `iface_error_rate`, `port_flap_count`,
`proto_flap_count` — declared in the catalog as **disabled** until M13 lands the source
data; utilization/percentage forms only (absolute byte/Hz values are spec-revealing →
sovereign).

### Never (sovereign, never in the catalog)
Real IP/MAC/VLAN/port/VMID; rule names + rule actions; IPS signature detail; hardware specs
(RAM size, CPU model, link speed); physical link/segment topology.

---

## 5. Tool surface, classification & phase-0 lockdown

### Classification (`classification.py`)
- Add `metrics` to `DATA_CLASSES` and `CONFIGURABLE_CLASSES`; default `sovereign`
  (secure-by-default). De-identified by construction in the resolver, so `shareable` is safe
  to enable.
- `TOOL_DATA_CLASSES`: the three public metric tools → `frozenset({"metrics"})`;
  `reidentify` → `frozenset({"identity"})`.

### New public tools (ct113, class `metrics`)
- `metric_timeseries(metric, window, bucket, dim=None)` → aggregate series from
  `ssdf_public.metric_timeseries`.
- `top_series(metric, n, window)` → top-N surrogate trends from `ssdf_public.entity_series`.
- `entity_metric_timeseries(surrogate, metric, window, bucket)` → one surrogate's series.

All three: SELECT-only over `ssdf_public.*`, result-row-capped, coarse buckets (≥5-min).

### New sovereign tool (ct106)
- `reidentify(surrogate)` → real value(s) + kind from `ssdf.pseudonym_map` (class `identity`,
  sovereign, audited).

### Phase 0 — lockdown (prerequisite, lands in the same change)
- Flip `topology` and `identity` back to **sovereign** in `classification.public.json`
  (was `shareable` in `classification.public.example.json`); set `metrics: shareable`.
- Result: `public_tool_names` drops the 5 M7b topology/identity tools and returns **only**
  the 3 `metrics` tools. The M7b definer views remain but are unreferenced by the public
  tier.

### Inference throttling
- Coarse time buckets only (≥5-min) — no per-event timing.
- `entity_series` written **only for the top-N busiest surrogates** per window — bounds host
  inventory disclosure; the remainder rolls into `metric_timeseries` aggregates.
- Metric series carry **no edges/links/segment** dimension — topology is not reconstructable.
- Reuse ct113's existing nginx `limit_req`/`limit_conn` (edge-hardening); cap result rows in
  the tools; 30-day TTL on both metric tables.
- Stance measures only as ratio-to-baseline indices (§4 Tier 2).

---

## 6. Testing

### Unit
- **Pseudonym:** determinism (same input → same surrogate), per-kind prefix, collision
  lengthening, `key_version` carried.
- **Aggregation builders:** `metric_timeseries`/`entity_series` SQL; top-N selection;
  `deny_rate_index`/`ips_volume_index` normalization math (current ÷ baseline) incl.
  zero-baseline guard.
- **Classification:** `metrics` accepted as configurable; `public_tool_names` returns **only**
  the 3 metrics tools when `topology`/`identity` are sovereign and `metrics` shareable;
  unknown/hard-excluded unchanged.
- **reidentify:** surrogate→real round-trip; unknown surrogate → not-found.

### Live integration
- Resolver pass writes rows to both `ssdf_public.*` metric tables and `ssdf.pseudonym_map`.
- **Hard-floor:** `ssdf_public` SELECTs the two metric tables, but is **DENIED**
  (`ACCESS_DENIED`) on `ssdf.pseudonym_map` and on base `ssdf.events`/`ssdf.entities`.
- `reidentify` resolves a known live surrogate to its real value via ct106.
- `deny_rate_index` computes against live data; baseline window respected.

---

## 7. Deployment

- **ct104:** apply migration `013_public_metrics.sql` — `ssdf_public.metric_timeseries`,
  `ssdf_public.entity_series`, `ssdf.pseudonym_map`, the `ssdf_pubmetrics` writer user, the
  `ssdf_public` SELECT grants on the two metric tables, and the `ssdf_ro` SELECT grant on
  `ssdf.pseudonym_map` (for `reidentify`).
- **ct109:** new `services/public-metrics/` venv + `ssdf-public-metrics.timer`/`.service`
  (DynamicUser + `LoadCredential` for `PUBLIC_PSEUDONYM_KEY`), `/etc/ssdf-public-metrics/`
  (mode 600). Fourth role beside topo/entity/policy.
- **ct113:** sync source; set `classification.json` to `{topology:sovereign,
  identity:sovereign, metrics:shareable}`; restart `ssdf-mcp-public.service`. Confirm it
  lists exactly the 3 metrics tools and zero topology/identity tools.
- **ct106:** sync source; `reidentify` registered sovereign-only; restart
  `ssdf-mcp-query.service`.
- Onboarding runbook: `onboarding/public-metrics/` (key generation + rotation procedure).

---

## 8. Open items / future

- **M13 dependency:** Tier-3 health metrics stay disabled until M13 ingest lands.
- **Eval corpus:** a public *predictive* eval question is deferred (the deterministic harness
  scores facts, not forecasts) — revisit how to score predictive answers separately.
- **Re-identification audit review:** `reidentify` is sovereign + audited; consider a
  per-principal rate/quota on it later (consistent with the edge-hardening out-of-scope
  "per-principal quotas" follow-up).
