# M13a — Host Resource-Pressure Ingest (Design)

**Date:** 2026-06-20
**Status:** Design (approved in brainstorm; pending spec review)
**Milestone:** M13a (first slice of M13 operational-health telemetry)

## Problem & motivation

SSDF ingests flows (SRX/PAN-OS), IPS detections (UniFi), and host-audit events
(Proxmox) — but **no operational-health telemetry**. Today the `honesty-device-metrics`
eval is a *refusal* because the fabric genuinely has no CPU/memory/temperature data.
The M7c public metrics catalog (`services/public-metrics/.../measures.py`) already ships
**disabled** Tier-3 placeholders (`mem_util_pct`, `cpu_util_pct`, `iface_error_rate`,
`port_flap_count`, `proto_flap_count`) precisely so a health source can light them up
without a redesign.

M13a is the **first** operational-health source: **host/device resource pressure** —
CPU utilization %, memory utilization %, and component temperatures — across every device
we can already reach over MCP. Later slices: M13b (interface counters/error-rates),
M13c (link/protocol flap).

### Scope

Poll **everything that exposes CPU / memory / temperature through an MCP path we already
have**:

- **Proxmox** (pve3 node + guests) — CPU %, mem %. No temperature via the guest/node API.
- **vSRX / Junos** (devices in `JUNOS_DEVICES`) — CPU %, mem %, multi-sensor temps.
- **PAN-OS** (`PANOS_DEVICE`) — CPU %, mem %, multi-sensor temps.
- **UniFi** (gateway/switches/APs) — CPU %, mem %, multi-sensor temps.

**Research conclusion (live-confirmed):** all four expose these via existing MCP
operational commands. **No SNMP poll and no device-side log enablement are required.**

### Out of scope (deliberate, for M13a)

- **Public-tier de-identified exposure.** M13a delivers sovereign ingest + queryability
  only. Flipping the M7c `mem_util_pct`/`cpu_util_pct` catalog placeholders to `enabled`
  and routing them through the pseudonym pipeline is a clean follow-on (keeps M13a minimal
  and avoids coupling ingest to the public resolver in one milestone).
- **A new MCP tool.** The data is queryable immediately via the existing generic
  `run_sql`/`describe_schema` sovereign tools (the M11 proxmox-audit precedent).
- **Interface counters / error-rates / flap** (M13b/M13c).
- **Per-vendor cadence** (configurable single cadence now; per-vendor split is a future
  option, not built — YAGNI).

## Architecture

A **5th ct109 collector role**, `services/health`, alongside topo/entity/policy/
public-metrics. One unified poller, thin per-vendor collector modules, fault-isolated;
writes a **new dedicated table** `ssdf.health_metrics` as a new INSERT-only CH user
`ssdf_health`. 5-minute systemd timer (configurable). Sovereign-queryable via `run_sql`.

```
            ct109 ssdf-health.timer (5-min oneshot)
                        │
                  collect_main
                        │  run_collectors()  (per-collector try/except → skip on failure)
        ┌───────────────┼───────────────┬───────────────┐
     proxmox          junos           panos           unifi
   get_node_status  execute_junos_  execute_pan_op  get_device_by_mac
   + guests         command         <resources>     (legacy stat API)
        └───────────────┴───────────────┴───────────────┘
                        │  list[Gauge]  (normalized at collect)
                     writer.py  ──INSERT──►  ssdf.health_metrics  (as ssdf_health)
                                                     │
                                          sovereign run_sql / describe_schema
```

## Storage — `ssdf.health_metrics` (migration 014)

A narrow long-format (EAV-style) table: one row per `(device, metric, sensor, timestamp)`
reading. A vendor exposing a new sensor lands as new rows with a new `sensor` value —
**zero schema change** (the discovery requirement). Kept **separate from `ssdf.events`**
(a gauge is not an event; keeps the event stream clean).

```sql
CREATE TABLE IF NOT EXISTS ssdf.health_metrics (
    timestamp     DateTime64(3,'UTC'),
    tenant_id     LowCardinality(String) DEFAULT 't_main',
    provider      LowCardinality(String),           -- proxmox|juniper|paloalto|unifi
    device        LowCardinality(String),           -- node/router/host/device name (sovereign identity)
    scope         LowCardinality(String) DEFAULT 'device',   -- device|guest|node
    metric_class  LowCardinality(String),           -- cpu|memory|temperature  (discovery axis #1)
    sensor        LowCardinality(String) DEFAULT '', -- sensor label; '' = device-scalar (discovery axis #2)
    metric_name   LowCardinality(String),           -- cpu_util_pct|mem_util_pct|temp_celsius
    metric_value  Float64,
    unit          LowCardinality(String),           -- percent|celsius
    raw           String DEFAULT ''                  -- source snippet for provenance/debug
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (tenant_id, provider, device, metric_class, sensor, timestamp)
TTL toDateTime(timestamp) + INTERVAL ${HEALTH_TTL_DAYS:-30} DAY;
```

- **`metric_class` + `sensor` are the two discovery axes.** Scalar gauges (cpu/mem %) are
  one row with `sensor=''`; multi-sensor classes (temps, future per-core CPU) emit N rows
  differing only in `sensor`. Sensor classes we never planned for slot in by value, not
  migration.
- **`device`** uses the **same name** topo/policy use, so a future join bridges health →
  topology firewall identity.
- TTL 30 days default, configurable via `HEALTH_TTL_DAYS` (envsubst at apply, mirrors the
  existing migration pattern).
- Apply: `HEALTH_TTL_DAYS=30 envsubst < infra/clickhouse/014_health_metrics.sql |
  clickhouse-client --host <ct104> --multiquery`.

### CH user — `ssdf_health` (migration 015)

INSERT-only on `ssdf.health_metrics`, mirroring `005_entity_user.sql` / `011`:

```sql
CREATE USER IF NOT EXISTS ssdf_health IDENTIFIED WITH sha256_password BY '${HEALTH_PW}';
GRANT INSERT ON ssdf.health_metrics TO ssdf_health;
```

Apply: `HEALTH_PW=<pw> envsubst < infra/clickhouse/015_health_user.sql |
clickhouse-client --multiquery`.

## Collector architecture — `services/health`

```
services/health/
  pyproject.toml
  src/ssdf_health/
    config.py            # env: cadence, CH conn, device lists, MCP URLs/tokens, HEALTH_TTL_DAYS
    gauge.py             # @dataclass Gauge — the normalized unit
    collectors/
      base.py            # run_collectors(): per-collector try/except → skip on failure
      proxmox.py
      junos.py
      panos.py
      unifi.py
    writer.py            # batch INSERT into ssdf.health_metrics as ssdf_health
    collect_main.py      # entrypoint: collect all → normalize → write one batch
  tests/
```

### `Gauge` — the normalized unit (`gauge.py`)

```python
@dataclass(frozen=True)
class Gauge:
    provider: str        # proxmox|juniper|paloalto|unifi
    device: str          # same name topo/policy use
    scope: str           # device|guest|node
    metric_class: str    # cpu|memory|temperature
    sensor: str          # '' for device-scalar; label for multi-sensor
    metric_name: str     # cpu_util_pct|mem_util_pct|temp_celsius
    value: float
    unit: str            # percent|celsius
    raw: str             # source line/snippet
```

Each collector returns `list[Gauge]`; the writer is vendor-agnostic and maps fields →
columns. **Normalize at collect** — the contract lives in one place (CLAUDE.md
normalize-at-ingest).

### Fault isolation

`run_collectors()` calls each collector inside try/except and **skips** on failure (the
existing topo `run_collectors` pattern). A collector returning 0 gauges logs a warning,
never fails the pass. One flaky vendor MCP cannot zero out the whole cycle.

### Device discovery

- **Proxmox:** enumerate via `get_nodes()` + `get_vms()`/`get_containers()` — no static list.
- **Junos / PAN-OS:** from env `JUNOS_DEVICES` / `PANOS_DEVICE` (same names as topo/policy).
- **UniFi:** enumerate via `search_devices`/`list_devices_by_type`, then `get_device_by_mac`
  per device for the legacy stat payload.

## Per-vendor metric mapping

All paths are existing MCP/op-commands (research-confirmed live).

### Proxmox (`provider=proxmox`)
- `get_nodes()` → per node `get_node_status(node)`; `get_vms()`/`get_containers()` for guests.
- Node CPU: `cpu` is a fraction 0–1 → `value = cpu*100`, `metric_name=cpu_util_pct`,
  `scope=node`, `sensor=''`.
- Node mem: `mem`/`maxmem` → `mem_util_pct = mem/maxmem*100`, `scope=node`.
- Guests: each running VM/CT has `cpu` (fraction) + `mem`/`maxmem` → same two metrics,
  `scope=guest`, `device=<vmid-or-name>`.
- Temperature: none via this API → Proxmox emits no `temperature` rows (expected).

### vSRX / Junos (`provider=juniper`, devices from `JUNOS_DEVICES`)
- CPU + mem: `execute_junos_command(router_name, "show chassis routing-engine")` →
  `Memory utilization NN percent` → `mem_util_pct`; CPU `Idle NN percent` →
  `cpu_util_pct = 100 − idle`. `scope=device`, `sensor=''`.
- Temperature: `execute_junos_command(router_name, "show chassis environment")` → multiple
  `Temp` sensors (e.g. `Routing Engine`, `CPU`) → one row each, `metric_class=temperature`,
  `metric_name=temp_celsius`, `sensor=<component label>`, `unit=celsius`.

### PAN-OS (`provider=paloalto`, device from `PANOS_DEVICE`)
- CPU + mem: `execute_pan_op(host, "<show><system><resources></resources></system></show>")`
  → top-style header: `%Cpu(s)` idle → `cpu_util_pct = 100 − idle`; `MiB Mem` used/total →
  `mem_util_pct`. `scope=device`, `sensor=''`.
- Temperature:
  `execute_pan_op(host, "<show><system><environmentals></environmentals></system></show>")`
  → thermal entries → one row per sensor, `sensor=<slot/description>`,
  `metric_name=temp_celsius`.

### UniFi (`provider=unifi`, devices via `search_devices`/`list_devices_by_type` → `get_device_by_mac`)
- CPU + mem: `get_device_by_mac(site, mac)` → `system-stats.cpu` / `.mem` (percent strings)
  → `cpu_util_pct` / `mem_util_pct`, `scope=device`, `sensor=''`. (The integration
  `get_device_statistics` returns null cpu/mem — the legacy stat path via MAC is the
  correct source, found live.)
- Temperature: same payload's `temperatures[]` array → one row per entry, `sensor=<name>`
  (e.g. `CPU`, `PHY`, `System`), `metric_name=temp_celsius`.

### Normalization invariants (all vendors)
- Percent metrics clamp to `[0,100]`; a single parse failure **skips that one gauge** and
  does not fail the collector.
- `device` matches topo/policy names (future health → topology join).
- `raw` carries the source line/snippet for provenance.
- Collectors are **defensive on shape** — vendor output drift (a PAN-OS/Junos upgrade)
  degrades to "0 gauges + warning," never a crash. Re-validate parsers on a major vendor
  upgrade.

## M7c catalog wiring (seam, documented — not flipped in M13a)

M13a leaves the Tier-3 placeholders **`enabled=False`** but updates the `measures.py`
note: their source is now `ssdf.health_metrics`, **not** `ssdf.events`. The follow-on
milestone flips them on and adds a health-table `AGG_VALUE_EXPR` branch + the pseudonym
pipeline. Recorded as the **M13a → public-metrics dependency** so it isn't lost.

## Deployment (ct109)

- systemd `ssdf-health.service` (oneshot) + `ssdf-health.timer` (5-min default,
  `OnUnitActiveSec` configurable; `HEALTH_POLL_SECS` informational).
- venv `/opt/ssdf-health`, env `/etc/ssdf-health/ENV.local` mode 600.
- `DynamicUser=yes` + hardening block; `LoadCredential=` for the CH password + MCP tokens
  (the P1 pattern — DynamicUser cannot read root-owned 600 secrets directly).
- Writes CH ct104 (TLS 8443) as `ssdf_health`.

## Testing

### Unit (no live)
- Per-vendor parser tests with **captured fixture payloads** (`show chassis routing-engine`,
  `show chassis environment`, PAN-OS `<resources>`/`<environmentals>`, UniFi
  `get_device_by_mac` JSON) → assert exact `Gauge` lists, including:
  - multi-sensor temperature fan-out (N rows, distinct `sensor`),
  - the **parse-failure-skips-one-gauge** invariant,
  - percent clamp to `[0,100]`.
- `run_collectors` **fault-isolation** test: one collector raises → others still return
  their gauges.

### Live integration (`-m integration`)
- One real poll cycle against ct104 + the four MCPs → assert rows land in
  `ssdf.health_metrics` with expected `metric_name`/`unit`, and `cpu_util_pct ∈ [0,100]`.

## Follow-on tasks (post-M13a, flagged not done here)

- Flip M7c `mem_util_pct`/`cpu_util_pct` placeholders to enabled + public de-id pipeline.
- Update the `honesty-device-metrics` eval — once health is surfaced it becomes answerable
  rather than a refusal.
- M13b (interface counters/error-rates), M13c (link/protocol flap).

## Commands (to record in CLAUDE.md on build)

- Unit tests: `cd services/health && uv run pytest -m "not integration"`
- Live: `cd services/health && CH_HOST=<ip> CH_PORT=8443 CH_SECURE=1 CH_CA_FILE=…
  CH_USER=ssdf_health CH_PASSWORD=<pw> JUNOS_MCP_URL=… JUNOS_MCP_TOKEN=… JUNOS_DEVICES=…
  PANOS_MCP_URL=… PANOS_MCP_TOKEN=… PANOS_DEVICE=… PROXMOX_MCP_URL=… UNIFI_MCP_URL=…
  uv run pytest -m integration`
- One pass: `cd services/health && uv run python -m ssdf_health.collect_main`
- Apply migrations: `HEALTH_TTL_DAYS=30 envsubst < infra/clickhouse/014_health_metrics.sql
  | clickhouse-client …`; `HEALTH_PW=<pw> envsubst < infra/clickhouse/015_health_user.sql
  | clickhouse-client …`
