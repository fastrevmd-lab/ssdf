# SSDF M9 — UniFi Suricata IPS + Flow Ingest (Design)

**Date:** 2026-06-13
**Status:** Design approved; ready for implementation plan.
**Milestone:** M9 (third vendor; first detection-class source).
**Supersedes the M9 charter** in `plans/2026-06-12-ssdf-next-phase-roadmap.md` (Phase 3) —
this design widens scope from "alerts only" to "alerts + flows" (see Scope decisions).

---

## 1. Goal

Add **UniFi** as the third log source and the **first detection-class** source. Ingest the
UniFi Gateway Max's **Suricata IPS/IDS alerts** *and* its **traffic flows** via remote syslog,
normalized at ingest into the existing `ssdf.events` contract, and surface the alerts to agents
through a new `detections` field on `explain_access`.

**Why this matters:** the Gateway Max is the real edge for the `198.51.100.0/24` LAN and **all
WiFi clients** — segments the vSRX test fleet and panosvm never see. So UniFi flows are genuine
network-visibility breadth (not duplication), and the IPS alerts are the first IDS data in SSDF,
making `explain_access` answer "allowed by rule R **and** flagged by Suricata sig S".

## 2. Live investigation findings (2026-06-13)

Probed the live UniFi via `unifi-mcp` (local API, v0.2.4) before designing:

- **Gateway:** UniFi **Gateway Max (UXGB)**, UniFi OS `5.0.16`, one site `Default`
  (`00000000-0000-4000-8000-000000000001`). Plus 4 switches + 4 APs.
- **API threat/flow pull is NOT viable here:** `get_flow_risks`, `get_top_flows`, and the
  underlying `v2/.../traffic-flows` resource all **404** on this controller. Pulling IDS/flow
  data via `unifi-mcp` (collector pattern) is off the table.
- **DNS filtering is off** (CyberSecure DNS — a separate feature from Suricata IPS; not our
  source).
- The Gateway Max supports Threat Management (Suricata IPS/IDS); whether IPS is currently
  enabled is not visible via read-only tools — it is an operator prerequisite (below).

**Conclusion:** the only viable route is **remote syslog → Vector** (path A), which is also the
sovereign, M5-consistent "normalize at ingest" pattern.

## 3. Scope decisions (locked)

| # | Decision | Choice |
|---|---|---|
| Data path | syslog→Vector vs. API pull | **syslog → Vector** (API path 404s; syslog is the M5 pattern) |
| Scope | alerts only vs. alerts+flows | **alerts + flows** (gateway is the only visibility into LAN/WiFi) |
| Surfacing | ingest-only vs. `explain_access` enrichment vs. materialized edges | **ingest + `explain_access` query-side `detections`** (no new entity/edge/resolver) |
| Provenance | UniFi flows set `observer_hostname`? | **Yes** — gateway is a real enforcement point; full M6c-B provenance, `coverage.configured:0` until UniFi rules are collected (out of scope) |
| IPv6 | mirror PAN-OS vs. widen schema | **Mirror PAN-OS** — IPv4-guard typed columns, IPv6 kept in `ext`+`raw`; no schema change |
| Parse strategy | capture-first vs. assume-JSON vs. dual-mode | **Capture-first (Approach A)** — finalize VRL against a real captured sample |

**Materialized `FLAGGED_BY` edges are explicitly deferred to M10** (derived findings).

## 4. Architecture & data flow

One-directional, read-only — unchanged. UniFi config (enabling IPS + remote syslog) is an
operator onboarding step applied **outside** SSDF's data path, exactly like `onboarding/panos/`.

```
UniFi Gateway Max (Suricata IPS + traffic logging)
   │  remote syslog: IPS/IDS alerts + traffic flows
   ▼
ct102 Vector  UDP :516   ── new source `unifi_syslog`  (514 SRX, 515 PAN-OS, 516 UniFi)
   ▼  new VRL transform `unifi_ips`  — branch on log type:
       ├─ ALERT → event_kind='alert', event_category=['intrusion_detection'], unifi.ips.*
       └─ FLOW  → event_kind='event', event_category=['network'],            src/dst/ports/bytes
   ▼
ssdf.events  (event_provider='unifi')
   ├──► run_sql (sovereign only — class security_log)
   ├──► flows feed the EXISTING observed-flow path → explain_access sessions
   │      + provenance (observer_hostname = gateway, via M6c-B)
   └──► alerts → explain_access new `detections` field (sovereign only)
```

- **Normalize at ingest** — the `unifi_ips` VRL transform is the *only* place UniFi's format
  lives, feeding the existing single `ssdf.events` contract and the existing ClickHouse sink
  (add `unifi_ips` to the sink `inputs`).
- **No new service, no new host, no ClickHouse migration.**

## 5. Ingest components (ct102 / Vector)

### 5.1 New Vector source

```toml
[sources.unifi_syslog]
type = "socket"
mode = "udp"
address = "0.0.0.0:516"
max_length = 102400
```

### 5.2 New VRL transform `unifi_ips`

`inputs = ["unifi_syslog"]`; added to `[sinks.clickhouse].inputs`. Structure mirrors
`panos_ecs`:

- `parse_syslog` the wrapper, then parse the payload **per Approach A** — `parse_json` if the
  captured sample is EVE JSON, else regex extraction (like the SRX SD-block parse). The *output*
  ECS mapping is identical regardless; only the extraction differs.
- Branch on event type:
  - **Alert** → `event_kind='alert'`, `event_category=['intrusion_detection']`,
    `event_action='alert_'+<category-slug>`, `event_outcome` = `failure` if blocked/dropped
    else `detection`.
  - **Flow** → `event_kind='event'`, `event_category=['network']`,
    `event_action='flow_'+<state>`, typed IPv4-guarded src/dst, ports, bytes, transport.
  - Other/malformed → `event_action='unknown'`, everything kept in `raw`+`ext`.
- Both set `event_provider='unifi'`, `tenant_id='t_main'`, `observer_hostname` = gateway
  (H2-gated), `raw` = original line, vendor extras under `unifi.ips.*` / `unifi.*`.

### 5.3 H2 known-device gate (security review finding H2)

Extend the `_obs_known` allow-list (currently `panosvm` exact + `^vsrx-test\d`) to also accept
the UniFi gateway's stamped syslog hostname. The exact token is captured live in the plan; the
**stored value keeps original case** (M6c-B provenance-bridge rule). Unknown senders ⇒
`observer_hostname=""`.

### 5.4 H1 nftables allow-list (security review finding H1)

In `infra/firewall/ct102-ingest.nft`: add UDP **516** to the dport sets, and add the gateway's
LAN syslog **source IP** (likely `198.51.100.1`, confirmed live in the plan) — it is outside the
current `198.51.100.220-198.51.100.242` range, so it needs its own `accept` rule. Re-applied
idempotently via `scripts/apply_ct102_nftables.sh`.

## 6. ECS field mapping

### 6.1 Alert events (`event_kind='alert'`)

| ECS column | Source |
|---|---|
| `event_kind` | `'alert'` |
| `event_category` | `['intrusion_detection']` |
| `event_action` | `'alert_' + category-slug` (e.g. `alert_attempted-admin`) |
| `event_outcome` | `failure` if blocked/dropped, else `detection` |
| `event_provider` | `'unifi'` |
| `source_ip`/`destination_ip` | IPv4-guarded; IPv6 → null, kept in `ext`+`raw` |
| `source_port`/`destination_port` | if present |
| `network_transport` | proto (tcp/udp/icmp) |
| `observer_hostname` | gateway (H2-gated) |
| `ext['unifi.ips.signature']` | Suricata signature message |
| `ext['unifi.ips.signature_id']` | SID |
| `ext['unifi.ips.category']` | Suricata category |
| `ext['unifi.ips.severity']` | severity |
| `ext['unifi.ips.app_proto']` | app protocol (if present) |
| `raw` | original line |

### 6.2 Flow events (`event_kind='event'`, `event_category=['network']`)

Mapped identically to existing SRX/PAN-OS flows: typed IPv4-guarded src/dst, ports, bytes
(`network_bytes`/`source_bytes`/`destination_bytes`), `network_transport`,
`event_action='flow_'+<state>`, `observer_hostname`=gateway. Vendor extras under `unifi.*` as
the captured sample dictates.

**`rule_name`:** UniFi flow logs may not carry a firewall rule name (unlike SRX `policy-name` /
PAN-OS rule). Leave `rule_name=''` when absent — the honest value; it is why UniFi-only paths
yield `coverage.configured:0`.

## 7. Classification (M7a/M7b)

UniFi events are content in `ssdf.events`, class **`security_log`** → **sovereign-only**, never
shareable. **No `classification.py` change needed** — the public tier (ct113) already excludes
`security_log`, so UniFi alerts/flows are invisible to the public MCP by construction.

## 8. `explain_access` enrichment — `detections`

`access_tools.py` on ct106 (sovereign only):

- After resolving the client/server entities and their flow window, run one additional read
  against `ssdf.events` for `event_provider='unifi' AND event_kind='alert'` matching either IP
  in the pair, within the same `since_hours` window.
- Add a `detections` array to the response:
  `[{signature, signature_id, category, severity, timestamp, source_ip, destination_ip}, ...]`
  (empty when none). Delivers "allowed by rule R **and** flagged by Suricata sig S".
- **Bounded surface:** no new entity kind, no new edge, no resolver change — pure query-side
  read, symmetric with how the tool already reads observed flows; capped by the existing
  `MCP_MAX_RESULT_ROWS`.
- **Public tier untouched** — `explain_access` is not a shareable tool; `detections` is
  sovereign-only by inheritance.

## 9. Testing

- **Vector unit tests** (in `vector.toml`, run on ct102 — `vector test`): alert→ECS, flow→ECS,
  IPv6-left-null, malformed→`unknown`, unknown-host→`observer_hostname=''`, known-gateway passes
  through (case preserved). Fixtures = the **captured real samples** (Approach A).
- **mcp-query unit tests** (`services/mcp-query`, `uv run pytest -m "not integration"`):
  `explain_access` returns `detections` populated when alerts match, empty when none;
  sovereign-only.
- **Live integration:** after deploy, trigger a real IPS alert + a real flow → confirm rows in
  `ssdf.events` with correct typed columns; then `explain_access` on the alerted pair returns
  the detection.

## 10. Deployment (operator-gated — same convention as M5/P0)

1. **Operator:** enable Threat Management/IPS + remote syslog → `198.51.100.150:516` on the
   Gateway Max (runbook `onboarding/unifi/ips-syslog.md`).
2. **Capture** real alert + flow samples on ct102 (Approach A) → finalize VRL + unit tests.
3. **Apply nftables** (UDP 516 + gateway IP) via `scripts/apply_ct102_nftables.sh`.
4. `vector validate` then deploy the toml + restart Vector on ct102; confirm **3** UDP sources
   listening, CH sink healthy.
5. **Sync** `access_tools.py` to ct106, restart `ssdf-mcp-query`.
6. **Live-verify** alerts + flows land; `explain_access` shows `detections`.

## 11. Files

**New:**
- `onboarding/unifi/ips-syslog.md` (operator runbook: enable IPS + remote syslog, capture
  sample, gateway hostname/source-IP findings).

**Modified:**
- `infra/vector/vector.toml` — `unifi_syslog` source, `unifi_ips` transform, sink `inputs`,
  H2 gate, unit tests.
- `infra/firewall/ct102-ingest.nft` — UDP 516 + gateway source IP.
- `services/mcp-query/.../access_tools.py` (+ tests) — `detections` enrichment.

**No new ClickHouse migration.**

## 12. Out of scope (explicitly not in M9)

- Materialized `FLAGGED_BY` edges / Alert/Signature entities → **M10** (derived findings).
- Collecting UniFi *configured* firewall rules (the M6b extension that would make UniFi-path
  `coverage.configured>0`) → future M6b extension, not M9.
- UniFi flow query API / `unifi-mcp` collector path → not viable here (endpoints 404) and not
  needed (syslog covers it).
- Schema widening for IPv6 → YAGNI in an IPv4 lab.

## 13. Cross-cutting seam check

- **Normalize at ingest:** all UniFi format knowledge stays in the `unifi_ips` VRL transform;
  downstream sees only the common `ssdf.events` schema. ✔
- **MCP tool surface:** only `explain_access` gains an *additive* `detections` field (existing
  agents that bind to it are unaffected); no new tool, no renamed/removed tool. ✔
- **Read-only boundary:** SSDF only ingests/queries UniFi data; enabling IPS/syslog is an
  external operator action. ✔
- **Provider-agnostic:** UniFi enters under namespaced extras (`unifi.ips.*`), no new core
  columns. ✔
