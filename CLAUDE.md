# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

**SSDF — Sovereign Security Data Fabric.** A minimal, AI-native security data platform
built from scratch to power **conversational / agent-based management of security
products** (NGFWs, SASE, IDaaS, XDR, etc.) through **MCP tools driven by multiple LLMs**.

Two principles shape every design decision:

- **AI-native, not AI-bolted-on.** The data model, APIs, and tooling exist so that LLM
  agents can query, correlate, and act on security data via MCP. Human UIs are secondary;
  the MCP tool surface is the primary product.
- **Sovereign.** All data and inference stay under the operator's control (self-hosted,
  no mandatory SaaS). Do **not** introduce hard dependencies on external/cloud SIEM/XDR
  platforms (e.g. Wazuh, Splunk, cloud-only LLM APIs). LLM and storage backends must be
  swappable, with self-hosted options as first-class citizens. "Minimal" is a hard
  constraint — prefer the smallest thing that works over feature-complete frameworks.

## Stack (as built)

- **Ingest = Vector (VRL transforms)** on LXC ct102 — vendor syslog (SRX UDP/514,
  PAN-OS UDP/515) normalized to ECS-ish events at ingest. Vendor log formats live ONLY
  in `infra/vector/vector.toml`.
- **Storage = ClickHouse** on LXC ct104 — `ssdf.events` (events), `ssdf.entities`/
  `ssdf.entity_edges` (entity graph), topology observations, `ssdf.audit`. The
  swappable-backend seam is the Python store classes (graphstore/entitystore), not a
  Rust fabric.
- **Services + MCP layer = Python** (`services/*`, uv + FastMCP) — resolvers
  (topo/entity/policy on ct109 systemd timers) and the MCP tool surface
  (sovereign ct106 :30032, public ct113 :30033) behind an nginx TLS edge.
- **Rust is permitted, not doctrine** — use it where a future component is genuinely
  performance-critical; nothing in SSDF is Rust today. `rust-junosmcp` remains the
  external reference implementation, not part of this repo.
- Everything runs on Proxmox LXCs (no Docker) on pve3.example.com.

## Architecture (as built)

Data flows one direction; LLM agents are read-only consumers via MCP:

```
security products ──► Vector VRL (ct102) ──► ClickHouse (ct104) ──► MCP tools (ct106/ct113)
  SRX / PAN-OS syslog    normalize at ingest     events + entity        ▲
                                                 graph + audit          │
                          resolvers (ct109): topo/entity/policy   LLM agents (multi-LLM)
```

- **Ingest (Vector):** the only place vendor-specific log formats live; normalize at
  ingest into the common event schema.
- **Data fabric (ClickHouse + Python resolvers):** the system of record — events plus
  derived entity/topology/policy graph; correlation happens in the resolvers.
- **MCP tool layer (Python/FastMCP):** exposes the fabric as MCP tools. This is the
  contract LLM agents bind to. Treat tool definitions as the public API.
- **Agent/LLM layer:** multiple LLMs behind MCP; no single model provider may be
  load-bearing. **SSDF is read-only**: it stores, queries, and correlates — it never
  applies configuration to security products in its own data path (onboarding configs
  are applied by the operator via external vendor MCPs, e.g. rust-junosmcp/panos-mcp).

### Cross-cutting rules

- **Normalize at ingest, never downstream.** A single common schema is the contract every
  other layer depends on. Schema changes ripple everywhere — treat them as breaking and
  version them.
- **The MCP tool surface is an API.** Adding/renaming/removing a tool changes what every
  agent and LLM can do. Design tools to be safe for autonomous invocation (clear scope,
  explicit destructive-action gating) given they manage live security infrastructure.
- **Provider-agnostic by construction.** Anything that assumes one specific LLM, one storage
  engine, or one SIEM violates the sovereignty principle. Put such choices behind interfaces.

## Commands

### M1 (SRX → Vector → ClickHouse)
- Run Vector unit tests: `vector test infra/vector/vector.toml`
- Validate Vector config: `CH_HOST=127.0.0.1 vector validate --no-environment infra/vector/vector.toml`
- Apply ClickHouse schema: `CH_HOST=<ip> ./scripts/apply_clickhouse_schema.sh`
- Query events: `clickhouse-client --host <ch-host> --query "SELECT ... FROM ssdf.events ..."`
- Infra runs on Proxmox LXC (no Docker): ClickHouse=ct104, Vector=ct102 on pve3.example.com.
- SRX onboarding applied via rust-junosmcp using onboarding/srx/stream-config.set.

### M2 (MCP query layer — ssdf-mcp-query)
- Unit tests: `cd services/mcp-query && uv run pytest -m "not integration"`
- Integration tests (live CH): `CH_HOST=<ip> CH_USER=ssdf_ro CH_PASSWORD=<pw> uv run pytest -m integration`
- Run locally: `uv run python -m ssdf_mcp_query.server`
- Deployed: streamable-HTTP MCP on its own Proxmox LXC (ct106, no Docker), bearer-token auth,
  reading ClickHouse ct104 as the read-only `ssdf_ro` user. As-built coords in gitignored
  `services/mcp-query/infra/ENV.local`.
- Add to an agent via `.mcp.json`: `{"type":"http","url":"http://<ip>:30032/mcp",
  "headers":{"Authorization":"Bearer <token>"}}`.

### M3 (PAN-OS ingest — Vector VRL/CSV → ClickHouse)
- Run Vector unit tests (on ct102 where Vector is installed, not dev host): `ssh root@ct102 "cd /etc/vector && vector test /path/to/vector.toml"` or push the toml and run `vector test infra/vector/vector.toml` remotely.
- Validate config locally (syntax only, no live sinks): `CH_HOST=127.0.0.1 vector validate --no-environment infra/vector/vector.toml`
- PAN-OS source: Vector ct102 listens UDP **port 515** (SRX uses 514; PAN-OS is separate source to avoid collision).
- Onboarding artifact: `onboarding/panos/log-forwarding.set` — apply to host `panosvm` (VMID 900) via panos-mcp. Preview first with `pan_config_diff`, then commit with `load_and_commit_pan_config`. SSDF never applies device config in its own data path.
- Sample query: `clickhouse-client --host <ch-host> --query "SELECT event_action, count() FROM ssdf.events WHERE event_provider='paloalto' GROUP BY event_action"`
- PAN-OS version pinned: **12.1.5**. Field positions in the `panos_ecs` VRL transform are tied to the PAN-OS 12.1 default CSV syslog format — re-validate the transform on any major PAN-OS upgrade before relying on parsed fields.

### M4 (topology graph — services/topo + topology MCP tools)
- Unit tests: `cd services/topo && uv run pytest -m "not integration"`
- Live integration: `cd services/topo && CH_HOST=<ip> CH_PASSWORD=<pw> JUNOS_MCP_URL=… JUNOS_MCP_TOKEN=… uv run pytest -m integration`
- One collection cycle: `cd services/topo && uv run python -m ssdf_topo.collect_all`
- One resolver pass: `cd services/topo && uv run python -m ssdf_topo.resolve_main`
- Deployed: collectors+resolver on Proxmox LXC **ct109** (`ssdf-topo`, 198.51.100.153, no
  Docker) on a 5-min systemd timer (`ssdf-topo.timer` → oneshot collect→resolve); writes CH
  ct104 as `ssdf_topo`. Topology MCP tools (`get_entity`, `locate`, `neighbors`, `find_path`,
  `enforcement_points`, `topology_snapshot`) live on the existing `ssdf-mcp-query` (ct106).
  As-built coords in gitignored `services/topo/infra/ENV.local`.
- **Firewall-role device nodes (M6c, issue #6 scope A).** The junos + panos collectors self-emit one `device_inventory(role=firewall, name=<device>)` observation per device (helper `collectors/base.py:firewall_inventory`), so `panosvm`/`vSRX-test10` resolve as `kind=device, attrs.role=firewall` and `enforcement_points` can attribute them. Requires `JUNOS_DEVICES` to be set on ct109 (`/etc/ssdf-topo/ENV.local`) — junos collector is a no-op with an empty device list.
- **Collector MCP arg names (latent-bug fix, M6c):** `execute_junos_command` takes `router_name` (NOT `router`); `execute_pan_op` takes `host` + `cmd`. Wrong names raise `missing_argument`, which `run_collectors` catches and silently skips — surfaced only when a collector first runs live.

### M6a (entity/correlation — services/entity + explain_access tool)
- Entity unit tests: `cd services/entity && uv run pytest -m "not integration"`
- Entity live integration (writes CH): `cd services/entity && CH_HOST=<ip> CH_USER=ssdf_entity CH_PASSWORD=<pw> uv run pytest -m integration`
- mcp-query unit tests (incl. entitystore/access_tools): `cd services/mcp-query && uv run pytest -m "not integration"`
- One resolver pass: `cd services/entity && uv run python -m ssdf_entity.resolve_main`
- One reconcile pass (merge+delete stale ip_only twins): `cd services/entity && uv run python -m ssdf_entity.reconcile_assets`
- Apply entity schema + user: `clickhouse-client < infra/clickhouse/004_entities.sql` then `ENTITY_PW=<pw> envsubst < infra/clickhouse/005_entity_user.sql | clickhouse-client`.
- Deployed: resolver on Proxmox LXC **ct109** (shares host with M4 topo; venv `/opt/ssdf-entity`, env `/etc/ssdf-entity/ENV.local` mode 600) on a 5-min systemd timer (`ssdf-entity.timer` → oneshot `ssdf-entity.service`); writes CH ct104 as `ssdf_entity` into `ssdf.entities`/`ssdf.entity_edges`. The `explain_access(client, server)` MCP tool lives on `ssdf-mcp-query` (ct106), reading as `ssdf_ro`. As-built coords in gitignored `services/entity/infra/ENV.local`.
- **ClickHouse `toString(col) AS col` alias trap:** aliasing a `toString(...)` back to the source column name shadows the real typed column in WHERE/ORDER BY, turning datetime comparisons into lexical string compares. Qualify the column (e.g. `entity_edges.last_seen`) in filters. (Bug found in M6a live validation; see STATUS.md.)
- **Segment-scoped asset identity (asset-duplication fix).** MAC is identity; IP is a per-vantage observation. Asset key is `mac:<mac>` when an ARP binding for the flow's firewall segment binds IP→MAC, else the segment-local fallback `ip:<segment>:<ip>` (was a global `ip:<ip>` that duplicated whenever the same IP sometimes did/didn't bind a MAC). `normalize_segment(name)` = first dotted label lowercased, so flow-side `observer_hostname` (FQDN) and binding-side `source_device` (short name) agree (`panosvm.example.com`→`panosvm`). A binding map `(segment, ip)→mac` is read from `topo_observations` arp_entry over `TOPO_BINDING_LOOKBACK_HOURS` (default 168h), latest-observation-wins; same IP+different MAC in one segment flags `ip_conflict` and never merges; same IP across segments stays distinct (NAT/branch reuse). The `COMMUNICATED_WITH` edge is keyed on **entity ids** (not raw IP pairs), so two IPs collapsing to one MAC share one edge and accumulate stats.
- **Reconcile pass (`reconcile_assets`).** Standalone idempotent cleanup for twins already written before the fix: merges a stale ip_only twin's COMMUNICATED_WITH edge attrs into the MAC asset's edge, then `ALTER TABLE … DELETE` (mutations_sync=1) the twin + its edges — only when the IP maps to exactly one MAC and that MAC asset exists. Twin GOVERNED_BY edges are dropped (not re-pointed) and re-derived by the next resolver pass.
- **`find_entity` confidence-first ordering.** By-IP lookups can match both a MAC asset (confidence 1.0) and a stale ip_only twin (0.5); `ORDER BY confidence DESC, entities.last_seen DESC` makes the MAC asset win so explain_access reads its `observer_hosts`-bearing edge (fixes the M6c-B provenance caveat where a by-IP lookup returned the stale twin).

### M6b (configured policy — services/policy + explain_access configured_controls)
- Policy unit tests: `cd services/policy && uv run pytest -m "not integration"`
- Live integration (needs CH + vendor MCPs): `cd services/policy && CH_PASSWORD=<pw> PANOS_MCP_URL=… PANOS_MCP_TOKEN=… JUNOS_MCP_URL=… JUNOS_MCP_TOKEN=… JUNOS_DEVICES=vSRX-test10 uv run pytest -m integration`
- One pass: `cd services/policy && uv run python -m ssdf_policy.collect_resolve`
- Deployed: collector+resolver on ct109 (third role alongside topo+entity; venv `/opt/ssdf-policy`, env `/etc/ssdf-policy/ENV.local` mode 600) on an HOURLY systemd timer (`ssdf-policy.timer` → oneshot `ssdf-policy.service`); writes CH ct104 as `ssdf_entity` into the shared `ssdf.entities`/`ssdf.entity_edges` (kind='firewall'|'policy', source='configured'). `explain_access` (ct106) gains `configured_controls` + integer `coverage.configured`. As-built coords in gitignored `services/policy/infra/ENV.local`.
- Configured Policy is keyed `provider:device_name:rule_name` (per-firewall identity — fixes M6a's same-name collapse where two firewalls' identically-named rules merged); Firewall entities keyed `device:<name>` linked by `Firewall──GOVERNED_BY(configured)──►Policy` edges.
- Device names in `JUNOS_DEVICES`/`PANOS_DEVICE` MUST match M4 `source_device` names so explain_access can bridge topology firewalls → Firewall entities by name.
- Junos rules read via `execute_junos_command "show configuration security policies | display set"`; PAN-OS via `get_pan_config` (vsys1 security rulebase, pinned to 12.1 config shape).
- **M4↔M6b name-bridge gap (live finding):** `explain_access` attaches configured rules to a path via M4 `enforcement_points`, which only returns graph nodes with `kind=="device"` AND `attrs.role=="firewall"`. M4 currently models **0** such nodes, so live `explain_access` on real transit pairs returns `configured_basis:no_path_firewall` and `coverage.configured:0` even though the configured side is correct (direct `configured_policies_for_firewalls(["panosvm","vSRX-test10"])` returns all 6 policies). Closing this needs M4 to emit firewall-role device nodes; tracked as the M6b→M4 dependency in issue #6 (milestone M6c). **Closed by M6c scope A (PR #7 — M4 now emits firewall-role nodes, fixing the topology/fallback path) + M6c scope B (provenance attribution as the primary, transit-robust path; below).**

### M6c scope B (provenance firewall attribution — observer_hostname → explain_access)
- Apply migration: `clickhouse-client < infra/clickhouse/006_observer_hostname.sql` (idempotent `ADD COLUMN IF NOT EXISTS observer_hostname LowCardinality(String)` on `ssdf.events`).
- Run Vector unit tests (validate `observer_hostname` emission): on ct102, `vector test infra/vector/vector.toml` — the `srx_observer_hostname_from_syslog_host` + `panos_observer_hostname_from_syslog_host` tests assert it from the syslog HOSTNAME.
- entity unit tests (flow-agg `observer_hosts` + edge attr): `cd services/entity && uv run pytest -m "not integration"`.
- mcp-query unit tests (provenance-primary attribution): `cd services/mcp-query && uv run pytest -m "not integration"`.
- **Mechanism:** the firewall that *logged* a flow is by definition on its path. `observer_hostname` (ECS `observer.hostname`) is normalized at ingest (both `srx_ecs` + `panos_ecs` transforms emit `string(parsed.hostname)`); the entity resolver collects it per pair via `groupUniqArray(observer_hostname)` in `build_flow_agg_sql` and merges it onto the `COMMUNICATED_WITH` edge as a comma-set `observer_hosts`; `explain_access` reads `observer_hosts` first → `firewall_basis:provenance`, falling back to M4 `enforcement_points` only when absent (`firewall_basis:topology`/`no_path_firewall`). New response field: `firewall_basis`.
- **Live proof:** resolve the client by an identifier that lands on the flow-owning asset (`explain_access("203.0.113.1"` server, client = the MAC/asset that owns the flow) → `firewall_basis:provenance`, `firewalls:[vSRX-test10]`, `coverage.configured:1`).
- **Proof caveat (pre-existing M6a duplication):** an IP that sometimes binds a MAC (M4 topo) and sometimes doesn't yields TWO Asset entities; `find_entity` orders `last_seen DESC LIMIT 1`, so a by-IP lookup can return a stale ip-only asset whose edge lacks `observer_hosts`. This is M6a's IP-vs-MAC identity split, not a scope-B defect. vSRX-test10 is the live-proven path.
- **Provenance suffix normalization (M6c-B follow-up):** `explain_access` normalizes each `observer_hosts` value to its first DNS label (`access_tools._short_host` — case-preserved, IPv4/IPv6-guarded) before matching Firewall entities, so PAN-OS `panosvm.example.com` bridges to `device_name=panosvm`. vSRX (`vSRX-test10`, dot-free) is a no-op, so the live-proven path is unchanged. Side effect: the `firewalls` response field is now vendor-consistent (short device names for both vendors). Unit-proven (`test_short_host`, `test_explain_access_provenance_normalizes_panos_fqdn`, `test_explain_access_provenance_preserves_mixed_case_short_name`); NOT yet live-proven end-to-end — no PAN-OS transit flow exists in the lab (same M5/M6c-B carve-out). Spec: `docs/superpowers/specs/2026-06-10-ssdf-panos-provenance-suffix-normalization-design.md`.

### M7a (classification + multi-principal auth + audit — ssdf-mcp-query hardening)
- Unit tests: `cd services/mcp-query && uv run pytest -m "not integration"` (adds classification/auth/audit/wrapper/server-audit suites).
- Live audit integration: `cd services/mcp-query && CH_HOST=<ip> CH_PASSWORD=<ro_pw> CH_AUDIT_PASSWORD=<audit_pw> [CH_ADMIN_PASSWORD=<pw>] uv run pytest -m integration`.
- Apply audit schema + user: `AUDIT_PW="$CH_AUDIT_PASSWORD" envsubst < infra/clickhouse/007_audit.sql | clickhouse-client --host <ct104> --multiquery` (creates `ssdf.audit` + INSERT-only `ssdf_audit`; pattern mirrors `005_entity_user.sql`).
- **Multi-principal auth:** set `MCP_TOKENS_FILE` (JSON `{ "<token>": {"principal": "...", "allowed_tools": [...]} }`; omit `allowed_tools` ⇒ all tools). Leaving it unset keeps the single-token path (`MCP_AUTH_TOKEN`/`MCP_TOKEN_FILE`) mapped to principal `agent`/all-tools — existing ct106 deploy works unchanged. Example: `services/mcp-query/infra/tokens.example.json`.
- **Classification:** secure-by-default; only `topology`/`identity` are configurable to `shareable` via `MCP_CLASSIFICATION_FILE`. Overriding `security_log`/`firewall_config`, an unknown class, or a bad value ⇒ `ConfigError` at startup (fail closed). M7a only *labels*+*audits* — it never withholds data (that is M7b). Example: `services/mcp-query/infra/classification.example.json`.
- **Audit path:** every tool call writes one `ssdf.audit` row (ts, principal, tier=`sovereign`, tool, args-JSON, data_classes, decision allow|deny, row_count, error) as the `ssdf_audit` user on a connection SEPARATE from the `ssdf_ro` query path. Audit is best-effort — an insert failure is logged to stderr but never fails the tool call. A disallowed tool returns `{"error":"forbidden"}` (HTTP 200) and audits `decision="deny"` without invoking the tool. `CH_AUDIT_PASSWORD` unset ⇒ no-op auditor (server still runs).
- **Per-tool wrapper:** `wrapper.audited_tool` wraps each tool with `functools.wraps`, so FastMCP's schema (built via `get_type_hints`+`inspect.signature`) still sees the real tool signature/docstring. Tool return shapes are unchanged (agents already bind to them).
- ct106 is an editable install at `/opt/src/mcp-query/src` — sync source + `systemctl restart ssdf-mcp-query.service`; add `MCP_TOKENS_FILE`/`MCP_CLASSIFICATION_FILE`/`CH_AUDIT_USER`/`CH_AUDIT_PASSWORD` to `/etc/ssdf-mcp/…` (mode 600).
- **Hands to M7b:** `classification.py` (taxonomy+map), `audit.py`+`ssdf.audit` (public process writes `tier="public"`), and the token-map auth pattern. Classes flagged `shareable` drive M7b's shareable views + `ssdf_public` grants.

### M7b (public MCP split — ssdf-mcp-public tier)
- Unit tests: `cd services/mcp-query && uv run pytest -m "not integration"` (adds `test_server_public` + classification/graphstore public-schema suites).
- Live floor/audit integration: `cd services/mcp-query && CH_HOST=<ip> CH_PUBLIC_PASSWORD=<pub_pw> CH_AUDIT_PASSWORD=<audit_pw> CH_PASSWORD=<pub_pw> [CH_ADMIN_PASSWORD=<pw>] uv run pytest tests/test_public_views_integration.py -m integration`.
- Apply public views + users: `DEFINER_PW="$CH_DEFINER_PASSWORD" PUBLIC_PW="$CH_PUBLIC_PASSWORD" envsubst < infra/clickhouse/008_public_views.sql | clickhouse-client --host <ct104> --multiquery` (creates `ssdf_public` db, `ssdf_view_definer`, two `SQL SECURITY DEFINER` views, and the `ssdf_public` reader granted on views only).
- **Tier select:** the SAME `ssdf_mcp_query.server` runs public when `MCP_TIER=public` (default `sovereign`). Public build registers only tools whose data classes are ALL `shareable` (per `MCP_CLASSIFICATION_FILE`), **minus `run_sql`** (hard-excluded). No shareable class ⇒ 0 tools + a stderr warning (secure default). Public stores read the `ssdf_public` schema (`graphstore` `schema` param); audit rows are tagged `tier="public"`.
- **Hard floor:** `ssdf_public` has SELECT on `ssdf_public.graph_nodes`/`graph_edges` ONLY; the definer views read base `ssdf.*` as `ssdf_view_definer`. `ssdf_public` selecting any base `ssdf.*` table ⇒ `ACCESS_DENIED` (proven by `test_public_cannot_read_sovereign_base_tables`).
- **Deployed:** LXC **ct113** (`ssdf-mcp-public`, 198.51.100.154, port 30033) on pve3 — mirrors ct106 (pip editable venv `/opt/ssdf-mcp` over `/opt/src/mcp-query`, deployed from `main`, NOT copied from ct106 which still runs M7a). Unit `services/mcp-query/infra/ssdf-mcp-public.service`; `/etc/ssdf-mcp/secrets.env` (mode 600) holds `CH_PASSWORD`=ssdf_public pw + `CH_AUDIT_PASSWORD`; `/etc/ssdf-mcp/classification.json` flips `topology`/`identity` to `shareable` (see `infra/classification.public.example.json`). A public LLM connects as an MCP client to `http://198.51.100.154:30033/mcp` with a public-tier token — MCP is the only interface; no API/egress to configure. **VMID note:** the design said ct110 but VMID 110 is the `vSRX-test1` VM — the container is **ct113** (hostname/IP/port unchanged). Auditor connects with default-db `ssdf_public` but inserts to fully-qualified `ssdf.audit` (the `ssdf_audit` grant covers it).

### P0 ingest hardening (H1 nftables allow-list + H2 observer_hostname device gate)
- Security-review P0 fixes from `docs/security/2026-06-10-vulnerability-review.md` (findings H1+H2); spec `docs/superpowers/specs/2026-06-10-ssdf-p0-ingest-hardening-design.md`, plan `docs/superpowers/plans/2026-06-10-ssdf-p0-ingest-hardening.md`. PR #15 (merged `0156368`); both DEPLOYED + verified live on ct102 2026-06-10.
- **H1 (nftables source allow-list on the ingest host):** apply with `./scripts/apply_ct102_nftables.sh` (idempotent; env `PVE_HOST_SSH` default `root@pve3.example.com`, `SSDF_VECTOR_CTID` default `102`). Rule file `infra/firewall/ct102-ingest.nft` → pushed to ct102 `/etc/nftables.d/ssdf-ingest.nft`; dedicated `inet ssdf_ingest` table accepts UDP 514/515 only from `198.51.100.220-198.51.100.242` (vSRX test fleet + panosvm .225) and drops everything else on those ports. Base chain `policy accept` ⇒ all other traffic passes; the default `inet filter` table is untouched. Flat /24 LAN means interface-binding can't isolate senders, so source-IP filtering is required. Verify: `ssh root@pve3.example.com "pct exec 102 -- nft list table inet ssdf_ingest"` shows both rules; `include "/etc/nftables.d/ssdf-ingest.nft"` in `/etc/nftables.conf` makes it reboot-persistent. Revert: `nft delete table inet ssdf_ingest`.
- **H2 (known-device gate, both VRL transforms):** `srx_ecs` + `panos_ecs` in `infra/vector/vector.toml` now gate `observer_hostname` — normalize the syslog HOSTNAME to its first DNS label, lowercase **for the membership test only**, accept iff `panosvm` (exact) or regex `^vsrx-test\d`, else blank to `""`. **Stored value keeps original case** so the M6c-B `vSRX-test10` exact-match provenance bridge in `explain_access` is intact. Defense-in-depth for spoofed-but-source-allowed packets. Tests (run on ct102): `vector test infra/vector/vector.toml` — 14/14 incl. `srx_observer_hostname_unknown_is_blanked`, `panos_observer_hostname_unknown_is_blanked` (unknown HOSTNAME ⇒ `observer_hostname==""`) plus regression that known hosts pass through.
- **H2 live deploy (gated on ClickHouse being reachable):** Vector's CH-sink healthcheck fails if ct104 is down, so deploy when CH is up. Push the updated toml, `vector validate /etc/vector/vector.toml.new` (CH healthcheck must pass), back up the old config, `mv` into place, `systemctl restart vector.service`, confirm `active` + both UDP sources listening. Vector config path on ct102 is `/etc/vector/vector.toml`; env drop-in sets `CH_HOST` + `VECTOR_CONFIG`.
- **Remaining review backlog:** ALL CLOSED — P1 (M1/M3/M4/M5/M6) via PR #16 (deployed 2026-06-11/12), M2 + L1–L6 via the edge-hardening batch below. See STATUS.md "Security hardening backlog".

### P1 in-place hardening (M1/M3/M4/M5/M6 — PR #16, deployed)
- CH query caps live in `clickhouse.py` `run()` (`MCP_MAX_EXEC_SECS`/`MCP_MAX_RESULT_ROWS`/`MCP_MAX_MEMORY_BYTES`); **migration `010_ro_settings_constraints.sql` is required** — readonly=1 users reject per-query settings unless declared `CHANGEABLE_IN_READONLY` with MAX bounds (live-found).
- Audit hash chain: `audit_chain.py` (per-tier `row_hash = SHA256(prev_hash + canonical(row))`); offline verifier `uv run python -m ssdf_mcp_query.verify_audit` (reads as `ssdf_audit_verify`, needs `CH_AUDIT_VERIFY_PASSWORD` + base CH/token envs; exit 0 clean / 1 issues / 2 config). Pre-009 rows (`row_hash=''`) are legacy chain-starts, excluded by design.
- systemd: all 5 units run `DynamicUser=yes` + hardening block. **DynamicUser cannot read root-owned 600 secrets** — units use `LoadCredential=` + `%d/...` paths (live-found). Tokens/classification now via `LoadCredential=tokens.json:/etc/ssdf-mcp/tokens.json` → `MCP_TOKENS_FILE=%d/tokens.json`.

### Edge hardening (M2 + L1–L6 — TLS, nginx edge, token expiry, grant split)
- Spec: `docs/superpowers/specs/2026-06-11-ssdf-edge-hardening-design.md`. All deployed + live-verified 2026-06-12.
- **PKI:** `./scripts/gen_ssdf_tls.sh` → gitignored `infra/tls-local/` (CA 10y + ct104/ct106/ct113 leaves 825d, IP SANs). CA key never leaves the dev host; only `ssdf-ca.crt` is distributed. Re-issue leaves: `--force`.
- **CH TLS (ct104):** apply with `./scripts/apply_ct104_tls.sh` — https 8443 (`config.d/ssdf-tls.xml`), nftables `inet ssdf_ch` closes plaintext 8123/9000 to loopback-only (container-local admin still works). Clients opt in via `CH_PORT=8443 CH_SECURE=1 CH_CA_FILE=<ca>` (same envs across mcp-query/topo/entity/policy and the integration tests). **Trap:** clickhouse-connect infers https from port 8443 even without `interface=` — stale code on a host then fails cert-verify instead of falling back.
- **Vector (ct102):** endpoint is `${CH_PROTO:-http}://${CH_HOST}:${CH_HTTP_PORT:-8123}` (env-nesting inside defaults does NOT parse — proven Vector 0.56.0). Live host sets `CH_PROTO=https CH_HTTP_PORT=8443` in the systemd drop-in and appends `[sinks.clickhouse.tls] ca_file="/etc/vector/ssdf-ca.crt"` to the deployed toml (a checked-in tls block would break the plain-http default).
- **nginx MCP edge (ct106/ct113):** apply with `./scripts/apply_mcp_edge.sh` — TLS on LAN 30032/30033, uvicorn rebound to `127.0.0.1:31032/31033` via drop-in `edge.conf`; rate limit 10r/s burst 30 + 32 conns/IP (429), Host gate (444), Origin gate (403), SSE-safe proxying. Clients now use `https://198.51.100.152:30032/mcp` / `https://…154:30033/mcp` with `ssdf-ca.crt` trust (Claude Code: `NODE_EXTRA_CA_CERTS`).
- **Token expiry/rotation:** `tokens.json` entries take optional `"not_after": "<ISO-8601 UTC>"` — enforced per call in `wrapper` (expired ⇒ `{"error":"forbidden"}` + audit deny); malformed ⇒ fail-closed. Rotation: add new entry → restart → move clients → delete old → restart. Both tiers run named principals with +90d expiry; local client config in gitignored `.mcp.json`.
- **L4 grant split:** `ENTITY_MAINT_PW=… envsubst < infra/clickhouse/011_entity_maint_user.sql | clickhouse-client --multiquery` — reconcile runs as `CH_USER=ssdf_entity_maint python -m ssdf_entity.reconcile_assets`; the 5-min resolver identity `ssdf_entity` no longer holds ALTER DELETE.
- **PAN-OS timestamps fixed to UTC (P2, 2026-06-12):** panosvm now runs `timezone UTC`
  (onboarding/panos/timezone-utc.md) and pre-cutover rows were backfilled +4h
  (`infra/clickhouse/012_backfill_paloalto_utc.sql.example`, cutover 2026-06-12 12:00:00 UTC —
  chosen by boundary inspection in a row-free gap, NOT the commit time; see 012).
  Any NEW log source must be onboarded with a UTC device clock — naive-parse skew otherwise.

### Ops (backups + lab traffic)
- **vzdump backups (P2, 2026-06-12):** `PVE_BACKUP_STORAGE=local ./scripts/apply_pve_backup_job.sh`
  idempotently maintains two cluster jobs — `ssdf-ch-daily` (ct104, 03:30, keep-daily=7/weekly=4)
  and `ssdf-all-weekly` (ct102/104/106/109/113, Sun 04:30, keep-weekly=4); snapshot mode + zstd.
  `local` is the only backup-capable storage on pve3 (host's own disk) — covers container
  loss/fat-fingers, NOT host-disk loss. Schedule times are pve3-host-local. Verify:
  `pvesh get /cluster/backup` / restore drill to a SCRATCH VMID only, never ct104 itself.
- **Lab transit traffic (P2):** ct115 `ssdf-labgen` (Alpine, 10.74.11.20 on panosvm trust
  VLAN 103) runs `scripts/labgen_transit.sh` via 15-min cron so PAN-OS TRAFFIC ingest +
  the M6c-B provenance bridge stay continuously live-proven. Runbook:
  `onboarding/panos/transit-traffic.md`. Do not destroy ct115 without replacing the source.
  ct115 is deliberately NOT in the weekly backup job — it is fully reproducible from the runbook.

### M8 (agent evals — services/evals, SSDF side only)
- Unit tests + corpus lint: `cd services/evals && uv run pytest -m "not integration"`
- Live integration (corpus SQL validity + audit join): `CH_HOST=<ip> CH_PORT=8443 CH_SECURE=1 CH_CA_FILE=… CH_PASSWORD=<ro_pw> CH_AUDIT_VERIFY_PASSWORD=<av_pw> [CH_AUDIT_PASSWORD=<audit_pw>] uv run pytest -m integration`
- Score a run: `uv run python -m ssdf_evals.score <manifest.json>` (exit 0 scored / 2 config/contract/scoring error); regression gate: `uv run python -m ssdf_evals.regress results/<scorecard>.json` (exit 0 = no regressions / 1 = regressions listed on stderr / 2 = unreadable or schema-invalid scorecard).
- **Boundary:** this repo stops at the MCP layer — NO runner code, NO LLM-judge, NO new MCP tools, nothing deploys. External runner projects execute the corpus against the live MCP endpoints (prod https+token path) under a dedicated eval principal (`eval-*` in tokens.json) and hand back a run-manifest JSON (`services/evals/schemas/manifest.schema.json` = the contract). `ssdf.audit` is the only trusted tool trace.
- Scoring is 100% deterministic: `reference_sql` predicates compute ground truth against live CH **at scoring time** (live lab data — static answers would rot); `expected_json` for stable facts; `refusal` for honesty questions. Structured answers via per-question `answer_format` (verbatim prompt suffix) are what make this possible.
- Corpus: `golden/core.yaml` (23 questions, 5 categories, tier-tagged sovereign|public|both); lint enforced in unit tests (unique ids, public questions restricted to public tools, SELECT-only SQL). Scorecards committed under `services/evals/results/` — git history is the eval database.
- **Corpus live-fixes:** configured-policy questions filter `identifiers['provider']`/`identifiers['device_name']` (live entity_ids are 16-hex hashes, not natural keys); the panosvm policy count uses `count(DISTINCT entity_id)` (ReplacingMergeTree duplicate-version trap).
- **Audit-check integrity:** `started`/`finished` + principal are trusted from the manifest — this only holds if the runner uses a **dedicated eval-only principal** (e.g. `eval-claude`, `eval-qwen`) that is never shared with regular agents or other runners. Serial reuse across runs is fine; two runs must never execute concurrently (or with overlapping ±slop audit windows) under the same principal — otherwise the audit tool-check window is untrustworthy and SSDF will not vouch for the scorecard. Add eval principals to ct106/ct113 tokens.json at first run.
- **External runner (the other half of M8, NOT in this repo):** the runner is the standalone sibling repo `~/ssdf-eval-runner/` (its own git — never merge runner code into SSDF). Pure `core` (corpus load/tier-filter/prompt build/JSON extraction/manifest assemble+validate) + two adapters: `claude_adapter` shells `claude -p --output-format json --mcp-config <f> --strict-mcp-config --allowedTools "mcp__ssdf__*" --permission-mode bypassPermissions --no-session-persistence` (the CLI owns MCP; `NODE_EXTRA_CA_CERTS=<ca>` for CA trust; uses the CLI's OAuth — no `ANTHROPIC_API_KEY`); `qwen_adapter` drives MCP itself via `streamable_http_client(url, http_client=httpx.AsyncClient(verify=ssl_ctx, headers=...))` (the factory path `streamablehttp_client` can't inject CA `verify=`) + an Ollama tool loop. Run: `SSDF_ROOT=… ssdf-eval-run --model {claude,qwen} --tier {sovereign,public} --out <f>` with eval tokens sourced from `services/evals/infra/ENV.local`. **First full matrix ran 2026-06-13** → 4 committed scorecards (claude sov 16/22 + pub 4/6; qwen sov 4/22 + pub 1/6); see STATUS.md M8. The corpus sovereign run is **22 questions** (17 sovereign + 5 both), public is **6** (1 public + 5 both).

### M9 (UniFi Gateway Max Suricata IPS ingest — Vector CEF → ClickHouse)
- SSDF's first **detection-class** source (prior sources SRX/PAN-OS were flow/traffic). UniFi Gateway Max Suricata IPS/IDS alerts ingest via remote syslog on Vector ct102 UDP **port 516** (SRX=514, PAN-OS=515, each a separate source to avoid collision) → `ssdf.events`. Merged to `main` (merge `818a984`); **end-to-end live-proven 2026-06-14**.
- Run Vector unit tests (on ct102 where Vector is installed): `ssh root@pve3.example.com "pct exec 102 -- bash -c 'cd /etc/vector && vector test vector.toml'"` — 20/20 incl. the UniFi CEF suite. Validate locally (syntax only): `CH_HOST=127.0.0.1 vector validate --no-environment infra/vector/vector.toml`.
- **Wire format is CEF (Common Event Format), NOT Suricata EVE-JSON** (the original synthetic baseline was wrong). Lines look like `CEF:0|Ubiquiti|UniFi Network|<ver>|200|Threat Detected|<sev>|<ext>`, carry NO syslog PRI. Sender is the **Cloud Key controller `198.51.100.30`** (host `UCK-G2-Plus-HarmanHoldfast`) forwarding the SIEM export — NOT the Gateway Max `198.51.100.1` (which only emits RFC3164 system-log noise on the same port, dropped by the filter).
- VRL: `[transforms.unifi_cef_threat]` filter gates on `CEF:0|Ubiquiti` + `|Threat Detected|` before `[transforms.unifi_ips]`, which parses via **`parse_cef`** (NOT regex/key-value — CEF extension values contain spaces and Rust regex has no lookahead). Re-validate the transform on any UniFi Network upgrade that changes the CEF schema (DeviceVersion pinned **10.68.57**).
- **No MAC columns in `ssdf.events`** + `skip_unknown_fields=false` ⇒ MACs/aliases/zones/signature detail go in `ext` (keys `unifi.ips.*`, `unifi.src_mac`, etc.). Detections carry MAC + alias only (no client IPs) → source_ip/destination_ip stay null. Event time from `UNIFIutcTime` (clean ISO-8601 UTC, trailing Z — no clock backfill needed).
- nftables ct102 ingest allow-list: UDP/516 source must be **198.51.100.30** (the controller). Apply with `./scripts/apply_ct102_nftables.sh` (rule file `infra/firewall/ct102-ingest.nft`).
- **Trailing-newline live bug (caught only on the wire):** the real UDP datagram is newline-terminated; the `$`-anchored CEF slice regex with default non-dotall `.` never reaches end-of-haystack past the trailing `\n`, so every real event hit `parse_error` while `vector test` (newline-stripped `insert_at` fixtures) passed. Fix: `strip_whitespace(raw)` before the regex + a `unifi_cef_trailing_newline_still_parses` regression test (TOML `'''…\n'''` literal keeps the newline). Lesson: socket sources deliver the trailing newline that `insert_at`/stdin fixtures silently drop.
- **Live trigger = behavioral ET SCAN rules** (outbound port-sweep to a routable range, e.g. Linode 45.33.x) — payload tests (EICAR/testmyids/GPL SIDs) do NOT fire (ruleset is ET-only + hardware flow-offload bypasses DPI). Detections lag ~60-90s. Live-proven SIDs: 2003068 (SSH scan), 2013479 (terminal-server), 2013054 (pycurl UA).
- ct106 surfaces detections: the `detections` field on `explain_access` + the `alerts_for_pair` store method read UniFi IPS alerts. Runbook (real captured samples in §3/§4): `onboarding/unifi/ips-syslog.md`.

Future Rust/Python components will record their own commands here as they are scaffolded.

## Related external systems

- This operator already runs a live Junos MCP server (`rust-junosmcp`, see the global
  `~/.claude/CLAUDE.md`). It is a reference implementation for the Rust + MCP pattern this
  project follows, and a likely first product-control integration target.
