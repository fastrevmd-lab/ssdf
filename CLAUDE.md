# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

> **Status: greenfield.** As of this writing the repository is empty — no code, no
> git history, no build files. Everything below describes the *intended* architecture
> and conventions for the project, derived from the project brief. When you scaffold
> real code, update this file to match what actually exists and remove this notice.

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

## Stack & language split

The project is intentionally **polyglot (Rust + Python)**, split by responsibility:

- **Rust** — performance- and correctness-critical core: log/event ingestion, parsing,
  the data-fabric storage/query layer, and any long-running services. Favor single-binary,
  low-overhead services. (Mirrors the existing `rust-junosmcp` MCP work.)
- **Python** — LLM orchestration, MCP tool/server implementations, agent logic, and
  product-integration adapters (NGFW / SASE / IDaaS / XDR connectors). Use async
  (FastAPI-style) services.

The boundary between the two is a network/IPC contract (HTTP/gRPC or a message bus), **not**
shared in-process code. Keep the interface schema-defined and versioned so either side can
be rebuilt independently.

## Architecture (intended, big-picture)

Data flows in one direction with agents acting back through the same fabric:

```
security products ──► ingest/parse (Rust) ──► data fabric (Rust) ──► MCP tools (Python)
   NGFW/SASE/IDaaS/XDR     normalize/enrich        store + query        ▲
                                                                        │
                                          LLM agents (Python, multi-LLM) ┘
```

- **Ingest/parse (Rust):** receive raw telemetry from security products, normalize into a
  common event/entity schema, enrich, and hand off to the fabric. This is the only place
  vendor-specific log formats should live.
- **Data fabric (Rust):** the system of record — stores normalized events/entities and
  serves correlation/query. Storage backend must be swappable (sovereignty requirement).
- **MCP tool layer (Python):** exposes the fabric and product-control actions as MCP tools.
  This is the contract LLM agents bind to. Treat tool definitions as the public API.
- **Agent/LLM layer (Python):** multiple LLMs are supported behind a common abstraction;
  no single model provider may be load-bearing. Agents read via MCP tools and issue
  management actions back to security products via MCP tools.

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
- **Proof caveat (pre-existing M6a duplication):** an IP that sometimes binds a MAC (M4 topo) and sometimes doesn't yields TWO Asset entities; `find_entity` orders `last_seen DESC LIMIT 1`, so a by-IP lookup can return a stale ip-only asset whose edge lacks `observer_hosts`. This is M6a's IP-vs-MAC identity split, not a scope-B defect. PAN-OS provenance also doesn't yet bridge to configured policy (observer = `panosvm.example.com` vs Firewall entity `panosvm` — domain-suffix mismatch); vSRX-test10 is the live-proven path.

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

Future Rust/Python components will record their own commands here as they are scaffolded.

## Related external systems

- This operator already runs a live Junos MCP server (`rust-junosmcp`, see the global
  `~/.claude/CLAUDE.md`). It is a reference implementation for the Rust + MCP pattern this
  project follows, and a likely first product-control integration target.
