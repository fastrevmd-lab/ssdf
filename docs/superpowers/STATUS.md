# SSDF — Build Status & Milestone Ledger

**Last updated:** 2026-06-15
**Purpose:** Single source of truth for *what is actually built* vs. what the design docs
planned. Read this first; the dated specs/plans are historical and have drifted from reality.

---

## Authoritative design

`docs/superpowers/specs/2026-06-06-ssdf-v0-simplified-design.md` is the current design of
record. It **supersedes** the original `2026-06-05-ssdf-data-fabric-design.md` and the seven
`2026-06-05-ssdf-*.md` plans (custom ontology, Redpanda, Neo4j, gRPC mesh, docker-compose) —
those are **historical only, do not execute them.**

The long-term *principles* from the 2026-06-05 design still hold: sovereign, read-only product
boundary, AI-native, minimal.

## As-built milestones (canonical numbering)

| Milestone | What | Status | Where | Proof |
|---|---|---|---|---|
| **M1** | SRX security logs → Vector (VRL/ECS-subset) → ClickHouse `ssdf.events`, SQL-queryable | ✅ Done | `infra/vector/`, `infra/clickhouse/`, `onboarding/srx/`; LXC ct102 (Vector, .150) + ct104 (ClickHouse, .151) | PR #1; real vSRX-test10 data |
| **M2** | Read-only **MCP query layer** over `ssdf.events` (Python/FastMCP): `query_flows`, `describe_schema`, `top_talkers`, guarded `run_sql` | ✅ Done | `services/mcp-query/`; LXC ct106 (.152:30032), reads CH as read-only `ssdf_ro` | PR #2; 47 unit + 5 live integration tests; bearer-auth enforced |
| **M4** | Dynamic topology/connectivity graph: collectors (junos/unifi/panos/proxmox) → `ssdf.topo_observations`; resolver fuses with L3 flow rollups into `ssdf.graph_nodes`/`graph_edges` (MAC-anchored identity); 6 read-only topology MCP tools | ✅ Done | `services/topo/`, `infra/clickhouse/002_topology.sql`; topo tools in `services/mcp-query/`; LXC ct109 (.153, 5-min timer) + tools on ct106 | PR #4; first cycle 197 obs → 209 nodes / 205 edges |
| **M5** | PAN-OS firewall logs → Vector (VRL/CSV) → ClickHouse `ssdf.events` (2nd vendor; `event_provider=paloalto`, vendor extras under `panw.panos.*`) | ✅ Done (Stage A+B live; real-wire validated) | `infra/vector/vector.toml` (`panos_ecs` transform), `onboarding/panos/`; live device panosvm (VMID 900, PAN-OS 12.1.5, 198.51.100.225); Vector ct102 UDP:515 (live); reads via M2 MCP ct106 | PR #3; 10 vector unit tests; real-wire validated: SYSTEM (9 subtypes) + CONFIG logs → `ssdf.events`; TRAFFIC via synthetic line → `query_flows(provider="paloalto")`; both vendors coexist |
| **M6a** | Semantic **entity/correlation layer**: deterministic Asset (MAC-anchored, IP-never-merges-alone) + observed Policy resolution from `ssdf.events` + M4 hosts → `ssdf.entities`/`ssdf.entity_edges` behind a swappable `EntityStore` seam; `explain_access(client, server)` MCP tool fuses observed flows + observed controls + M4 topology firewall attribution | ✅ Done (live-validated) | `services/entity/` (resolver), `infra/clickhouse/004_entities.sql`+`005_entity_user.sql`, `entitystore.py`/`access_tools.py` in `services/mcp-query/`; resolver on LXC ct109 (5-min timer, writes CH as `ssdf_entity`), `explain_access` tool on ct106 | 9+4+5+4 unit tests + live integration; first live cycle 6 entities / 4 edges; `explain_access` returns sessions>0, controls `source:observed`, `coverage.configured:pending_m6b` |
| **M6b** | **Configured-policy layer**: read each firewall's *configured* security ruleset (PAN-OS `get_pan_config` + vSRX `display set`) → `source='configured'` Policy entities keyed `provider:device:rule_name` (per-firewall identity, fixes M6a same-name collapse) + Firewall entities + `Firewall──GOVERNED_BY(configured)──►Policy` edges into shared `ssdf.entities`/`ssdf.entity_edges` (no schema change); `explain_access` gains `configured_controls` + integer `coverage.configured` | ✅ Done (deployed; configured-side live-proven) | `services/policy/` (collectors+resolver+writer), `entitystore.py`/`access_tools.py` in `services/mcp-query/`; collector+resolver on LXC ct109 (hourly `ssdf-policy.timer`, writes CH as `ssdf_entity`), updated `explain_access` on ct106 | 22 policy unit + 2 live integration; first live pass 8 entities / 6 edges (2 firewalls: panosvm=5 rules paloalto, vSRX-test10=1 rule juniper; 6 configured policies; 6 governed_by edges); `configured_policies_for_firewalls` returns all 6 live. **Live `explain_access` coverage.configured=0** — M4↔M6b bridge gap (issue #6; see below). PR #5 (merged) |
| **M6c-A** | **Firewall-node tagging**: M4 junos/panos collectors self-emit `device_inventory(role=firewall)` so `panosvm`/`vSRX-test10` resolve as `kind=device, attrs.role=firewall` graph nodes, giving `enforcement_points` real firewalls to return — the topology-side half of the issue #6 bridge gap (and the fallback that M6c-B's provenance attribution degrades to). Also fixes latent collector MCP arg-name bugs (`router_name`, `host`). | ✅ Done | `services/topo/collectors/base.py` (`firewall_inventory` helper)+`junos.py`+`panos.py`; LXC ct109 | PR #7 (merged); collect cycle 197→223 obs / 204→218 nodes; CH confirms both firewalls `role=firewall` |
| **M6c-B** | **Provenance-based firewall attribution**: normalize the logging device (ECS `observer.hostname`) at ingest as a typed column, thread it to the `COMMUNICATED_WITH` edge as `observer_hosts`, and have `explain_access` attribute the on-path firewall from flow provenance (the firewall that *logged* the flow is by definition on its path) — `firewall_basis:provenance` primary, the M4 L2-topology heuristic (powered by M6c-A's firewall-role nodes) only as fallback. Closes the issue #6 `coverage.configured>0` gap as the primary, transit-robust path. New response field `firewall_basis`. | ✅ Done (deployed; mechanism live-proven) | `infra/clickhouse/006_observer_hostname.sql`, `infra/vector/vector.toml` (`srx_ecs`+`panos_ecs` emit `observer_hostname`), `chwriter.py`/`resolve_entities.py` in `services/entity/`, `access_tools.py` in `services/mcp-query/`; deployed ct104 (schema) + ct102 (Vector) + ct109 (resolver) + ct106 (tool) | 12 vector + 23 entity + 81 mcp-query unit tests. **Live proof:** `explain_access(<asset owning the flow>, 203.0.113.1)` → `firewall_basis:provenance`, `firewalls:[vSRX-test10]`, `coverage.configured:1` (rule `baseline-permit`). Caveat below. branch `m6c-scopeb-provenance` |
| **M6a-fix** | **Segment-scoped asset identity** (closes the M6c-B by-IP provenance caveat): the M6a ip_only fallback key becomes segment-local `ip:<segment>:<ip>` (was global `ip:<ip>`), so an IP that sometimes binds a MAC and sometimes doesn't no longer spawns a duplicate Asset; a segment-aware binding map `(segment,ip)→mac` from `topo_observations` arp_entry (latest-wins, `TOPO_BINDING_LOOKBACK_HOURS`=168h) anchors MAC identity; `COMMUNICATED_WITH` is keyed on entity ids; standalone `reconcile_assets` merges+deletes already-written twins; `find_entity` orders `confidence DESC, last_seen DESC` so a by-IP lookup resolves the MAC asset (provenance-bearing edge) over a stale ip_only twin | ✅ Done (deployed + live-proven 2026-06-08) | `resolve_entities.py`/`chwriter.py`/`config.py`/`resolve_main.py`/`reconcile_assets.py` in `services/entity/`, `entitystore.py` in `services/mcp-query/`, grants in `infra/clickhouse/005_entity_user.sql`; deployed ct109 (resolver+reconcile) + ct106 (tool) | PR #9 (feature) + PR #10 (deploy hotfix: binding-SQL alias trap + `ssdf_entity` grants for `topo_observations` SELECT & `ALTER DELETE`). 40 entity + 82 mcp-query unit tests. **Live:** ran `reconcile_assets` once → 2 twins deleted / 2 edges merged / 4 deleted (dup-IP twins 0); by-IP `explain_access("198.51.100.150","203.0.113.1",since_hours=72)` → `firewall_basis:provenance, firewalls:[vSRX-test10], coverage.configured:1` (was `no_path_firewall` on the stale twin) |
| **M7a** | **Classification + multi-principal auth + audit** (ssdf-mcp-query hardening): 4-class data taxonomy (`security_log`/`firewall_config`/`topology`/`identity`) secure-by-default, only `topology`/`identity` configurable to `shareable` (fail-closed at startup); multi-principal token map (`MCP_TOKENS_FILE`) with per-token `principal`+`allowed_tools`, single-token backward-compat; append-only `ssdf.audit` (90-day TTL) written by INSERT-only `ssdf_audit` user on a connection SEPARATE from `ssdf_ro`; per-tool `audited_tool` wrapper (`functools.wraps`) records one row/call (allow/deny), best-effort (never blocks the call), deny returns `{"error":"forbidden"}` without invoking the tool. M7a only *labels*+*audits* — never withholds data (that is M7b). | ✅ Done (deployed + live-proven 2026-06-09) | `services/mcp-query/src/ssdf_mcp_query/` (`classification.py`, `auth.py`, `audit.py`, `wrapper.py`, rewritten `server.py`, `config.py`), `infra/clickhouse/007_audit.sql`, `infra/{tokens,classification}.example.json`; deployed ct104 (`007_audit.sql`: `ssdf.audit` + INSERT-only `ssdf_audit`) + ct106 (source sync + `CH_AUDIT_USER`/`CH_AUDIT_PASSWORD` in secrets.env, service restarted) | classification/config/auth/audit/wrapper/server-audit unit suites (full mcp-query unit run green) + 2 live audit integration tests. **Live proof:** ct104 verified `ssdf_audit` INSERT works / SELECT denied (`ACCESS_DENIED`); a real streamable-HTTP `top_talkers` call wrote `ssdf.audit` row `principal=agent, tier=sovereign, tool=top_talkers, decision=allow, data_classes=[security_log]` through the INSERT-only path. Running single-token fallback (`MCP_TOKENS_FILE`/`MCP_CLASSIFICATION_FILE` unset → principal `agent`/all-tools, default-sovereign) |
| **M7b** | **Public MCP split**: a 2nd physical PUBLIC MCP process exposing ONLY `shareable`-classed tools (minus hard-excluded `run_sql`) over ClickHouse `SQL SECURITY DEFINER` views, enforced at the grant floor (`ssdf_public` reader granted SELECT on `ssdf_public.*` views only — structurally cannot name a base `ssdf.*` table). Same `ssdf_mcp_query.server` runs public via `MCP_TIER=public`; `build_app(tier)` registers only all-`shareable` tools, routes the graph store to `schema=ssdf_public`, tags audit `tier="public"`. Sovereign path provably unchanged. | ✅ Done (deployed + live-proven 2026-06-10) | `classification.py` (`public_tool_names`/`is_tool_shareable`/`PUBLIC_EXCLUDED_TOOLS`), `graphstore.py` (`schema` param), `server.py` (`build_app(tier)`/`MCP_TIER`), `infra/clickhouse/008_public_views.sql`, `infra/ssdf-mcp-public.service`, `infra/classification.public.example.json`; deployed ct104 (`008_public_views.sql`: `ssdf_public` db + `ssdf_view_definer` + 2 definer views + `ssdf_public` reader) + **LXC ct113** (`ssdf-mcp-public`, 198.51.100.154:30033 — VMID 110 was taken by `vSRX-test1`) | 130 mcp-query unit + 3 live integration (grant-floor allow/deny + `tier=public` audit). **Live proof:** MCP at `http://198.51.100.154:30033/mcp` lists EXACTLY the 5 shareable tools (`get_entity,locate,neighbors,find_path,topology_snapshot`), zero forbidden; `topology_snapshot` returns from `ssdf_public` views; `ssdf_public` DENIED (`ACCESS_DENIED`) on base `ssdf.graph_nodes`/`events`/`entities`; audit row `principal=agent, tier=public, tool=topology_snapshot, decision=allow` landed in `ssdf.audit`. PR #13 (merged 8ca3aac) |
| **P0-hardening** | **Security-review P0 fixes (H1+H2)** from `docs/security/2026-06-10-vulnerability-review.md`, sharing one root cause — *unauthenticated network-level trust of syslog*. **H1:** nftables source allow-list on the ingest host — dedicated `inet ssdf_ingest` table accepts UDP 514/515 only from `198.51.100.220-198.51.100.242` (vSRX test fleet + panosvm), drops everything else on those ports; base chain `policy accept` so all other traffic passes and the default `inet filter` table is untouched (flat /24 LAN ⇒ interface-binding can't isolate, source-IP filtering required). **H2:** known-device gate in both Vector VRL transforms — normalize syslog HOSTNAME to first DNS label, lowercase for the membership test only, accept iff `panosvm` exact or regex `^vsrx-test\d`, else blank `observer_hostname` (stored value keeps original case so the M6c-B `vSRX-test10` provenance bridge is intact). Defense-in-depth for spoofed-but-source-allowed packets. | ✅ Done (deployed + verified 2026-06-10) | `infra/firewall/ct102-ingest.nft`, `scripts/apply_ct102_nftables.sh`, `infra/vector/vector.toml` (H2 gate in `srx_ecs`+`panos_ecs`); deployed ct102 (nftables + Vector restart) | PR #15 (merged 0156368). 14/14 `vector test` (adds `srx_observer_hostname_unknown_is_blanked`, `panos_observer_hostname_unknown_is_blanked`; regression: known hosts pass through, case preserved). **Live:** `nft list table inet ssdf_ingest` on ct102 shows both rules + `include` in `/etc/nftables.conf` (reboot-persistent); H2 config `vector validate`'d against live CH then swapped + Vector restarted (active, both sources listening, CH sink healthy) |
| **P1-hardening** | **Security-review P1 in-place fixes (M1/M3/M4/M5/M6)** from the same review doc — harden existing services, no new components. **M1:** wire CH query limits (the dead `max_execution_time` config) — `clickhouse.py` `run()` now passes `max_execution_time`+`max_result_rows`+`max_memory_usage`+`result_overflow_mode=throw` (envs `MCP_MAX_RESULT_ROWS`/`MCP_MAX_MEMORY_BYTES`, safe defaults 100k rows / 1 GB). **M3:** per-tier in-process **audit hash chain** for tamper-evidence — new pure `audit_chain.py` (`ts_ms_iso` ms-truncated to match `DateTime64(3)`, `canonical`, `compute_row_hash`); `audit.py` splits `AUDIT_BASE_COLUMNS`(9)+`AUDIT_COLUMNS`(11), chains under a lock, advances head only on insert success, `make_ch_auditor(config,tier)` seeds from new read-only `ssdf_audit_verify`; migration `009` adds `prev_hash`/`row_hash` + verifier user; offline `verify_audit.py` CLI detects content-edit/deletion/reorder by linkage (not ts). **M4:** parse PAN-OS vendor XML with **defusedxml** in topo+policy collectors (entity-expansion DoS); stdlib ET kept only for `tostring`/type-hints. **M5:** systemd hardening block (`DynamicUser=yes`, `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, empty `CapabilityBoundingSet`, `RestrictAddressFamilies`, `PYTHONDONTWRITEBYTECODE`) on all 5 unit files. **M6:** scrub raw upstream error text in `tools.py` (2 upstream handlers → fixed `"query failed"` + uuid `correlation_id`, real exc logged server-side; validation detail preserved). M2 (rate-limit/proxy/token-rotation) deferred to a separate edge-hardening spec. | ✅ Done (deployed + live-verified 2026-06-12) | `services/mcp-query/src/ssdf_mcp_query/` (`config.py`, `clickhouse.py`, `tools.py`, new `audit_chain.py`, rewritten `audit.py`, `server.py`, new `verify_audit.py`), `infra/clickhouse/009_audit_hash_chain.sql`, `services/{topo,policy}/src/.../collectors/panos.py` + `pyproject.toml`, 5× `infra/ssdf-*.service` | **PR #16** (merged 2026-06-11). 226 unit tests green (mcp-query 158, topo 45, policy 23). Subagent-driven TDD, 1 commit/finding; final whole-branch review APPROVED — empirically verified M3 write/verify hash reproducibility (ts ms-trunc + field order/types + `007`+`009` column alignment). **Not yet deployed** — operator-gated steps in the plan's "Operator-gated live deploy" section (sync ct106/ct113, reinstall topo/policy venvs *with* deps on ct109, apply `009` on ct104 + `CH_AUDIT_VERIFY_PASSWORD` on ct106/ct113, redeploy hardened units). **Deployed 2026-06-11/12** with 3 live-found fixes (edge-hardening branch): systemd `LoadCredential=` for DynamicUser token access, migration `010` (`CHANGEABLE_IN_READONLY` + MAX bounds so readonly=1 users accept the M1 per-query caps), `verify_audit` excludes pre-009 legacy rows (`row_hash=''`) per the migration contract. **Live:** all 5 units active under DynamicUser; `verify_audit` OK both tiers; tamper test (ALTER UPDATE → `content_edit` detected → restore → OK) passed |
| **M9** | **UniFi Gateway Max Suricata IPS/IDS ingest** — SSDF's first *detection-class* source. UniFi IPS detections arrive as **CEF** ("Common Event Format", `CEF:0\|Ubiquiti\|UniFi Network\|…\|200\|Threat Detected\|…`), forwarded by the **Cloud Key controller** (198.51.100.30, no syslog PRI) over UDP/516 — **not** Suricata EVE-JSON, and not from the gateway itself (which only emits RFC3164 system-log noise on the same port). A `unifi_cef_threat` filter keeps only IPS detections; the `unifi_ips` VRL `parse_cef`s them to the ECS-subset (`event_kind=alert`, `event_category=[intrusion_detection]`, `event_action=alert_<policy>`, time from `UNIFIutcTime` clean-UTC). Detections identify endpoints by MAC/alias only (no client IPs) ⇒ src/dst IP null, identity + signature detail under `ext.unifi.*`. `explain_access` gains a `detections` field + `alerts_for_pair` store method. | ✅ Done (merged + end-to-end live-proven 2026-06-14) | `infra/vector/vector.toml` (`unifi_cef_threat`+`unifi_ips`), `infra/firewall/ct102-ingest.nft` (UDP/516 ⇐ .30), `onboarding/unifi/ips-syslog.md`, `access_tools.py`/`entitystore.py` in `services/mcp-query/`; deployed ct102 (nft + Vector) + ct106 (tool) | PRs on branch `m9-unifi-ips-ingest` (merged `818a984`). **20/20 `vector test`. Live proof:** an outbound ET SCAN port-sweep tripped SID 2003068 → controller CEF → UDP/516 → Vector `parse_cef` → `ssdf.events` as `alert_scanning-activity, outcome=detection, dpt=22, observer_hostname=Gateway Max`. **Live-found bug** (caught only on the wire, not by `vector test`): the real UDP datagram is newline-terminated and the `$`-anchored CEF slice failed on the trailing `\n` ⇒ every real event `parse_error`'d; fixed with `strip_whitespace()` + a `unifi_cef_trailing_newline_still_parses` regression test |
| **Edge-hardening** | **Security-review M2 + L1–L6** (closes the review backlog). **PKI:** local sovereign CA (`scripts/gen_ssdf_tls.sh`, gitignored `infra/tls-local/`; CA 10y, leaves 825d with IP SANs; CA key never leaves the dev host). **L1a CH TLS:** ClickHouse https_port 8443 on ct104 (`config.d/ssdf-tls.xml`) + nftables `inet ssdf_ch` closing plaintext 8123/9000 to loopback-only; all CH consumers opt in via `CH_SECURE=1`+`CH_CA_FILE` (mcp-query/topo/entity/policy `get_client(**tls_kwargs)`), Vector endpoint env-flippable `${CH_PROTO:-http}://${CH_HOST}:${CH_HTTP_PORT:-8123}` + host-appended `[sinks.clickhouse.tls]` (nested env defaults don't parse — proven on Vector 0.56.0). **M2+L3+L6+L1b nginx MCP edge (ct106/ct113):** uvicorn rebinds loopback 3103x via systemd drop-in; nginx terminates TLS on LAN 3003x with `limit_req` 10r/s burst 30 + `limit_conn` 32/IP (429), `default_server` 444 Host gate, Origin allow-list 403, SSE-safe proxying. **M2 tokens:** `tokens.json` gains optional `not_after` (ISO-8601, fail-closed parse, per-call expiry deny in `wrapper` — same seam as `allowed_tools`); both tiers rotated to named principals with +90d expiry; old single-token path rejected live. **L2:** parametrized sql_guard test pins the structural `FROM <fn>()` boundary for 16 table functions incl. ones absent from the denylist (no code change needed). **L4:** migration `011` — new `ssdf_entity_maint` (SELECT/INSERT/ALTER DELETE) for manual reconcile; `REVOKE ALTER DELETE FROM ssdf_entity` (the 5-min resolver). **L5:** public tier no longer constructs `ClickHouseEntityStore`/`AccessTools`. | ✅ Done (deployed + live-verified 2026-06-12) | `scripts/gen_ssdf_tls.sh`+`apply_ct104_tls.sh`+`apply_mcp_edge.sh`, `infra/clickhouse/config.d/ssdf-tls.xml`+`010_ro_settings_constraints.sql`+`011_entity_maint_user.sql`, `infra/firewall/ct104-clickhouse.nft`, `infra/nginx/ssdf-{limits,mcp-query,mcp-public}.conf`, `services/mcp-query/src/` (`config.py`/`auth.py`/`wrapper.py`/`server.py`/`clickhouse.py`/`audit.py`/`verify_audit.py`), `services/{topo,entity,policy}` (`config.py`/`chwriter.py`), `infra/vector/vector.toml`, both unit files (`MCP_TOKENS_FILE` via LoadCredential); deployed ct104+ct102+ct109+ct106+ct113 | Spec `docs/superpowers/specs/2026-06-11-ssdf-edge-hardening-design.md`. 320 unit (mcp-query 197, topo 50, entity 45, policy 28) + 8 live integration over TLS. **Live:** CH 8443 CA-verified / LAN 8123 dropped; Vector ingest proven end-to-end over TLS (PAN-OS system logs → `ssdf.events`); MCP tool calls succeed via nginx https on both tiers (public lists exactly 5 tools, no entity tools); burst 50 → 429s; Origin 403; bad Host → connection closed (444); old tokens 401; `verify_audit` OK over TLS; post-revoke resolver cycle green + `ssdf_entity_maint` authenticated |
| **M11** | **Proxmox host audit ingest** — the pve3 hypervisor host's **auth + admin-action audit stream** (logins + VM/CT task operations) as an SSDF event source (the "who logged into / acted on my infrastructure host" story). rsyslog on pve3 forwards `auth`/`authpriv`/`daemon` facilities **RFC5424** (`RSYSLOG_SyslogProtocol23Format`) over UDP/**517** → Vector `proxmox_syslog` source → `proxmox_sec` filter (parse_syslog + app-gate + known-pattern gate) → `proxmox_ecs` remap → `ssdf.events` (`event_provider=proxmox`). Branches: sshd login `Accepted`/`Failed password` → `auth_*` (source_ip+port); pvedaemon pam `successful auth`/`authentication failure; rhost=` → `auth_*`; task `starting|end task UPID:…:<dtype>:<vmid>:<user>:` → `configuration`/`task_<dtype>`/`task_end_<dtype>` with UPID-parsed task_type+vmid+user. Ingest-only: no new MCP tool, no schema migration — Proxmox detail (node/upid/vmid/task_type/task_status/realm/appname/invalid_user) rides the `ext` Map; `observer_hostname` stays empty (firewall-provenance field; pve3 is not a firewall). Queryable immediately via `run_sql`/generic tools. | ✅ Done (deployed + end-to-end live-proven 2026-06-14) | `infra/vector/vector.toml` (`proxmox_syslog`+`proxmox_sec`+`proxmox_ecs` + 11 `[[tests]]`), `infra/firewall/ct102-ingest.nft` (UDP/517 ⇐ 198.51.100.201), `onboarding/proxmox/rsyslog.md`; deployed ct102 (nft + Vector) + pve3 (rsyslog drop-in) | Branch `m11-proxmox-ingest`. Spec `docs/superpowers/specs/2026-06-14-ssdf-m11-proxmox-host-audit-ingest-design.md`. **31/31 `vector test`. Live proof:** a real failed SSH login (`auth_failure`, baduser_ssdf, source_ip+port), successful logins (`auth_success`, root, source_ip+port), and a scratch-VMID (701) snapshot create+delete (`task_vzsnapshot`/`task_end_vzsnapshot` success, vmid 701, realm pam) all landed in `ssdf.events` with **UTC-correct** time (EDT -0400 wire offset applied at parse), 0 parse_errors. **Live-found (caught only on the wire, not by `vector test`):** (1) OpenSSH 9.8+/Debian 13 logs per-connection auth under appname **`sshd-session`** not `sshd` (silently dropped all SSH auth) → match `sshd*` family; (2) CLI/API admin tasks log under **`pct`/`qm`/`pvesh`** not `pvedaemon` → app-gate broadened; (3) the redundant sshd pam_unix auth-failure line surfaced as `unknown` → auth-failure gate anchored to `authentication failure; rhost=`. All three pinned by regression tests |
| **M6a-fix2 — pair-aware twin resolution** | **Closes the M6a IP-vs-MAC/segment provenance caveat on the read path.** `explain_access` resolved each identifier to a single globally-top entity (`find_entity` … `ORDER BY confidence DESC, last_seen DESC LIMIT 1`), so when an IP has multiple entity twins (shared external IPs like 8.8.8.8 spawn one ip_only twin per observing segment; LAN hosts are a MAC asset *and* a per-segment ip_only twin) the pick often wasn't the twin with an edge to the counterpart → `sessions:0`/`no_path_firewall` and the correctly-stamped firewall provenance never surfaced. Now resolves each side to **all** candidate twins (`find_entities` = `find_entity` SQL minus `LIMIT 1`; `communicated_edges_multi` = IN-list both directions, empty-list guarded) and `_select_pair` selects the (client,server) pair that actually has `communicated_with` edges, **preferring pairs that carry firewall provenance** (non-empty `observer_hosts`). Read-path only — no resolver, schema, or migration change; existing `find_entity`/`communicated_edges` left intact for their callers; ct113 public tier unaffected (doesn't construct `AccessTools`). | ✅ Done (deployed + live-proven 2026-06-15) | `services/mcp-query/src/ssdf_mcp_query/` (`entitystore.py` 2 builders + 2 store methods + Protocol; `access_tools.py` `_select_pair` + rewritten `explain_access` resolution head); deployed ct106 (source sync + restart) | **PR #22** (merged `1eb7d5e`). Spec/plan `docs/superpowers/{specs,plans}/2026-06-15-ssdf-m6a-pair-aware-resolution*`. 219 mcp-query unit tests; final whole-branch review APPROVED. **Live proof:** `explain_access("10.74.12.20","8.8.8.8")` → `firewall_basis:provenance`, `firewalls:[vSRX-Production]`, sessions 368; `("10.74.12.20","198.51.100.1")` → same, sessions 606; regression `("10.74.11.20","198.51.100.1")` → panosvm unchanged (`configured:7`); `not_found` unchanged. **Live-found:** the spec's plain most-sessions selection lost to a stale pre-Phase-2 unstamped twin-pair (1812 vs 352 sessions) → provenance (`observer_hosts` presence) made the primary `_select_pair` sort key |
| **Phase 2 — live transit sources** | **vSRX-Production + panosvm as continuously-ingesting transit firewalls.** Both real firewalls were previously SSDF sources only for system/synthetic logs (SRX transit-only-logging trap + PAN-OS empty-session carve-out). Phase 2 puts a behind-the-firewall Alpine endpoint behind each (ct198 `ssdf-ep-srx` 10.74.12.20 on vSRX-Production trust VLAN 198; ct199 `ssdf-ep-panos` 10.74.11.20 on panosvm trust VLAN 199 — Proxmox-only bridge tags on vmbr1, VLAN id = CTID), both running the shared `scripts/labgen_endpoint.sh` daemon under OpenRC (self-loops ~30s jittered): permitted internet egress + a deliberate denied DNS attempt to 8.8.8.8. Both firewalls gained a strict-DNS policy pair (`allow-approved-dns` → approved resolvers 198.51.100.1/1.1.1.2/1.0.0.2, `deny-rogue-dns` → deny) + permit-all egress, applied via rust-junosmcp (SRX) / panos-mcp (PAN-OS, native-CLI syntax, no vsys keyword). The H2 device gate (`infra/vector/vector.toml`) was broadened to `^vsrx-(test\d\|production)` so vSRX-Production carries `observer_hostname` (case-preserved for the provenance bridge). Old single-vendor ct115 retired. | ✅ Done (deployed + end-to-end live-proven 2026-06-15) | `scripts/labgen_endpoint.sh` (replaces deleted `labgen_transit.sh`), `infra/vector/vector.toml` (H2 gate + `srx_observer_hostname_production_is_known` test), `onboarding/srx/transit-endpoint.md`, `onboarding/panos/transit-traffic.md` (rewritten); ct198+ct199 (new), vSRX-Production (VMID 103) + panosvm (VMID 900) policy, ct102 (Vector) | Branch `m-srx-panos-live-transit`. Spec/plan `docs/superpowers/{specs,plans}/2026-06-14-ssdf-srx-panos-live-transit-sources*`. 34 `vector test` (adds production-known gate test). **Live proof:** both `juniper` (observer_hostname=`vSRX-Production`) and `paloalto` (observer_hostname=`panosvm.example.com`) now show permit **and** deny rows in `ssdf.events`; 8.8.8.8:53/udp denies present on both vendors |

## Security hardening backlog

**All findings closed.** P0 (H1+H2) done (PR #15). P1 in-place batch (M1/M3/M4/M5/M6)
merged PR #16 + deployed 2026-06-11/12. M2 + L1–L6 built and deployed via the
edge-hardening branch 2026-06-12 (see rows above). Findings from
`docs/security/2026-06-10-vulnerability-review.md`:

- ~~**M1** query-execution timeout (dead config)~~ — done (PR #16; live needed migration `010` for readonly users).
- ~~**M3** audit hash-chain tamper-evidence~~ — done (PR #16; per-tier in-process chain + `verify_audit`).
- ~~**M4** `defusedxml` for vendor XML collectors~~ — done (PR #16).
- ~~**M5** systemd hardening (services ran as root)~~ — done (PR #16; all 5 units; live needed `LoadCredential=`).
- ~~**M6** scrub upstream error text~~ — done (PR #16).
- ~~**M2** rate-limit/reverse-proxy + token rotation~~ — done (edge-hardening: nginx limit_req/limit_conn on both MCP edges; token expiry `not_after` + both tiers rotated).
- ~~**L1–L6** defense-in-depth~~ — done (edge-hardening: L1 CH+MCP TLS via local CA, L2 sql_guard structural-boundary test, L3 loopback uvicorn bind, L4 `ssdf_entity` ALTER DELETE split to `ssdf_entity_maint`, L5 public tier skips entity-store construction, L6 nginx Host/Origin gates).

Out-of-scope follow-ups (recorded in the edge-hardening spec, not built): cert renewal
automation (825d leaves, manual runbook), WORM audit mirroring, per-principal quotas,
vendor-MCP TLS.

## Numbering reconciliation (the drift)

The simplified-design doc used a *different* milestone numbering than what got built. Canonical
= the as-built column.

| Simplified-design doc | As-built reality |
|---|---|
| M1 = SRX→Vector→ClickHouse | **M1** (same) ✅ |
| M2 = entity/resolver → Postgres-graph | *not built* — deferred (see forward roadmap) |
| M3 = PAN-OS + query seam | PAN-OS **built as M5** ✅; query seam = M2 |
| M4 = MCP read server + sovereignty | **M2** (MCP read server, pulled forward; sovereignty/scope-gating not yet built) ✅(partial) |

**Why the reorder:** the AI-native query surface (the product thesis) was prioritized over the
entity graph, consistent with the design's own open question — "when does ClickHouse-only stop
sufficing and the graph become load-bearing?" Answer so far: it still suffices.

## Forward roadmap (proposed, renumbered from as-built — adjust as we go)

- **M3 — retired placeholder slot.** Used transitionally during the M4 build; no standalone
  artifact. Canonical built milestones are M1, M2, M4, M5. Do not reuse the M3 number.
- **M4 — dynamic connectivity / topology graph.** ✅ Built 2026-06-07. Collectors (junos,
  unifi, panos, proxmox) reuse the deployed read-only MCPs to gather LLDP/MAC/ARP/interface +
  VM-NIC facts into `ssdf.topo_observations`; a resolver fuses them with L3 flow rollups into
  `ssdf.graph_nodes`/`graph_edges` (MAC-anchored identity, IP-never-identity-alone). Six
  read-only topology tools added to `ssdf-mcp-query`. Deployed on LXC **ct109** (`ssdf-topo`,
  .153, 5-min timer); graph tools on ct106. First live cycle: 197 observations → 209 nodes /
  205 edges. Spec: `specs/2026-06-07-ssdf-m4-topology-graph-design.md`; plan:
  `plans/2026-06-07-ssdf-m4-topology-graph*.md`. (Supersedes the earlier proposed M4 —
  `connectivity_edges_hourly` rollups; the shipped M4 is the richer topology-graph design.
  Note: plan reserved ct107, but VMID 107 was occupied by an unrelated VM, so ct109 was used.)
- **M5 — second source: PAN-OS.** ✅ Done. VRL/CSV parser (`panos_ecs`) + 10 unit tests; live
  Vector config on ct102 listening UDP:515. **Stage A onboarding live on panosvm** (VMID 900,
  PAN-OS 12.1.5, 198.51.100.225): syslog server profile `SSDF` → 198.51.100.150:515 BSD, log-
  forwarding profile `SSDF-LF` (applied via XML), attached `log-setting SSDF-LF` to all 5 security
  rules (via XML — the panos-mcp set-CLI mangles quoted `filter "All Logs"`). Pipeline validated
  end-to-end: a PAN-OS 12.1 TRAFFIC CSV line → ct102:515 → `ssdf.events` with `event_provider=
  paloalto`, IPv4 src/dst, ports, bytes, `rule_name`, `panw.panos.*` extras; returned by the M2
  MCP `query_flows(provider="paloalto")`; both vendors coexist (`juniper:13, paloalto:1`). Proves
  the ECS-subset schema generalizes to a 2nd vendor.
  - **Stage B device-plane log-settings (system + config) — applied & validated 2026-06-07.**
    `shared log-settings system|config` match-lists → SSDF syslog profile, committed live. Gave
    **real-wire validation** without transit traffic: the firewall's own SYSTEM logs (9 subtypes:
    general/vpn/routing/ras/sslmgr/satd/auth/url-filtering/device-telemetry) and CONFIG set/commit
    logs land in `ssdf.events` with correct typed columns — CONFIG `user_name`/`command`/`client`/
    `result` map exactly as the unit tests asserted (admin idx 10, command idx 9). correlation/
    globalprotect/hipmatch intentionally not applied (those features aren't configured → no logs).
  - **The earlier "Unauthorized request" was NOT an auth defect.** Root cause: pan-os-python's
    `xapi.set` does not prepend `/config/`, so a relative xpath (`shared/log-settings`) is rejected
    by PAN-OS as "Unauthorized request". Fix = pass **absolute `/config/...` xpaths** to
    `load_and_commit_pan_config` (fmt=xml). The `mcp-api` admin is superuser; no credential change
    was needed.
  - **Remaining carve-out:** panosvm still has **no transit traffic** (empty session table), so
    real-wire **TRAFFIC** validation used a synthetic-but-positionally-exact line; it self-confirms
    the first time traffic hits a logged rule (PAN-OS transit-only-logging trap, same as SRX).
    **CLOSED 2026-06-12 by P2** (ct115), **superseded 2026-06-15 by Phase 2:** ct199
    `ssdf-ep-panos` now generates continuous transit flows; real-wire TRAFFIC permit+deny
    rows verified in `ssdf.events` (see Phase 2 row above). ct115 retired.
  - **Observation (pre-existing M1 concern, not M5):** PAN-OS stamps receive-time in local EDT
    (`-04:00`); ingest stores it without TZ conversion, so event `timestamp` sits ~4h behind
    ClickHouse `now()` (UTC). Affects relative-time `WHERE` filters across all sources.
    **FIXED 2026-06-12 by P2:** panosvm device clock → UTC + historical rows backfilled +4h.
- **M6a — entity/correlation layer (Asset + observed Policy).** ✅ Built 2026-06-07. Deterministic
  resolution from `ssdf.events` flow-aggregates + M4 `graph_nodes` hosts into `ssdf.entities`/
  `ssdf.entity_edges` (`ReplacingMergeTree(last_seen)`, 30-day TTL), separate from M4's
  graph_nodes so M6c can relocate just the entity store to Postgres. Asset identity is
  MAC-anchored (IP-only assets are low-confidence 0.5 singletons, never merged on IP alone);
  Policy is keyed `(provider, rule_name)` and stamped `source:observed`. New `EntityStore`
  Protocol + `ClickHouseEntityStore` seam; one MCP tool `explain_access(client, server)` answers
  "show me end-to-end flow + security controls for this client→server" — fusing observed flows,
  observed controls, and M4 topology firewall attribution (firewall named only when topology
  yields exactly one; `firewall_basis:topology`). Honesty contract: `coverage.configured ==
  "pending_m6b"`. Resolver on LXC ct109 (5-min `ssdf-entity.timer`, writes CH as `ssdf_entity`).
  Spec: `specs/2026-06-07-ssdf-m6-entity-correlation-design.md`; plan:
  `plans/2026-06-07-ssdf-m6a-entity-correlation.md`.
  - **Known limitation — `first_seen` collapses to the current window.** Each resolver pass
    recomputes `first_seen` from the active window only, and `ReplacingMergeTree(last_seen)`
    keeps the latest row, so `first_seen` does not track the true earliest sighting across passes.
    This is the **same trade-off M4's topology resolver already makes**; accepted for M6a rather
    than deviating mid-build. Revisit if/when historical first-seen becomes load-bearing.
  - **Live-validation bug fixed:** the comm-edge window filter compared the `toString(last_seen)`
    SELECT alias (a String) instead of the real DateTime64 column, silently dropping every edge
    (lexical compare: space < 'T'). Fixed by qualifying `entity_edges.last_seen` in the WHERE.
- **M6b — configured policy.** ✅ Built 2026-06-08, merged to `main` via PR #5. Pull device-configured rules (not just observed)
  so `explain_access` exposes configured controls alongside observed traffic. New `services/policy/`
  service: per-vendor collectors (PAN-OS via `get_pan_config`, vSRX via `show configuration security
  policies | display set`) → normalized rule dicts → resolver emits `source='configured'` Policy
  entities keyed `provider:device:rule_name` (per-firewall identity — **fixes M6a's same-name
  collapse** where two firewalls' identically-named rules merged into one entity), Firewall entities
  keyed `device:<name>`, and `Firewall──GOVERNED_BY(configured)──►Policy` edges, written to the shared
  `ssdf.entities`/`ssdf.entity_edges` (no schema change, reuses the `ssdf_entity` CH user). `explain_
  access` (ct106) gains `configured_controls` + an integer `coverage.configured`. Deployed as ct109's
  **third** role (venv `/opt/ssdf-policy`, env `/etc/ssdf-policy/ENV.local` mode 600) on an HOURLY
  `ssdf-policy.timer` → oneshot `ssdf-policy.service`, installed without disturbing the two existing
  5-min M4/M6a timers. First live pass: 8 entities / 6 edges upserted (2 firewalls: panosvm=5 rules
  paloalto, vSRX-test10=1 rule juniper; 6 configured policies; 6 governed_by edges). Spec:
  `specs/2026-06-08-ssdf-m6b-configured-policy-design.md`; plan:
  `plans/2026-06-08-ssdf-m6b-configured-policy.md`.
  - **M4↔M6b name-bridge gap (live finding, blocks `coverage.configured>0`).** `explain_access`
    discovers a path's firewalls via M4 `enforcement_points`, which only returns graph nodes with
    `kind=="device"` AND `attrs.role=="firewall"`. M4 currently models **0** such nodes (confirmed by
    CH query), so live `explain_access` on real transit pairs returns `configured_basis:no_path_
    firewall` and `coverage.configured:0`. **The configured side is proven correct independently:** a
    direct `configured_policies_for_firewalls(["panosvm","vSRX-test10"])` returns all 6 policies. The
    gap is purely topology→firewall attribution; closing it requires M4 to emit firewall-role device
    nodes (tracked as the M6b→M4 dependency in **issue #6**). This was recorded honestly rather than fabricating M4
    nodes to make the number non-zero.
    - **Scope A closed by M6c scope A (2026-06-08, PR #7).** M4's junos/panos collectors now
      self-emit a `device_inventory(role=firewall)` observation per device, so `panosvm` and
      `vSRX-test10` resolve as `kind=device, attrs.role=firewall` in `ssdf.graph_nodes` (verified
      live on ct104). `enforcement_points` now returns them when they sit in a path's L1/L2
      component — this powers the **topology fallback** of the provenance attribution in scope B.
    - **Scope B closed by M6c scope B (2026-06-08, PR #8).** Provenance attribution names the
      firewall that *logged* the flow, which is robust to transit firewalls the L2 heuristic cannot
      see; issue #6's `coverage.configured>0` is met end-to-end. See the M6c scope B milestone below.
- **M6c scope A — firewall-node tagging (issue #6).** ✅ Built 2026-06-08 (PR #7, merged). Closes
  the M6b→M4 bridge gap's *node-tagging* half and supplies the firewall-role nodes that scope B's
  topology fallback consumes. New `firewall_inventory()` helper in `collectors/base.py`;
  junos + panos collectors each append one `device_inventory(role=firewall, name=<device>)`
  observation, merged by the resolver onto the same name-keyed device node. Also fixed a latent
  M4 collector bug surfaced when the collectors first ran live on ct109: `execute_junos_command`
  needs `router_name` (not `router`) and `execute_pan_op` needs `host` — both raised
  `missing_argument` and were silently skipped before. Added `JUNOS_DEVICES=vSRX-test10` to
  ct109's `/etc/ssdf-topo/ENV.local` (junos collector had never run live — list was empty).
  Live proof: collect cycle 197→223 obs, 204→218 nodes; CH query returns `panosvm` and
  `vSRX-test10` both `kind=device, role=firewall`. Spec:
  `specs/2026-06-08-m4-firewall-node-tagging-design.md`; plan:
  `plans/2026-06-08-m4-firewall-node-tagging.md`.
- **M6c scope B — provenance-based firewall attribution.** ✅ Built 2026-06-08 (PR #8). The M4
  L1/L2 connected-component heuristic (`enforcement_points`) is structurally incapable of naming a
  *transit* firewall, which is why live M6b returned `coverage.configured:0`. Scope B makes
  **provenance the primary** attribution — the firewall that *logged* a flow is by definition on
  the flow's path — and keeps scope A's topology heuristic as the **fallback**. Ingest now
  normalizes the syslog source device into a typed `observer_hostname` column (ECS
  `observer.hostname`, migration `006`); the `srx_ecs` and `panos_ecs` Vector transforms emit it;
  the entity resolver collects it per pair (`groupUniqArray(observer_hostname)`) and threads it
  onto the `COMMUNICATED_WITH` edge as a comma-set `observer_hosts`; `explain_access` attributes
  firewalls from `observer_hosts` first (`firewall_basis:provenance`) and only falls back to M4
  topology (powered by scope A's firewall-role nodes) when provenance is absent
  (`firewall_basis:topology`/`no_path_firewall`). **Live-proven mechanism:** for the asset that
  owns the flow, `explain_access(...,"203.0.113.1")` returns `firewall_basis:provenance`,
  `firewalls:[vSRX-test10]`, `coverage.configured:1` (configured rule `baseline-permit`).
  Spec: `specs/2026-06-08-m6c-scopeb-provenance-firewall-attribution-design.md`; plan:
  `plans/2026-06-08-m6c-scopeb-provenance-firewall-attribution.md`.
  - **Proof caveat — pre-existing M6a asset duplication, not a scope-B defect.** The IP
    `198.51.100.150` resolves to two Asset entities: a MAC-anchored one (`d3bb…`, whose edge carries
    `observer_hosts=vSRX-test10`) and a stale ip-only one (`540b…`, newer `last_seen`, edge predates
    the provenance backfill). `find_entity` orders `last_seen DESC LIMIT 1`, so a *by-IP* lookup
    returns the ip-only asset and yields `no_path_firewall`. Resolving by an identifier that lands on
    the flow-owning asset (e.g. the MAC) gives the full provenance result. The duplication is the
    known M6a IP-vs-MAC identity split (see M6a notes), independent of scope B. **Addressed by the
    M6a-fix milestone (branch `m6a-identity-segment`):** segment-scoped identity stops new twins,
    `reconcile_assets` cleans up existing ones, and `find_entity`'s `confidence DESC` ordering makes
    a by-IP lookup resolve the MAC asset so provenance is returned.
  - **PAN-OS provenance carve-out — bridged (2026-06-10).** PAN-OS stamps `observer.hostname` as
    `panosvm.example.com` but the M6b Firewall entity is named `panosvm` (domain-suffix mismatch), so
    PAN-OS provenance did not bridge to its configured policies. **Closed at read time:**
    `explain_access` now maps each `observer_hosts` value through `access_tools._short_host` (first
    DNS label, case-preserved, IPv4/IPv6-guarded) before matching Firewall entities, so
    `panosvm.example.com`→`panosvm`; vSRX (`vSRX-test10`, dot-free) is a no-op. Read-path only — no
    ingest/schema/resolver change. Unit-proven 2026-06-10; **live-proven 2026-06-12 by P2's
    transit-traffic generator** (`explain_access` ⇒ `firewall_basis:provenance`,
    `firewalls:[panosvm]` — see P2 below). Spec: `specs/2026-06-10-ssdf-panos-provenance-suffix-normalization-design.md`; plan:
    `plans/2026-06-10-ssdf-panos-provenance-suffix-normalization.md`.
- **M6d — multi-hop L3 stitching + Postgres-as-graph.** Relocate the entity store off ClickHouse
  to Postgres-as-graph (Neo4j still deferred); stitch multi-hop paths. Deferred. (Renumbered from
  M6c, which is now the firewall attribution milestone above.)
- **M7 — sovereignty + MCP split.** Decomposed into M7a + M7b.
  - **M7a — classification + multi-principal auth + audit.** ✅ Done (deployed + live-proven
    2026-06-09; see as-built row above). Labels data classes, authenticates per-principal, and
    records every tool call to append-only `ssdf.audit` (INSERT-only `ssdf_audit` user). Labels
    + audits only — never withholds data beyond the explicit `forbidden` authz deny.
  - **M7b — public MCP split.** ✅ Done (deployed + live-proven 2026-06-10; see as-built row
    above). 2nd physical PUBLIC MCP process (LXC ct113, `ssdf-mcp-public`, 198.51.100.154:30033)
    running as least-privilege `ssdf_public`, granted SELECT only on `ssdf_public.*` definer
    **shareable views** (never base tables), reusing M7a's classification + audit (`tier="public"`).
    Exposes the 5 shareable graph tools only. **M7 (sovereignty + public/sovereign split) is now
    complete end-to-end.**
- **P2 — data-quality & ops batch.** ✅ Done 2026-06-12 (plan:
  `plans/2026-06-12-ssdf-next-phase-roadmap.md`, Phase 1). (1) PAN-OS device clock → UTC
  (`onboarding/panos/timezone-utc.md`) + one-time +4h backfill of pre-cutover paloalto rows
  (`infra/clickhouse/012_backfill_paloalto_utc.sql.example` — documents three live-found
  ClickHouse mutation traps incl. a recovered data-loss incident); (2) SRX clock verified
  UTC + requirement pinned in `onboarding/srx/stream-config.set`; (3) lab transit-traffic
  generator ct115 `ssdf-labgen` (`scripts/labgen_transit.sh`,
  `onboarding/panos/transit-traffic.md`; **retired + superseded by Phase 2's ct199**)
  — **closed the PAN-OS TRAFFIC carve-out and
  live-proved the M6c-B suffix-normalization bridge** (`explain_access` 10.74.11.20→
  198.51.100.1 ⇒ `firewall_basis:provenance`, `firewalls:[panosvm]`,
  `coverage:{observed:true, configured:5}`); (4) scheduled vzdump backups
  (`scripts/apply_pve_backup_job.sh`); (5) retired the greenfield/Rust-core doctrine
  drift in CLAUDE.md.
- **M8 — agent-eval harness + external runner.** ✅ Done end-to-end 2026-06-13.
  SSDF-side harness merged (corpus v1: 23 questions / 5 categories / tier-tagged;
  deterministic scorer + regression gate + contract schemas). External runner is a
  **standalone sibling repo** `~/ssdf-eval-runner/` (never merged into SSDF, per the
  M8 boundary) — pure unit-tested `core` + two adapters (`claude_adapter` shells the
  `claude` CLI which owns MCP; `qwen_adapter` drives MCP + Ollama directly). Ran the
  full **2 models × 2 tiers = 4 scorecards** against the live MCP edges under dedicated
  `eval-claude`/`eval-qwen` principals (added to ct106/ct113 `tokens.json`):
  **claude-sonnet-4-6** sovereign **16/22**, public **4/6**; **qwen2.5-coder:7b**
  sovereign **4/22**, public **1/6** (committed under `services/evals/results/`,
  regress gate exit 0 each — first baseline). Live proofs: (a) audit tool-checks join
  the `eval-claude` window (per-question `tools_observed` populated); (b) **tier
  containment** — every tool in both public runs is from the 5-tool shareable set,
  zero sovereign-tool leaks, and claude correctly refuses the sovereign-only
  top-talkers question; (c) qwen's honest low score (all 22 sovereign questions show
  empty `tools_observed` — the 7B text-emits tool calls as JSON instead of structured
  `tool_calls`, so it makes zero real MCP calls) demonstrates the harness fail-closes
  tool-checks and that no single model is load-bearing.
  Specs: `specs/2026-06-12-ssdf-m8-eval-harness-design.md` (harness),
  `specs/2026-06-12-ssdf-m8-external-eval-runner-design.md` (runner).
  **Corpus fix 2026-06-15 (`3cf1263`):** `reach-firewall-attribution`'s `reference_sql`
  returned the raw `observer_hostname` FQDN (`panosvm.example.com`), but `explain_access`
  normalizes firewalls to the first DNS label via `_short_host` (`panosvm`), so
  `match:exact` could never pass. Reference now extracts the short label
  (`splitByChar('.', observer_hostname)[1]` — a no-op for dot-free `vSRX-Production`),
  live-verified on ct104. **Full 2026-06-15 matrix re-run** (2 models × 2 tiers, serial
  per principal so audit windows don't overlap; `aa1d8e6` + `76fb12b`):
  **claude-sonnet-4-6** sovereign **15/22** + public **4/6**; **qwen2.5-coder:7b**
  sovereign **3/22** + public **2/6** — same shape as the 2026-06-13 baseline (claude
  strong; the 7B text-emits tool calls so it makes few real MCP calls and fails the
  audit tool-checks, the harness fail-closing as designed). The `reach-firewall-attribution`
  miss this run is agent-side (model answered the vendor `paloalto` and skipped
  `explain_access`), not a corpus defect. **Regress gate flags accepted as variance:**
  the gate (baseline = the committed `results/` "ever-passed" set) exits 1 on claude
  sovereign (`flows-paloalto-actions-7d`, `reach-configured-policy-count-panosvm`,
  `reach-rule-trust-untrust`) and qwen sovereign (`honesty-device-metrics`,
  `honesty-identity-user`); both public runs exit 0. All flags are run-to-run model
  nondeterminism / live-data drift (skipped tool calls, a wrong count, refusal
  flip-flops at 7B), not corpus or fix-caused regressions — accepted, no action.
- **M9 — UniFi Suricata IPS ingest.** ✅ Done 2026-06-14 (merged `818a984`; see as-built
  row above). First detection-class source via the established Vector→ClickHouse pattern.
  **Charter correction proven on the wire:** the source is **CEF from the Cloud Key
  controller (198.51.100.30)**, NOT Suricata EVE-JSON from the gateway — parsed with VRL
  `parse_cef`. End-to-end live-proven against a real ET SCAN detection. Charter in the
  Phase-3 plan; spec/plan
  `docs/superpowers/{specs,plans}/2026-06-13-ssdf-m9-unifi-suricata-ips-ingest*.md`.
- **M10 — derived findings layer.** Gated on M8 (evals must first show where agents
  struggle without it). Charter in the same plan, Phase 4.
- **M11 — Proxmox host audit ingest.** ✅ Done 2026-06-14 (branch `m11-proxmox-ingest`;
  see as-built row above). The pve3 hypervisor's auth + admin-action stream via rsyslog
  RFC5424 → Vector UDP/517 → `ssdf.events` (`event_provider=proxmox`), reusing the
  SRX/PAN-OS `parse_syslog` pattern. Ingest-only (no MCP tool, no schema migration). The
  **rsyslog push** transport was chosen over the considered PVE-API poller. Spec/plan
  `docs/superpowers/{specs,plans}/2026-06-14-ssdf-m11-proxmox-host-audit-ingest*.md`.
- **M6d stays deferred** — ClickHouse-only still suffices; Postgres-as-graph/multi-hop
  stitching only when load-bearing.
- **Later sources:** ~~UniFi~~ ✅ done as M9 (CEF IPS detections via remote syslog, not
  the unifi-mcp flow API which 404s on this controller). ~~Proxmox~~ ✅ done as M11
  (host auth+task audit via rsyslog RFC5424; the PVE-API poller was considered and
  rejected as a heavier pattern). Remaining: Okta/Wazuh (same connector pattern).

## Cross-cutting seams (kept clean, watch when extending)

- **Storage seam:** all ClickHouse access stays in `services/mcp-query/.../clickhouse.py` and
  the M1 Vector sink. Swapping storage shouldn't touch tools/builders.
- **Normalization:** ECS-subset typed columns + `raw` + `ext` map; versioned. New vendors add
  fields under namespaces (`juniper.srx.*`, `panw.panos.*`), not new core columns, where possible.
- **Read-only boundary:** no write/management tools in SSDF. Acting on insights = separate
  vendor-MCP project.

## Protected lab infra (do not reclaim)

SSDF LXCs on Proxmox pve3.example.com: **ct102** (Vector), **ct104** (ClickHouse), **ct106**
(MCP query server + topology/`explain_access` tools), **ct109** (topo collectors+resolver **and**
the M6a entity resolver — two independent 5-min timers on the same host). Plus the cluster-wide
protected VMIDs in `~/.claude/CLAUDE.md`.
