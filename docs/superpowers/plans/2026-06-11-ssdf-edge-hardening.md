# SSDF edge hardening — implementation plan

Spec: `docs/superpowers/specs/2026-06-11-ssdf-edge-hardening-design.md`.
Branch: `edge-hardening` → one PR. Live deploy same evening (operator pre-approved).

## Task A — mcp-query code (services/mcp-query)
1. **Token expiry (M2):** `TokenProfile` gains `not_after: datetime | None`;
   `load_token_map` parses ISO-8601 (`ConfigError` on bad value, fail closed);
   `server.build_app` puts `not_after` (ISO string) into verifier claims;
   `wrapper.audited_tool` denies expired tokens (same path as `allowed_tools`
   deny: `{"error":"forbidden"}`, audit `decision="deny"`). Tests: parse,
   bad-format ConfigError, wrapper allows unexpired/no-expiry, denies expired
   (+ audit row decision=deny).
2. **L5:** `build_app` constructs `ClickHouseEntityStore`/`AccessTools` only when
   `tier != "public"`. Test: public build has no entity store side effects
   (e.g. constructor not invoked — patch and assert).
3. **L2:** parametrized `test_sql_guard.py` cases: `SELECT * FROM <fn>(...)`
   rejected for `s3, url, file, remote, gcs, azureBlobStorage, iceberg, deltaLake,
   mongodb, redis, sqlite, executable, remoteSecure, cluster, jdbc, odbc`.
4. **CH TLS client:** `Config` gains `ch_secure` (env `CH_SECURE`, default 0) +
   `ch_ca_file` (env `CH_CA_FILE`); `ClickHouseClient` and `make_ch_auditor`/
   `verify_audit` pass `interface="https"`, `ca_cert` when secure. Tests:
   get_client kwargs (mock).

## Task B — topo/entity/policy TLS + Vector endpoint
1. Each service `config.py`: `CH_SECURE`/`CH_CA_FILE`; each `chwriter.py`
   `get_client(...)` passes `interface="https"`, `ca_cert` when secure. Unit
   tests mirror existing config/chwriter tests per service.
2. `infra/vector/vector.toml`: sink `endpoint = "${CH_ENDPOINT:-http://${CH_HOST}:8123}"`
   + `[sinks.clickhouse.tls] ca_file = "${CH_CA_FILE:-}"`… (only if Vector
   supports optional tls block cleanly — otherwise document the live drop-in
   override and keep the checked-in default plain). `vector validate` must pass
   with and without `CH_ENDPOINT` set.

## Task C — infra artifacts
1. `scripts/gen_ssdf_tls.sh` (CA + ct104/ct106/ct113 leaves, IP SANs, idempotent);
   `.gitignore` += `infra/tls-local/`.
2. `infra/clickhouse/config.d/ssdf-tls.xml` (https_port 8443, cert paths).
3. `infra/firewall/ct104-clickhouse.nft` (8123+9000 loopback-only, 8443 LAN) +
   `scripts/apply_ct104_tls.sh` (push certs+xml+nft, restart CH, verify).
4. `infra/nginx/ssdf-mcp-query.conf` + `ssdf-mcp-public.conf` (TLS 30032/30033 →
   loopback 31032/31033, limit_req/limit_conn, 444 default server, Origin gate,
   SSE-safe proxying) + `scripts/apply_mcp_edge.sh` (install nginx, push certs+
   conf, patch unit env MCP_BIND/MCP_PORT, restart, smoke).
5. `infra/clickhouse/011_entity_maint_user.sql` (ssdf_entity_maint + REVOKE).
6. `services/mcp-query/infra/tokens.example.json`: add `not_after` example.

## Task D — deploy + verify (operator-approved tonight)
Spec §6 order. Every step verified before the next; rollback notes in spec.

## Task E — docs + PR
STATUS.md backlog rows, CLAUDE.md commands section, review-doc checkboxes,
memory update, single PR.
