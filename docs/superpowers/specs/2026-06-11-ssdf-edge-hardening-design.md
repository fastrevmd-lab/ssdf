# SSDF edge hardening — M2 + L1–L6 (design)

Closes the remaining items from `docs/security/2026-06-10-vulnerability-review.md`:
**M2** (rate-limit / reverse proxy / token rotation) and **L1–L6** (defense-in-depth).
Operator decisions (2026-06-11): self-signed local CA, nginx, build **and** deploy.

## Goals / non-goals

- TLS for every SSDF network hop that carries credentials or security data:
  ClickHouse (ct104) and both MCP edges (ct106 sovereign, ct113 public).
- App-layer rate limiting + connection caps at the MCP edge (worst case: ct113).
- Token expiry + a documented rotation procedure.
- Tighten the widest writer grant (`ssdf_entity` ALTER DELETE) and remove the
  public tier's unused sovereign-store construction.
- **Non-goals:** no new services beyond nginx; no auth-protocol change (bearer
  stays); no cert automation (825-day leaves, manual re-issue runbook); vendor
  MCPs (junos/panos/unifi/proxmox) are out of scope — they are separate products.

## 1. PKI — SSDF local CA (sovereign, offline)

- `scripts/gen_ssdf_tls.sh` (idempotent): creates `infra/tls-local/` (gitignored;
  `.gitignore` gains `infra/tls-local/`) with `ssdf-ca.{key,crt}` (10y, CA:TRUE)
  and per-host leaves `ct104|ct106|ct113.{key,crt}` (825d) with IP SANs
  (198.51.100.151 / .152 / .154). CA key never leaves the dev host.
- Only `ssdf-ca.crt` is distributed (services trust it via explicit ca-file
  config, not the system trust store).

## 2. L1a — ClickHouse TLS (ct104)

- `infra/clickhouse/config.d/ssdf-tls.xml`: `https_port 8443`, cert/key at
  `/etc/clickhouse-server/tls/` (mode 600, owner clickhouse).
- Plain 8123 stays for container-local admin (`clickhouse-client` on ct104) but
  is firewalled: `infra/firewall/ct104-clickhouse.nft` (`inet ssdf_ch` table)
  accepts tcp/8123 from 127.0.0.1 only, drops the rest; tcp/8443 open to LAN.
  Reboot-persistent via `/etc/nftables.d/` include (same pattern as H1/ct102).
- Native port 9000 likewise restricted to 127.0.0.1 (admin use on ct104 only).

### Client migration (all CH consumers)

- **Python services** (mcp-query, topo, entity, policy): config gains
  `CH_SECURE` (default `0`) + `CH_CA_FILE`; chwriter/client passes
  `interface="https"`, `ca_cert=...` when secure. One shared pattern, four repos
  of code — same two-line change in each `get_client(...)` call site.
- **Vector (ct102)**: sink endpoint becomes
  `endpoint = "${CH_PROTO:-http}://${CH_HOST}:${CH_HTTP_PORT:-8123}"` — Vector's
  env interpolation cannot nest `${…}` inside a default, so the originally
  proposed single `CH_ENDPOINT` var fails `vector validate` (proven on ct102,
  Vector 0.56.0). Live env flips `CH_PROTO=https CH_HTTP_PORT=8443` and appends
  `[sinks.clickhouse.tls] ca_file = "/etc/vector/ssdf-ca.crt"` on the host
  (a checked-in `tls` block with an env-defaulted empty path would break the
  plain-http default). CA cert pushed to `/etc/vector/ssdf-ca.crt`.
- **verify_audit / integration tests**: same `CH_SECURE`/`CH_CA_FILE` envs.

## 3. M2 + L3 + L6 + L1b — nginx MCP edge (ct106, ct113)

- uvicorn rebinds to loopback: unit env `MCP_BIND=127.0.0.1`, `MCP_PORT=31032`
  (ct106) / `31033` (ct113). The LAN-facing ports stay 30032/30033 — only the
  scheme changes for clients (http → https).
- nginx (distro package) terminates TLS on 30032/30033 with the host leaf cert:
  - `limit_req_zone $binary_remote_addr zone=mcp:10m rate=10r/s;` →
    `limit_req zone=mcp burst=30 nodelay;` + `limit_conn` 32/IP (M2).
  - Host allow-list: `server_name` = host IP (+ hostname); `default_server`
    catch-all returns 444 (L6 DNS-rebinding defense).
  - Origin gate: requests carrying an `Origin` header that isn't in the
    allow-list (the server's own https origin) get 403 (L6; MCP CLI clients
    send no Origin, browsers must match).
  - Streamable-HTTP requirements: `proxy_buffering off`, `proxy_http_version 1.1`,
    `proxy_read_timeout 3600s`, `proxy_set_header Connection ""`.
- Configs checked in at `infra/nginx/ssdf-mcp-query.conf` / `ssdf-mcp-public.conf`;
  apply scripts push cert+conf, install nginx, flip the unit env, restart both.
- ct102 ingest nftables (H1) is untouched; ct106/ct113 host firewalling stays
  out of scope (bearer + TLS + loopback bind is the boundary).

## 4. M2 — token expiry + rotation

- `tokens.json` entries gain optional `"not_after": "<ISO-8601 UTC>"`.
  `load_token_map` parses/validates it (bad format ⇒ `ConfigError`, fail closed)
  and puts `not_after` into the verifier claims.
- Per-call enforcement in `wrapper.audited_tool` (same seam as the M7a
  `allowed_tools` gate): expired token ⇒ `{"error":"forbidden"}` +
  audit `decision="deny"`. Static startup maps can't expire tokens mid-process
  otherwise.
- ct106 moves from the single-token path to `MCP_TOKENS_FILE` with named
  principals; both tiers get fresh tokens with `not_after` set (+90d).
- Rotation runbook (in the ops doc): add new token entry → restart (≈1s gap on
  oneshot-free MCP hosts) → move clients → delete old entry → restart.

## 5. L2 / L4 / L5 (small, independent)

- **L2:** parametrized test in `test_sql_guard.py` asserting `FROM <fn>(...)` is
  rejected for a list of table functions *including ones absent from the
  denylist* (`gcs`, `iceberg`, `mongodb`, `executable`, …) — pins the structural
  allow-list as the boundary so denylist drift can't regress coverage.
- **L4:** `infra/clickhouse/011_entity_maint_user.sql` — new
  `ssdf_entity_maint` (SELECT + INSERT + ALTER DELETE on the two entity tables);
  `REVOKE ALTER DELETE … FROM ssdf_entity`. The 5-min resolver identity keeps
  SELECT/INSERT only. Reconcile (manual, occasional) is run as the maint user
  (`CH_USER=ssdf_entity_maint`); docs updated. No code change.
- **L5:** `server.py` constructs `ClickHouseEntityStore`/`AccessTools` only when
  `tier != "public"` (entity tools are sovereign-classified; the store
  hard-codes `ssdf.entities` and could never serve public).

## 6. Deploy order (single evening, rollback noted)

1. Repo code + tests green (unit suites in all four services; `vector validate`).
2. Generate PKI; push certs.
3. CH TLS on ct104 + nftables; flip ct109 services (topo/entity/policy), ct106,
   ct113, then Vector ct102 to `CH_SECURE`/8443; verify each before the next.
4. nginx on ct106/ct113; rebind uvicorn to loopback; smoke MCP over https.
5. Tokens: new files with expiry on both hosts; update local agent client config
   (`~/.claude.json` / `.mcp.json`) to `https://` + CA trust
   (`NODE_EXTRA_CA_CERTS` for Claude Code).
6. Migration 011 (L4) + revoke; run one resolver cycle to confirm no grant break.
7. `verify_audit` + full live smoke; update STATUS.md / CLAUDE.md / review doc.

- **Rollback:** every step is reversible — remove nginx site + restore unit env
  (bind 0.0.0.0:3003x), drop `CH_ENDPOINT`/`CH_SECURE` envs (8123 still listens
  for localhost; nft table delete restores LAN 8123), re-grant ALTER DELETE.

## Out-of-scope follow-ups (recorded, not built)

- Cert renewal automation; mirroring audit to WORM storage (M3 "optionally");
  per-principal request quotas beyond per-IP nginx limits; vendor-MCP TLS.
