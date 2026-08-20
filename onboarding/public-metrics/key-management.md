# Public-metrics pseudonym key management

`PUBLIC_PSEUDONYM_KEY` is the HMAC-SHA256 key that turns real identifiers (host IPs)
into the opaque surrogates published on the public tier. It is the ONLY secret whose
disclosure would let a public-tier reader correlate surrogates back to a guessed IP
(by re-deriving the HMAC). It lives ONLY on guest 704 (was ct109) (the public-metrics resolver host).

## Generate (one-time)

    openssl rand -hex 16          # 128-bit key, 32 hex chars

Write it to guest 704 (was ct109) at `/etc/ssdf-public-metrics/pseudonym.key` (mode 600, root). The
systemd unit passes it to the resolver via `LoadCredential` — it is never an env
value in the unit. For a manual run, export `PUBLIC_PSEUDONYM_KEY=<hex>` instead.

## Where it must NEVER go

- Not on guest 703 (was ct113) (public MCP) — the public process only reads `ssdf_public.*`.
- Not in ClickHouse — `ssdf.pseudonym_map` stores the real<->surrogate mapping, but
  that table is granted to `ssdf_ro` (sovereign reidentify) only, never `ssdf_public`.
- Not in git, not in the env example committed to the repo.

## Rotation (key_version)

Surrogates embed no version, but `ssdf.pseudonym_map.key_version` records which key
minted each mapping. To rotate:

1. Generate a new key; bump `PUBMETRICS_KEY_VERSION` (e.g. 1 -> 2) in
   `/etc/ssdf-public-metrics/ENV.local`.
2. Replace `/etc/ssdf-public-metrics/pseudonym.key`; `systemctl restart
   ssdf-public-metrics.service` (or wait for the timer).
3. New mappings are minted under key_version 2 (new surrogates for the same IPs).
   Old key_version-1 rows remain for historical reidentify until TTL-expired.
4. Published series under old surrogates age out with the 30-day TTL on the metric
   tables; consumers see the new surrogates going forward.

Rotation is only needed on suspected key disclosure — there is no scheduled cadence.
