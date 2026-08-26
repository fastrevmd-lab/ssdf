#!/usr/bin/env bash
# Generate the SSDF local PKI (edge-hardening design, §1).
#
# Creates infra/tls-local/ (gitignored — keys never leave the dev host) with:
#   ssdf-ca.{key,crt}            10-year self-signed CA, CN "SSDF Local CA"
#   ct104.{key,crt}              ClickHouse  leaf, SAN IP:198.51.100.151, 825d
#   ct106.{key,crt}              MCP query   leaf, SAN IP:198.51.100.152, 825d
#   ct113.{key,crt}              MCP public  leaf, SAN IP:198.51.100.154, 825d
#
# Idempotent: existing files are never overwritten. `--force` re-issues the
# LEAVES only (manual 825-day renewal runbook); the CA is never regenerated
# automatically — delete ssdf-ca.* by hand if you really mean to re-root,
# because that invalidates every distributed leaf and trust anchor at once.
#
# Usage: ./scripts/gen_ssdf_tls.sh [--force]
set -euo pipefail

FORCE=0
[ "${1:-}" = "--force" ] && FORCE=1

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TLS_DIR="$REPO_ROOT/infra/tls-local"
CA_KEY="$TLS_DIR/ssdf-ca.key"
CA_CRT="$TLS_DIR/ssdf-ca.crt"
CA_DAYS=3650   # 10 years — the CA outlives every leaf
LEAF_DAYS=825  # max lifetime modern clients accept for server certs

mkdir -p "$TLS_DIR"

# --- CA -----------------------------------------------------------------
if [ -f "$CA_KEY" ] && [ -f "$CA_CRT" ]; then
  echo "CA exists ($CA_CRT) — skipping (delete by hand to re-root)"
else
  # -addext is explicit even though modern `openssl req -x509` defaults to
  # CA:TRUE — we want the constraint critical and pinned, not version-dependent.
  openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days "$CA_DAYS" \
    -keyout "$CA_KEY" -out "$CA_CRT" \
    -subj "/CN=SSDF Local CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"
  chmod 600 "$CA_KEY"
  echo "generated CA: $CA_CRT"
fi

# --- leaves --------------------------------------------------------------
gen_leaf() {
  local name="$1" san_ip="$2"
  local key="$TLS_DIR/$name.key" crt="$TLS_DIR/$name.crt" csr="$TLS_DIR/$name.csr"

  if [ "$FORCE" -eq 0 ] && [ -f "$key" ] && [ -f "$crt" ]; then
    echo "leaf $name exists — skipping (use --force to re-issue)"
    return
  fi

  openssl req -newkey rsa:2048 -nodes -sha256 \
    -keyout "$key" -out "$csr" -subj "/CN=$name"
  # Services dial these hosts by IP, so the SAN is an IP entry (CN alone is
  # ignored by modern verifiers).
  openssl x509 -req -in "$csr" -sha256 -days "$LEAF_DAYS" \
    -CA "$CA_CRT" -CAkey "$CA_KEY" -CAcreateserial \
    -extfile <(printf 'subjectAltName=IP:%s\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n' "$san_ip") \
    -out "$crt"
  rm -f "$csr"
  chmod 600 "$key"
  echo "generated leaf: $crt (SAN IP:$san_ip, ${LEAF_DAYS}d)"
}

# These names are stable CERT BASENAMES, not container ids. They predate the
# 2026-08-12 renumber and are intentionally NOT tracked to it: the files are
# referenced by name from apply_ct104_tls.sh / apply_mcp_edge.sh and from every
# deployed host, so renaming them means re-issuing and redistributing all leaves.
gen_leaf ct104 198.51.100.151   # ClickHouse
gen_leaf ct106 198.51.100.152   # sovereign MCP (ssdf-mcp-query)
gen_leaf ct113 198.51.100.154   # public MCP (ssdf-mcp-public)

echo "done — distribute ONLY ssdf-ca.crt to clients; leaf keys go to their own host."
