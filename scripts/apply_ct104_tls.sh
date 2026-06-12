#!/usr/bin/env bash
# Apply ClickHouse TLS (edge-hardening L1a) to ct104 via pve3.
# Pushes the ct104 leaf + CA cert, the https_port drop-in, and the nftables
# policy that closes plaintext 8123/9000 to the LAN. Idempotent; safe to re-run.
#
# Prereq: ./scripts/gen_ssdf_tls.sh has populated infra/tls-local/.
# Usage:  ./scripts/apply_ct104_tls.sh
# Env:    PVE_HOST_SSH (default root@pve3.example.com), SSDF_CH_CTID (default 104)
set -euo pipefail

PVE_HOST="${PVE_HOST_SSH:-root@pve3.example.com}"
CTID="${SSDF_CH_CTID:-104}"
CH_IP="198.51.100.151"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TLS_DIR="$REPO_ROOT/infra/tls-local"
XML_SRC="$REPO_ROOT/infra/clickhouse/config.d/ssdf-tls.xml"
NFT_SRC="$REPO_ROOT/infra/firewall/ct104-clickhouse.nft"
NFT_DST="/etc/nftables.d/ssdf-clickhouse.nft"

for f in "$TLS_DIR/ct104.crt" "$TLS_DIR/ct104.key" "$TLS_DIR/ssdf-ca.crt" "$XML_SRC" "$NFT_SRC"; do
  [ -f "$f" ] || { echo "missing $f (run scripts/gen_ssdf_tls.sh first?)" >&2; exit 1; }
done

# Push a local file into the container via a pve3 scratch copy (ct102 pattern).
# umask 077 keeps private keys from sitting world-readable in pve3 /tmp.
push_file() {
  local src="$1" dst="$2"
  ssh "$PVE_HOST" "umask 077 && cat > /tmp/ssdf-push.tmp && pct push $CTID /tmp/ssdf-push.tmp $dst && rm -f /tmp/ssdf-push.tmp" < "$src"
}

echo '=== pushing TLS material + config ==='
ssh "$PVE_HOST" "pct exec $CTID -- mkdir -p /etc/clickhouse-server/tls /etc/clickhouse-server/config.d /etc/nftables.d"
push_file "$TLS_DIR/ct104.crt"   /etc/clickhouse-server/tls/ct104.crt
push_file "$TLS_DIR/ct104.key"   /etc/clickhouse-server/tls/ct104.key
push_file "$TLS_DIR/ssdf-ca.crt" /etc/clickhouse-server/tls/ssdf-ca.crt
# clickhouse-server drops root after reading config, so the key must be
# readable by the clickhouse user; 600 + ownership keeps it from everyone else.
ssh "$PVE_HOST" "pct exec $CTID -- sh -c 'chown -R clickhouse:clickhouse /etc/clickhouse-server/tls && chmod 600 /etc/clickhouse-server/tls/*'"
push_file "$XML_SRC" /etc/clickhouse-server/config.d/ssdf-tls.xml

echo '=== loading nftables policy (8123/9000 loopback-only) ==='
push_file "$NFT_SRC" "$NFT_DST"
# Ensure /etc/nftables.conf includes our drop-in (idempotent), load it, enable service.
ssh "$PVE_HOST" "pct exec $CTID -- sh -c '
  grep -qF \"include \\\"$NFT_DST\\\"\" /etc/nftables.conf 2>/dev/null \
    || echo \"include \\\"$NFT_DST\\\"\" >> /etc/nftables.conf
  nft -f $NFT_DST
  systemctl enable --now nftables.service
'"

echo '=== restarting clickhouse-server ==='
ssh "$PVE_HOST" "pct exec $CTID -- systemctl restart clickhouse-server"
# CH takes a few seconds to open listeners after restart.
ssh "$PVE_HOST" "pct exec $CTID -- sh -c 'for i in \$(seq 1 15); do curl -s --cacert /etc/clickhouse-server/tls/ssdf-ca.crt https://$CH_IP:8443/ping >/dev/null 2>&1 && break; sleep 1; done'"

echo '=== verify: HTTPS 8443 (CA-verified) ==='
ssh "$PVE_HOST" "pct exec $CTID -- curl -s --cacert /etc/clickhouse-server/tls/ssdf-ca.crt https://$CH_IP:8443/ping" \
  | grep -q 'Ok' && echo "PASS: https://$CH_IP:8443/ping -> Ok" \
  || { echo "FAIL: https ping on 8443" >&2; exit 1; }

echo '=== verify: loopback 8123 still answers (container-local admin) ==='
ssh "$PVE_HOST" "pct exec $CTID -- curl -s http://127.0.0.1:8123/ping" \
  | grep -q 'Ok' && echo 'PASS: loopback 8123 -> Ok' \
  || { echo 'FAIL: loopback 8123' >&2; exit 1; }

# LAN 8123 must be DROPPED, not refused: a 3s curl from pve3 (a LAN peer of
# the container) should time out, never return "Ok.". Drop (vs reject) means
# curl exit 28 — we only assert it did NOT succeed.
echo '=== verify: LAN 8123 dropped (curl from pve3 must time out) ==='
if ssh "$PVE_HOST" "curl -sm 3 http://$CH_IP:8123/ping" 2>/dev/null | grep -q 'Ok'; then
  echo "FAIL: LAN 8123 still reachable from pve3" >&2; exit 1
fi
echo 'PASS: LAN 8123 unreachable'

echo '=== ssdf_ch table on ct104 ==='
ssh "$PVE_HOST" "pct exec $CTID -- nft list table inet ssdf_ch"
echo 'done.'
