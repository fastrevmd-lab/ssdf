#!/bin/sh
# Apply the SSDF ingest firewall (security review finding H1) to ct102 via pve3.
# Idempotent; safe to re-run. Usage: ./scripts/apply_ct102_nftables.sh
set -eu

PVE_HOST="${PVE_HOST_SSH:-root@pve3.example.com}"
CTID="${SSDF_VECTOR_CTID:-102}"
RULE_SRC="$(dirname "$0")/../infra/firewall/ct102-ingest.nft"
RULE_DST="/etc/nftables.d/ssdf-ingest.nft"

[ -f "$RULE_SRC" ] || { echo "missing $RULE_SRC" >&2; exit 1; }

# Push the rule file into the container (via a pve3 scratch copy).
ssh "$PVE_HOST" "pct exec $CTID -- mkdir -p /etc/nftables.d"
cat "$RULE_SRC" | ssh "$PVE_HOST" "cat > /tmp/ssdf-ingest.nft && pct push $CTID /tmp/ssdf-ingest.nft $RULE_DST"

# Ensure /etc/nftables.conf includes our drop-in (idempotent), load it, enable service.
ssh "$PVE_HOST" "pct exec $CTID -- sh -c '
  grep -qF \"include \\\"$RULE_DST\\\"\" /etc/nftables.conf 2>/dev/null \
    || echo \"include \\\"$RULE_DST\\\"\" >> /etc/nftables.conf
  nft -f $RULE_DST
  systemctl enable --now nftables.service
'"

# Verify the table loaded.
echo '=== ssdf_ingest table on ct102 ==='
ssh "$PVE_HOST" "pct exec $CTID -- nft list table inet ssdf_ingest"
