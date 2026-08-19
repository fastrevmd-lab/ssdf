#!/bin/sh
# Manage the SSDF ingest firewall (security review finding H1) on the Vector
# ingest guest: an nftables allow-list restricting UDP 514-518 to known senders.
#
# Dry-run by default (AGENTS.md: scripts default to validation/plan mode). It
# prints the exact target and the rules that WOULD be applied, and changes
# nothing until you pass --apply.
#
#   ./scripts/apply_ct102_nftables.sh                    # plan only
#   ./scripts/apply_ct102_nftables.sh --apply            # apply to the default target
#   SSDF_VECTOR_CTID=600 ./scripts/apply_ct102_nftables.sh --apply   # another guest
#
# Target defaults track the 2026-08-12 renumber+migration (ct102/pve3 -> 700/pve2);
# override PVE_HOST_SSH / SSDF_VECTOR_CTID if the guest moves again.
#
# Rollback: ssh $PVE_HOST "pct exec $CTID -- nft delete table inet ssdf_ingest"
# and remove the include line from /etc/nftables.conf. The dedicated table is
# separate from the default `inet filter`, so removing it cannot disturb other rules.
set -eu

APPLY=0
for arg in "$@"; do
  case "$arg" in
    --apply) APPLY=1 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

PVE_HOST="${PVE_HOST_SSH:-root@pve2.example.com}"
CTID="${SSDF_VECTOR_CTID:-700}"
RULE_SRC="$(dirname "$0")/../infra/firewall/ct102-ingest.nft"
RULE_DST="/etc/nftables.d/ssdf-ingest.nft"

[ -f "$RULE_SRC" ] || { echo "missing $RULE_SRC" >&2; exit 1; }

# State the exact target before doing anything, in both modes.
echo "=== target ==="
echo "  host : $PVE_HOST"
echo "  guest: $CTID"
echo "  rules: $RULE_SRC -> $RULE_DST"

# Confirm the target guest is the one intended, and show what it runs now.
echo "=== target guest identity ==="
ssh "$PVE_HOST" "pct config $CTID | grep -E '^hostname|^net0' || true"

if [ "$APPLY" -eq 0 ]; then
  echo "=== rules that WOULD be applied ==="
  cat "$RULE_SRC"
  echo "=== current table on the target (empty means not yet applied) ==="
  ssh "$PVE_HOST" "pct exec $CTID -- nft list table inet ssdf_ingest 2>/dev/null" || true
  echo
  echo "DRY RUN — nothing was changed. Re-run with --apply to apply the above."
  exit 0
fi

# Push the rule file into the container (via a host scratch copy).
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
echo "=== ssdf_ingest table on guest $CTID ==="
ssh "$PVE_HOST" "pct exec $CTID -- nft list table inet ssdf_ingest"
echo "Rollback: ssh $PVE_HOST \"pct exec $CTID -- nft delete table inet ssdf_ingest\""
