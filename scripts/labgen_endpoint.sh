#!/usr/bin/env bash
# SSDF lab endpoint traffic generator. Runs ON an Alpine endpoint LXC behind a
# lab firewall (ct198 behind vm103 SRX, ct199 behind panosvm) to keep SRX/PAN-OS
# transit logs flowing continuously. Produces permitted internet egress plus a
# deliberate denied DNS attempt, so deny-action events land in SSDF too.
#
# Daemon: loops forever, one "round" per ~LABGEN_INTERVAL seconds (jittered).
# Runs under OpenRC (see onboarding runbook). Requires: bash curl bind-tools.
#
# Self-test:  LABGEN_DRYRUN=1 LABGEN_ONESHOT=1 ./labgen_endpoint.sh
#   prints the action plan for one round and exits 0 (sends nothing).
set -u

LABGEN_INTERVAL="${LABGEN_INTERVAL:-30}"                       # seconds between rounds
LABGEN_HTTPS_DESTS="${LABGEN_HTTPS_DESTS:-1.1.1.1 cloudflare.com example.com}"
LABGEN_DNS_OK="${LABGEN_DNS_OK:-198.51.100.1}"                  # an allowed resolver
LABGEN_DNS_DENY="${LABGEN_DNS_DENY:-8.8.8.8}"                  # blocked by FW DNS policy
LABGEN_ICMP_DEST="${LABGEN_ICMP_DEST:-1.1.1.1}"
LABGEN_DRYRUN="${LABGEN_DRYRUN:-0}"                            # 1 = print actions, send nothing
LABGEN_ONESHOT="${LABGEN_ONESHOT:-0}"                          # 1 = run one round then exit

# Pick one element of a space-separated list at random.
pick() {
  # shellcheck disable=SC2206
  local arr=($1)
  echo "${arr[$((RANDOM % ${#arr[@]}))]}"
}

# $1 = human label; $2.. = command (executed only when not dryrun).
do_action() {
  local label="$1"; shift
  if [ "$LABGEN_DRYRUN" = "1" ]; then
    echo "DRYRUN ${label}"
    return 0
  fi
  "$@" >/dev/null 2>&1 || true
}

run_round() {
  local https_dest
  https_dest="$(pick "$LABGEN_HTTPS_DESTS")"
  do_action "https ${https_dest}:443"               curl -s -m 5 -o /dev/null "https://${https_dest}"
  do_action "dns-ok example.com@${LABGEN_DNS_OK}"   timeout 5 nslookup example.com "$LABGEN_DNS_OK"
  do_action "dns-deny example.com@${LABGEN_DNS_DENY}" timeout 5 nslookup example.com "$LABGEN_DNS_DENY"
  do_action "icmp ${LABGEN_ICMP_DEST}"              ping -c 2 -W 2 "$LABGEN_ICMP_DEST"
}

while :; do
  run_round
  [ "$LABGEN_ONESHOT" = "1" ] && break
  # jitter: INTERVAL +/- up to 10s so flows do not perfectly align
  sleep "$(( LABGEN_INTERVAL + (RANDOM % 21) - 10 ))"
done
