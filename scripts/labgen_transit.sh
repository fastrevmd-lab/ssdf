#!/usr/bin/env bash
# SSDF lab transit-traffic generator — keeps PAN-OS TRAFFIC logs flowing so the
# ingest pipeline is continuously live-proven (see onboarding/panos/transit-traffic.md).
# Runs ON the traffic-source host (ct115 ssdf-labgen, 10.74.11.20 on panosvm's trust
# segment). Install with cron: */15 * * * * /usr/local/bin/labgen_transit.sh
# Requires bash (Alpine: apk add bash) for the /dev/tcp connect.
set -u
DEST="${LABGEN_DEST:-198.51.100.1}"
PORT="${LABGEN_PORT:-443}"
# TCP connect (logged on session end by PAN-OS) + ICMP, through panosvm trust→untrust.
timeout 5 bash -c "exec 3<>/dev/tcp/${DEST}/${PORT}" 2>/dev/null
ping -c 2 -W 2 "${DEST}" >/dev/null 2>&1
exit 0
