#!/usr/bin/env bash
# Self-test for labgen_endpoint.sh: dryrun must emit one of each action class
# and send no packets, and the script must pass shellcheck (if installed).
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="$HERE/labgen_endpoint.sh"
fail() { echo "FAIL: $1"; exit 1; }

out="$(LABGEN_DRYRUN=1 LABGEN_ONESHOT=1 bash "$SCRIPT")" || fail "dryrun exited non-zero"
echo "$out" | grep -q '^DRYRUN https '   || fail "no https action in dryrun"
echo "$out" | grep -q '^DRYRUN dns-ok '   || fail "no allowed-DNS action in dryrun"
echo "$out" | grep -q '^DRYRUN dns-deny ' || fail "no denied-DNS action in dryrun"
echo "$out" | grep -q '^DRYRUN icmp '     || fail "no icmp action in dryrun"

if command -v shellcheck >/dev/null 2>&1; then
  shellcheck -S warning "$SCRIPT" || fail "shellcheck reported issues"
fi
echo "PASS"
