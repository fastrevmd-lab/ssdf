#!/usr/bin/env bash
# Applies the ClickHouse DDL and asserts the events table exists.
# Usage: CH_HOST=<ip> ./scripts/apply_clickhouse_schema.sh
set -euo pipefail
CH_HOST="${CH_HOST:-127.0.0.1}"
SQL_FILE="$(dirname "$0")/../infra/clickhouse/001_events.sql"

clickhouse-client --host "$CH_HOST" --multiquery < "$SQL_FILE"

COLS=$(clickhouse-client --host "$CH_HOST" --query \
  "SELECT count() FROM system.columns WHERE database='ssdf' AND table='events'")
if [ "$COLS" -lt 22 ]; then
  echo "FAIL: ssdf.events has $COLS columns (expected >= 22)"; exit 1
fi
echo "OK: ssdf.events present with $COLS columns"
