#!/usr/bin/env bash
# Applies the topology DDL and asserts the three tables exist.
# Usage: CH_HOST=<ip> ./scripts/apply_topology_schema.sh
set -euo pipefail
CH_HOST="${CH_HOST:-127.0.0.1}"
SQL_FILE="$(dirname "$0")/../infra/clickhouse/002_topology.sql"

clickhouse-client --host "$CH_HOST" --multiquery < "$SQL_FILE"

N=$(clickhouse-client --host "$CH_HOST" --query \
  "SELECT count() FROM system.tables WHERE database='ssdf' AND name IN ('topo_observations','graph_nodes','graph_edges')")
if [ "$N" -ne 3 ]; then
  echo "FAIL: expected 3 topology tables, found $N"; exit 1
fi
echo "OK: topology tables present"
