#!/usr/bin/env bash
# Idempotently create/update the SSDF backup jobs on the PVE cluster.
# Daily ct104 (ClickHouse, system of record) + weekly all SSDF LXCs (secrets/env
# files on ct102/106/109/113 are not reproducible from the repo).
# NOTE: the only backup-capable storage on pve3 is `local` (dir on the host's own
# disk) — protects against container loss/fat-fingers, NOT host-disk loss.
set -euo pipefail
PVE="${PVE_HOST_SSH:-root@pve3.example.com}"
STORAGE="${PVE_BACKUP_STORAGE:?set PVE_BACKUP_STORAGE (e.g. local; see onboarding notes)}"
ensure_job() { # id vmids schedule keep
  local id="$1" vmids="$2" sched="$3" keep="$4"
  if ssh "$PVE" "pvesh get /cluster/backup/${id}" >/dev/null 2>&1; then
    ssh "$PVE" "pvesh set /cluster/backup/${id} --vmid '${vmids}' --schedule '${sched}' --storage '${STORAGE}' --mode snapshot --compress zstd --prune-backups '${keep}' --enabled 1"
  else
    ssh "$PVE" "pvesh create /cluster/backup --id '${id}' --vmid '${vmids}' --schedule '${sched}' --storage '${STORAGE}' --mode snapshot --compress zstd --prune-backups '${keep}' --enabled 1"
  fi
}
ensure_job ssdf-ch-daily   "104"                 "03:30"     "keep-daily=7,keep-weekly=4"
ensure_job ssdf-all-weekly "102,104,106,109,113" "sun 04:30" "keep-weekly=4"
echo "Backup jobs applied. Verify: ssh $PVE 'pvesh get /cluster/backup'"
