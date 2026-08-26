#!/usr/bin/env bash
# Idempotently create/update the SSDF backup jobs on the PVE cluster.
# Daily ClickHouse (701, the system of record) + weekly all SSDF LXCs (the
# secrets/env files on 700/702/703/704 are not reproducible from the repo).
#
# VMIDs track the 2026-08-12 renumber+migration (ct102/104/106/109/113 on pve3
# -> 700/701/702/703/704 on pve2). The pre-renumber ids named guests that no
# longer exist: this script would have created two jobs backing up NOTHING,
# which reads as "backups configured" and is worse than an outright failure.
#
# BEFORE RUNNING, CHECK WHETHER YOU NEED THIS AT ALL. As of 2026-08-26 the
# cluster already runs `pve2-all-daily` / `pve3-all-daily` (all guests ->
# nas-backup, keep-daily 14 / weekly 8 / monthly 12), which covers every guest
# below. These per-VMID jobs are additive, not a replacement, and running this
# script on top of them just adds a second, narrower copy on different storage.
# Verify first: ssh <pve> 'pvesh get /cluster/backup'
#
# NOTE: `local` is a dir on the host's own disk — it protects against container
# loss/fat-fingers, NOT host-disk loss. Prefer a NAS-backed storage.
set -euo pipefail
PVE="${PVE_HOST_SSH:-root@pve2.example.com}"
STORAGE="${PVE_BACKUP_STORAGE:?set PVE_BACKUP_STORAGE (e.g. local; see onboarding notes)}"
ensure_job() { # id vmids schedule keep
  local id="$1" vmids="$2" sched="$3" keep="$4"
  if ssh "$PVE" "pvesh get /cluster/backup/${id}" >/dev/null 2>&1; then
    ssh "$PVE" "pvesh set /cluster/backup/${id} --vmid '${vmids}' --schedule '${sched}' --storage '${STORAGE}' --mode snapshot --compress zstd --prune-backups '${keep}' --enabled 1"
  else
    ssh "$PVE" "pvesh create /cluster/backup --id '${id}' --vmid '${vmids}' --schedule '${sched}' --storage '${STORAGE}' --mode snapshot --compress zstd --prune-backups '${keep}' --enabled 1"
  fi
}
#                          701 = ClickHouse; 700 ingest, 702 sovereign MCP,
#                          703 public MCP, 704 resolvers.
ensure_job ssdf-ch-daily   "701"                 "03:30"     "keep-daily=7,keep-weekly=4"
ensure_job ssdf-all-weekly "700,701,702,703,704" "sun 04:30" "keep-weekly=4"
echo "Backup jobs applied. Verify: ssh $PVE 'pvesh get /cluster/backup'"
