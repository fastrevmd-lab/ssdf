# SSDF Next-Phase Roadmap (P2 + M8/M9/M10) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking. **Only Phase 1 (P2) is execution-ready** — Phases
> 2–4 are milestone charters that MUST each go through brainstorm → spec → plan before
> implementation (operator's standing workflow).

**Goal:** Shift effort from infrastructure hardening to data quality, data breadth, and
*proof that LLM agents get correct answers* — the actual product thesis.

**Architecture:** Phase 1 (P2) is a small data-quality/ops batch on the existing pipeline
(UTC timestamps, backups, transit traffic, doc drift). Phases 2–4 are new milestones: M8
agent-eval harness (golden questions vs. real MCP endpoints, Claude + local Ollama), M9
UniFi/Suricata EVE as the third source (first detection-class data), M10 derived findings.

**Tech Stack:** Existing: Vector VRL, ClickHouse, Python/FastMCP, Proxmox LXC, panos-mcp /
rust-junosmcp / unifi-mcp. New in M8: Claude Agent SDK + an MCP-capable local-model harness.

**Decisions locked (operator, 2026-06-12):** PAN-OS TZ fix = device → UTC. Third source =
UniFi Suricata EVE. Evals = Claude + local Ollama. Backups = Proxmox vzdump.

---

## Critical-point → plan mapping

| Review finding | Addressed by |
|---|---|
| PAN-OS timestamps device-local (-4h skew) | P2 Task 1 (device → UTC) + Task 2 (backfill) + Task 3 (SRX verify) |
| No proof agents answer correctly (no evals) | M8 (Phase 2) |
| Data breadth: 2 firewalls, no identity/detection data | M9 (Phase 3); Okta deferred after M9 |
| PAN-OS transit traffic never existed (perpetual carve-out) | P2 Task 4 (traffic generator) |
| No backup/DR for system of record | P2 Task 5 (vzdump job) |
| Doctrine drift (CLAUDE.md says greenfield/Rust-core) | P2 Task 6 |
| Findings/derived value vs. passive store | M10 (Phase 4, gated on M8 results) |
| M6d Postgres-as-graph churn risk | Explicitly stays deferred — do not build |

---

# Phase 1 — P2: data-quality & ops batch (execution-ready)

Branch: `p2-data-quality-ops`. No new services; touches onboarding artifacts, one comment in
`vector.toml`, `scripts/`, and docs. Several steps are **operator-gated** (live device config,
CH mutation, PVE job creation) — same convention as the P0/P1 hardening plans.

### Task 1: PAN-OS device clock → UTC

The root fix for the -4h skew: PAN-OS stamps GeneratedTime in the device's local TZ
(`vector.toml:145-151` parses it naively). Setting the device TZ to UTC makes the stamp true
UTC with zero parser change and no DST fragility. SSDF never applies device config in its own
data path — this is an onboarding artifact applied via panos-mcp, like
`onboarding/panos/log-forwarding.set`.

**Files:**
- Create: `onboarding/panos/timezone-utc.md` (artifact + runbook)
- Modify: `infra/vector/vector.toml` (comment only, ~lines 145-146)

- [ ] **Step 1: Write the onboarding artifact**

Create `onboarding/panos/timezone-utc.md`:

```markdown
# PAN-OS device timezone → UTC (P2 data-quality fix)

PAN-OS stamps syslog GeneratedTime in the device-local timezone with no offset
field. SSDF's `panos_ecs` transform parses it as naive UTC, so a non-UTC device
skews every `ssdf.events.timestamp` (live finding: EDT ⇒ −4h). SSDF requires
log-source devices to run UTC.

Apply via panos-mcp (`load_and_commit_pan_config`, fmt=xml, ABSOLUTE xpath —
relative xpaths are rejected as "Unauthorized request", see STATUS.md M5):

  xpath:   /config/devices/entry[@name='localhost.localdomain']/deviceconfig/system
  element: <timezone>UTC</timezone>

Preview first with `pan_config_diff`, then commit. Record the commit time —
it is the backfill cutover (`infra/clickhouse/012` runbook in the P2 plan).

Verify (allow one syslog to arrive, e.g. a config commit generates one):

  SELECT max(timestamp), now() FROM ssdf.events WHERE event_provider='paloalto'

max(timestamp) must be within minutes of now(), not ~4h behind.
```

- [ ] **Step 2 (operator-gated): Preview the change on panosvm**

Via panos-mcp: `pan_config_diff` with the xpath/element above against host `panosvm`.
Expected: diff shows only `deviceconfig/system/timezone` = UTC.

- [ ] **Step 3 (operator-gated): Commit on panosvm**

`load_and_commit_pan_config` (fmt=xml, absolute xpath). Record commit timestamp (UTC) as
`CUTOVER_TS` for Task 2.

- [ ] **Step 4: Live-verify ingest skew is gone**

The commit itself emits CONFIG syslog. Edge hardening closed plaintext CH to loopback-only
(only https 8443 is on the LAN), so run ALL plan verification queries container-local:

```bash
ssh root@pve3.example.com "pct exec 104 -- clickhouse-client --query \
  \"SELECT max(timestamp), now() FROM ssdf.events WHERE event_provider='paloalto' AND timestamp > now() - INTERVAL 1 HOUR\""
```

(All later `clickhouse-client --host <ct104>` steps in this plan mean this same
container-local pattern.)

Expected: a row lands with `max(timestamp)` within minutes of `now()`. (If zero rows in a
UTC-relative window was the old symptom, rows appearing IS the proof.)

- [ ] **Step 5: Update the stale caveat comment in vector.toml**

In `infra/vector/vector.toml` replace the two comment lines (~145-146):

```toml
# field 7 (index 6) = GeneratedTime, device-local US/Eastern. v0: parse as-is
# without TZ conversion (caveat: stored timestamp is wall-clock, not true UTC).
```

with:

```toml
# field 7 (index 6) = GeneratedTime, stamped in the DEVICE's local timezone with
# no offset. SSDF requires log sources to run UTC (onboarding/panos/timezone-utc.md);
# parsed here as naive UTC. A non-UTC device skews ssdf.events.timestamp.
```

Comment-only change — no `vector test` delta expected; still run it on ct102 when next
deploying the toml (14/14 must stay green).

- [ ] **Step 6: Commit**

```bash
git add onboarding/panos/timezone-utc.md infra/vector/vector.toml
git commit -m "fix(p2): PAN-OS device timezone -> UTC onboarding artifact; correct stale TZ caveat comment"
```

### Task 2: Backfill historical paloalto rows (+4h)

Pre-cutover paloalto rows are EDT-as-UTC, i.e. 4h behind. Data volume is tiny; one gated
mutation fixes history so agents never see mixed-epoch data.

**Files:**
- Create: `infra/clickhouse/012_backfill_paloalto_utc.sql.example` (template — `.example`
  because `CUTOVER_TS` is deployment-specific, same pattern as `tokens.example.json`)

- [ ] **Step 1: Write the migration template**

```sql
-- 012: one-time backfill — shift pre-cutover paloalto timestamps EDT->UTC (+4h).
-- Substitute CUTOVER_TS with the Task-1 commit time (UTC) before running.
-- Run as admin with mutations_sync=1. Idempotence: guarded by the WHERE window —
-- run EXACTLY ONCE; a second run would double-shift. Verify counts first:
--   SELECT count() FROM ssdf.events
--   WHERE event_provider='paloalto' AND timestamp < toDateTime64('${CUTOVER_TS}', 3, 'UTC');
ALTER TABLE ssdf.events
UPDATE timestamp = timestamp + INTERVAL 4 HOUR
WHERE event_provider = 'paloalto'
  AND timestamp < toDateTime64('${CUTOVER_TS}', 3, 'UTC')
SETTINGS mutations_sync = 1;
```

- [ ] **Step 2 (operator-gated): Run it once on ct104**

Substitute `CUTOVER_TS`, run as the admin user, then verify no paloalto row remains >1h
behind its insert window:

```bash
clickhouse-client --host <ct104> ... --query \
  "SELECT count() FROM ssdf.events WHERE event_provider='paloalto' AND timestamp < toDateTime64('<CUTOVER_TS>','UTC') - INTERVAL 1 HOUR"
```

Expected: `0` (all old rows shifted past the old skew).

- [ ] **Step 3: Update CLAUDE.md trap note**

In `CLAUDE.md` Edge-hardening section, replace the line
`**PAN-OS event timestamps are device-local (EDT, UTC-4)** — …` with:

```markdown
- **PAN-OS timestamps fixed to UTC (P2, 2026-06-12):** panosvm now runs `timezone UTC`
  (onboarding/panos/timezone-utc.md) and pre-cutover rows were backfilled +4h (012). Any
  NEW log source must be onboarded with a UTC device clock — naive-parse skew otherwise.
```

- [ ] **Step 4: Commit**

```bash
git add infra/clickhouse/012_backfill_paloalto_utc.sql.example CLAUDE.md
git commit -m "fix(p2): backfill template for pre-UTC paloalto rows; document UTC device-clock requirement"
```

### Task 3: Verify SRX/vSRX clock is UTC (and pin the requirement)

M1 worked against UTC-relative windows, so vSRX-test10 is *probably* UTC — verify, don't
assume; the same naive-parse skew applies to any source.

**Files:**
- Create: `onboarding/srx/timezone-utc.md` (only if a fix is needed; else fold the
  requirement into `onboarding/srx/` README text within `stream-config.set`'s companion notes)

- [ ] **Step 1 (live check): Device clock**

Via rust-junosmcp: `execute_junos_command(router_name="vSRX-test10", command="show system uptime")`.
Expected: `Current time:` reports `UTC`. If not: stage `set system time-zone UTC` as an
onboarding artifact mirroring Task 1 (operator-gated commit), and re-verify.

- [ ] **Step 2 (live check): Stored rows agree with wall clock**

```bash
clickhouse-client --host <ct104> ... --query \
  "SELECT now() - max(timestamp) FROM ssdf.events WHERE event_provider='juniper' AND timestamp > now() - INTERVAL 1 DAY"
```

Expected: small positive lag (minutes), not ~hours.

- [ ] **Step 3: Commit any artifact/doc produced**

```bash
git add onboarding/srx/
git commit -m "chore(p2): verify/pin UTC clock requirement for SRX log sources"
```

### Task 4: Lab transit-traffic generator (closes the PAN-OS TRAFFIC carve-out)

panosvm has had an empty session table since M5; PAN-OS TRAFFIC parsing and the M6c-B
provenance suffix path (`panosvm.example.com`→`panosvm`) have never been live-proven. A tiny
periodic flow through a logged rule self-proves both, permanently.

**Files:**
- Create: `scripts/labgen_transit.sh` (runs ON the traffic-source host, cron/systemd-timer)
- Create: `onboarding/panos/transit-traffic.md` (topology findings + setup runbook)

- [ ] **Step 1 (investigation — do this FIRST, it gates the design):** Map panosvm's dataplane

Via panos-mcp `get_pan_config` on `panosvm`: pull interfaces, zones, virtual-router routes,
and the 5 security rules' zone pairs. Via proxmox-mcp `get_vm_config(900)`: which bridges its
NICs sit on. Cross-check with SSDF's own tools (`mcp__ssdf-mcp-query__neighbors` on
`panosvm`) — dogfooding. Record findings in `onboarding/panos/transit-traffic.md`. Decision
output: a (source-host, destination, rule) triple where the flow transits two zones of
panosvm and matches a rule with `log-setting SSDF-LF`.

- [ ] **Step 2 (operator-gated): Place/confirm a traffic source**

Preferred: an EXISTING lab VM/LXC already on a panosvm-facing bridge (investigation step 1
tells us). Only if none exists: one minimal LXC on the inside bridge (operator approves
VMID/bridge — protected-VMID list applies). Mirror for the vSRX side only if vSRX transit
ever dries up (it currently has organic flows; don't build what exists).

- [ ] **Step 3: Write the generator**

`scripts/labgen_transit.sh` (exact dest/port filled from Step 1's runbook):

```bash
#!/usr/bin/env bash
# SSDF lab transit-traffic generator — keeps PAN-OS TRAFFIC logs flowing so the
# ingest pipeline is continuously live-proven. Install on the source host with:
#   systemd timer or cron: */15 * * * * /usr/local/bin/labgen_transit.sh
set -u
DEST="${LABGEN_DEST:?set LABGEN_DEST per onboarding/panos/transit-traffic.md}"
PORT="${LABGEN_PORT:-443}"
# TCP connect (logged on session end by PAN-OS) + ICMP, through panosvm.
timeout 5 bash -c "exec 3<>/dev/tcp/${DEST}/${PORT}" 2>/dev/null
ping -c 2 -W 2 "${DEST}" >/dev/null 2>&1
exit 0
```

- [ ] **Step 4 (live proof): TRAFFIC rows + provenance bridge**

After ≥2 timer fires:

```bash
clickhouse-client --host <ct104> ... --query \
  "SELECT event_action, observer_hostname, count() FROM ssdf.events
   WHERE event_provider='paloalto' AND event_category=['network'] AND timestamp > now() - INTERVAL 1 HOUR
   GROUP BY event_action, observer_hostname"
```

Expected: nonzero rows, `observer_hostname='panosvm.example.com'`. Then after a resolver
cycle (5 min), `explain_access(<source>, <dest>)` via the sovereign MCP →
`firewall_basis:provenance`, `firewalls:[panosvm]`, `coverage.configured ≥ 1`. **This
closes the last NOT-live-proven item in STATUS.md** (M6c-B PAN-OS suffix normalization).

- [ ] **Step 5: Commit**

```bash
git add scripts/labgen_transit.sh onboarding/panos/transit-traffic.md
git commit -m "feat(p2): lab transit-traffic generator; live-proves PAN-OS TRAFFIC + provenance bridge end-to-end"
```

### Task 5: ClickHouse backups via Proxmox vzdump

ct104 is the system of record with zero backup story (audit hash chains don't survive disk
loss). Secrets env files on ct102/106/109/113 are also unreproducible from the repo.

**Files:**
- Create: `scripts/apply_pve_backup_job.sh` (idempotent, same pattern as
  `apply_ct102_nftables.sh`)

- [ ] **Step 1 (investigation): Find backup-capable storage on pve3**

```bash
ssh root@pve3.example.com "pvesh get /storage --output-format json" | jq -r '.[] | select(.content|contains("backup")) | .storage'
```

Record the chosen storage id; script takes it as `PVE_BACKUP_STORAGE`.

- [ ] **Step 2: Write the job script**

`scripts/apply_pve_backup_job.sh`:

```bash
#!/usr/bin/env bash
# Idempotently create/update the SSDF backup job on the PVE cluster.
# Daily ct104 (ClickHouse, system of record) + weekly all SSDF LXCs (secrets/env files).
set -euo pipefail
PVE="${PVE_HOST_SSH:-root@pve3.example.com}"
STORAGE="${PVE_BACKUP_STORAGE:?set PVE_BACKUP_STORAGE (see plan Task 5 Step 1)}"
ensure_job() { # id vmids schedule keep
  local id="$1" vmids="$2" sched="$3" keep="$4"
  if ssh "$PVE" "pvesh get /cluster/backup/${id}" >/dev/null 2>&1; then
    ssh "$PVE" "pvesh set /cluster/backup/${id} --vmid '${vmids}' --schedule '${sched}' --storage '${STORAGE}' --mode snapshot --compress zstd --prune-backups '${keep}' --enabled 1"
  else
    ssh "$PVE" "pvesh create /cluster/backup --id '${id}' --vmid '${vmids}' --schedule '${sched}' --storage '${STORAGE}' --mode snapshot --compress zstd --prune-backups '${keep}' --enabled 1"
  fi
}
ensure_job ssdf-ch-daily   "104"                 "03:30"      "keep-daily=7,keep-weekly=4"
ensure_job ssdf-all-weekly "102,104,106,109,113" "sun 04:30"  "keep-weekly=4"
echo "Backup jobs applied. Verify: ssh $PVE 'pvesh get /cluster/backup'"
```

- [ ] **Step 3 (operator-gated): Apply + fire one backup now**

```bash
PVE_BACKUP_STORAGE=<id> ./scripts/apply_pve_backup_job.sh
ssh root@pve3.example.com "vzdump 104 --storage <id> --mode snapshot --compress zstd"
```

Expected: backup completes; `pvesh get /nodes/pve3/storage/<id>/content --content backup`
lists a ct104 archive. Restore drill (optional but recommended once): restore to a SCRATCH
VMID (`pct restore <free-vmid> <archive> --storage <rootfs-storage>`), confirm
`clickhouse-client --query "SELECT count() FROM ssdf.events"` inside it, then destroy the
scratch container (never touch ct104 itself).

- [ ] **Step 4: Document + commit**

Add to `CLAUDE.md` (new `### Ops` bullet): daily ct104 / weekly all-SSDF vzdump via
`scripts/apply_pve_backup_job.sh`, storage id in the gitignored ENV convention.

```bash
git add scripts/apply_pve_backup_job.sh CLAUDE.md
git commit -m "feat(p2): scheduled vzdump backups for SSDF LXCs (daily CH, weekly fleet)"
```

### Task 6: Fix doctrine drift in CLAUDE.md + STATUS.md forward roadmap

**Files:**
- Modify: `CLAUDE.md` (top sections), `docs/superpowers/STATUS.md` (forward roadmap)

- [ ] **Step 1: CLAUDE.md** — (a) delete the `> **Status: greenfield.**` notice; (b) rewrite
  "Stack & language split" to as-built: ingest = Vector (VRL), storage = ClickHouse, services
  + MCP layer = Python/FastMCP on Proxmox LXC; Rust is *permitted* for future
  performance-critical components, not doctrine (rust-junosmcp remains the external
  reference); (c) keep the sovereignty/AI-native/minimal principles and read-only boundary
  verbatim — those held.

- [ ] **Step 2: STATUS.md** — append to "Forward roadmap": **P2** (this batch, link this
  plan), **M8** evals, **M9** UniFi Suricata EVE, **M10** findings (charters below); restate
  "M6d stays deferred — ClickHouse-only still suffices."

- [ ] **Step 3: Commit**

```bash
git add CLAUDE.md docs/superpowers/STATUS.md
git commit -m "docs(p2): retire greenfield/Rust-core doctrine drift; record M8-M10 forward roadmap"
```

### Task 7: Finish branch

- [ ] Final review pass, then superpowers:finishing-a-development-branch → PR titled
  `P2: data-quality & ops batch (UTC timestamps, backups, transit traffic, doc drift)`,
  honest live findings in the description (per standing workflow).

---

# Phase 2 — M8: agent-eval harness (charter — spec required before build)

**Why first among the milestones:** it is the product metric. It will rank every later tool
investment better than intuition, so it precedes M9/M10 feature work.

**Charter (locked decisions + scope for the spec):**
- **Golden set:** 20–30 questions a SOC analyst would ask, in a versioned YAML/JSON corpus
  (`services/evals/golden/`), each with: question, expected answer (or checkable predicate
  against live CH), required tool(s), difficulty tag. Seed categories: reachability/policy
  ("can X reach Y, which rule"), flows ("top talkers yesterday" — exercises the UTC fix),
  topology ("where is MAC/IP Z"), change ("what config changed on panosvm this week"),
  honesty ("what do you NOT have data for" — refusal correctness).
- **Runners:** (1) Claude via Agent SDK bound to the real sovereign MCP endpoint
  (https + token, through the nginx edge — evals exercise prod auth);
  (2) a local Ollama tool-calling model on ct605's Ollama (model choice = spec question:
  needs function-calling quality; candidates qwen2.5/llama3.1-class).
- **Scoring:** deterministic predicate checks where possible; LLM-judge only for free-text;
  per-question allow/deny of tools observed via the `ssdf.audit` trail (audit doubles as the
  eval trace — no new instrumentation).
- **Output:** scorecard per model per run, committed as artifacts; regression gate = "no
  question that ever passed may silently fail."
- **Sovereignty proof:** the local-model run passing ≥ a defined floor IS the demonstrable
  "no cloud LLM is load-bearing" claim.
- **Spec questions to settle:** local model choice + MCP client harness for Ollama; pass
  thresholds; where the public-tier eval subset fits; run cadence (manual vs. timer).

# Phase 3 — M9: UniFi Suricata EVE ingest (charter — spec required)

- First **detection-class** source (IDS alerts), making `explain_access` answers materially
  richer ("allowed by rule R AND flagged by Suricata sig S").
- Pattern: same as M5 — UDM IPS/EVE events → Vector (new source, new port, H1 nftables
  allow-list extension for the UDM source IP, H2 known-device gate extension) → `ssdf.events`
  with `event_provider=unifi`, vendor extras under `unifi.ips.*`; alert category maps to ECS
  `event_kind=alert`.
- New data wrinkle (spec question): EVE is JSON not CSV/structured-syslog — likely the
  easiest parse yet; decide alert-only vs. also flows (UDM flow data may duplicate what
  firewalls already log — minimal principle says alerts only first).
- Classification: alerts are `security_log` (sovereign-only) — no M7 changes needed.
- Entity hook: alerts join to Assets by IP+segment (M6a identity rules apply); spec must
  decide whether alerts become edges (`FLAGGED_BY`) or stay query-side in `explain_access`.
- **Device clock must be verified UTC at onboarding** (P2 lesson, now standing requirement).
- Okta/identity is the *next* source after M9 — the identity class is still empty; keep it
  on the roadmap, don't let it slip twice.

# Phase 4 — M10: derived findings (charter — spec required, gated on M8)

- Scheduled correlation passes writing `kind=finding` entities (e.g., "asset contacted N
  new peers vs. 7-day baseline", "config commit followed by new flow pattern", "Suricata
  alert on an allowed flow") — the store stops being passive while the **read-only product
  boundary is untouched** (findings are derived data, not device actions).
- **Hard gate:** build only finding types that M8 evals show agents can't already derive
  cheaply from existing tools, and that M9's alert data makes meaningful. No speculative
  detection library — minimal principle.
- Findings are `security_log` class (sovereign-only) until proven otherwise.

# Explicitly NOT doing

- **M6d (Postgres-as-graph / multi-hop stitching):** stays deferred; no agent-visible benefit
  while ClickHouse suffices.
- More edge/infra hardening beyond the recorded out-of-scope follow-ups (cert renewal
  runbook is manual by design until leaves near expiry).
- New Rust components for their own sake (doctrine corrected in P2 Task 6).
