# vSRX fleet → consistent naming + SSDF onboarding

**Date:** 2026-06-25
**Status:** Design — pending user review, then implementation plan
**Repos/systems touched:** SSDF (`services/topo` collector + ct109 env), rust-junosmcp (`/etc/jmcp/devices.json` on ct601), Proxmox (VM names + power state on pve3)
**Driver:** ModelMeshSec's firewall-status dashboard showed only 2 firewalls because SSDF's topology inventory only had `vSRX-test10` + `panosvm`. Goal: get the whole vSRX fleet into SSDF, consistently named across all three systems.

## Goal

1. Make the SSDF junos topology collector **resilient** (one bad device must not blank the whole junos collection).
2. **Reconcile vSRX naming** so Proxmox VM name == rust-junosmcp device key == SSDF `JUNOS_DEVICES` entry, for every in-scope device.
3. **Boot, verify, and onboard** the in-scope vSRX fleet into SSDF topology (so the MMS dashboard reflects the real fleet).
4. **End state:** all in-scope vSRXs are consistently named and known to SSDF; **only the original 6 reachable devices are left running** (`vSRX-Production, test10, test11, test16, test17, test18`); everything else powered back down.

## Scope

**In-scope:** vSRX VMs **VMID 101–220** on pve3 (24 VMs). **Template VMID 301 (`vSRX-preprovisionedOutpost`) is NEVER touched.** Reserved VMIDs (100/301/500/600/601-604/605/900) untouched.

All 24 are already provisioned in rust-junosmcp `devices.json` with a mgmt IP (`198.51.100.220–.245`) + `netconf` user — so they are **configured-but-powered-off**, not blank. Booting should restore netconf reachability.

### Device classification (canonical = rust-junosmcp name)

| VMID | Proxmox name now | Canonical name | Mgmt IP | Role | Power |
|---|---|---|---|---|---|
| 101 | vSRX-test3 | vSRX-test3 | .220 | standalone | stopped |
| 103 | vSRX-Production | vSRX-Production | .222 | standalone | **running (keep)** |
| 105 | vSRXtwin | **vSRX-twin** (rename VM) | .223 | standalone | stopped |
| 107 | vSRX-mm-A | vSRX-mm-A | .242 | standalone | stopped |
| 108 | vSRX-mm-B | vSRX-mm-B | .243 | standalone | running, **unreachable** |
| 110 | vSRX-test1 | vSRX-test1 | .244 | standalone | stopped |
| 111 | vSRX-test4 | vSRX-test4 | .226 | standalone | stopped |
| 112 | vSRX-test2 | vSRX-test2 | .224 | standalone (16 GB) | stopped |
| 114 | CI-tester-vSRX | **vSRX-CI-tester** (rename VM) | .227 | standalone | stopped |
| 206 | vSRX-test6 | vSRX-test6 | .228 | standalone | stopped |
| 207 | vSRX-test7 | vSRX-test7 | .229 | standalone | stopped |
| 208 | vSRX-test8 | vSRX-test8 | .230 | standalone | stopped |
| 209 | vSRX-test9 | vSRX-test9 | .231 | standalone | stopped |
| 210 | vSRX-test10 | vSRX-test10 | .232 | standalone | **running (keep)** |
| 211 | vSRX-test11 | vSRX-test11 | .233 | standalone | **running (keep)** |
| 212 | vSRX-test12 | vSRX-test12 | .234 | standalone | stopped |
| 213 | mnha-router | **vSRX-mnha-router** (rename VM + MCP key) | .235 | standalone (BGP w/ Node1/2) | stopped |
| 214 | vSRX-Node1 | vSRX-Node1 | .236 | MNHA node (own firewall) | stopped |
| 215 | vSRX-Node2 | vSRX-Node2 | .237 | MNHA node (own firewall) | stopped |
| 216 | vSRX-test16 | vSRX-test16 | .238 | standalone | **running (keep)** |
| 217 | vSRX-test17 | vSRX-test17 | .239 | standalone | **running (keep)** |
| 218 | vSRX-test18 | vSRX-test18 | .240 | standalone | **running (keep)** |
| 219 | vSRX-test19 | (cluster member) | — | chassis-cluster node | stopped |
| 220 | vSRX-test20 | (cluster member) | — | chassis-cluster node | stopped |

**Chassis cluster:** VM 219 + VM 220 form **one logical firewall**, managed as `vSRX-test19-20` (.241). Boot **both** nodes; SSDF collects it as a single device via .241. The standalone `vSRX-test20` (.245) `devices.json` entry is **stale → remove it**.

**Totals:** 24 VMs → **23 logical firewalls** (22 standalone + 1 cluster). Resource: pve3 has **156 GB free**; the ~17 stopped VMs need **~76 GB** → staggered boot fits with headroom (pve1 is full; all these VMs are on pve3).

## Phases

### Phase A — Harden the SSDF junos collector
`services/topo/src/ssdf_topo/collectors/junos.py`. Today `collect()` loops devices with no per-device guard; `run_collectors` catches errors per *collector*, so one unreachable device blanks the **entire** junos collection (the reason only `vSRX-test10` is configured).

Change: wrap each device. Probe with the first command (`show lldp neighbors`); on connection/transport failure, **log + skip the device** (no inventory node → it correctly ages to "down" via stale `last_seen`, never falsely "up"). On success, **emit `firewall_inventory`** and run the remaining commands best-effort (each wrapped, failures logged, non-fatal). TDD with SSDF's pytest (`cd services/topo && uv run pytest -m "not integration"`); deploy to ct109 (rsync venv `/opt/ssdf-topo`, restart timer/oneshot).

### Phase B — Naming reconciliation (canonical = rust-junosmcp names)
- **Proxmox VM renames:** 105 `vSRXtwin → vSRX-twin`; 114 `CI-tester-vSRX → vSRX-CI-tester`; 213 `mnha-router → vSRX-mnha-router`. (`qm set <vmid> --name <new>`; VM must be stopped or it's fine live — name only.)
- **rust-junosmcp `devices.json` (ct601):** rename key `mnha-router → vSRX-mnha-router` (keep IP .235); **remove stale `vSRX-test20` (.245)**; keep `vSRX-test19-20` (.241) as the cluster. Hot-reload: `systemctl kill -s HUP rust-junosmcp.service`.
- **SSDF:** `JUNOS_DEVICES` (Phase D) uses these canonical names.
- All other names already match.

### Phase C — Boot + verify
Staggered power-on (e.g. 3–4 at a time) of the stopped in-scope VMs on pve3 (`qm start <vmid>`), waiting for Junos boot (~60–120 s). Per device, verify netconf reachability via rust-junosmcp (`execute_junos_command_batch` with `show lldp neighbors`, the exact collector probe). Classify each:
- **Reachable** → eligible for `JUNOS_DEVICES`.
- **Up but unreachable** (e.g. `vSRX-mm-B` at .243 `No route to host`) → **quarantine list** for individual fix-up (config audit: mgmt IP / fxp0 / netconf service); do NOT block the rest.
The cluster (219+220): boot both; verify the cluster mgmt IP .241 responds.

### Phase D — SSDF inventory + dashboard
Set ct109 `/etc/ssdf-topo/ENV.local` `JUNOS_DEVICES` to the **verified-reachable** canonical set (comma-separated). Trigger `ssdf-topo` oneshot (`systemctl start ssdf-topo.service`). Confirm new firewall-role nodes appear (`topology_snapshot(role=firewall)`), then confirm the **MMS dashboard count climbs** on its next 2-min poll (cache repopulates).

### Phase E — Settle
Power **down** every in-scope VM that is NOT one of the original 6 reachable (`vSRX-Production, test10, test11, test16, test17, test18`) via `qm shutdown <vmid>` (graceful). After power-down, those firewalls correctly read **"down"** on the dashboard (in inventory, stale `last_seen`). Leave `JUNOS_DEVICES` listing the full set (the hardened collector tolerates the now-offline ones — they just don't refresh). Final running set = the 6.

## Risks / notes
- **Collector hardening is a hard prerequisite for Phase D** — without it, listing any offline device in `JUNOS_DEVICES` blanks the whole junos collection. Phase A ships and is verified first.
- **HA representation:** Node1/Node2 = MNHA = two independent firewalls (two entries). `vSRX-mnha-router` (213) = a third standalone doing BGP with them. test19+test20 = chassis cluster = one logical firewall.
- **mm-B** is the known up-but-unreachable case; expect 1–N devices to land in the Phase C quarantine list needing manual config fix-up — that's variable-effort and may spill beyond this pass.
- **SSDF syslog ingest allow-list (H1, ct102 nftables) is `.220–.242`** — devices at `.243/.244/.245` (mm-B, test1, the stale test20) fall outside it, so their *syslog events* would be dropped. This does NOT affect the dashboard's up/connected (topology via netconf), only future `events_24h`. Out of scope here; note for a follow-up if event volume is wanted for those.
- **Boot storm:** staggered starts (3–4 at a time) to avoid CPU/IO spikes from many simultaneous Junos boots.
- **Reversibility:** renames are metadata; power changes are reversible. The only data change is `devices.json` (remove stale .245) — back it up first.

## Verification
- **Phase A:** new pytest proves a failing device is skipped and a reachable one still yields its inventory node; deployed collector run logs per-device skips without aborting.
- **Phase C:** per-device reachability table (reachable vs quarantine) captured.
- **Phase D:** `topology_snapshot(role=firewall)` node count + MMS dashboard `firewall_up_count` reflect the booted set.
- **Phase E:** final `qm list` shows exactly the 6 running; dashboard shows the rest as down.

## Out of scope
- Fixing every quarantined device's Junos config (tracked per-device as discovered).
- SSDF syslog ingest allow-list expansion for `.243+`.
- panosvm / UniFi (separate SSDF issues #26/#27).
