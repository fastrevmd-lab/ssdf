# vSRX fleet → consistent naming + SSDF onboarding — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax. **Tasks 1 is code (TDD).** **Tasks 2–6 are live infrastructure ops** — run them controller/human-driven, not via blind subagents; each VM action is reversible and gated by a verification step.

**Goal:** Harden the SSDF junos collector for per-device resilience, reconcile vSRX naming across Proxmox/rust-junosmcp/SSDF, boot+verify the VMID 101–220 fleet into SSDF topology, then settle back to the original 6 running.

**Architecture:** One SSDF code change (Phase A, the safety prerequisite) followed by four ordered live-ops phases (B naming, C boot+verify, D SSDF inventory, E settle). The hardened collector makes it safe to list offline devices in `JUNOS_DEVICES`.

**Tech Stack:** Python (SSDF `ssdf_topo`, uv + pytest), Proxmox `qm`/`pvesh`, rust-junosmcp (`devices.json`, systemd), SSDF systemd (`ssdf-topo` on ct109).

## Global Constraints

- **NEVER touch template VMID 301** (`vSRX-preprovisionedOutpost`) or any reserved VMID (100/301/500/600/601–604/605/900).
- Canonical name = **rust-junosmcp device key**; Proxmox VM name and SSDF `JUNOS_DEVICES` entry must match it exactly.
- **Phase A must ship and be verified before Phase D** — without per-device resilience, one offline device in `JUNOS_DEVICES` blanks the entire junos collection.
- **Original 6 reachable (final running set):** `vSRX-Production` (103), `vSRX-test10` (210), `vSRX-test11` (211), `vSRX-test16` (216), `vSRX-test17` (217), `vSRX-test18` (218).
- A device reads **"up"** on the dashboard only if SSDF freshly inventoried it (recent `last_seen`); never emit an inventory node for an unreachable device.
- All Proxmox/MCP/SSDF hosts reached via `ssh root@pve3.example.com` then `pct exec <ctid>` / `qm`. rust-junosmcp = **ct601** (`/etc/jmcp/devices.json`, reload `systemctl kill -s HUP rust-junosmcp.service`). ssdf-topo = **ct109** (`/etc/ssdf-topo/ENV.local`, venv `/opt/ssdf-topo`, `ssdf-topo.service` + `.timer`).

---

### Task 1: Harden the junos collector (per-device resilience) — SSDF code, TDD

**Files:**
- Modify: `services/topo/src/ssdf_topo/collectors/junos.py` (`JunosCollector.collect`, add `logging`)
- Test: `services/topo/tests/test_collector_junos.py` (add two tests)

**Interfaces:**
- Consumes: `parse_lldp_neighbors`, `parse_mac_table`, `parse_arp`, `firewall_inventory` (existing).
- Produces: `JunosCollector.collect(client, now)` that skips unreachable devices (no inventory node, no exception) and emits inventory + best-effort data for reachable ones.

- [ ] **Step 1: Write the failing tests**

Add to `services/topo/tests/test_collector_junos.py`:

```python
def test_collect_skips_unreachable_device_without_aborting():
    from ssdf_topo.collectors.junos import JunosCollector

    class _OneBadClient:
        """Reachable for every device except 'vSRX-bad', which raises (unreachable)."""
        def call_tool(self, name, args=None):
            if (args or {}).get("router_name") == "vSRX-bad":
                raise RuntimeError("connect failed: netconf transport error: No route to host")
            return ""

    obs = JunosCollector(["vSRX-test10", "vSRX-bad", "vSRX-test11"]).collect(_OneBadClient(), NOW)
    inv = {o.source_device for o in obs if o.observation_type == "device_inventory"}
    # The unreachable device is skipped entirely; the reachable ones still inventory.
    assert inv == {"vSRX-test10", "vSRX-test11"}


def test_collect_emits_inventory_when_secondary_command_fails():
    from ssdf_topo.collectors.junos import JunosCollector

    class _LldpOnlyClient:
        """Device is reachable (lldp ok) but rejects the other commands."""
        def call_tool(self, name, args=None):
            if (args or {}).get("command") == "show lldp neighbors":
                return ""
            raise RuntimeError("error: command is not valid on the mx/srx in this mode")

    obs = JunosCollector(["vSRX-test10"]).collect(_LldpOnlyClient(), NOW)
    inv = [o for o in obs if o.observation_type == "device_inventory"]
    # Reachable device is still recorded as a firewall despite the secondary failures.
    assert len(inv) == 1 and inv[0].source_device == "vSRX-test10"
```

- [ ] **Step 2: Run them to verify they fail**

Run: `cd services/topo && uv run pytest tests/test_collector_junos.py -k "unreachable or secondary" -v`
Expected: FAIL — current `collect()` calls `call_tool` unguarded, so the unreachable case raises out of `collect()` (no skip) and the secondary-fail case raises before `firewall_inventory`.

- [ ] **Step 3: Implement the hardened `collect()`**

In `services/topo/src/ssdf_topo/collectors/junos.py`, add near the top (after the existing imports):

```python
import logging

logger = logging.getLogger(__name__)
```

Replace the `collect` method body with:

```python
    def collect(self, client, now: str) -> list[Observation]:
        """Pull topology facts from each configured Junos device via the MCP client.

        Per-device resilient: a device that fails its first probe is logged and
        skipped (no inventory node -> it ages to 'down' via stale last_seen, never
        falsely 'up'). A reachable device is recorded as a firewall and its
        remaining commands run best-effort so one unsupported command can't drop it.
        """
        observations: list[Observation] = []
        for dev in self.devices:
            try:
                lldp_text = client.call_tool(
                    "execute_junos_command",
                    {"router_name": dev, "command": "show lldp neighbors"},
                )
            except Exception:
                logger.warning("junos device %r unreachable; skipping", dev, exc_info=True)
                continue

            # Reachable -> record as a firewall, then collect the rest best-effort.
            observations.append(firewall_inventory("junos", dev, now))
            observations.extend(parse_lldp_neighbors(lldp_text, dev, now))
            for cmd, parser in (
                ("show ethernet-switching table", parse_mac_table),
                ("show arp no-resolve", parse_arp),
            ):
                try:
                    text = client.call_tool(
                        "execute_junos_command", {"router_name": dev, "command": cmd}
                    )
                    observations.extend(parser(text, dev, now))
                except Exception:
                    logger.warning(
                        "junos %r: command %r failed; continuing", dev, cmd, exc_info=True
                    )
        return observations
```

- [ ] **Step 4: Run the full junos test file to verify pass (incl. the pre-existing inventory test)**

Run: `cd services/topo && uv run pytest tests/test_collector_junos.py -v`
Expected: PASS — the two new tests pass AND the existing `test_collect_emits_firewall_inventory_per_device` (both devices reachable via `_EmptyClient`) still passes (both get inventory).

- [ ] **Step 5: Run the non-integration topo suite (no regressions)**

Run: `cd services/topo && uv run pytest -m "not integration" -q`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add services/topo/src/ssdf_topo/collectors/junos.py services/topo/tests/test_collector_junos.py
git commit -m "fix(topo): per-device resilience in junos collector (skip unreachable, best-effort commands)"
```

---

### Task 2: Deploy the hardened collector to ct109 + live-verify resilience

**Files:** none (deploy + verification of Task 1's code on ct109).

- [ ] **Step 1: Sync the collector source to ct109's venv**

The topo service runs from `/opt/ssdf-topo` on ct109. Push the updated `services/topo` (rsync to pve3 then into the container, mirroring the established health/topo deploy):

Run:
```bash
rsync -a --delete ~/SSDF/services/topo/src/ssdf_topo/ root@pve3.example.com:/tmp/ssdf_topo_src/
ssh root@pve3.example.com 'tar -C /tmp -czf /tmp/ssdf_topo_src.tgz ssdf_topo_src && pct push 109 /tmp/ssdf_topo_src.tgz /tmp/ssdf_topo_src.tgz && pct exec 109 -- bash -lc "tar -C /opt/ssdf-topo/lib/python*/site-packages/ -xzf /tmp/ssdf_topo_src.tgz --strip-components=1 -C /opt/ssdf-topo 2>/dev/null || true"'
```
Expected: files land. **Verify the actual install layout first** (`pct exec 109 -- bash -lc "pip show -f ssdf-topo 2>/dev/null | grep Location; ls /opt/ssdf-topo"`) and adjust the target path — if it's an editable install (`pip install -e`), sync into the source checkout dir instead. (Implementer confirms the install mode before copying.)

- [ ] **Step 2: Trigger a one-shot collection and watch the log**

Run:
```bash
ssh root@pve3.example.com 'pct exec 109 -- systemctl start ssdf-topo.service; sleep 20; pct exec 109 -- journalctl -u ssdf-topo.service -n 30 --no-pager'
```
Expected: `collect_all: inserted N observations` with no traceback; for the current `JUNOS_DEVICES=vSRX-test10` it still inserts test10's data.

- [ ] **Step 3: Resilience smoke test — add one known-unreachable device temporarily**

Temporarily append an unreachable name and confirm collection still succeeds for the good device:
```bash
ssh root@pve3.example.com 'pct exec 109 -- bash -lc "
  cp /etc/ssdf-topo/ENV.local /etc/ssdf-topo/ENV.local.bak
  sed -i \"s/^JUNOS_DEVICES=.*/JUNOS_DEVICES=vSRX-test10,vSRX-bad-nonexistent/\" /etc/ssdf-topo/ENV.local
  systemctl start ssdf-topo.service; sleep 25
  journalctl -u ssdf-topo.service -n 20 --no-pager | grep -iE \"unreachable|inserted\"
  mv /etc/ssdf-topo/ENV.local.bak /etc/ssdf-topo/ENV.local
"'
```
Expected: a `junos device 'vSRX-bad-nonexistent' unreachable; skipping` warning AND a non-zero `inserted` count (test10 still collected) — proving one bad device no longer blanks the run. Env restored.

- [ ] **Step 4: Record** the deploy + smoke-test output in the run notes. No commit (deploy step).

---

### Task 3: Naming reconciliation across Proxmox + rust-junosmcp

**Files:** none in-repo (live config: Proxmox VM names, ct601 `devices.json`).

**Canonical renames:** `105 vSRXtwin → vSRX-twin`, `114 CI-tester-vSRX → vSRX-CI-tester`, `213 mnha-router → vSRX-mnha-router`. **devices.json:** rename key `mnha-router → vSRX-mnha-router` (keep IP .235); **remove stale `vSRX-test20` (.245)** (keep `vSRX-test19-20` .241 as the cluster).

- [ ] **Step 1: Back up devices.json**

Run: `ssh root@pve3.example.com 'pct exec 601 -- cp -a /etc/jmcp/devices.json /etc/jmcp/devices.json.bak.$(date +%Y%m%d-%H%M%S)'`
Expected: backup created.

- [ ] **Step 2: Rename the three Proxmox VMs (name metadata only; safe while stopped or running)**

Run:
```bash
ssh root@pve3.example.com '
  qm set 105 --name vSRX-twin
  qm set 114 --name vSRX-CI-tester
  qm set 213 --name vSRX-mnha-router
'
```
Expected: each prints `update VM <id>: -name ...`. Verify: `qm config 105 | grep name` → `name: vSRX-twin` (repeat 114, 213).

- [ ] **Step 3: Edit devices.json — rename mnha key, remove stale .245**

In ct601 `/etc/jmcp/devices.json`: change the `"mnha-router"` key to `"vSRX-mnha-router"` (value unchanged, IP .235); delete the `"vSRX-test20"` (.245) entry. Use a precise edit (jq if present, else a verified manual edit). Validate JSON:
```bash
ssh root@pve3.example.com 'pct exec 601 -- python3 -c "import json; d=json.load(open(\"/etc/jmcp/devices.json\")); ks=d.get(\"devices\",d).keys(); assert \"vSRX-mnha-router\" in ks and \"mnha-router\" not in ks and \"vSRX-test20\" not in ks; print(\"ok\", len(ks))"'
```
Expected: `ok 23` (24 → 23 after removing stale .245).

- [ ] **Step 4: Hot-reload rust-junosmcp + confirm the new name resolves**

Run: `ssh root@pve3.example.com 'pct exec 601 -- systemctl kill -s HUP rust-junosmcp.service'`
Then verify via the MCP `get_router_list` that `vSRX-mnha-router` is present and `mnha-router`/`vSRX-test20` are gone.
Expected: list reflects the renames.

---

### Task 4: Staggered boot + per-device reachability verification

**Files:** none (live ops + a captured reachability table).

**Boot set (17 stopped in-scope):** `101,105,107,110,111,112,114,206,207,208,209,212,213,214,215,219,220`. (`108 mm-B` is already running-but-unreachable → goes straight to the quarantine list.)

- [ ] **Step 1: Staggered power-on (≤4 at a time, ~90 s apart) to avoid a boot storm**

Run, in batches (wait ~90 s between batches for Junos to boot):
```bash
ssh root@pve3.example.com 'for vmid in 101 105 107 110; do qm start $vmid; done'   # batch 1
# wait ~90s, then batch 2: 111 112 114 206 ; batch 3: 207 208 209 212 ;
# batch 4: 213 214 215 219 ; batch 5: 220
```
Expected: each `qm start` returns without error. Verify all started: `qm list | grep -E "running"` includes the booted VMIDs.

- [ ] **Step 2: Wait for Junos to finish booting, then probe reachability**

After the last batch, wait ~3 min, then probe every in-scope canonical device with the exact collector command via rust-junosmcp (`execute_junos_command_batch`, command `show lldp neighbors`, `command_timeout: 25`). Probe the full canonical set (standalones + `vSRX-test19-20` cluster IP). Capture per-router `ok: true/false`.

Expected output: a reachability table — each device `ok` (reachable) or `error` (quarantine). The cluster `vSRX-test19-20` (.241) should respond once both 219+220 are up and clustered.

- [ ] **Step 3: Build the reachable + quarantine lists**

From Step 2, write two lists:
- **REACHABLE** → goes into `JUNOS_DEVICES` (Task 5).
- **QUARANTINE** (e.g. `vSRX-mm-B`, plus any booted-but-not-responding) → recorded with its error for individual config fix-up (out of scope to fix here; tracked).

Expected: explicit lists captured in run notes. Do not let quarantined devices block Task 5.

---

### Task 5: Set SSDF `JUNOS_DEVICES` + verify topology and the MMS dashboard

**Files:** none (ct109 env + verification).

- [ ] **Step 1: Set `JUNOS_DEVICES` to the REACHABLE canonical set**

On ct109, set `/etc/ssdf-topo/ENV.local` `JUNOS_DEVICES=` to the comma-separated REACHABLE list from Task 4 (canonical names, including `vSRX-test19-20` if the cluster responded). Back up first:
```bash
ssh root@pve3.example.com 'pct exec 109 -- cp -a /etc/ssdf-topo/ENV.local /etc/ssdf-topo/ENV.local.bak.$(date +%Y%m%d-%H%M%S)'
```
Then edit the `JUNOS_DEVICES=` line. Verify: `pct exec 109 -- grep JUNOS_DEVICES /etc/ssdf-topo/ENV.local`.

- [ ] **Step 2: Trigger collection + confirm firewall nodes**

Run: `ssh root@pve3.example.com 'pct exec 109 -- systemctl start ssdf-topo.service; sleep 30; pct exec 109 -- journalctl -u ssdf-topo.service -n 25 --no-pager | grep -iE "inserted|unreachable"'`
Expected: `inserted N observations`; any unreachable devices logged-and-skipped (not fatal).

- [ ] **Step 3: Verify SSDF topology node count**

Query SSDF via the MMS-registered `ssdf-mcp-query` `topology_snapshot(role=firewall, kind=device)` (or directly on ct104 CH if creds available): node count == number of REACHABLE devices.
Expected: firewall-role node count matches the reachable set.

- [ ] **Step 4: Verify the MMS dashboard count climbs**

The MMS poller refreshes every 2 min. After one cycle, query the MMS cache on LXC 400:
```bash
ssh root@pve3.example.com 'pct exec 400 -- bash -lc "DBURL=\$(grep -E ^DATABASE_URL= /opt/ModelMeshSec/.env | cut -d= -f2-); psql \"\$DBURL\" -A -F\"|\" -c \"SET app.current_tenant_id=\047\047 || true\"" ' # (use the tenant-scoped query pattern established earlier)
```
Expected: `dashboard_firewall_status` row count == reachable count; the **Firewall Connectivity Status** dashboard shows the new FIREWALLS UP / TOTAL. (Open it in the UI to confirm visually.)

---

### Task 6: Settle — power down all but the original 6

**Files:** none (live ops + final verification).

- [ ] **Step 1: Graceful shutdown of every in-scope VM that is NOT one of the 6**

Keep running: `103, 210, 211, 216, 217, 218`. Shut down the rest of the in-scope booted set:
```bash
ssh root@pve3.example.com 'for vmid in 101 105 107 108 110 111 112 114 206 207 208 209 212 213 214 215 219 220; do qm shutdown $vmid --timeout 90 || qm stop $vmid; done'
```
Expected: each shuts down (Junos may ignore ACPI; the `|| qm stop` hard-stops after the 90 s timeout). Verify: `qm list` shows only the 6 in-scope VMs running (plus unrelated infra).

- [ ] **Step 2: Confirm final running set**

Run: `ssh root@pve3.example.com 'qm list | grep -iE "vsrx|mnha" | grep running'`
Expected: exactly `103 vSRX-Production, 210 vSRX-test10, 211 vSRX-test11, 216 vSRX-test16, 217 vSRX-test17, 218 vSRX-test18`.

- [ ] **Step 3: Verify the dashboard now shows the powered-down firewalls as "down"**

`JUNOS_DEVICES` still lists the full reachable set, so on the next poll the now-offline devices have a stale `last_seen` → `is_up=false`. Confirm in the MMS cache + UI:
Expected: `dashboard_firewall_status` still has all the devices, with `is_up=true` for the 6 and `is_up=false` for the rest. The dashboard's "FIREWALLS UP" == 6, "TOTAL" == the full inventoried count.

- [ ] **Step 4: Record final state + quarantine list** in the run notes (and as an SSDF issue if devices need config fix-up).

---

## Self-Review

**Spec coverage:** Phase A → Task 1 (code) + Task 2 (deploy/verify) ✓; Phase B → Task 3 ✓; Phase C → Task 4 ✓; Phase D → Task 5 ✓; Phase E → Task 6 ✓. Resilience-before-inventory ordering enforced (Task 1/2 precede Task 5). Naming canonical = MCP key ✓. Template 301 never referenced in any boot/rename/shutdown list ✓ (verified: 301 absent from all VMID lists). Original-6 final set consistent across Global Constraints + Task 6 ✓.

**Placeholder scan:** no TBD/TODO. Two implementer-verify notes are explicit (Task 2 Step 1 install-layout confirmation; Task 5 Step 4 reuse the established tenant-scoped psql pattern) — these are real "confirm against the live system" instructions, not vague placeholders.

**Consistency:** device VMID↔name↔IP map matches the spec's classification table; boot set (Task 4) and shutdown set (Task 6) are complementary about the 6 keepers; `vSRX-mnha-router`/`vSRX-twin`/`vSRX-CI-tester` rename names identical in Tasks 3 and the constraints.

**Note:** Tasks 2–6 mutate live infrastructure (VM power, names, device inventory). They are reversible (renames are metadata; power is reversible; the only data deletion is the stale `.245` entry, backed up in Task 3 Step 1). Execute controller/human-driven with the per-task verification gates — not as unattended subagents.
