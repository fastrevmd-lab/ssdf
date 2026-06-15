# SRX + PAN-OS Live Transit Sources Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make vm103 (Junos vSRX "ProductionSRX") and panosvm (PAN-OS 12.1.5) live, continuously-ingesting SSDF transit sources by placing one Alpine LXC endpoint behind each firewall and running a shared traffic generator that produces permitted internet egress plus deliberate denied DNS attempts.

**Architecture:** Source-onboarding + lab infra ONLY — SSDF's read-only data path is unchanged (Vector `srx_ecs`/`panos_ecs` VRL and both deny paths already exist; no schema or MCP-tool change). Each firewall has an untrust leg on the flat LAN (`198.51.100.0/24` over vmbr0) and a trust leg on a Proxmox-only VLAN over vmbr1 whose tag matches the endpoint CTID (ct198→VLAN 198 `10.74.12.0/24`, ct199→VLAN 199 `10.74.11.0/24`). Firewall configs are applied via the external vendor MCPs (rust-junosmcp / panos-mcp), never by SSDF. ct115 is retired.

**Tech Stack:** Proxmox (pct/qm, proxmox-mcp), UniFi MCP (DHCP reservations), rust-junosmcp (Junos set-config), panos-mcp (PAN-OS config), Vector VRL (verify only), ClickHouse (verify), bash (the generator), Alpine/OpenRC.

**Reference spec:** `docs/superpowers/specs/2026-06-14-ssdf-srx-panos-live-transit-sources-design.md`

**Standing constraints (read before starting):**
- NEVER touch protected VMIDs (`~/.claude/CLAUDE.md`): 500, 600, 601–604, 100/301, 900-config-only-as-approved, 105/110/112 are stopped vSRX twins — leave them. ct198/ct199 are new and free; ct115 is the only deletion (approved).
- Firewall changes to vm103 and panosvm are operator-approved. PAN-OS changes MUST be previewed with `pan_config_diff` before `load_and_commit_pan_config`.
- All `qm`/`pct` ops run as `ssh root@pve3.example.com`.

---

## File Structure

| File | Responsibility | Action |
|---|---|---|
| `scripts/labgen_endpoint.sh` | Shared continuous traffic daemon (permit egress + denied DNS); env-tunable; dryrun self-test | Create |
| `scripts/labgen_endpoint_test.sh` | Dryrun + shellcheck guard for the generator | Create |
| `scripts/labgen_transit.sh` | Old single-shot ct115 generator | Delete (Task 11) |
| `onboarding/srx/transit-endpoint.md` | Runbook: vm103 live config + ct198 + generator | Create |
| `onboarding/panos/transit-traffic.md` | Old ct115 runbook | Rewrite → ct199 endpoint runbook |
| `infra/firewall/ct102-ingest.nft` | Ingest allow-list | No change (`.240` already in `.220–.242`; verify only) |
| `CLAUDE.md`, `docs/superpowers/STATUS.md` | As-built record | Append (Task 11) |

No SSDF service code, schema, or Vector transform changes.

---

## Task 1: Feature branch

**Files:** none (git only)

- [ ] **Step 1: Create and switch to the feature branch**

```bash
cd /home/mharman/SSDF
git checkout main && git pull --ff-only
git checkout -b m-srx-panos-live-transit
git status
```

Expected: `On branch m-srx-panos-live-transit`, clean tree (the spec commit `77d0db9` is already on main).

---

## Task 2: Traffic generator script (`labgen_endpoint.sh`)

**Files:**
- Create: `scripts/labgen_endpoint.sh`
- Create (test): `scripts/labgen_endpoint_test.sh`

- [ ] **Step 1: Write the failing test**

Create `scripts/labgen_endpoint_test.sh`:

```bash
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
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `bash scripts/labgen_endpoint_test.sh`
Expected: `FAIL: dryrun exited non-zero` (script does not exist yet).

- [ ] **Step 3: Write the generator**

Create `scripts/labgen_endpoint.sh`:

```bash
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
```

- [ ] **Step 4: Make both executable and run the test to verify it passes**

```bash
chmod 0755 scripts/labgen_endpoint.sh scripts/labgen_endpoint_test.sh
bash scripts/labgen_endpoint_test.sh
```

Expected: `PASS` (4 DRYRUN lines matched; shellcheck clean if installed).

- [ ] **Step 5: Commit**

```bash
git add scripts/labgen_endpoint.sh scripts/labgen_endpoint_test.sh
git commit -m "feat(lab): shared endpoint traffic generator (permit egress + denied DNS)"
```

---

## Task 3: Build Alpine endpoints ct198 + ct199

**Files:** none (Proxmox infra). Records values used by Task 5/6/7.

- [ ] **Step 1: Confirm template + VMIDs are free cluster-wide**

```bash
ssh root@pve3.example.com 'pvesh get /cluster/resources --type vm --output-format json | grep -oE "\"vmid\":(198|199|115)" ; echo "---templates---"; pveam list local | grep alpine'
```

Expected: NO match for 198/199 (free); 115 present (ct115, to be retired later). An `alpine-3.22-*amd64.tar.xz` template is listed. If 198/199 collide, STOP and escalate (do not reuse a live VMID).

- [ ] **Step 2: Create ct198 (behind SRX, VLAN 198) and ct199 (behind PAN-OS, VLAN 199)**

```bash
ssh root@pve3.example.com 'pct create 198 local:vztmpl/alpine-3.22-default_20250617_amd64.tar.xz \
  --hostname ssdf-ep-srx --unprivileged 1 --cores 1 --memory 128 --swap 0 \
  --rootfs local-lvm:1 \
  --net0 name=eth0,bridge=vmbr1,tag=198,ip=10.74.12.20/24,gw=10.74.12.1 \
  --onboot 1 --start 1'

ssh root@pve3.example.com 'pct create 199 local:vztmpl/alpine-3.22-default_20250617_amd64.tar.xz \
  --hostname ssdf-ep-panos --unprivileged 1 --cores 1 --memory 128 --swap 0 \
  --rootfs local-lvm:1 \
  --net0 name=eth0,bridge=vmbr1,tag=199,ip=10.74.11.20/24,gw=10.74.11.1 \
  --onboot 1 --start 1'
```

Expected: each prints `extracting archive ...` then the container starts. (Gateways `.1` are the firewall trust interfaces, configured in Tasks 6/7 — endpoints come up now but have no upstream until then.)

- [ ] **Step 3: Install generator deps on both endpoints**

```bash
for c in 198 199; do
  ssh root@pve3.example.com "pct exec $c -- sh -c 'echo nameserver 198.51.100.1 > /etc/resolv.conf && apk add --no-cache bash curl bind-tools'"
done
```

Expected: `OK: N MiB ...` apk success on both. (DNS resolver is an allowed one so apk works once the firewall is up; if Task 6/7 are not yet applied this may fail — re-run after the firewalls are live.)

- [ ] **Step 4: Commit a checkpoint note (no repo files changed yet — skip if nothing to stage)**

No file change in this task; proceed to Task 4. (Container build is recorded in the runbook in Task 11.)

---

## Task 4: Map vm103 vNICs and add it to rust-junosmcp

**Files:** none (reads/edits live MCP inventory on ct601). Records the ge-0/0/0 vNIC MAC for Task 5.

- [ ] **Step 1: Read vm103's current NIC layout**

```bash
ssh root@pve3.example.com 'qm config 103 | grep -E "^net[0-9]+:"'
```

Expected: one or more `netN: virtio=<MAC>,bridge=vmbr0...` lines. Record which `netN` is on **vmbr0** (untrust/LAN candidate) and its MAC. vSRX maps vNICs in order: `net0`→fxp0 (mgmt), `net1`→ge-0/0/0, `net2`→ge-0/0/1, ... — but this MUST be verified on the device (Step 4), not assumed.

- [ ] **Step 2: Ensure vm103 has a trust vNIC on vmbr1 tag 198 (add if missing)**

If no `netN` is on `vmbr1,tag=198`, add the next free index (example uses net2):

```bash
ssh root@pve3.example.com 'qm set 103 -net2 virtio,bridge=vmbr1,tag=198'
ssh root@pve3.example.com 'qm config 103 | grep -E "^net[0-9]+:"'
```

Expected: a `net2: virtio=<MAC>,bridge=vmbr1,tag=198` line now present. Record this MAC as the **trust** vNIC. (A vSRX may need a reboot to detect a hot-added vNIC — if Step 4 does not show the new ge interface, `qm reboot 103` and re-check.)

- [ ] **Step 3: Add vm103 to rust-junosmcp devices.json on ct601 and hot-reload**

vm103 is reachable today on fxp0 lease `198.51.100.222` (hostname `vSRX-A`). Append an entry mirroring the existing devices (user `netconf`, key `/etc/jmcp/id_ed25519`):

```bash
ssh root@pve3.example.com 'pct exec 601 -- sh -c '"'"'
python3 - <<PY
import json,io
p="/etc/jmcp/devices.json"
d=json.load(open(p))
d["vm103-srx"]={"host":"198.51.100.222","port":22,"username":"netconf","ssh_key":"/etc/jmcp/id_ed25519"}
json.dump(d,open(p,"w"),indent=2)
print("devices now:",list(d))
PY
'"'"''
ssh root@pve3.example.com 'pct exec 601 -- systemctl kill -s HUP rust-junosmcp.service'
```

Expected: `devices now: [..., 'vm103-srx']`. (Confirm the exact key path `/etc/jmcp/devices.json` and key filename first with `pct exec 601 -- ls /etc/jmcp`; adjust if different. Do not change other devices.)

- [ ] **Step 4: Verify reachability + interface mapping via the MCP**

Use the rust-junosmcp tool `get_router_list` to confirm `vm103-srx` appears, then `execute_junos_command(router_name="vm103-srx", command="show interfaces terse")`.

Expected: `ge-0/0/0` and `ge-0/0/1` are listed. Correlate each ge interface's MAC (`show interfaces ge-0/0/0 | match "Hardware|Current address"`) to the vmbr0 vNIC MAC (Step 1) and the vmbr1-tag198 vNIC MAC (Step 2). Record the verified mapping: **ge-0/0/0 = untrust (vmbr0)**, **ge-0/0/1 = trust (vmbr1 tag 198)**. If the order is reversed, swap the interface names used in Task 6 accordingly.

- [ ] **Step 5: Commit the rust-junosmcp note (no repo change here)**

No repo files changed; the device addition lives on ct601. Proceed to Task 5.

---

## Task 5: UniFi DHCP reservations (untrust LAN)

**Files:** none (UniFi MCP). site_id = `00000000-0000-4000-8000-000000000001`.

- [ ] **Step 1: Reserve `198.51.100.240` for the SRX ge-0/0/0 (untrust) vNIC**

Use the verified vmbr0 vNIC MAC from Task 4 Step 1 (call it `<SRX_GE000_MAC>`). Call `mcp__unifi-mcp__create_dhcp_reservation` with `site_id`, `mac=<SRX_GE000_MAC>`, `fixed_ip=198.51.100.240`, name `vm103-srx-untrust`.

Expected: reservation created. `.240` is inside the nft band `.220–.242` so SRX syslog will be accepted with no nft change.

- [ ] **Step 2: Confirm panosvm eth1/1 (untrust) MAC**

```bash
ssh root@pve3.example.com 'qm config 900 | grep -E "^net1:"'
```

Expected: `net1: virtio=02:01:01:48:9D:D3,bridge=vmbr0,...` (the eth1/1 untrust NIC). Record the MAC (`<PANOS_ETH11_MAC>`). If it differs from `02:01:01:48:9d:d3`, use the actual value.

- [ ] **Step 3: Repoint the `.210` reservation from the phantom to panosvm eth1/1**

The `.210` reservation (id `697c22106befbd1dbd2cc4f1`, name `OnpremSD`) currently points to a not-present MAC `02:01:01:f0:d6:a5`. Delete it and create the correct one:

```
mcp__unifi-mcp__remove_dhcp_reservation(site_id, reservation_id="697c22106befbd1dbd2cc4f1")
mcp__unifi-mcp__create_dhcp_reservation(site_id, mac=<PANOS_ETH11_MAC>, fixed_ip="198.51.100.210", name="panosvm-untrust")
```

Expected: old reservation gone, new one bound to `<PANOS_ETH11_MAC>`. Verify with `mcp__unifi-mcp__list_dhcp_reservations(site_id)` → `.210` now maps to the panosvm MAC, `.240` maps to the SRX MAC.

- [ ] **Step 4: No repo change — proceed to Task 6.**

---

## Task 6: Configure vm103 SRX live (via rust-junosmcp)

**Files:** none (applies set-config to the device). Uses the verified interface mapping from Task 4 Step 4 (this plan assumes ge-0/0/0=untrust, ge-0/0/1=trust; swap if Task 4 found otherwise).

- [ ] **Step 1: Verify the device clock is UTC**

`execute_junos_command(router_name="vm103-srx", command="show system uptime")`.

Expected: `Current time: ... UTC`. If NOT UTC, STOP — SSDF parses SRX syslog as naive UTC. Junos defaults UTC when `system time-zone` is unset; if a non-UTC zone is set, `delete system time-zone` and commit before continuing (record this).

- [ ] **Step 2: Stage the live config (interfaces, zones, NAT, strict-DNS policy, syslog)**

Apply this set-config via rust-junosmcp `load_and_commit_config` (router `vm103-srx`). It mirrors `onboarding/srx/stream-config.set` for the stream part and adds the transit + strict-DNS policy:

```
set interfaces ge-0/0/0 unit 0 family inet address 198.51.100.240/24
set interfaces ge-0/0/1 unit 0 family inet address 10.74.12.1/24
set routing-options static route 0.0.0.0/0 next-hop 198.51.100.1
set security zones security-zone untrust interfaces ge-0/0/0.0
set security zones security-zone trust interfaces ge-0/0/1.0 host-inbound-traffic system-services ping
set security zones security-zone trust interfaces ge-0/0/1.0 host-inbound-traffic system-services dns
set security nat source rule-set trust-to-untrust from zone trust
set security nat source rule-set trust-to-untrust to zone untrust
set security nat source rule-set trust-to-untrust rule snat-egress match source-address 10.74.12.0/24
set security nat source rule-set trust-to-untrust rule snat-egress then source-nat interface
set security address-book global address dns-cloudflare-1 1.1.1.2/32
set security address-book global address dns-cloudflare-2 1.0.0.2/32
set security address-book global address dns-gateway 198.51.100.1/32
set security address-book global address-set dns-allowed address dns-cloudflare-1
set security address-book global address-set dns-allowed address dns-cloudflare-2
set security address-book global address-set dns-allowed address dns-gateway
set applications application-set web-set application junos-https
set applications application-set web-set application junos-http
set security policies from-zone trust to-zone untrust policy allow-dns match source-address any destination-address dns-allowed application junos-dns-udp
set security policies from-zone trust to-zone untrust policy allow-dns match application junos-dns-tcp
set security policies from-zone trust to-zone untrust policy allow-dns then permit
set security policies from-zone trust to-zone untrust policy allow-dns then log session-close
set security policies from-zone trust to-zone untrust policy allow-web match source-address any destination-address any application web-set
set security policies from-zone trust to-zone untrust policy allow-web then permit
set security policies from-zone trust to-zone untrust policy allow-web then log session-close
set security policies from-zone trust to-zone untrust policy allow-icmp match source-address any destination-address any application junos-icmp-all
set security policies from-zone trust to-zone untrust policy allow-icmp then permit
set security policies from-zone trust to-zone untrust policy allow-icmp then log session-close
set security policies from-zone trust to-zone untrust policy deny-rest match source-address any destination-address any application any
set security policies from-zone trust to-zone untrust policy deny-rest then deny
set security policies from-zone trust to-zone untrust policy deny-rest then log session-init
set security log mode stream
set security log source-address 198.51.100.240
set security log stream SSDF format sd-syslog
set security log stream SSDF category all
set security log stream SSDF severity info
set security log stream SSDF host 198.51.100.150 port 514
```

Note the policy ORDER matters (Junos evaluates top-down): `allow-dns` before `deny-rest`. The denied 8.8.8.8 lookups fall to `deny-rest` → `RT_FLOW_SESSION_DENY` (already mapped to `flow_session_deny` in `srx_ecs`). `junos-dns-udp` only matches the three allowed resolvers via the destination address-set; 8.8.8.8 is not in the set so it never matches `allow-dns`.

- [ ] **Step 3: Preview the diff, then commit**

Use rust-junosmcp `junos_config_diff` (router `vm103-srx`) to preview, then `load_and_commit_config`.

Expected: diff shows the new interfaces/zones/nat/policies/log stanza; commit returns `commit complete`. If the diff shows it changing the fxp0/mgmt address or removing existing config, STOP and escalate.

- [ ] **Step 4: Verify interfaces and policy compiled**

```
execute_junos_command(router_name="vm103-srx", command="show interfaces ge-0/0/0.0 terse")   # 198.51.100.240/24
execute_junos_command(router_name="vm103-srx", command="show interfaces ge-0/0/1.0 terse")   # 10.74.12.1/24
execute_junos_command(router_name="vm103-srx", command="show security policies from-zone trust to-zone untrust")
```

Expected: both interfaces `up/up` with the right addresses; four policies listed in order allow-dns, allow-web, allow-icmp, deny-rest.

- [ ] **Step 5: No repo change — proceed to Task 7.**

---

## Task 7: Configure panosvm strict-DNS policy + re-tag trust VLAN

**Files:** none (PAN-OS config via panos-mcp; Proxmox NIC re-tag via qm). PAN-OS device host = `panosvm` (see panos-mcp `list_devices`).

- [ ] **Step 1: Re-tag the panosvm trust NIC on Proxmox from VLAN 103 → 199**

```bash
ssh root@pve3.example.com 'qm config 900 | grep -E "^net2:"'   # current: bridge=vmbr1,tag=103 (eth1/2 trust)
ssh root@pve3.example.com 'qm set 900 -net2 virtio=<PANOS_ETH12_MAC>,bridge=vmbr1,tag=199'
ssh root@pve3.example.com 'qm config 900 | grep -E "^net2:"'   # now tag=199
```

Use the existing eth1/2 MAC from the first `grep` for `<PANOS_ETH12_MAC>` (keep the same MAC; only the tag changes). PAN-OS keeps `10.74.11.1/24` — only the L2 tag moves so it shares VLAN 199 with ct199. (ct199 was already created on tag 199 in Task 3.)

- [ ] **Step 2: Preview the PAN-OS strict-DNS policy diff**

Apply (via panos-mcp, previewed with `pan_config_diff` first) a security rule set on vsys1 that permits DNS only to the three resolvers, permits web/ICMP, and denies+logs the rest, all with `log-end` and `log-setting SSDF-LF` (the existing log profile). Add an address group `dns-allowed` = {198.51.100.1, 1.1.1.2, 1.0.0.2} and place the DNS-allow rule ABOVE the existing broad `drifttest1`/`allow-trust-to-untrust` rules, and a `deny-dns-other` rule that denies service `application-default` DNS to non-allowed destinations, also above the broad allow. Concretely, render and preview:

```
mcp__panos-mcp__get_pan_config(host="panosvm", xpath="/config/devices/entry/vsys/entry[@name='vsys1']/rulebase/security")
# build: address dns-gw/dns-cf1/dns-cf2; address-group dns-allowed;
# rule allow-dns-ok (from trust to untrust, dest dns-allowed, app dns, action allow, log-end, log-setting SSDF-LF)
# rule deny-dns-other (from trust to untrust, app dns, action deny, log-end, log-setting SSDF-LF)
mcp__panos-mcp__pan_config_diff(host="panosvm", ...candidate...)
```

Expected: diff adds the two DNS rules + address objects ABOVE the existing broad allow; nothing else changes (NAT, log-forwarding, untrust/trust interfaces untouched).

- [ ] **Step 3: Commit the PAN-OS change**

`mcp__panos-mcp__load_and_commit_pan_config(host="panosvm", ...)`.

Expected: commit job succeeds. The denied 8.8.8.8 DNS now hits `deny-dns-other` → PAN-OS TRAFFIC `deny` (already mapped to `flow_deny` in `panos_ecs`).

- [ ] **Step 4: No repo change — proceed to Task 8.**

---

## Task 8: Deploy the generator on both endpoints

**Files:** none (pushes `scripts/labgen_endpoint.sh` to ct198/ct199). Depends on Tasks 6/7 (firewalls live) so the endpoints have upstream.

- [ ] **Step 1: Re-confirm endpoint deps (apk now works through the live firewall)**

```bash
for c in 198 199; do
  ssh root@pve3.example.com "pct exec $c -- sh -c 'apk add --no-cache bash curl bind-tools && echo nameserver 198.51.100.1 > /etc/resolv.conf'"
done
```

Expected: apk success on both (proves trust→untrust DNS/web egress works end-to-end through SRX/panosvm).

- [ ] **Step 2: Push the generator and an OpenRC service to each endpoint**

```bash
for c in 198 199; do
  ssh root@pve3.example.com "pct push $c /home/mharman/SSDF/scripts/labgen_endpoint.sh /usr/local/bin/labgen_endpoint.sh --perms 0755"
  ssh root@pve3.example.com "pct exec $c -- sh -c 'cat > /etc/init.d/labgen <<EOF
#!/sbin/openrc-run
name=\"labgen\"
command=\"/usr/local/bin/labgen_endpoint.sh\"
command_background=true
pidfile=\"/run/labgen.pid\"
output_log=\"/var/log/labgen.log\"
error_log=\"/var/log/labgen.log\"
EOF
chmod 0755 /etc/init.d/labgen && rc-update add labgen default && rc-service labgen restart'"
done
```

Note: scp/`pct push` runs from pve3, but the file lives on the dev host. If pve3 cannot read `/home/mharman/...`, first `scp scripts/labgen_endpoint.sh root@pve3.example.com:/tmp/` then `pct push $c /tmp/labgen_endpoint.sh ...`.

Expected: `labgen` added to the default runlevel and started on both; `pct exec $c -- rc-service labgen status` shows `started`.

- [ ] **Step 3: Confirm rounds are firing locally**

```bash
ssh root@pve3.example.com "pct exec 198 -- sh -c 'sleep 5; tail -n 5 /var/log/labgen.log 2>/dev/null; pgrep -f labgen_endpoint'"
```

Expected: a PID is returned (daemon running). (Live action logging is silent by default; the daemon does work each round.)

- [ ] **Step 4: No repo change — proceed to Task 9.**

---

## Task 9: Live-proof end to end

**Files:** none (verification only).

- [ ] **Step 1: Confirm frames on the wire at the ingest host**

```bash
ssh root@pve3.example.com "pct exec 102 -- timeout 30 tcpdump -n -c 10 'udp port 514 or udp port 515'"
```

Expected: packets from `198.51.100.240` (UDP 514, SRX) and `198.51.100.225` (UDP 515, panosvm syslog source). If none on 514, re-check Task 6 log stream + the nft allow-list (`pct exec 102 -- nft list table inet ssdf_ingest` must show `.220–.242`).

- [ ] **Step 2: Confirm fresh permit AND deny rows in ClickHouse for both providers**

```bash
ssh root@pve3.example.com "pct exec 104 -- clickhouse-client --query \"
  SELECT event_provider, event_action, observer_hostname, count() AS n
  FROM ssdf.events
  WHERE timestamp > now() - INTERVAL 15 MINUTE
    AND event_provider IN ('srx','paloalto')
  GROUP BY event_provider, event_action, observer_hostname
  ORDER BY event_provider, event_action\""
```

Expected: nonzero rows including SRX `flow_session_close` (permit) AND `flow_session_deny`, and PAN-OS `flow_end`/`flow_*` (permit) AND `flow_deny`, with `observer_hostname` populated (`vSRX`-style short name / `panosvm.example.com`).

- [ ] **Step 3: Confirm the deny events carry the 8.8.8.8 destination**

```bash
ssh root@pve3.example.com "pct exec 104 -- clickhouse-client --query \"
  SELECT event_provider, destination_ip, count()
  FROM ssdf.events
  WHERE timestamp > now() - INTERVAL 15 MINUTE
    AND event_action IN ('flow_session_deny','flow_deny')
    AND destination_ip = toIPv4('8.8.8.8')
  GROUP BY event_provider, destination_ip\""
```

Expected: a row for `srx` and a row for `paloalto` with `destination_ip = 8.8.8.8`.

- [ ] **Step 4: Confirm provenance bridge via the MCP (after one resolver cycle, ≤5 min)**

On the sovereign MCP, `explain_access` for the SRX endpoint pair (`client=10.74.12.20`, `server=1.1.1.1` or the LAN gateway) and the PAN-OS pair (`10.74.11.20` → gateway). Expected: `firewall_basis:provenance`, `firewalls` containing the SRX / `panosvm` short name, `coverage.configured ≥ 1`.

- [ ] **Step 5: No repo change — proceed to Task 10.**

---

## Task 10: Retire ct115

**Files:** none (Proxmox).

- [ ] **Step 1: Stop and destroy ct115**

```bash
ssh root@pve3.example.com 'pct stop 115 && pct destroy 115'
ssh root@pve3.example.com 'pct status 115 || echo "ct115 removed"'
```

Expected: `ct115 removed` (status errors because it no longer exists). ct115 was deliberately NOT in the weekly backup job, so no backup-job edit is needed.

- [ ] **Step 2: No repo change — proceed to Task 11.**

---

## Task 11: Docs — runbooks + as-built records

**Files:**
- Create: `onboarding/srx/transit-endpoint.md`
- Rewrite: `onboarding/panos/transit-traffic.md`
- Delete: `scripts/labgen_transit.sh`
- Modify: `CLAUDE.md` (append a section), `docs/superpowers/STATUS.md` (append a row)

- [ ] **Step 1: Write the SRX endpoint runbook**

Create `onboarding/srx/transit-endpoint.md` capturing, with the REAL values recorded during execution: vm103 interface map (ge-0/0/0 untrust `.240`, ge-0/0/1 trust `10.74.12.1`, VLAN 198), the strict-DNS policy intent (allow DNS only to 198.51.100.1/1.1.1.2/1.0.0.2, deny+log rest → `flow_session_deny`), the stream-syslog stanza, ct198 build command, generator install (OpenRC service), and the UTC-clock requirement. Mirror the structure of `onboarding/proxmox/rsyslog.md` (deployment-values section + captured-samples section with one real `RT_FLOW_SESSION_DENY` line for 8.8.8.8).

- [ ] **Step 2: Rewrite the PAN-OS transit runbook for ct199**

Rewrite `onboarding/panos/transit-traffic.md`: replace the ct115/labgen_transit content with ct199 (`ssdf-ep-panos`, 10.74.11.20, VLAN 199 over vmbr1), the trust-NIC re-tag 103→199, the new strict-DNS rules (allow-dns-ok / deny-dns-other above the broad allow), and the shared `scripts/labgen_endpoint.sh` generator. Keep the existing verify queries (update VLAN/tag references).

- [ ] **Step 3: Delete the superseded single-shot generator**

```bash
git rm scripts/labgen_transit.sh
```

Verify nothing else references it:

```bash
grep -rn "labgen_transit" --include='*.md' --include='*.sh' . || echo "no refs"
```

Expected: `no refs` after the two runbook rewrites (if any remain, fix them).

- [ ] **Step 4: Append the as-built records**

Add a `### SRX/PAN-OS live transit sources` subsection to `CLAUDE.md` (under the milestone command sections) summarizing: ct198/ct199 endpoints, Proxmox-only trust VLANs 198/199, generator, strict-DNS deny path, ct115 retired, no SSDF data-path change. Add a matching as-built row to `docs/superpowers/STATUS.md`.

- [ ] **Step 5: Commit**

```bash
git add onboarding/srx/transit-endpoint.md onboarding/panos/transit-traffic.md CLAUDE.md docs/superpowers/STATUS.md
git rm --cached scripts/labgen_transit.sh 2>/dev/null; git add -A scripts/labgen_transit.sh 2>/dev/null
git commit -m "docs(lab): SRX+PAN-OS live transit runbooks; retire labgen_transit/ct115"
```

---

## Task 12: Finish the branch

**Files:** none (git/PR).

- [ ] **Step 1: Run the script self-test once more and review the diff**

```bash
bash scripts/labgen_endpoint_test.sh   # expect PASS
git log --oneline main..HEAD
```

- [ ] **Step 2: Open the PR (only after user confirms)**

Use `superpowers:finishing-a-development-branch`. Push and open a PR summarizing the new live SRX/PAN-OS sources, the ct198/ct199 endpoints, the generator, and ct115 retirement. Do NOT push/PR without explicit user go-ahead.

---

## Self-Review notes (author)

- **Spec coverage:** addressing/VLAN table → Task 3/6/7; UniFi reservations (.240, repoint .210) → Task 5; SRX config incl. UTC + strict-DNS + stream syslog → Task 6; panosvm strict-DNS + re-tag → Task 7; Alpine endpoints → Task 3; shared generator → Task 2/8; data-flow/live-proof (permit+deny, observer_hostname, 8.8.8.8) → Task 9; ct115 retire → Task 10; runbooks/supersede → Task 11; vSRX vNIC-ordering risk → Task 4 Step 4; SRX MAC-after-up risk → Task 5 uses the Proxmox vNIC MAC (known from vm config). The spec's "possible SRX deny VRL tweak" risk is RESOLVED — `flow_session_deny` already exists and is tested, so no VRL task is needed.
- **No SSDF code/schema/transform change** — consistent with the read-only-fabric constraint.
- **Naming consistency:** ct198=VLAN198=10.74.12.x=SRX everywhere; ct199=VLAN199=10.74.11.x=PAN-OS everywhere; generator `labgen_endpoint.sh` + test `labgen_endpoint_test.sh` consistent across Tasks 2/8/12.
