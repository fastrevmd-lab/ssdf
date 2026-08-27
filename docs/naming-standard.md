# SSDF Device Naming Standard

All vSRX devices in the SSDF lab follow a consistent **lowercase kebab-case** naming convention: `vsrx-<role>`. The same string is used uniformly across all layers:

- Proxmox VM name (e.g., `qm set <vmid> --name vsrx-prod`)
- Junos on-box hostname (`set system host-name vsrx-prod`)
- rust-junosmcp `devices.json` key
- SSDF `JUNOS_DEVICES` environment variable (704 `ssdf-topo` resolvers)
- `observer_hostname` field on the wire (syslog HOSTNAME → normalized at ingest)

Role names derive from the enterprise topology described in `~/homelab/topology/DESIGN.md`. The entire 23-device vSRX fleet was renamed live on **2026-07-06**.

## Fleet Inventory

| New name | Old inventory key | Old on-box name | Role | VMID |
|----------|-------------------|-----------------|------|------|
| vsrx-prod | vSRX-Production | vSRX-Production | Standalone production edge (SSDF transit source, labgen ct198) | 103 |
| vsrx-wan-edge | vSRX-mnha-router | mnha-router | Enterprise WAN edge router | 213 |
| vsrx-core-a | vSRX-Node1 | vSRX-Node1 | MNHA pair node A (top enterprise firewall) | 214 |
| vsrx-core-b | vSRX-Node2 | vSRX-Node2 | MNHA pair node B | 215 |
| vsrx-dc | vSRX-test19-20 | vSRX-test19/vSRX-test20 | DC chassis cluster + IPsec hub (one logical device; VM names vsrx-dc-n0/vsrx-dc-n1, node host-names vsrx-dc-n0/vsrx-dc-n1) | 219+220 |
| vsrx-dmz | vSRX-test2 | vSRX-test2 | DMZ firewall (IDP/AppSecure) | 112 |
| vsrx-campus-a | vSRX-mm-A | vSRX-mm-A | Campus firewall (Mist) | 107 |
| vsrx-campus-b | vSRX-mm-B | vSRX-mm-B | Campus firewall (Mist) | 108 |
| vsrx-isp-a | vSRX-test1 | vSRX-ISP-A | ISP-A sim router | 110 |
| vsrx-isp-b | vSRX-twin | vSRX-ISP-B | ISP-B sim router | 105 |
| vsrx-br01 | vSRX-test6 | vSRX-test6 | Branch BR-01 (hub-spoke full-tunnel) | 206 |
| vsrx-br02 | vSRX-test7 | vSRX-test7 | Branch BR-02 (hub-spoke full-tunnel) | 207 |
| vsrx-br03 | vSRX-test8 | vSRX-test8 | Branch BR-03 (hub-spoke full-tunnel) | 208 |
| vsrx-br04 | vSRX-test9 | vSRX-test9 | Branch BR-04 (hub-spoke full-tunnel) | 209 |
| vsrx-br05 | vSRX-test10 | vSRX-test10 | Branch BR-05 (hub-spoke full-tunnel) — hosts the CDE PCI-audit fixture, was SSDF's original live-proven device | 210 |
| vsrx-br06 | vSRX-test11 | vSRX-test11 | Branch BR-06 (hub-spoke full-tunnel) | 211 |
| vsrx-br07 | vSRX-test12 | vSRX-test12 | Branch BR-07 (ADVPN) | 212 |
| vsrx-br08 | vSRX-test16 | vSRX-test16 | Branch BR-08 (ADVPN) | 216 |
| vsrx-br09 | vSRX-test17 | vSRX-test17 | Branch BR-09 (ADVPN) | 217 |
| vsrx-br10 | vSRX-test18 | vSRX-test18 | Branch BR-10 (ADVPN) | 218 |
| vsrx-br11 | vSRX-test3 | vSRX-test3 | Branch BR-11 (ADVPN) | 101 |
| vsrx-br12 | vSRX-test4 | vSRX-test4 | Branch BR-12 (ADVPN) | 111 |
| vsrx-ci | vSRX-CI-tester | vSRX-CI-tester | CI tester | 114 |
| panosvm | (unchanged) | panosvm | PAN-OS inspection firewall, VMID 900 — NOT renamed (protected) | 900 |

## Changing a Device Name

When renaming a device or onboarding a new one, update all layers in this order:

1. **Device hostname + commit** — `set system host-name <new-name>` on the Junos device
2. **rust-junosmcp devices.json** — update the key in `/etc/jmcp/devices.json` (ct601), then reload: `systemctl kill -s HUP rust-junosmcp.service`
3. **Proxmox VM name** — `qm set <vmid> --name <new-name>` on the guest's own node
4. **704 JUNOS_DEVICES** — update `JUNOS_DEVICES` in all three resolver ENV.local files on 704 `ssdf-topo` (`/etc/ssdf-topo/ENV.local`, `/etc/ssdf-policy/ENV.local`, `/etc/ssdf-health/ENV.local`)
5. **Vector observer_hostname gate** — update the regex in `infra/vector/vector.toml` transforms `srx_ecs` and `panos_ecs` to accept the new name
6. **Eval corpus** — if the device appears in `services/evals/golden/core.yaml` questions/predicates, update the references

The Vector gate dual-accepts legacy names during a transition period (typically ~30 days after the rename) before pruning old patterns.
