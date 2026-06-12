# PAN-OS lab transit traffic (labgen)

Keeps panosvm's session table non-empty so PAN-OS TRAFFIC parsing and the M6c-B
provenance bridge (`panosvm.example.com` → `panosvm`) stay continuously live-proven.
Until 2026-06-12 panosvm had never logged a transit flow (the "PAN-OS TRAFFIC
carve-out" in STATUS.md).

## Topology findings (investigated 2026-06-12)

Sources: panos-mcp `get_pan_config`, proxmox-mcp `get_vm_config(900)`, and SSDF's own
`neighbors("panosvm")` (dogfood — returned the firewall-role device node, no edges yet).

| panosvm (VMID 900) | zone | address | Proxmox NIC |
|---|---|---|---|
| ethernet1/1 | untrust | 198.51.100.210/24 ("Comcast Internet") | net1 → vmbr0 (LAN) |
| ethernet1/2 | trust | 10.74.11.1/24 (comment "to tester") | net2 → vmbr1 **tag=103** |

- Default route 0.0.0.0/0 → 198.51.100.1 via ethernet1/1.
- NAT `toInternet`/`trust-egress-nat`: trust→untrust dynamic SNAT to ethernet1/1.
- Security rules: `drifttest1` (any→any allow, log-end, `log-setting SSDF-LF`) sits
  first, so ALL transit traffic is logged to SSDF regardless of which specific rule
  was intended; `allow-trust-to-untrust` (same logging) is the designed match.
- Trust segment was dead at investigation time: ARP table empty; the only other
  VMs on vmbr1 tag=103 (vSRXtwin 105, vSRX-test1 110, vSRX-test2 112) all stopped.

**Chosen triple:** source ct115 (10.74.11.20, trust) → dest 198.51.100.1:443 (LAN
gateway, untrust) → matches `drifttest1` / `allow-trust-to-untrust`, SNAT out
ethernet1/1, TRAFFIC log at session end → Vector ct102 UDP/515 → ssdf.events.

## Traffic source: ct115 `ssdf-labgen`

Minimal Alpine LXC on pve3 (operator-approved 2026-06-12). VMID 114 was free on
pve3 but taken cluster-wide (pve1) — always check `pvesh get /cluster/resources`.

```bash
pct create 115 local:vztmpl/alpine-3.22-default_20250617_amd64.tar.xz \
  --hostname ssdf-labgen --unprivileged 1 --cores 1 --memory 128 --swap 0 \
  --rootfs local-lvm:1 \
  --net0 name=eth0,bridge=vmbr1,tag=103,ip=10.74.11.20/24,gw=10.74.11.1 \
  --onboot 1 --start 1
```

Setup (run once):

```bash
pct exec 115 -- sh -c 'echo "nameserver 1.1.1.1" > /etc/resolv.conf && apk add --no-cache bash'
# push the generator
pct push 115 scripts/labgen_transit.sh /usr/local/bin/labgen_transit.sh --perms 0755
# cron every 15 min (busybox crond is enabled by default on Alpine)
pct exec 115 -- sh -c 'grep -q labgen_transit /etc/crontabs/root || echo "*/15 * * * * /usr/local/bin/labgen_transit.sh" >> /etc/crontabs/root; rc-service crond restart'
```

Notes:
- `ping 10.74.11.1` (the trust interface itself) does NOT reply — no
  interface-mgmt profile permits ping. Test transit with a LAN dest instead
  (`ping 198.51.100.1` answers, ttl=63 = one hop through panosvm).
- The generator needs bash for `/dev/tcp` (Alpine default shell is busybox ash).
- ct115's apk/DNS egress itself transits panosvm — also logged, also useful.

## Verify (end to end)

```bash
# TRAFFIC rows arriving (run container-local on ct104):
pct exec 104 -- clickhouse-client --query "
  SELECT event_action, observer_hostname, count() FROM ssdf.events
  WHERE event_provider='paloalto' AND has(event_category, 'network')
    AND timestamp > now() - INTERVAL 1 HOUR
  GROUP BY event_action, observer_hostname"
# expect nonzero counts, observer_hostname='panosvm.example.com'
```

Then after an entity-resolver cycle (≤5 min): `explain_access("10.74.11.20",
"198.51.100.1")` on the sovereign MCP → `firewall_basis:provenance`,
`firewalls:["panosvm"]`, `coverage.configured ≥ 1`.
