# SRX lab transit traffic (labgen endpoint)

Keeps vsrx-prod's session table non-empty so SRX RT_FLOW parsing and the
M6c-B provenance bridge (`vsrx-prod` exact-match) stay continuously
live-proven. SRX logs **transit only** (never host-originated) — a behind-the-firewall
endpoint is required to generate flows.

## Topology (as built, Phase 2 2026-06-15)

vsrx-prod is VMID 905 on pve2 (renumbered from 103 and migrated on 2026-08-12) (vSRX 3.0 NIC order: net0→fxp0, net1→ge-0/0/0, …,
net4→ge-0/0/3).

| vsrx-prod (VMID 905) | zone | address | Proxmox NIC |
|---|---|---|---|
| ge-0/0/0.0 | untrust | 198.51.100.240/24 | net1 → vmbr0 (LAN) |
| ge-0/0/3.0 | trust | 10.74.12.1/24 | net4 → vmbr1 **tag=198** |
| fxp0.0 | (mgmt) | 198.51.100.222/24 | net0 → vmbr0 |

- Syslog source toward Vector is **198.51.100.240** (ge-0/0/0) — inside the guest 700 (was ct102)
  nft allow-list band `198.51.100.220-.242` (`infra/firewall/ct102-ingest.nft`).
- The trust VLAN is a **Proxmox-only bridge tag on vmbr1** (VLAN id was the endpoint's ORIGINAL CTID; the guest was renumbered to 710 on 2026-08-12 but the tag stayed **198** — do NOT derive the tag from the current VMID,
  here 198). No UniFi network object exists for it.

### Security policy (DNS allow/deny + permit-all egress)

```
from trust to untrust allow-approved-dns  match dst approved-resolvers app junos-dns-{udp,tcp} → permit, log session-close
from trust to untrust deny-rogue-dns       match any/any app junos-dns-{udp,tcp}              → deny,   log session-init
global               allow_outbound_all     any/any                                            → permit, log session-close, count
```

`approved-resolvers` address-set = `DNS-RESOLVER` (198.51.100.1), `resolver-cf1`
(1.1.1.2), `resolver-cf2` (1.0.0.2). DNS to any other resolver (e.g. 8.8.8.8) hits
`deny-rogue-dns` and logs an **RT_FLOW_SESSION_DENY** — that is the deliberate
deny-event source. Everything else egresses via `allow_outbound_all`.

## Traffic source: guest 710 (was ct198) `ssdf-traffic-gen-srx`

Minimal Alpine LXC on pve2 (10.74.12.20/24, gw 10.74.12.1 = the SRX trust interface).
Trust VLAN tag is **198** and is NOT derived from the VMID: the guest was renumbered to 710 on 2026-08-12 while the tag was deliberately left alone, because changing it would mean re-addressing the firewall interface too.

```bash
pct create 710 local:vztmpl/alpine-3.22-default_20250617_amd64.tar.xz \
  --hostname ssdf-traffic-gen-srx --unprivileged 1 --cores 1 --memory 128 --swap 0 \
  --rootfs local-lvm:1 \
  --net0 name=eth0,bridge=vmbr1,tag=198,ip=10.74.12.20/24,gw=10.74.12.1 \
  --onboot 1 --start 1
```

Setup (run once):

```bash
pct exec 710 -- sh -c 'echo "nameserver 198.51.100.1" > /etc/resolv.conf && apk add --no-cache bash curl bind-tools'
# push the shared generator
pct push 710 scripts/labgen_endpoint.sh /usr/local/bin/labgen_endpoint.sh --perms 0755
```

OpenRC service `/etc/init.d/labgen` (daemon, not cron — the generator loops itself):

```sh
#!/sbin/openrc-run
name="labgen"
description="SSDF lab endpoint traffic generator"
command="/usr/local/bin/labgen_endpoint.sh"
command_background=true
pidfile="/run/labgen.pid"
output_log="/var/log/labgen.log"
error_log="/var/log/labgen.log"
depend() { need net }
```

Enable + start:

```bash
pct exec 710 -- sh -c 'rc-update add labgen default && rc-service labgen start'
```

Self-test the generator without sending anything:
`LABGEN_DRYRUN=1 LABGEN_ONESHOT=1 /usr/local/bin/labgen_endpoint.sh`

Notes:
- `ping 10.74.12.1` (the SRX trust interface) DOES reply — `host-inbound-traffic
  system-services ping` is set on the trust zone. (PAN-OS differs; see panos runbook.)
- The generator needs `bash curl bind-tools`; Alpine's default shell is busybox ash.
- The shared generator defaults already target the approved resolver (198.51.100.1) for
  dns-ok and 8.8.8.8 for dns-deny — no per-endpoint override needed.

## Verify (end to end)

```bash
# RT_FLOW rows arriving + denies present (container-local on guest 701 (was ct104)):
pct exec 701 -- clickhouse-client --query "
  SELECT event_action, observer_hostname, count() FROM ssdf.events
  WHERE event_provider='juniper' AND observer_hostname='vsrx-prod'
    AND timestamp > now() - INTERVAL 1 HOUR
  GROUP BY event_action, observer_hostname"
# expect permit + deny rows, observer_hostname='vsrx-prod'
```

`observer_hostname=vsrx-prod` requires the H2 device gate in
`infra/vector/vector.toml` to accept it — the gate regex is
`^vsrx-(test\d|production)` (broadened from test-fleet-only in Phase 2). The stored
value keeps original case so the `explain_access` provenance bridge matches the
`device:vsrx-prod` Firewall entity exactly.
