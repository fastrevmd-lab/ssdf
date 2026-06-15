# PAN-OS lab transit traffic (labgen endpoint)

Keeps panosvm's session table non-empty so PAN-OS TRAFFIC parsing and the M6c-B
provenance bridge (`panosvm.example.com` → `panosvm`) stay continuously live-proven.

> Phase 2 (2026-06-15) replaced the old cron-driven ct115 (`labgen_transit.sh`) with
> ct199 running the shared `labgen_endpoint.sh` daemon — symmetric with the SRX
> endpoint (`onboarding/srx/transit-endpoint.md`). ct115 was retired.

## Topology (as built)

| panosvm (VMID 900) | zone | address | Proxmox NIC |
|---|---|---|---|
| ethernet1/1 | untrust | 198.51.100.210/24 ("Comcast Internet") | net1 → vmbr0 (LAN) |
| ethernet1/2 | trust | 10.74.11.1/24 ("to tester") | net2 → vmbr1 **tag=199** |

- Default route 0.0.0.0/0 → 198.51.100.1 via ethernet1/1; NAT `toInternet`/
  `trust-egress-nat`: trust→untrust dynamic SNAT to ethernet1/1.
- Syslog source toward Vector is **198.51.100.225** — inside the ct102 nft allow-list
  band `198.51.100.220-.242` (`infra/firewall/ct102-ingest.nft`).
- The trust VLAN is a **Proxmox-only bridge tag on vmbr1** (VLAN id = endpoint CTID,
  here 199; re-tagged from the old 103). No UniFi network object exists for it.

### Security policy (DNS allow/deny + permit-all egress)

PAN-OS is first-match-wins, so order matters (`drifttest1` any/any/allow sits below):

```
allow-approved-dns  from trust to untrust  dst approved-resolvers  svcg-dns  → allow, log-end
deny-rogue-dns      from trust to untrust  dst any                 svcg-dns  → deny,  log-start+log-end
drifttest1          any/any                                                   → allow, log-end   (pre-existing)
```

`approved-resolvers` group = `resolver-unifi` (198.51.100.1), `resolver-cf1` (1.1.1.2),
`resolver-cf2` (1.0.0.2); `svcg-dns` = udp/53 + tcp/53. DNS to any other resolver
(e.g. 8.8.8.8) hits `deny-rogue-dns` → a TRAFFIC **deny** row. All rules log to
`log-setting SSDF-LF`.

> **panos-mcp loader syntax trap:** the loader pipes into the native SSH CLI configure
> session, which rejects the XML-API `set vsys vsys1 …` prefix ("Invalid syntax").
> Use native syntax with **no** `vsys` keyword (it auto-scopes to the default vsys1 —
> the same vsys every existing rule already lives in; no new virtual system is created).
> `move … top` / `move … after <rule>` ordering commands work in the same payload.

## Traffic source: ct199 `ssdf-ep-panos`

Minimal Alpine LXC on pve3 (10.74.11.20/24, gw 10.74.11.1 = the panosvm trust interface).
VMID = trust VLAN id by convention.

```bash
pct create 199 local:vztmpl/alpine-3.22-default_20250617_amd64.tar.xz \
  --hostname ssdf-ep-panos --unprivileged 1 --cores 1 --memory 128 --swap 0 \
  --rootfs local-lvm:1 \
  --net0 name=eth0,bridge=vmbr1,tag=199,ip=10.74.11.20/24,gw=10.74.11.1 \
  --onboot 1 --start 1
```

Setup, OpenRC service, and self-test are identical to the SRX endpoint — see
`onboarding/srx/transit-endpoint.md` (same `scripts/labgen_endpoint.sh`, same
`/etc/init.d/labgen`). Push + enable:

```bash
pct exec 199 -- sh -c 'echo "nameserver 198.51.100.1" > /etc/resolv.conf && apk add --no-cache bash curl bind-tools'
pct push 199 scripts/labgen_endpoint.sh /usr/local/bin/labgen_endpoint.sh --perms 0755
pct exec 199 -- sh -c 'rc-update add labgen default && rc-service labgen start'
```

Notes:
- `ping 10.74.11.1` (the trust interface itself) does NOT reply — PAN-OS answers ICMP
  only with an interface-mgmt profile. Test transit with an internet dest instead
  (`ping 1.1.1.2` answers, 0% loss = transit through panosvm works).
- ct199's apk/DNS egress itself transits panosvm — also logged, also useful.

## Verify (end to end)

```bash
# TRAFFIC rows arriving + denies present (container-local on ct104):
pct exec 104 -- clickhouse-client --query "
  SELECT event_action, observer_hostname, count() FROM ssdf.events
  WHERE event_provider='paloalto' AND has(event_category, 'network')
    AND timestamp > now() - INTERVAL 1 HOUR
  GROUP BY event_action, observer_hostname"
# expect permit + deny rows, observer_hostname='panosvm.example.com'
```
