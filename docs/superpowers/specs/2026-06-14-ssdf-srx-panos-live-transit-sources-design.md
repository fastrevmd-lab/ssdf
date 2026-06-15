# SSDF — SRX + PAN-OS live transit sources (Alpine endpoints + traffic generator)

**Date:** 2026-06-14
**Status:** Design approved (brainstorming), pre-plan.

## Goal

Turn the two synthetic firewalls — **vm103 ProductionSRX** (Junos vSRX) and
**panosvm** (PAN-OS 12.1.5, VMID 900) — into live, continuously-ingesting SSDF
event sources, on par with the already-real UniFi and Proxmox sources. Build one
Alpine LXC endpoint behind each firewall and a shared traffic-generator daemon
that produces continuous permitted internet egress plus deliberate denied
attempts, so SSDF's SRX (UDP/514) and PAN-OS (UDP/515) ingest paths — and the
`observer_hostname` provenance bridge — stay continuously live-proven.

This is **source onboarding + lab infrastructure only**. SSDF stays read-only and
its data path is unchanged: no Vector transform rewrites are expected (both
`srx_ecs` and `panos_ecs` VRL paths already exist), no ClickHouse schema change,
no MCP tool change. Firewall configs are applied by the operator via the external
vendor MCPs (rust-junosmcp for Junos, panos-mcp for PAN-OS), never by SSDF.

## Background / why

- UniFi (M9) and Proxmox (M11) are real devices on the home network and emit real
  events. SRX and PAN-OS are lab VMs: SRX currently emits **0 events** (genuinely
  dead), and PAN-OS's current `paloalto` volume is **system noise**, not endpoint
  transit (confirmed: 577 system vs 16 transit events in a 2h window).
- A prior generator, **ct115 `ssdf-labgen`** (10.74.11.20, 15-min cron), fed only
  the PAN-OS trust segment. This work supersedes it with a symmetric pair of
  endpoints (one per firewall) running a richer continuous daemon. ct115 is
  retired (its sole job was traffic generation).

## Addressing & VLAN plan (UniFi-verified 2026-06-14)

LAN `198.51.100.0/24` ("Mgmt Network"): **DHCP pool = .6–.195**, so **.196–.254 is
static-safe**. The ingest nft allow-list (`infra/firewall/ct102-ingest.nft`)
accepts SRX/PAN-OS syslog (UDP 514/515) only from **.220–.242**, so the SRX
syslog source IP must land in that band.

| Element | Side | Network / VLAN | IP | Bridge / NIC |
|---|---|---|---|---|
| vm103 SRX `ge-0/0/0.0` | untrust | LAN 198.51.100.0/24 | **198.51.100.240/24** (new, free, in nft band) | vmbr0 |
| vm103 SRX `ge-0/0/1.0` | trust | **VLAN 198** 10.74.12.0/24 | 10.74.12.1/24 (gateway) | vmbr1 tag 198 |
| ct198 (Alpine) | trust | VLAN 198 10.74.12.0/24 | **10.74.12.20/24** | vmbr1 tag 198 |
| panosvm `eth1/1` | untrust | LAN 198.51.100.0/24 | **198.51.100.210/24** (existing) | vmbr0 (net1) |
| panosvm `eth1/2` | trust | **VLAN 199** 10.74.11.0/24 | 10.74.11.1/24 (gateway) | vmbr1 tag 199 (re-tag from 103) |
| ct199 (Alpine) | trust | VLAN 199 10.74.11.0/24 | **10.74.11.20/24** | vmbr1 tag 199 |
| panosvm mgmt / syslog source | — | LAN | 198.51.100.225 (existing reservation) | — |

Decisions locked during brainstorming:

- **Separate trust VLANs per firewall** (SRX=198, PAN-OS=199) — two gateways on one
  L2 would be wrong. VLAN IDs deliberately **match the CTIDs** (ct198→VLAN 198,
  ct199→VLAN 199) for operator legibility.
- **Trust VLANs are Proxmox-only** — pure bridge VLAN tags on vmbr1 (LXC NIC tag +
  firewall trust NIC tag). **No UniFi network objects** are created for 198/199;
  UniFi never sees them. ct198↔vm103 and ct199↔panosvm L2 stays local to pve3's
  vmbr1.
- PAN-OS trust keeps its existing subnet `10.74.11.0/24` and IP `10.74.11.1`; only
  the bridge VLAN tag changes 103→199, and ct199 reuses ct115's old `10.74.11.20`.
- **untrust side** is the flat LAN over vmbr0. The only UniFi-side changes are two
  LAN reservations (below).

### UniFi reservation changes (the only UniFi-side edits)

1. **SRX ge-0/0/0** → reserve `198.51.100.240` to the SRX data-plane MAC (read the
   actual MAC after the interface is up).
2. **panosvm eth1/1** → reserve `198.51.100.210` to MAC `02:01:01:48:9d:d3`.
   The `.210` reservation is currently a **phantom** pointing to
   `02:01:01:f0:d6:a5` "OnpremSD" (a MAC not present). Repoint it to the real
   panosvm eth1/1 MAC (or delete the phantom and create the correct one) so `.210`
   is unambiguously panosvm's.

## Per-firewall configuration

### vm103 SRX (applied via rust-junosmcp)

Prerequisite: **add vm103 to rust-junosmcp** `/etc/jmcp/devices.json` on ct601
(username `netconf`, key `/etc/jmcp/id_ed25519`), then HUP-reload the service.
Reachable today on its fxp0 management lease `198.51.100.222` (hostname `vSRX-A`).

- `ge-0/0/0.0` untrust = `198.51.100.240/24`, security-zone `untrust`; default
  route `0.0.0.0/0` → `198.51.100.1`.
- `ge-0/0/1.0` trust = `10.74.12.1/24` (the vNIC mapped to vmbr1 tag 198),
  security-zone `trust`; host-inbound DNS/ping as needed for the endpoint.
- **Source NAT** trust→untrust: interface NAT (translate to `ge-0/0/0`).
- **Security policies** trust→untrust:
  - permit **DNS (udp/tcp 53) only to** `198.51.100.1`, `1.1.1.2`, `1.0.0.2`;
  - permit HTTP/HTTPS and ICMP to any;
  - **deny-and-log** everything else (this catches the `8.8.8.8` DNS attempts);
  - `then log session-init` on deny and `session-close` on permit so both land in
    SSDF.
- **Stream syslog**: reuse `onboarding/srx/stream-config.set` with
  `source-address 198.51.100.240`, `host 198.51.100.150 port 514`,
  `format sd-syslog category all severity info`.
- **Clock MUST be UTC** — SSDF parses SRX syslog as naive UTC. Verify
  `show system uptime` reads `... UTC`; do not set a non-UTC `system time-zone`
  (Junos defaults UTC when unset).

### panosvm (applied via panos-mcp; preview with `pan_config_diff`, commit with `load_and_commit_pan_config`)

- Keep eth1/1 untrust `.210`, eth1/2 trust `10.74.11.1`, existing SNAT and
  log-forwarding profile to `198.51.100.150:515` (pinned to PAN-OS 12.1 shape).
- Bridge re-tag 103→199 is a Proxmox-side change on the panosvm trust NIC, not a
  PAN-OS config change (PAN-OS keeps `10.74.11.1`).
- Add the **same strict-DNS policy** trust→untrust: permit DNS only to the three
  resolvers, permit web/ICMP, **deny-and-log** the rest; `log-end` (and log-start
  on deny) on the relevant rules so permits and denies both forward to SSDF.
- panosvm runs **UTC** (P2, onboarding/panos/timezone-utc.md) — already done; do
  not regress it.

## Alpine endpoints (ct198, ct199)

Two Alpine LXCs on pve3 (VMIDs **198**, **199** — not in the protected list).

- One NIC each on **vmbr1** with the matching VLAN tag (198 / 199).
- Static IP `10.74.12.20/24` (ct198) / `10.74.11.20/24` (ct199); default route to
  the firewall trust gateway (`10.74.12.1` / `10.74.11.1`); `/etc/resolv.conf`
  nameserver `198.51.100.1` (an allowed resolver, so normal lookups succeed).
- `apk add bash curl bind-tools` (bash for `/dev/tcp`; bind-tools for `nslookup`).
- The traffic daemon runs under OpenRC/busybox `crond` (Alpine has no systemd) —
  either a short cron cadence re-launching a bounded run, or an OpenRC service
  wrapping the loop. Implementation plan picks one; both are acceptable.

## Shared traffic generator

`scripts/labgen_endpoint.sh` (replaces `scripts/labgen_transit.sh`), identical on
both endpoints, env-tunable, no secrets, idempotent:

- Continuous sleep-jittered loop (~every 20–40s, `LABGEN_INTERVAL`-tunable) so
  flows stay fresh:
  - **Allowed egress:** HTTPS to a rotating set of public hosts (e.g. `1.1.1.1`,
    `cloudflare.com`, `example.com`) via `curl`/`/dev/tcp` → permitted
    session-close events.
  - **Allowed DNS:** `nslookup <name> 198.51.100.1` → permitted.
  - **Denied DNS:** `nslookup <name> 8.8.8.8` (and/or raw udp/53 to 8.8.8.8) → the
    firewall **deny-and-log** path.
  - Occasional ICMP to `1.1.1.1` (permitted).
- Destination lists and interval are env-overridable; the script logs each action
  to stdout/local syslog for self-check.

## Data flow

```
ct198 ─VLAN198─► vm103 SRX ─SNAT ge-0/0/0 .240─► LAN ─► internet
                    │ session-close / deny  ─syslog 514─► Vector .150 ─► CH
ct199 ─VLAN199─► panosvm   ─SNAT eth1/1 .210─► LAN ─► internet
                    │ session-end / deny    ─syslog 515─► Vector .150 ─► CH
```

Each firewall SNATs trust→untrust and logs sessions to Vector ct102, where the
existing `srx_ecs` / `panos_ecs` VRL normalizes to `ssdf.events` with
`observer_hostname` set (the M6c-B provenance bridge: SRX→`vSRX-test10`-style
short name; PAN-OS→`panosvm`). Permits arrive as flow/allow events, denied 8.8.8.8
attempts as deny-action events.

## Testing / live-proof

1. `vector test infra/vector/vector.toml` stays green. No transform change is
   expected; **if** SRX deny-action parsing needs a tweak to surface the deny, add
   a regression test in the `srx_*` suite (do not silently change behavior).
2. On the wire (ct102): `tcpdump -n udp port 514` and `udp port 515` show frames
   from `.240` and `.210` respectively after cutover.
3. ClickHouse freshness query:
   `SELECT event_provider, event_action, count() FROM ssdf.events
    WHERE timestamp > now() - INTERVAL 15 MINUTE GROUP BY 1,2`
   shows fresh `srx`/`paloalto` permit **and** deny rows with `observer_hostname`
   populated.
4. Confirm deny events carry the `8.8.8.8` destination.
5. nft allow-list: confirm `.240` is within `.220–.242` so SRX syslog is accepted
   (no nft change needed); panosvm syslog source stays `.225` (already allowed).

## Retirement

- Stop and delete **ct115 `ssdf-labgen`**; remove its cron entry.
- Mark `onboarding/panos/transit-traffic.md` superseded by a new endpoint runbook
  documenting ct198/ct199 + `labgen_endpoint.sh`.

## Rollout order

1. UniFi reservations (`.240` SRX, repoint `.210` panosvm).
2. Proxmox: vmbr1 VLAN tags 198/199, build ct198 + ct199, re-tag panosvm trust NIC
   103→199.
3. Firewall configs: add vm103 to rust-junosmcp + apply SRX config; apply panosvm
   strict-DNS policy via panos-mcp.
4. Deploy `labgen_endpoint.sh` on both endpoints.
5. Retire ct115.
6. Live-proof (testing section above).

## Out of scope (YAGNI)

- No new SSDF MCP tools, no ClickHouse schema migration, no new Vector source/port
  (514/515 already exist).
- No UniFi network objects for the trust VLANs (Proxmox-only by design).
- No changes to UniFi/Proxmox real-source ingest.
- No renumbering of the PAN-OS trust subnet (only the VLAN tag changes).

## Risks / open items for the plan

- **vSRX vNIC ordering** (fxp0-first vs ge-first on KVM) must be verified on vm103
  before trusting `ge-0/0/0` = untrust and `ge-0/0/1` = trust; the plan must
  include a verification step (`show interfaces terse`) and map vNICs to bridges
  accordingly.
- The SRX data-plane MAC for the `.240` reservation is only knowable after the
  interface is up — sequence the reservation after interface bring-up, or reserve
  by MAC read from `show interfaces`.
- If `vector test` reveals the SRX deny is not normalized to a deny action,
  surface it as a small, test-backed VRL addition — still source onboarding, not a
  schema change.
```
