# Proxmox host audit → SSDF (M11 onboarding)

SSDF ingests the pve3 hypervisor host's auth + admin-action syslog
(`pvedaemon`/`pveproxy`/`sshd`) via remote rsyslog. SSDF never configures the source in
its own data path; the operator applies the rsyslog drop-in on pve3.

## 0. Verify the host clock is UTC (do this FIRST)
SSDF stores event time from the syslog timestamp. Run on pve3:
  timedatectl
Confirm `Time zone: ... (UTC, +0000)`. The rsyslog template below forwards RFC5424
(ISO-8601 with offset), so a UTC host clock yields correct stored time — fix the clock
before relying on parsed times (the PAN-OS/SRX local-time skew lesson).

## 1. rsyslog drop-in (forward to Vector)
Create `/etc/rsyslog.d/49-ssdf.conf` on pve3:

  auth,authpriv,daemon.*  @198.51.100.150:517;RSYSLOG_SyslogProtocol23Format

(single `@` = UDP; `RSYSLOG_SyslogProtocol23Format` = RFC5424 with offset timestamp.)
The facility filter is the coarse gate; Vector's `proxmox_sec` filter does the fine
`pvedaemon|pveproxy|sshd` + known-pattern gate, so non-security daemon noise is dropped
at ingest.

## 2. Restart + verify on the wire
On pve3:  systemctl restart rsyslog
On ct102: tcpdump -n -A -i any udp port 517 -c 20
Trip an event (e.g. from another host: `ssh baduser@pve3` with a wrong password) and
confirm the line arrives.

## 3. Deployment-specific values (used by the nft allow-list + ext.proxmox.node)
  - PVE3_LAN_IP    = <the src IP from `ip -4 route get 198.51.100.150` on pve3>
                     (nft allow-list source on ct102; see infra/firewall/ct102-ingest.nft)
  - NODE_HOSTNAME  = pve3   (rides ext.proxmox.node)

## 4. Captured samples (real lines — fill at live-proof; these are the VRL test fixtures)
ParseSyslog yields appname + message; the proxmox_ecs transform maps them as:
  - pvedaemon "successful auth for user 'root@pam'"        -> authentication / auth_success
  - pvedaemon "authentication failure; rhost=<ip> user=<u>"-> authentication / auth_failure (source_ip)
  - sshd "Accepted <m> for <u> from <ip> port <p>"          -> authentication / auth_success (source_ip+port)
  - sshd "Failed password for [invalid user] <u> from <ip>"-> authentication / auth_failure
  - pvedaemon "starting task UPID:..:<dtype>:<vmid>:<u>:"   -> configuration / task_<dtype>
  - pvedaemon "end task UPID:.. OK"                          -> configuration / task_end_<dtype> (success)
(paste the real captured lines here after §2)
