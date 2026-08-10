# Junos SYSTEM syslog → SSDF (M14c P3 onboarding)

SSDF ingests vSRX fleet SSH auth + config commits/rollbacks via device `system syslog host`
config. SSDF never configures the source in its own data path; the operator applies the
device config via rust-junosmcp (the controller).

## 0. Verify the device clock is accurate + in UTC (do this FIRST)
SSDF stores event time from the syslog timestamp. Run on the target device:
  show system uptime
The live fleet runs NTP-synced UTC. An accurate UTC clock is ideal, but **not required**
for Junos SYSTEM streams (RFC5424 includes the UTC offset). What matters is that the
clock is **not skewed** (NTP-synced).

## 1. Device config (forward to Vector ct102 on UDP 518)

**Check which case the device is in FIRST — the routing-instance line is conditional:**

```
show configuration system management-instance
```

### Case A — `management-instance;` is configured (fxp0 lives in mgmt_junos)

```
set system syslog host 198.51.100.150 any info
set system syslog host 198.51.100.150 port 518
set system syslog host 198.51.100.150 structured-data
set system syslog host 198.51.100.150 routing-instance mgmt_junos
```

`routing-instance mgmt_junos` is **required here**. fxp0 lives in the `mgmt_junos`
routing-instance, so without this line the syslog egresses the default routing-instance
(where fxp0 is not reachable) and nothing arrives at Vector. Proven live on vsrx-ci
2026-07-06 — adding the line immediately unblocked the stream.

### Case B — no management-instance (fxp0 lives in the default routing-instance)

```
set system syslog host 198.51.100.150 any info
set system syslog host 198.51.100.150 port 518
set system syslog host 198.51.100.150 structured-data
```

**Omit the routing-instance line.** With fxp0 in the default instance, 198.51.100.0/24 is
directly connected in inet.0 and syslog egresses correctly on its own. Adding the line here
does not merely fail to help — the commit is **rejected** with
`Routing-instance must be defined`, because `mgmt_junos` does not exist on these devices.

Verified live 2026-07-19 on vsrx-dmz: 7 packets captured on ct102
(`198.51.100.224.514 > 198.51.100.150.518 SYSLOG auth.info`) with no routing-instance
configured.

**Which devices are in Case B:** vsrx-dmz, vsrx-campus-a, vsrx-br05, vsrx-br08, vsrx-dc.
These had `management-instance` removed on 2026-07-19 during the Recovery Mode recovery
(see the caution below). The rest of the fleet remains Case A.

### Caution: do NOT pin the dynamic-address feed-server to mgmt_junos

Related trap in the same area. This line is **boot-fatal** and must never be committed:

```
set security dynamic-address feed-server <name> routing-table mgmt_junos.inet   # DO NOT
```

A `routing-table` reference requires its routing-instance to already exist at validation
time. Committed interactively it validates fine, because mgmt_junos was committed earlier.
But at boot Junos validates the whole config in a single pass, fails with
`Error routing table mgmt_junos.inet cannot find`, **auto-activates Recovery Mode, and rolls
the device back** to the last config that loads — silently discarding everything since.

This took down 19 fleet devices on 2026-07-10 when pve3 rebooted; the bad line had been
committed on 07-04 and sat dormant for six days. Devices reverted past the m14 fleet rename
and dropped off their inventory addresses entirely, requiring console recovery.

Symptom to look for: `show system commit` showing `Junos has activated Recovery Mode` a
minute or two after boot. Upstream skill bug: fwskillsshare#18.

If feeds need to reach a feed server over fxp0, remove `management-instance` instead so
fxp0 sits in the default instance (Case B) — that is what the five Case B devices did, and
their feeds work.

### Both cases

The legacy RT_FLOW security logs (UDP 514) use stream-mode via the data-plane interface
(ge-0/0/0, no routing-instance needed) regardless of case; only SYSTEM syslog egresses fxp0.

## 2. Verify on the wire
On ct102:  tcpdump -n -A -i any udp port 518 -c 20
Trip an event (e.g. from another host: `ssh baduser@vsrx-ci` with a wrong password) and
confirm the line arrives. A successful commit from the NETCONF-based MCP collector also
emits a UI_COMMIT line.

## 3. What is kept vs. dropped (see the VRL filter gate)
**Kept** (auth + config audit):
  - SSHD_LOGIN_FAILED, SSHD_LOGIN_ATTEMPTS_THRESHOLD (structured SSH failure lines)
  - sshd/sshd-session "Accepted ..." freeform lines (SSH success; structured msgid not guaranteed)
  - UI_LOGIN_EVENT, UI_LOGOUT_EVENT, UI_AUTH_EVENT (Junos UI/NETCONF auth events)
  - UI_COMMIT, UI_COMMIT_COMPLETED, UI_COMMIT_NOT_CONFIRMED, UI_ROLLBACK_EVENT (commits/rollbacks)
  - UI_CFG_AUDIT_SET, UI_CFG_AUDIT_OTHER (per-stanza configuration changes)

**Dropped** (high-volume noise):
  - UI_COMMIT_PROGRESS (~25 lines per commit, "Obtaining lock for commit", etc.)
  - UI_NETCONF_CMD, UI_CMDLINE_READ_LINE (every 5-min MCP collector poll emits these — a firehose)
  - sshd "Failed password for ..." freeform companions (SSHD_LOGIN_FAILED already carries user+source)
  - cron/daemon system logs (not security-relevant)

The live fleet's 5-min MCP collector polls would flood ssdf.events with UI_NETCONF_CMD
lines (every rust-junosmcp `get_junos_config` or `execute_junos_command` emits 1-2 per device).
Dropping them at the filter gate keeps only the actionable audit stream.

## 4. Deployment-specific values
  - VECTOR_IP       = **198.51.100.150** (ct102 LAN IP)
  - VECTOR_UDP_PORT = **518** (Junos SYSTEM; 514=SRX security, 515=PAN-OS, 516=UniFi, 517=Proxmox)
  - SOURCE_RANGES   = 198.51.100.219-245 (full fleet) + 198.51.100.150-175 (data-plane range)
                      (nft allow-list on ct102; see infra/firewall/ct102-ingest.nft)

## 5. Captured samples (real lines from live-proof 2026-07-06 — the VRL test fixtures)
parse_syslog yields msgid + structured-data; the junos_sys_ecs transform maps them as:
  - SSHD_LOGIN_FAILED [username="u" source-address="ip"]             -> authentication / auth_failure
  - SSHD_LOGIN_ATTEMPTS_THRESHOLD [limit="3" username="u"]           -> authentication / auth_attempts_threshold
  - sshd "Accepted <method> for <u> from <ip> port <p>"              -> authentication / auth_success
  - UI_LOGIN_EVENT / UI_LOGOUT_EVENT / UI_AUTH_EVENT [username="u"]  -> auth_login / auth_logout / auth_event
  - UI_COMMIT [username="u" command="commit" message="..."]          -> configuration / configuration_commit
  - UI_COMMIT_COMPLETED                                              -> configuration / configuration_commit_completed
  - UI_COMMIT_NOT_CONFIRMED                                          -> configuration / configuration_commit_rollback (outcome=failure)
  - UI_ROLLBACK_EVENT [username="u"]                                 -> configuration / configuration_rollback
  - UI_CFG_AUDIT_SET [username="u" pathname="..." data="..."]        -> configuration / configuration_change

Real captured wire lines (RFC5424 UTC Z timestamps, junos@2636... structured-data):
  <37>1 2026-07-06T03:50:42.589Z vsrx-ci sshd - SSHD_LOGIN_FAILED [junos@2636.1.1.1.2.129 username="baduser" source-address="198.51.100.148"] Login failed for user 'baduser' from host '198.51.100.148'
  <38>1 2026-07-06T03:50:42.590Z vsrx-ci sshd 4139 - - Failed password for baduser from 198.51.100.148 port 59308 ssh2
  <37>1 2026-07-06T03:51:07.617Z vsrx-ci sshd - SSHD_LOGIN_ATTEMPTS_THRESHOLD [junos@2636.1.1.1.2.129 limit="3" username="baduser"] Threshold for unsuccessful authentication attempts (3) reached by user 'baduser'
  <189>1 2026-07-06T03:52:49.972Z vsrx-ci mgd 97400 UI_COMMIT [junos@2636.1.1.1.2.129 username="netconf" command="commit" message="m14c canary commit C (capture UI_COMMIT lines)"] User 'netconf' requested 'commit' operation (comment: m14c canary commit C (capture UI_COMMIT lines))
  <182>1 2026-07-06T03:52:49.931Z vsrx-ci mgd 97400 UI_CFG_AUDIT_SET [junos@2636.1.1.1.2.129 username="netconf" action="set" pathname="[system login message\]" delimiter="\"" data="m14c commit capture" value="m14c commit capture"] User 'netconf' set: [system login message] "m14c commit capture -- "m14c commit capture"

Dropped UI_COMMIT_PROGRESS example (flooded progress messages during the commit):
  <190>1 2026-07-06T03:52:49.974Z vsrx-ci mgd 97400 UI_COMMIT_PROGRESS [junos@2636.1.1.1.2.129 message="Obtaining lock for commit"] Commit operation in progress: Obtaining lock for commit

Dropped UI_NETCONF_CMD example (every MCP collector poll emits these):
  <190>1 2026-07-06T03:52:49.930Z vsrx-ci mgd 97400 UI_NETCONF_CMD [junos@2636.1.1.1.2.129 username="netconf" command="lock cannot reconstruct arguments"] User 'netconf' used NETCONF client to run command 'lock cannot reconstruct arguments'

Dropped cron noise:
  <78>1 2026-07-06T03:51:00.003Z vsrx-ci /usr/sbin/cron 16860 - - (*system*) RELOAD (/etc/crontab)

## 6. Verification SQL (run once events land in ssdf.events)
On a ClickHouse client:
  SELECT event_action, user_name, observer_hostname, count()
  FROM ssdf.events
  WHERE event_provider = 'juniper' AND event_category = ['authentication']
  AND timestamp >= now() - INTERVAL 1 HOUR
  GROUP BY event_action, user_name, observer_hostname
  ORDER BY count() DESC;

A commit-bearing query:
  SELECT event_action, user_name, ext."junos.sys.commit_message"
  FROM ssdf.events
  WHERE event_provider = 'juniper' AND event_category = ['configuration']
  AND event_action = 'configuration_commit'
  ORDER BY timestamp DESC LIMIT 10;

## 7. Rollback (remove the syslog host config)
Apply via rust-junosmcp:
  delete system syslog host 198.51.100.150
Commit. The nft allow-list on ct102 stays — it harms nothing when the source is silent.
