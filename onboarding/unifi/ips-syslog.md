# UniFi Gateway Max — Suricata IPS + traffic flows → SSDF (M9 onboarding)

SSDF ingests UniFi IPS/IDS alerts + traffic flows via remote syslog (the gateway's
flow-query API is unavailable on this controller — every v2 traffic-flows endpoint
404s, confirmed 2026-06-13). SSDF never applies device config in its own data path;
the steps below are applied by the operator in the UniFi Network application.

> **VRL is now built on CAPTURED traffic (2026-06-14), not the original synthetic
> baseline.** The earlier assumption (Suricata **EVE JSON** over RFC5424, host
> `gatewaymax`) was WRONG. Reality: the Cloud Key controller (198.51.100.30) forwards
> the SIEM export as **CEF** (Common Event Format) "Threat Detected" events with NO
> syslog PRI; the Gateway Max (198.51.100.1) only emits RFC3164 system-log noise on the
> same port. The `unifi_ips` transform parses CEF via `parse_cef`, gated by the
> `unifi_cef_threat` filter, and its `[[tests]]` fixtures in `infra/vector/vector.toml`
> are the real captured lines below (§4). Re-validate with `vector test` on any UniFi
> Network upgrade that changes the CEF schema (DeviceVersion currently `10.68.57`).

## 0. Verify the gateway clock is UTC (do this FIRST)
SSDF stores event time from the Suricata `timestamp` field. PAN-OS previously shipped
local-time logs and forced a painful UTC backfill (see CLAUDE.md "PAN-OS timestamps
fixed to UTC"). Set the Gateway Max system timezone to **UTC**, or confirm the captured
EVE `timestamp` carries the correct `%z` offset (e.g. `+0000`). A wrong/missing offset
stores skewed timestamps — fix the device clock before relying on parsed times.

## 1. Enable Threat Management (Suricata IPS/IDS)
UniFi Network → Settings → Security → Threat Management → enable
(Detection or Detection+Prevention). This starts Suricata on the Gateway Max.

## 2. Enable remote syslog with IPS alerts + flows
UniFi Network → Settings → System → Logging / Remote Logging:
  - Server:  198.51.100.150   Port: 516   Protocol: UDP
  - Enable "IPS/IDS alerts" (or "Debug"/contents that include Suricata events)
  - Enable traffic/flow logging if presented as a separate toggle

## 3. Record deployment-specific values (used by the VRL + nftables)
Captured live 2026-06-14 by tripping a behavioral ET SCAN rule (an outbound port
sweep) — payload-based test signatures (EICAR/testmyids/GPL SIDs) do NOT fire on
this box: the ruleset is ET-only and hardware flow-offload bypasses DPI for
established flows, so use a behavioral SCAN rule to generate a detection. Capture
on ct102 with:
  tcpdump -n -A -i any udp port 516 -c 20
Recorded values:
  - SENDER_HOSTNAME = UCK-G2-Plus-HarmanHoldfast  (the Cloud Key controller —
                      it forwards the SIEM/CEF export, NOT the Gateway Max)
  - SENDER_SRC_IP   = 198.51.100.30                 (controller; nft allow-list source)
  - WIRE_FORMAT     = CEF (Common Event Format), NOT Suricata EVE-JSON.
                      Controller CEF lines carry NO syslog PRI. The same UDP/516
                      port also receives the Gateway Max's own RFC3164 system logs
                      (<pri>... UXGMax ...) from 198.51.100.1 — those are not
                      security events and the unifi_cef_threat filter drops them.
  - TROUBLESHOOTING: the gateway's syslog-ng disk-buffer can replay a stale backlog
                     after a reboot/toggle (drains ~5 msg/min); the controller CEF
                     stream is separate and real-time, so threat events are not
                     affected by that backlog.

UTC check (§0): UNIFIutcTime is clean ISO-8601 UTC with a trailing Z
(e.g. 2026-06-14T19:49:59.858Z) — the VRL stores event time from it, so no
device-clock backfill was needed.

## 4. Captured samples (real lines — these are the VRL unit-test fixtures in vector.toml)
The CEF extension carries scan endpoints by MAC + alias only (no client IPs), so
source_ip/destination_ip stay null and identity rides ext.*. Header severity, the
ET signature/SID, ports, bytes, and zones map to the ECS event.

ALERT (SID 2003068, ET SCAN Potential SSH Scan OUTBOUND, CEF sev 7):
  Jun 14 19:49:59 UCK-G2-Plus-HarmanHoldfast CEF:0|Ubiquiti|UniFi Network|10.68.57|200|Threat Detected|7|UNIFIcategory=Security UNIFIsite=Default UNIFIhost=UCK G2 Plus HarmanHoldfast proto=TCP spt=38738 dpt=22 act=allowed app=SSH UNIFIrisk=medium UNIFIpolicyName=Scanning Activity UNIFIpolicyType=IDS/IPS UNIFIdirection=outgoing deviceOutboundInterface=Internet 1 UNIFIdeviceMac=02:00:01:27:fb:2b UNIFIdeviceName=Gateway Max UNIFIdeviceModel=Gateway Max UNIFIdeviceIp=198.51.100.1 UNIFIdeviceVersion=5.0.16 UNIFIsrcClientAlias=ssdf-vector UNIFIsrcClientMac=02:01:01:02:a1:46 UNIFIsrcClientModel=Windows PC UNIFIsrcZone=Internal UNIFIdstClientAlias=02:00:01:27:fb:2c UNIFIdstClientMac=02:00:01:27:fb:2c UNIFIdstRegion=US UNIFIdstZone=External UNIFItotalBytes=74 UNIFItotalPackets=1 UNIFIpacketsReceived=0 UNIFIpacketsSent=1 UNIFIbytesReceived=0 UNIFIbytesSent=74 UNIFIflowCount=1 UNIFIflowId=null UNIFIflowStartTime=Jun 14, 2026 at 7:48:50.822 PM UNIFIipsSessionId=1190371755462149 UNIFIipsSignature=ET SCAN Potential SSH Scan OUTBOUND UNIFIipsSignatureId=2003068 UNIFIutcTime=2026-06-14T19:49:59.858Z msg=A network intrusion attempt from ssdf-vector to 02:00:01:27:fb:2c has been detected.

ALERT (SID 2013479, ET SCAN Behavioral ... Terminal Server ... Outbound, CEF sev 3):
  Jun 14 19:49:59 UCK-G2-Plus-HarmanHoldfast CEF:0|Ubiquiti|UniFi Network|10.68.57|200|Threat Detected|3|UNIFIcategory=Security ... proto=TCP spt=51002 dpt=3389 act=allowed app=Other UNIFIrisk=low UNIFIpolicyName=Scanning Activity ... UNIFIipsSignature=ET SCAN Behavioral Unusually fast Terminal Server Traffic Potential Scan or Infection (Outbound) UNIFIipsSignatureId=2013479 UNIFIutcTime=2026-06-14T19:49:59.884Z ...

NOTE: there is no separate "FLOW" wire format on this controller — the SIEM export
emits only CEF "Threat Detected" security events (the v2 traffic-flow API is 404 on
this controller, per the header). M9 ingests IPS detections only.
