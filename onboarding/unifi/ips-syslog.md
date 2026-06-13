# UniFi Gateway Max — Suricata IPS + traffic flows → SSDF (M9 onboarding)

SSDF ingests UniFi IPS/IDS alerts + traffic flows via remote syslog (the gateway's
flow-query API is unavailable on this controller — every v2 traffic-flows endpoint
404s, confirmed 2026-06-13). SSDF never applies device config in its own data path;
the steps below are applied by the operator in the UniFi Network application.

> **VRL is built on a SYNTHETIC baseline, not captured traffic.** The `unifi_ips`
> transform + its `vector test` fixtures assume standard Suricata **EVE JSON** over
> RFC5424 syslog (hostname `gatewaymax`, `event_type: "alert"|"flow"`). This has NOT
> been validated against the real gateway. In step 3/4 below, capture real lines and
> **re-validate the transform**: if the wire format differs (different syslog header,
> a process tag before the JSON, `event_type: "ids"`, different flow keys), update both
> §4 here AND the `[[tests]]` fixtures in `infra/vector/vector.toml`, then re-run
> `vector test` before declaring M9 live (Task 9 Step 3).

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
After one alert/flow arrives, on ct102:
  tcpdump -n -A -i any udp port 516 -c 5
Record:
  - GATEWAY_HOSTNAME = <short hostname the gateway stamps>  (e.g. gatewaymax)
  - GATEWAY_SRC_IP   = <source IP of the udp/516 packets>   (e.g. 198.51.100.1)
  - WIRE_FORMAT      = EVE-JSON | other  (paste one full alert line + one flow line)

## 4. Captured samples (paste real lines — these become the VRL unit-test fixtures)
ALERT:  <paste>
FLOW:   <paste>
