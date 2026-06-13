# UniFi Gateway Max — Suricata IPS + traffic flows → SSDF (M9 onboarding)

SSDF ingests UniFi IPS/IDS alerts + traffic flows via remote syslog (the gateway's
flow-query API is unavailable on this controller — every v2 traffic-flows endpoint
404s, confirmed 2026-06-13). SSDF never applies device config in its own data path;
the steps below are applied by the operator in the UniFi Network application.

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
