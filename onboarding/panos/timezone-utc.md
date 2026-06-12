# PAN-OS device timezone → UTC (P2 data-quality fix)

PAN-OS stamps syslog GeneratedTime in the device-local timezone with no offset
field. SSDF's `panos_ecs` transform parses it as naive UTC, so a non-UTC device
skews every `ssdf.events.timestamp` (live finding: EDT ⇒ −4h). SSDF requires
log-source devices to run UTC.

Apply via panos-mcp (`load_and_commit_pan_config`, fmt=xml, ABSOLUTE xpath —
relative xpaths are rejected as "Unauthorized request", see STATUS.md M5):

  xpath:   /config/devices/entry[@name='localhost.localdomain']/deviceconfig/system
  element: <timezone>UTC</timezone>

Preview first with `pan_config_diff`, then commit. Record the commit time —
it is the backfill cutover (`infra/clickhouse/012` runbook in the P2 plan).

Verify (allow one syslog to arrive, e.g. a config commit generates one):

  SELECT max(timestamp), now() FROM ssdf.events WHERE event_provider='paloalto'

max(timestamp) must be within minutes of now(), not ~4h behind.
