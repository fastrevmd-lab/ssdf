# PAN-OS device timezone → UTC (P2 data-quality fix)

PAN-OS stamps syslog GeneratedTime in the device-local timezone with no offset
field. SSDF's `panos_ecs` transform parses it as naive UTC, so a non-UTC device
skews every `ssdf.events.timestamp` (live finding: EDT ⇒ −4h). SSDF requires
log-source devices to run UTC.

This artifact is applied **once**, out-of-band, via the `panos-mcp` server against
host `panosvm`. SSDF itself never touches device configuration in its data path.

1. Preview the diff:
   ```
   pan_config_diff  host=panosvm
                    xpath=/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system
                    element=<timezone>UTC</timezone>
   ```

2. Load and commit (use the ABSOLUTE xpath — relative xpaths are rejected as
   "Unauthorized request", see STATUS.md M5):
   ```
   load_and_commit_pan_config  host=panosvm  fmt=xml
                               xpath=/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system
                               element=<timezone>UTC</timezone>
   ```

   Record the commit time — it is the backfill cutover (`infra/clickhouse/012`
   runbook in the P2 plan).

Verify (allow one syslog to arrive, e.g. a config commit generates one):

  SELECT max(timestamp), now() FROM ssdf.events WHERE event_provider='paloalto'

max(timestamp) must be within minutes of now(), not ~4h behind.
