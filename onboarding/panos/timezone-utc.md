# PAN-OS device timezone → UTC (P2 data-quality fix)

PAN-OS stamps syslog GeneratedTime in the device-local timezone with no offset
field. SSDF's `panos_ecs` transform parses it as naive UTC, so a non-UTC device
skews every `ssdf.events.timestamp` (live finding: EDT ⇒ −4h). SSDF requires
log-source devices to run UTC.

This artifact is applied **once**, out-of-band, via the `panos-mcp` server against
host `panosvm`. SSDF itself never touches device configuration in its data path.

> **These apply steps are stale and NOT runnable as written.** `pan_config_diff` and
> `load_and_commit_pan_config` were retired in the 2026-08-15 prod rename. The server
> now exposes an approval-gated change-set lifecycle (`get_candidate_fingerprint` →
> `create_panos_change_set` → `get_panos_change_set` → `approve_panos_change_set` →
> `apply_panos_change_set` → `diff_panos_candidate` → `validate_panos_candidate` →
> `commit_panos_candidate`). That API takes structured XPath/XML actions, not a
> set-format CLI file, so porting this artifact is real work rather than a rename —
> deliberately left undone rather than guessed at. Do NOT substitute
> `stage_panos_config`: it is the legacy direct-write path and bypasses independent
> approval. Read-only verification below is correct and current.


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

   Record the commit time — it is the **starting point** for choosing the
   backfill cutover. The actual cutover must be determined by boundary
   inspection (see `infra/clickhouse/012_backfill_paloalto_utc.sql.example`)
   because rows emitted during the commit window are already UTC-stamped and
   the commit time alone is not a safe cutover boundary.

Verify (allow one syslog to arrive, e.g. a config commit generates one):

  SELECT max(timestamp), now() FROM ssdf.events WHERE event_provider='paloalto'

max(timestamp) must be within minutes of now(), not ~4h behind.
