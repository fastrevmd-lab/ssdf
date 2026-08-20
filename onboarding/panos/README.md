# PAN-OS log-forwarding onboarding — SSDF M3

## What this does

Applies a syslog forwarding configuration to `panosvm` (PAN-OS 12.1.5, PA-VM) that
routes **all log types** — traffic, threat, URL, WildFire, data, tunnel, auth,
decryption, system, config, correlation, GlobalProtect, HIP match — to the SSDF
Vector collector at `198.51.100.150` UDP port **515** (LXC guest 700 (was ct102)).

Logs arrive in BSD syslog format (PAN-OS default CSV payload). The `panos_ecs`
VRL transform in `infra/vector/vector.toml` normalises them into `ssdf.events`
with `event_provider = 'paloalto'`.

## Prerequisite

The `panos_syslog` UDP:515 source **must be live on Vector guest 700 (was ct102)** before applying
this config. Confirm with:

```
ssh root@pve2.example.com "pct exec 700 -- ss -ulnp | grep 515"
```

## How to apply

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
   pan_config_diff  host=panosvm  config=onboarding/panos/log-forwarding.set
   ```

2. Load and commit:
   ```
   load_and_commit_pan_config  host=panosvm  config=onboarding/panos/log-forwarding.set
   ```

   Alternatively, if using `render_and_apply_j2_template` with no substitutions
   needed (values are already hardcoded), pass the `.set` file directly as the
   template with an empty variable map.

## Verify after apply

On the firewall (via panos-mcp `execute_panos_op`, renamed from `execute_pan_op`):
```xml
<show><log><traffic><last>20</last></traffic></log></show>
```
Or CLI: `show log traffic`.

Confirm rows reach ClickHouse (on guest 701 (was ct104)):
```sql
SELECT timestamp, source_ip, destination_ip, rule_name
FROM ssdf.events
WHERE event_provider = 'paloalto'
ORDER BY timestamp DESC
LIMIT 10;
```

Also queryable through the M2 MCP read server on guest 702 (was ct106) (`198.51.100.152:30032`).
