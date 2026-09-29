## Summary

<!-- What does this PR do, and why? -->

## Changes

<!-- Bullet list of what changed -->

## Verification

<!-- Exact commands you ran and their result. "Should work" is not verification. -->

```sh

```

## Checklist

- [ ] `ruff check services` and `ruff format --check services` pass (or the
      relevant pre-commit hooks)
- [ ] Unit tests added or updated for this change, and they fail against the
      old code (`uv run pytest -m "not integration" -q` in the affected
      `services/*` directory)
- [ ] If this touches an ingestion or data-handling path (Vector/VRL config,
      a ClickHouse schema file, a resolver, or an MCP tool that reads/writes
      `ssdf.events`, `ssdf.entities`, `ssdf.entity_edges`, or `ssdf.audit`):
      called out explicitly below, including what changes for existing data
- [ ] Any example/fixture/test data added or changed is synthetic — never
      real security telemetry, logs, hostnames, serials, or credentials from
      an actual environment
- [ ] No secrets, credentials, real hostnames, serials, or real device/host
      configs in code, tests, fixtures, or this description
- [ ] No new telemetry, analytics, or outbound network call added, and no new
      hard dependency on an external/cloud SaaS service
- [ ] If this touches a path that can influence a security decision: it
      remains true that deterministic code decides and a human approves — a
      model's output is not wired to act directly

## Anything you're unsure about

<!-- Flag it here rather than hoping review catches it -->
