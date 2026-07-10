# Python services instructions

- Each child service is an independent Python 3.12 uv project with its own lock.
- Keep unit tests offline and mark live tests `integration`.
- Bound ClickHouse and MCP I/O with timeouts; validate and redact all external
  data. Never log credentials, raw private configurations, or pseudonym keys.
- Preserve classification, authorization, de-identification, provenance, and
  tamper-evident audit behavior at service boundaries.
- Run the changed service's lint and non-integration tests before the root gate.
