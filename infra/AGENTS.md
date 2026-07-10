# Infrastructure instructions

- Treat ClickHouse, Vector, nginx, firewall, and TLS files as production-shaped
  infrastructure even when targeting the lab.
- Validate/render/diff by default. Never apply without explicit approval and a
  target-specific rollback plan.
- Keep secrets out of definitions; local PKI private material stays ignored.
- Preserve least privilege, TLS verification, loopback bindings, source
  allowlists, rate limits, audit retention, and data classification boundaries.
