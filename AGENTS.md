# SSDF repository instructions

## Purpose and architecture

SSDF is a sovereign security data fabric. `services/` contains independent
Python/uv collectors, resolvers, MCP tiers, entity/policy logic, health, public
metrics, and evaluations. `infra/` contains ClickHouse, Vector, nginx, and
firewall definitions; `scripts/` contains deployment/operations helpers;
`onboarding/` documents data sources. ClickHouse writes, firewall rules, MCP
auth, de-identification, audit chains, TLS, and deployment scripts are high risk.

## Setup and development

- Install the golden workstation baseline and run `just setup`.
- Each `services/*` directory is its own locked uv project. Run commands from
  the service directory or through the root `justfile`.
- Use fixtures for unit work. Live ClickHouse, MCP, Proxmox, and device checks
  belong only in the explicitly confirmed integration target.

## Required checks

- Offline: `just fmt`, `just lint`, `just test`, and `just guard`.
- Live lab: `just integration` with `CONFIRM_LAB_INTEGRATION=yes`; review each
  service because entity, policy, eval, and audit tests may write lab data.
- No browser E2E suite exists; `just e2e` records that exception.
- Run `just security` and `just release-check` before handoff.

## Generated files and dependencies

- Commit each service's `pyproject.toml` and `uv.lock` together. Do not hand-edit
  locks, generated TLS, scorecards/results, caches, or database output.
- Keep shared library source mappings explicit and reproducible.

## Secrets and infrastructure safety

- Never commit ClickHouse/MCP/device credentials, private TLS keys, pseudonym
  keys, raw configurations, audit data, or production telemetry.
- Default scripts and examples to validation, dry-run, plan, or read-only mode.
- Do not apply nftables, schemas, services, backups, TLS, or deployment changes
  without explicit approval, exact target, rollback steps, and verification.

## Completion evidence

Report files changed, service checks/results, skipped live checks, schema/data
impact, rollback considerations, and remaining risk.
