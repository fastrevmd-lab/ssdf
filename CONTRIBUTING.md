# Contributing to SSDF

Thanks for considering a contribution. SSDF (Sovereign Security Data Fabric) is
an AI-native security data platform — part of the [mechub](https://github.com/fastrevmd-lab)
family of open-source, self-hosted network-security tooling. See
[README.md](README.md) for the architecture and the two principles that shape
every design decision here: **AI-native, not AI-bolted-on**, and **sovereign**
(all data and inference stay under the operator's own infrastructure — local
ClickHouse, local Vector ingest, swappable LLM/storage backends, no mandatory
SaaS dependency). Nothing you contribute should introduce a hard dependency on
an external/cloud SIEM, XDR platform, or cloud-only LLM API.

This project also follows the hard rule that applies across the whole mechub
fleet: **deterministic code decides, a model may explain, a human approves.**
LLM/agent output may draft, summarize, or explain; it must never be the thing
that directly decides a security-relevant outcome (an ingest rule, an access
grant, a query result treated as ground truth) without deterministic code and
a human in the loop.

## Before you start

- Check open issues and PRs first — someone may already be working on it.
- For anything larger than a small fix, open an issue to discuss the approach
  before writing code.
- **No Docker / no docker-compose.** This repo deliberately runs each
  component (ClickHouse, Vector, nginx, the Python services) as a plain
  systemd unit on its own host in the reference deployment — see the "Stack"
  section of [README.md](README.md). Don't add a docker-compose-based dev
  workflow; it would describe a topology this project doesn't run.

## Repository layout

- `services/*` — independent Python/uv projects: MCP tool servers, resolvers
  (topo, entity, policy, public-metrics, health), evals, and shared code in
  `services/common`. Each has its own `pyproject.toml` and locked `uv.lock`.
- `infra/` — ClickHouse schema (`infra/clickhouse/*.sql`), Vector VRL config,
  nginx, and firewall definitions. Vendor log formats live only in
  `infra/vector/vector.toml`.
- `scripts/` — operational/deployment helpers (schema application, TLS
  generation, lab endpoint generation, etc).
- `onboarding/` — per-vendor (SRX, PAN-OS, UniFi, Proxmox) ingest onboarding
  docs.
- `docs/` — architecture and audit-evidence contract docs.
- `tests/fixtures/` — shared synthetic fixtures.

## Setup

Requires Python 3.12 and [`uv`](https://docs.astral.sh/uv/) (the exact
toolchain — `python`, `uv`, `ruff`, `just`, `pre-commit`, `trivy`, etc. — is
pinned in `mise.toml` if you use [mise](https://mise.jdx.dev/)). Then:

```sh
just setup
```

This syncs every `services/*` project (`uv sync --all-extras --locked`) and
installs the pre-commit hooks (`.pre-commit-config.yaml`: whitespace/merge
hygiene, `ruff-check` + `ruff-format --check`, and `gitleaks` secret
scanning).

There is no single "run the app" command — SSDF is a set of independent
services. To run one locally:

```sh
cd services/mcp-query && uv run python -m ssdf_mcp_query.server
```

Each service directory has its own `README.md` and `.env.example` with the
config it expects (non-secret defaults only — see `.env.example` at the repo
root and inside each service).

## Lint, format, and test

All from the repo root, via the `justfile`:

```sh
just lint   # ruff check services
just fmt    # git diff --check (whitespace hygiene on the diff)
just test   # for each services/* with a pyproject.toml: uv run pytest -m "not integration" -q
just guard  # lint + test
```

Note that `just fmt` runs `git diff --check`, not `ruff format` — actual
formatting is enforced by the `ruff-format --check` pre-commit hook and by CI.
If you want to check formatting locally before committing, run:

```sh
uvx ruff@0.12.4 format --check services
```

(matching the version pinned in `.pre-commit-config.yaml` and
`.github/workflows/ci.yml`, so it can't disagree with either).

### Tests

Each service under `services/*` has its own `tests/` directory and its own
`pyproject.toml`/`uv.lock` — there is no single top-level Python package.
Standard contributions only need the unit suites (`-m "not integration"`),
which run against fixtures and stubs, not a live ClickHouse.

`services/mcp-query` additionally has a `contract` marker
(`tests/test_sql_contract.py`): these tests run every SQL builder against a
*real* ClickHouse, because the unit suite's fakes only prove "the code called
ClickHouse", not "the SQL is correct". You don't need a local ClickHouse to
contribute — CI runs this job against a throwaway ClickHouse service
container (see `.github/workflows/ci.yml`'s `sql-contract` job) on every pull
request. If you want to run it locally, start any ClickHouse 24.x+ instance
yourself (self-hosted, per this project's sovereignty principle — there's no
bundled compose file), apply the schema with
`python3 scripts/apply_contract_schema.py --host <host> --port <port>`, then
run `uv run pytest tests/test_sql_contract.py -m contract -q` from
`services/mcp-query`.

`integration` (`@pytest.mark.integration`) tests require the real lab fabric
(live ClickHouse, MCP endpoints, or devices) and are not expected from
external contributors:

```sh
CONFIRM_LAB_INTEGRATION=yes just integration
```

There is no browser/end-to-end suite (`just e2e` just says so).

### Dependency/security scanning

`just security` runs `trivy fs --scanners vuln,misconfig,secret .` locally.
CI runs `ruff` and the full per-service test matrix on every pull request —
see `.github/workflows/ci.yml`. As of this PR, CI does not yet run a
dependency-vulnerability audit (e.g. `pip-audit`); see the PR description for
why that wasn't added here.

## Commit and PR conventions

- Match the existing commit style: `type(scope): summary` (`fix(auth):`,
  `feat(evals):`, `chore:`, etc.) — see `git log` for examples.
- Keep PRs focused on one change.
- Fill out the PR template, including the exact commands you ran to verify
  the change. "Should work" is not verification.
- This project does not require a `Signed-off-by` / DCO trailer on commits.
  By opening a pull request, you're agreeing your contribution is licensed
  under this repository's [MIT license](LICENSE).

## Review process

Every pull request goes through a security review and a code review, then an
independent test run, before anything merges. Only a maintainer merges —
contributors, including anyone with write access, should not merge their own
PR. CI (lint and the per-service test matrix, plus the ClickHouse
SQL-contract job) must be green first.

All contributions land as a pull request against `main` — there is no
direct-push path to the default branch.

## Reporting a vulnerability

Please don't open a public issue for a security vulnerability — see
[SECURITY.md](SECURITY.md) for how to report one privately.

## Fixtures and data handling

SSDF's whole reason for existing is to hold other people's security
telemetry (firewall/NGFW/SASE/IDaaS logs, topology, audit trails). Never
commit real device configs, hostnames, serial numbers, credentials, or real
security telemetry/logs pulled from an actual environment — use or extend the
synthetic fixtures under `tests/fixtures/`. If you find real data already
committed anywhere in this repo, don't add to it — report it privately
instead (see [SECURITY.md](SECURITY.md)).
