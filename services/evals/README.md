# ssdf-evals — M8 agent-eval harness (SSDF side)

SSDF builds **up to the MCP layer only**. This package owns the golden corpus,
the run-manifest contract, the deterministic scorer, scorecards, and the
regression gate. **Runner projects** (external repos) own the MCP client
harnesses (Claude Agent SDK, Ollama tool-calling, ...), model choice, run
cadence, and pass-rate policy.

Spec: `docs/superpowers/specs/2026-06-12-ssdf-m8-eval-harness-design.md`.

## The contract (3 versioned artifacts)

1. `golden/core.yaml` — the questions. Runner sends each `question` to its
   agent with `answer_format` appended **verbatim**, and records the agent's
   final JSON answer.
2. `schemas/manifest.schema.json` — what the runner hands back (one JSON file
   per run).
3. `schemas/scorecard.schema.json` — what the scorer emits into `results/`.

## Runner obligations

- Use a **dedicated eval principal token** (e.g. `eval-claude`, `eval-qwen`)
  added to the tier's `tokens.json` with expiry — never the regular agent
  token. `ssdf.audit` is the only trusted tool trace; self-reported tool calls
  are ignored.
- Bind to the real prod path: `https://198.51.100.152:30032/mcp` (sovereign) or
  `https://198.51.100.154:30033/mcp` (public) with `ssdf-ca.crt` trust — evals
  exercise prod auth by construction.
- Record per-question UTC `started`/`finished` (the scorer joins ssdf.audit on
  principal + this window ± `EVAL_AUDIT_SLOP_SECS`, default 5s).
- Run-tier subset: `sovereign` runs answer `tier: sovereign|both` questions;
  `public` runs answer `tier: public|both`.
- **IMPORTANT — audit integrity:** the audit tool-check trusts manifest
  `started`/`finished` + principal. This guarantee only holds if each run uses
  a **dedicated, per-run-unique eval principal** (e.g. `eval-claude`) and
  honest timestamps. SSDF treats a shared or reused principal's audit window as
  untrustworthy — a shared principal can mix audit rows from concurrent or
  adjacent runs, invalidating the tool-call trace.

## Scoring a run

    cd services/evals
    CH_HOST=<ct104> CH_PORT=8443 CH_SECURE=1 CH_CA_FILE=<ssdf-ca.crt> \
      CH_PASSWORD=<ssdf_ro pw> CH_AUDIT_VERIFY_PASSWORD=<ssdf_audit_verify pw> \
      uv run python -m ssdf_evals.score /path/to/manifest.json

Exit 0 = scored (scorecard written to `results/`, commit it — history is the
database). Exit 2 = config/contract error.

A question passes only if its predicate **and** its audit tool-check pass.
Fail-closed: missing question = fail, runner error = fail, SQL error = fail.

## Regression gate

    uv run python -m ssdf_evals.regress results/<new-scorecard>.json

Exit 1 if any question that **ever passed for that model** now fails. No
thresholds here — pass-rate floors (incl. the local-model sovereignty floor)
are runner-project policy.

## Tests

    uv run pytest -m "not integration"      # unit + corpus lint
    CH_HOST=... uv run pytest -m integration  # live corpus-SQL + audit join
