# M8 — Agent-Eval Harness (SSDF side, up to the MCP layer) — Design

**Date:** 2026-06-12
**Status:** Approved design (brainstorm complete)
**Charter:** `docs/superpowers/plans/2026-06-12-ssdf-next-phase-roadmap.md` Phase 2

## Scope constraint (governs everything below)

This repo builds **only up to the MCP layer**. The charter's two runners (Claude via
Agent SDK, local Ollama tool-calling model) move to **external runner projects** that tie
in via MCP. SSDF owns: the golden corpus, the run-manifest contract, the deterministic
scorer, the audit-trail tool check, scorecard artifacts, and the regression gate. Runner
projects own: model selection, MCP client harnesses, run cadence, and pass-rate policy
(including the sovereignty floor — SSDF supplies the data for that claim, not the policy).

## Locked decisions (brainstorm answers)

1. **Contract = run-manifest file.** Runner writes a manifest JSON; SSDF's scorer CLI
   consumes it. No eval MCP tools, no eval write-paths on the query servers.
2. **Scoring is 100% deterministic.** No LLM-judge anywhere in this repo. Questions
   needing judgment are written as checkable predicates or don't enter the corpus.
3. **One corpus, tier-tagged per question** (`sovereign | public | both`). Runners pick
   the subset; the scorer validates tool usage against the tier's allowed surface.

## Architecture

New package `services/evals` (uv + pytest, same conventions as entity/policy/topo).
Nothing deploys — it is an operator-run CLI pair (`score`, `regress`).

```
SSDF repo owns                          │  Runner projects own
                                        │
golden corpus (golden/*.yaml) ──────────┼──► runner binds model to MCP endpoint
manifest JSON-schema (contract) ────────┼──► runner executes questions, writes
                                        │     run-manifest JSON
scorer CLI  ◄───────────────────────────┼─── manifest handed back
  ├─ predicates vs live CH (ssdf_ro)    │
  ├─ tool-usage check vs ssdf.audit     │
scorecard JSON (results/, committed)    │
regression gate CLI (exit code)         │
```

**The contract is three versioned artifacts**, all living in this repo:
corpus schema, manifest schema, scorecard schema.

## Component 1 — Golden corpus

`services/evals/golden/core.yaml` — 20–30 questions across the charter's five seed
categories: reachability/policy, flows (exercises the UTC fix), topology, change,
honesty (refusal correctness).

Per-question schema:

```yaml
- id: flows-top-talkers-24h          # stable, unique, kebab-case
  question: "Who were the top 3 talkers by bytes in the last 24 hours?"
  tier: sovereign                     # sovereign | public | both
  category: flows                     # reachability | flows | topology | change | honesty
  difficulty: medium                  # easy | medium | hard
  answer_format: >                    # runner appends to the prompt VERBATIM
    Answer with JSON: {"talkers": [{"ip": "<str>", "bytes": <int>}, ...]}
  required_tools: [top_talkers]       # ≥1 of each listed tool must appear in the
                                      # question's audit window
  predicate:
    type: reference_sql               # reference_sql | expected_json | refusal
    sql: "SELECT source_ip, sum(network_bytes) AS b FROM ssdf.events ... LIMIT 3"
    match: set_overlap                # exact | set_overlap | numeric_tolerance
    params: {min_overlap: 2}          # match-mode-specific knobs
```

Key decision: **structured answers, not free text.** `answer_format` is a verbatim
prompt suffix instructing the agent to emit JSON; the manifest carries that JSON as the
agent's final answer. This is what makes deterministic-only scoring possible.

Predicate types:
- `reference_sql` — ground truth computed **at scoring time** against live CH (the lab
  is live data; static expected answers would rot). Match modes: `exact`,
  `set_overlap`, `numeric_tolerance`.
- `expected_json` — static expected value, for stable facts (e.g. "which firewall
  governs segment X").
- `refusal` — honesty questions: passes iff `answer.refusal == true` (the agent
  correctly states it has no data for the question).

Corpus constraints (enforced by a lint test):
- every question schema-valid; ids unique
- `tier: public|both` questions may only list `required_tools` that exist on the
  public tier (topology/identity tools), and their predicates may not require
  sovereign-only data
- every `reference_sql` is read-only SELECT

## Component 2 — Run-manifest schema (the contract)

`services/evals/schemas/manifest.schema.json` (JSON Schema, versioned).

```json
{
  "schema_version": 1,
  "run_id": "2026-06-12-claude-001",
  "model": "claude-opus-4-6",
  "runner": "agent-sdk-runner@<sha>",
  "tier": "sovereign",
  "principal": "eval-claude",
  "corpus_version": "<git sha of corpus at run time>",
  "questions": [
    { "id": "flows-top-talkers-24h",
      "started": "2026-06-12T18:00:01Z",
      "finished": "2026-06-12T18:00:14Z",
      "answer": { "talkers": [ {"ip": "10.74.11.20", "bytes": 12345} ] },
      "error": null }
  ]
}
```

Runner obligations:
- use a **dedicated eval principal token** (e.g. `eval-claude`, `eval-qwen` added to
  `tokens.json` with expiry, per the M7a multi-principal pattern) — never the regular
  agent token, so audit windows are unambiguous
- bind to the **real prod path** (https through the nginx edge, `ssdf-ca.crt` trust) —
  evals exercise prod auth by construction
- record per-question UTC `started`/`finished`
- append `answer_format` to the question prompt verbatim and place the agent's final
  JSON in `answer`

Anything the runner self-reports about tool calls is **ignored** — `ssdf.audit` is the
only trusted tool trace.

## Component 3 — Scorer

`cd services/evals && uv run python -m ssdf_evals.score <manifest.json>`

1. Validate manifest against the schema — malformed ⇒ **exit 2** (config error).
2. Per question, evaluate the predicate. `reference_sql` runs against live CH as
   `ssdf_ro` (standard envs: `CH_HOST`, `CH_PORT=8443`, `CH_SECURE=1`, `CH_CA_FILE`,
   `CH_USER=ssdf_ro`, `CH_PASSWORD`).
3. Tool check: query `ssdf.audit` as the existing **`ssdf_audit_verify`** user
   (`CH_AUDIT_VERIFY_PASSWORD`), `WHERE principal = <manifest.principal> AND ts BETWEEN
   started−slop AND finished+slop` (slop default 5s, env-tunable) — assert
   `required_tools ⊆ observed tools`; for `tier: public` runs additionally assert **no
   sovereign-only tool** appears in any window.
4. A question **passes only if predicate AND tool check pass**. Fail-closed: a question
   in the corpus (for the run's tier) but missing from the manifest = fail; manifest
   `error` set = fail; reference-SQL execution error = fail with reason recorded,
   scoring continues for remaining questions.
5. Emit scorecard `services/evals/results/<UTC-date>-<model>-<run_id>.json`
   (schema: `schemas/scorecard.schema.json`): per-question
   `{id, pass, reasons[], predicate_detail, tools_observed}` plus rollups by
   category/difficulty/tier, corpus version, manifest reference. Scorecards are
   **committed to git** — history is the database; no new storage.

Exit codes: 0 scored (regardless of pass rate), 2 config/schema error.

## Component 4 — Regression gate

`uv run python -m ssdf_evals.regress <new-scorecard.json>`

Scans `results/` history **per model**: any question that ever passed for that model
but fails in the new scorecard ⇒ **exit 1** listing the regressions; else exit 0.
No threshold logic in SSDF — pass-rate floors (including the local-model sovereignty
floor) are runner-project policy. SSDF guarantees the data and the monotonic gate:
"no question that ever passed may silently fail."

Corpus-version note: a question is only compared across scorecards sharing its `id`;
removing or renaming a question is a deliberate, reviewable corpus change.

## Error handling summary

| Condition | Behavior |
|---|---|
| Malformed manifest / unknown schema_version | exit 2, nothing scored |
| Question missing from manifest | scored as fail (fail-closed) |
| Manifest question `error` non-null | fail with runner's error as reason |
| reference_sql raises | fail that question, continue run |
| CH/audit unreachable | exit 2 (can't score honestly without ground truth) |
| Ambiguous predicate result | corpus bug — fix the corpus, not the scorer |

## Testing

- **Unit** (`uv run pytest -m "not integration"`): fixture manifests + mocked CH for
  scorer paths, all predicate match modes, regress logic (incl. per-model isolation and
  removed-question handling), manifest/scorecard schema validation, corpus lint
  (schema, id uniqueness, tier/tool consistency, SELECT-only reference SQL).
- **Integration** (`-m integration`, live CH): every corpus `reference_sql` executes
  and returns a sane shape; audit-join test inserts a synthetic audit window (as
  `ssdf_audit`) and asserts the tool check reads it back.

## Out of scope (owned by runner projects)

- MCP client harnesses (Claude Agent SDK, Ollama tool-calling)
- model choice, run cadence (manual vs timer), pass thresholds / sovereignty floor policy
- any LLM-judge scoring
- CI wiring of runs (this repo only provides `score`/`regress` exit codes to wire)

## Deliverables checklist

1. `services/evals` package scaffold (uv, pytest markers, README with the contract)
2. `schemas/manifest.schema.json` + `schemas/scorecard.schema.json` (v1)
3. `golden/core.yaml` — 20–30 questions, five categories, tier-tagged
4. `ssdf_evals.score` CLI + predicate engine + audit tool-check
5. `ssdf_evals.regress` CLI
6. corpus lint test + unit + integration suites
7. eval principals documented (tokens.json additions are a deploy step, not code)
