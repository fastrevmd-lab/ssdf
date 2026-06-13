# SSDF M8 external eval runner — design

**Date:** 2026-06-12
**Status:** approved (brainstorm)
**Depends on:** M8 eval harness (`services/evals`, PR #19), M7a/M7b MCP edges,
edge-hardening TLS path.

## Goal & boundary

Finish M8 **end-to-end** by building the missing half: a real, external eval
**runner** that executes the SSDF golden corpus against the **live** MCP edges
and hands back run-manifests, which the SSDF scorer turns into committed
scorecards.

The SSDF repo stops at the MCP layer — it owns the corpus, the manifest/
scorecard contract, the deterministic scorer, and the regression gate, and
explicitly **forbids runner code** (`services/evals/README.md`,
`CLAUDE.md` M8). Therefore the runner is a **standalone sibling repo** at
`~/ssdf-eval-runner/`, never merged into SSDF. Its only outputs that enter the
SSDF repo are the scorecards under `services/evals/results/` (git history is
the eval database).

Decisions locked during brainstorm:
- Run **both** LLMs (`claude-sonnet-4-6` via the `claude` CLI;
  `qwen2.5-coder:7b` via local Ollama) — directly exercises SSDF's
  "no single model is load-bearing" principle. **Prove the harness with Claude
  first**, then run qwen.
- Run **both tiers** (sovereign + public) per model ⇒ **4 scorecards**:
  `claude-sov`, `claude-pub`, `qwen-sov`, `qwen-pub`. The public runs are what
  prove tier *containment* end-to-end, not just in unit tests.
- **Two thin adapters** behind a shared core (no `ANTHROPIC_API_KEY` on the
  host, so Claude must go through the `claude` CLI, which owns its own MCP
  connection; qwen drives MCP directly from Python).

## Components

```
ssdf-eval-runner/                 # sibling repo, its own git
  ssdf_runner/
    core.py          # corpus load + tier-filter, prompt build,
                     # JSON-answer extraction, manifest assemble + schema-validate
    claude_adapter.py# drives `claude` CLI headless (CLI owns MCP)
    qwen_adapter.py  # python MCP streamable-HTTP client + ollama /api/chat tool loop
    run.py           # CLI: --model {claude,qwen} --tier {sovereign,public} --out <f>
  tests/             # unit tests for core (pure fns, fixtures); adapters proven live
  .env.example       # endpoint URLs + which token env vars to set
  README.md
  pyproject.toml
```

**Shared core, two thin adapters.** `core.py` is pure and unit-tested. Each
adapter exposes one function: take a prompt → run the agent against the tier's
endpoint with that model's eval token → return `(answer_obj | None,
error | None)`. `core` stamps `started`/`finished` (UTC) around the adapter
call and assembles the manifest. The adapters differ only because Claude-via-
CLI delegates MCP to the CLI while qwen speaks MCP itself.

## Run flow (per `model × tier`, strictly serial)

1. Load corpus from the SSDF checkout
   (`SSDF/services/evals/golden/core.yaml`), filter to the tier subset
   (sovereign run answers `tier ∈ {sovereign, both}`; public run answers
   `tier ∈ {public, both}`).
2. Per question: prompt = `question` + `"\n\n"` + `answer_format` (appended
   **verbatim**, per the contract). Stamp `started`, run the adapter, stamp
   `finished`. Extract a single JSON object from the model's final text
   (fenced ```json blocks or bare; balanced-brace scan, last object wins) →
   `answer`. Unparseable ⇒ `answer = null, error = "no JSON parsed"` (the
   scorer fail-closes on this).
3. **Serial, no concurrency.** The two runs that share a principal
   (`claude-sov` then `claude-pub`) execute strictly one-after-another so their
   `ssdf.audit` windows never overlap — the contract's audit-integrity
   requirement (overlapping windows under one principal ⇒ SSDF will not vouch
   for the scorecard).
4. Write `manifests/<UTC>-<model>-<tier>.json`:
   - `schema_version: 1`
   - `run_id`: `<model>-<tier>-<UTC-timestamp>`
   - `model`: `claude-sonnet-4-6` | `qwen2.5-coder:7b`
   - `runner`: `ssdf-eval-runner/<adapter>`
   - `tier`: `sovereign` | `public`
   - `principal`: `eval-claude` | `eval-qwen` (MUST match the token used)
   - `corpus_version`: `git -C SSDF rev-parse HEAD`
   - `questions[]`: `{id, started, finished, answer, error}`
   Validated against `manifest.schema.json` before write.

## Adapters

### Claude (`claude_adapter.py`)
Write a temp mcp-config:
```json
{"mcpServers":{"ssdf":{"type":"http","url":"<tier-url>",
  "headers":{"Authorization":"Bearer <tier eval-claude token>"}}}}
```
Invoke `claude -p "<prompt>" --output-format json --mcp-config <file>
--allowedTools "mcp__ssdf" --model claude-sonnet-4-6` with
`NODE_EXTRA_CA_CERTS=<ssdf-ca.crt>` in the env. Parse the `.result` text from
the JSON envelope, then extract the answer object. The exact `--allowedTools`
spelling (prefix vs explicit per-tool `mcp__ssdf__<tool>`) is verified live in
the first proving run and pinned in the README.

### Qwen (`qwen_adapter.py`)
`mcp` Python SDK `streamablehttp_client(url, headers={Authorization: Bearer
<tier eval-qwen token>})` with an `ssl.SSLContext` trusting the CA. Open an MCP
`ClientSession`, `list_tools()`, convert each tool's JSON schema into the
Ollama `tools` format. Loop: `POST http://127.0.0.1:11434/api/chat`
(`model: qwen2.5-coder:7b`, messages, tools); if the reply has `tool_calls`,
execute each via `session.call_tool(name, args)`, append a `role:"tool"`
message with the result, and continue; else take the final `content`. Cap at
~8 iterations to bound runaway loops, then extract the answer object.

## Models / principals / endpoints

| model string        | principal     | sovereign URL                      | public URL                         |
|---------------------|---------------|------------------------------------|------------------------------------|
| `claude-sonnet-4-6` | `eval-claude` | `https://198.51.100.152:30032/mcp`  | `https://198.51.100.154:30033/mcp`  |
| `qwen2.5-coder:7b`  | `eval-qwen`   | (same)                             | (same)                             |

Tokens sourced from `SSDF/services/evals/infra/ENV.local`
(`EVAL_{CLAUDE,QWEN}_{SOVEREIGN,PUBLIC}_TOKEN`), never hardcoded. CA =
`SSDF/infra/tls-local/ssdf-ca.crt`. The runner reads these via env vars; its
own token env file is gitignored.

## Scoring & commit (from the SSDF checkout)

Per manifest:
```
cd SSDF/services/evals
CH_HOST=198.51.100.151 CH_PORT=8443 CH_SECURE=1 \
  CH_CA_FILE=../../infra/tls-local/ssdf-ca.crt \
  CH_PASSWORD=<ssdf_ro> CH_AUDIT_VERIFY_PASSWORD=<…> \
  uv run python -m ssdf_evals.score <manifest>      # exit 0 ⇒ scorecard in results/
uv run python -m ssdf_evals.regress results/<scorecard>.json   # first run ⇒ exit 0
```
`CH_AUDIT_VERIFY_PASSWORD` is already in `services/mcp-query/infra/ENV.local`;
the `ssdf_ro` `CH_PASSWORD` is pulled from ct106 `/etc/ssdf-mcp/secrets.env`
(via the pve3 SSH path). Commit the 4 scorecards into SSDF
(`services/evals/results/`); commit the runner repo separately.

**Order of operations:** prove the whole chain with `claude × sovereign`
first (build → run → score → inspect a real scorecard), then `claude × public`,
then `qwen × {sovereign, public}`.

## Testing

Unit-test `core.py` only — tier filter, prompt build, JSON extraction (fenced,
bare, multiple-object, garbage) and manifest schema-validity against the real
`manifest.schema.json`. The adapters are integration code by nature; their
first integration test is the `claude × sovereign` proving run.

## Risks / non-goals

- A 7B model (qwen) may score low or loop — an **honest** result; the iteration
  cap prevents hangs. Low pass rates are recorded, not hidden.
- No LLM-judge, no new corpus questions, no pass-rate/threshold policy (the
  regress gate intentionally has none) — all out of scope.
- Runs are read-only, use dedicated eval principals, and issue ~23 low-volume
  calls each — negligible prod impact.
- The runner never writes to SSDF except the committed scorecards.
