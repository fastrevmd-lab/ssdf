# SSDF M8 External Eval Runner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a standalone sibling repo `~/ssdf-eval-runner/` that runs the SSDF golden corpus against the live sovereign+public MCP edges with two LLM adapters (Claude CLI, Ollama qwen), emits manifests, and have the SSDF scorer turn them into 4 committed scorecards — finishing M8 end-to-end.

**Architecture:** Pure unit-tested `core.py` (corpus load + tier filter, prompt build, JSON-answer extraction, manifest assembly+validation) behind two thin live adapters: `claude_adapter.py` shells out to the authenticated `claude` CLI (which owns its MCP connection); `qwen_adapter.py` drives an `mcp` streamable-HTTP client + Ollama tool loop. A `run.py` CLI ties model×tier into one manifest. Scoring/committing happens from the SSDF checkout using the existing `ssdf_evals.score`/`regress`.

**Tech Stack:** Python 3.12 + uv; libs `pyyaml`, `jsonschema`, `mcp`, `ollama`, `httpx`. External live deps: `claude` CLI (Claude Code, OAuth auth), local Ollama (`qwen2.5-coder:7b`), SSDF MCP edges, ct104 ClickHouse.

**Key constants (do not guess — these are verified):**
- SSDF checkout: `/home/mharman/SSDF` (env `SSDF_ROOT`, default this path).
- Corpus: `$SSDF_ROOT/services/evals/golden/core.yaml`. Manifest schema: `$SSDF_ROOT/services/evals/schemas/manifest.schema.json`.
- CA: `$SSDF_ROOT/infra/tls-local/ssdf-ca.crt`.
- Endpoints: sovereign `https://198.51.100.152:30032/mcp`, public `https://198.51.100.154:30033/mcp`.
- Tokens (gitignored): `$SSDF_ROOT/services/evals/infra/ENV.local` → `EVAL_{CLAUDE,QWEN}_{SOVEREIGN,PUBLIC}_TOKEN`.
- Models: `claude-sonnet-4-6` (principal `eval-claude`); `qwen2.5-coder:7b` (principal `eval-qwen`).
- Ollama: `http://127.0.0.1:11434`.

---

## File Structure

```
~/ssdf-eval-runner/
  pyproject.toml          # uv project, deps, console script
  .gitignore              # .env, manifests/, __pycache__, .venv
  .env.example            # documents SSDF_ROOT + token var names
  README.md               # how to run, what it produces, the contract boundary
  ssdf_runner/
    __init__.py
    core.py               # pure: corpus load+filter, prompt build, extract_answer, assemble_manifest, validate
    claude_adapter.py     # run_question(prompt, url, token, ca, model) -> (answer|None, error|None)
    qwen_adapter.py       # run_question(prompt, url, token, ca, model) -> (answer|None, error|None)
    run.py                # CLI: --model --tier --out
  tests/
    __init__.py
    fixtures/mini_corpus.yaml
    test_core.py
```

Scorecards are produced INTO `/home/mharman/SSDF/services/evals/results/` by the SSDF scorer (Task 8/10/11) — never written by the runner.

---

### Task 1: Scaffold the sibling repo

**Files:**
- Create: `~/ssdf-eval-runner/pyproject.toml`
- Create: `~/ssdf-eval-runner/.gitignore`
- Create: `~/ssdf-eval-runner/.env.example`
- Create: `~/ssdf-eval-runner/ssdf_runner/__init__.py` (empty)
- Create: `~/ssdf-eval-runner/tests/__init__.py` (empty)

- [ ] **Step 1: Create the project dir and git init**

```bash
mkdir -p ~/ssdf-eval-runner/ssdf_runner ~/ssdf-eval-runner/tests/fixtures
cd ~/ssdf-eval-runner && git init -q
```

- [ ] **Step 2: Write `pyproject.toml`**

```toml
[project]
name = "ssdf-eval-runner"
version = "0.1.0"
description = "External M8 eval runner for SSDF — binds via live MCP, emits run-manifests"
requires-python = ">=3.12"
dependencies = [
    "pyyaml>=6.0",
    "jsonschema>=4.0",
    "mcp>=1.0",
    "ollama>=0.3",
    "httpx>=0.27",
]

[project.optional-dependencies]
dev = ["pytest>=8.0"]

[project.scripts]
ssdf-eval-run = "ssdf_runner.run:main"

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"
```

- [ ] **Step 3: Write `.gitignore`**

```
.venv/
__pycache__/
*.pyc
.env
manifests/
```

- [ ] **Step 4: Write `.env.example`**

```bash
# Path to the SSDF checkout (corpus, schema, CA, tokens all read from here)
SSDF_ROOT=/home/mharman/SSDF
# Eval tokens live in $SSDF_ROOT/services/evals/infra/ENV.local — source that file
# before running; do NOT copy token values here.
```

- [ ] **Step 5: Sync deps and create empty package markers**

```bash
cd ~/ssdf-eval-runner
: > ssdf_runner/__init__.py
: > tests/__init__.py
uv sync --extra dev
```
Expected: a `.venv` is created and `mcp`, `ollama`, `pyyaml`, `jsonschema`, `pytest` resolve.

- [ ] **Step 6: Commit**

```bash
cd ~/ssdf-eval-runner
git add pyproject.toml .gitignore .env.example ssdf_runner/__init__.py tests/__init__.py
git commit -q -m "chore: scaffold ssdf-eval-runner project"
```

---

### Task 2: core — corpus load + tier filter

**Files:**
- Create: `~/ssdf-eval-runner/ssdf_runner/core.py`
- Create: `~/ssdf-eval-runner/tests/fixtures/mini_corpus.yaml`
- Create: `~/ssdf-eval-runner/tests/test_core.py`

- [ ] **Step 1: Write the fixture corpus**

`tests/fixtures/mini_corpus.yaml`:
```yaml
- id: q-sov
  question: How many events in the last 24 hours?
  tier: sovereign
  answer_format: 'Answer with JSON: {"count": <int>}'
- id: q-both
  question: Which devices are firewalls?
  tier: both
  answer_format: 'Answer with JSON: {"firewalls": ["<name>", ...]}'
- id: q-pub
  question: Top talkers?
  tier: public
  answer_format: 'Answer with JSON: {"refusal": <bool>}'
```

- [ ] **Step 2: Write the failing test**

`tests/test_core.py`:
```python
from pathlib import Path
from ssdf_runner import core

FIX = Path(__file__).parent / "fixtures" / "mini_corpus.yaml"


def test_load_and_filter_sovereign():
    qs = core.load_corpus(FIX)
    sov = core.filter_tier(qs, "sovereign")
    assert {q["id"] for q in sov} == {"q-sov", "q-both"}


def test_load_and_filter_public():
    qs = core.load_corpus(FIX)
    pub = core.filter_tier(qs, "public")
    assert {q["id"] for q in pub} == {"q-pub", "q-both"}
```

- [ ] **Step 3: Run test to verify it fails**

```bash
cd ~/ssdf-eval-runner && uv run pytest tests/test_core.py -q
```
Expected: FAIL — `AttributeError: module 'ssdf_runner.core' has no attribute 'load_corpus'`.

- [ ] **Step 4: Write minimal implementation**

`ssdf_runner/core.py`:
```python
"""Pure runner core: corpus load/filter, prompt build, answer extraction,
manifest assembly + validation. No network, no LLM — unit-tested."""
from __future__ import annotations

import json
from pathlib import Path

import yaml


def load_corpus(path: Path) -> list[dict]:
    """Load the SSDF golden corpus YAML into a list of question dicts."""
    return yaml.safe_load(Path(path).read_text())


def filter_tier(questions: list[dict], tier: str) -> list[dict]:
    """Run-tier subset: a sovereign run answers tier in {sovereign, both};
    a public run answers tier in {public, both}."""
    allowed = {tier, "both"}
    return [q for q in questions if q["tier"] in allowed]
```

- [ ] **Step 5: Run test to verify it passes**

```bash
cd ~/ssdf-eval-runner && uv run pytest tests/test_core.py -q
```
Expected: 2 passed.

- [ ] **Step 6: Commit**

```bash
cd ~/ssdf-eval-runner
git add ssdf_runner/core.py tests/test_core.py tests/fixtures/mini_corpus.yaml
git commit -q -m "feat(core): corpus load + run-tier filter"
```

---

### Task 3: core — prompt build + JSON answer extraction

**Files:**
- Modify: `~/ssdf-eval-runner/ssdf_runner/core.py`
- Modify: `~/ssdf-eval-runner/tests/test_core.py`

- [ ] **Step 1: Add failing tests**

Append to `tests/test_core.py`:
```python
def test_build_prompt_appends_answer_format_verbatim():
    q = {"question": "How many events?", "answer_format": 'JSON: {"count": <int>}'}
    p = core.build_prompt(q)
    assert p == 'How many events?\n\nJSON: {"count": <int>}'


def test_extract_answer_bare_object():
    assert core.extract_answer('the answer is {"count": 5} ok') == {"count": 5}


def test_extract_answer_fenced_json():
    text = "```json\n{\"firewalls\": [\"panosvm\"]}\n```"
    assert core.extract_answer(text) == {"firewalls": ["panosvm"]}


def test_extract_answer_last_object_wins():
    assert core.extract_answer('{"a":1} then {"count": 9}') == {"count": 9}


def test_extract_answer_garbage_is_none():
    assert core.extract_answer("no json here") is None
    assert core.extract_answer("") is None
    assert core.extract_answer(None) is None
```

- [ ] **Step 2: Run to verify failure**

```bash
cd ~/ssdf-eval-runner && uv run pytest tests/test_core.py -q
```
Expected: FAIL — `build_prompt`/`extract_answer` undefined.

- [ ] **Step 3: Implement**

Append to `ssdf_runner/core.py`:
```python
def build_prompt(question: dict) -> str:
    """Prompt = question text + blank line + answer_format appended verbatim."""
    return f"{question['question'].strip()}\n\n{question['answer_format'].strip()}"


def extract_answer(text: str | None) -> dict | None:
    """Return the LAST top-level balanced-brace JSON object that parses to a
    dict, else None. Handles fenced and bare output. Note: a naive brace scan
    can be fooled by braces inside string values — acceptable for the simple
    flat answers the corpus asks for."""
    if not text:
        return None
    candidates: list[str] = []
    depth = 0
    start: int | None = None
    for i, ch in enumerate(text):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}" and depth > 0:
            depth -= 1
            if depth == 0 and start is not None:
                candidates.append(text[start : i + 1])
                start = None
    for chunk in reversed(candidates):
        try:
            obj = json.loads(chunk)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            return obj
    return None
```

- [ ] **Step 4: Run to verify pass**

```bash
cd ~/ssdf-eval-runner && uv run pytest tests/test_core.py -q
```
Expected: all passed (7 total).

- [ ] **Step 5: Commit**

```bash
cd ~/ssdf-eval-runner
git add ssdf_runner/core.py tests/test_core.py
git commit -q -m "feat(core): prompt build + JSON answer extraction"
```

---

### Task 4: core — manifest assembly + schema validation

**Files:**
- Modify: `~/ssdf-eval-runner/ssdf_runner/core.py`
- Modify: `~/ssdf-eval-runner/tests/test_core.py`

- [ ] **Step 1: Add failing tests**

Append to `tests/test_core.py`:
```python
import os


def _schema_path():
    root = os.environ.get("SSDF_ROOT", "/home/mharman/SSDF")
    return Path(root) / "services" / "evals" / "schemas" / "manifest.schema.json"


def test_assemble_manifest_is_schema_valid():
    results = [
        {"id": "q-sov", "started": "2026-06-12T00:00:00Z",
         "finished": "2026-06-12T00:00:01Z", "answer": {"count": 5}, "error": None},
        {"id": "q-both", "started": "2026-06-12T00:00:02Z",
         "finished": "2026-06-12T00:00:03Z", "answer": None,
         "error": "no JSON parsed"},
    ]
    m = core.assemble_manifest(
        model="claude-sonnet-4-6", runner="ssdf-eval-runner/claude",
        tier="sovereign", principal="eval-claude",
        corpus_version="abc123", run_id="claude-sovereign-T", results=results)
    assert m["schema_version"] == 1
    assert m["tier"] == "sovereign"
    assert {q["id"] for q in m["questions"]} == {"q-sov", "q-both"}
    # validates clean against the REAL contract schema
    core.validate_manifest(m, _schema_path())


def test_validate_manifest_rejects_bad():
    import pytest
    bad = {"schema_version": 1}  # missing required fields
    with pytest.raises(Exception):
        core.validate_manifest(bad, _schema_path())
```

- [ ] **Step 2: Run to verify failure**

```bash
cd ~/ssdf-eval-runner && uv run pytest tests/test_core.py -q
```
Expected: FAIL — `assemble_manifest`/`validate_manifest` undefined.

- [ ] **Step 3: Implement**

Append to `ssdf_runner/core.py`:
```python
import jsonschema  # noqa: E402  (kept near use for clarity)


def assemble_manifest(*, model: str, runner: str, tier: str, principal: str,
                      corpus_version: str, run_id: str,
                      results: list[dict]) -> dict:
    """Build a contract-v1 manifest dict from per-question results.
    Each result must carry id/started/finished/answer/error."""
    return {
        "schema_version": 1,
        "run_id": run_id,
        "model": model,
        "runner": runner,
        "tier": tier,
        "principal": principal,
        "corpus_version": corpus_version,
        "questions": [
            {"id": r["id"], "started": r["started"], "finished": r["finished"],
             "answer": r["answer"], "error": r["error"]}
            for r in results
        ],
    }


def validate_manifest(manifest: dict, schema_path: Path) -> None:
    """Raise jsonschema.ValidationError if the manifest violates contract v1."""
    schema = json.loads(Path(schema_path).read_text())
    jsonschema.validate(manifest, schema)
```

- [ ] **Step 4: Run to verify pass**

```bash
cd ~/ssdf-eval-runner && SSDF_ROOT=/home/mharman/SSDF uv run pytest tests/test_core.py -q
```
Expected: all passed (9 total).

- [ ] **Step 5: Commit**

```bash
cd ~/ssdf-eval-runner
git add ssdf_runner/core.py tests/test_core.py
git commit -q -m "feat(core): manifest assembly + contract-schema validation"
```

---

### Task 5: claude adapter (live)

**Files:**
- Create: `~/ssdf-eval-runner/ssdf_runner/claude_adapter.py`

This adapter is live by nature (no unit test); it is exercised by the Task 7 proving run. Write it now, verify in Task 7.

- [ ] **Step 1: Implement the adapter**

`ssdf_runner/claude_adapter.py`:
```python
"""Claude adapter: drive the authenticated `claude` CLI headless. The CLI owns
the MCP connection (bearer token + CA in the temp mcp-config); we wrap timing
and answer extraction. Uses the host's existing Claude Code OAuth auth — no
ANTHROPIC_API_KEY (so NOT --bare, which would force key-only auth)."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path

from . import core


def run_question(prompt: str, *, url: str, token: str, ca_file: str,
                 model: str = "claude-sonnet-4-6",
                 timeout_secs: int = 180) -> tuple[dict | None, str | None]:
    """Run one question via `claude -p`. Returns (answer_obj|None, error|None)."""
    mcp_config = {"mcpServers": {"ssdf": {
        "type": "http", "url": url,
        "headers": {"Authorization": f"Bearer {token}"}}}}
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(mcp_config, fh)
        cfg_path = fh.name
    env = dict(os.environ)
    env["NODE_EXTRA_CA_CERTS"] = ca_file
    cmd = [
        "claude", "-p", prompt,
        "--output-format", "json",
        "--mcp-config", cfg_path,
        "--strict-mcp-config",
        "--allowedTools", "mcp__ssdf__*",
        "--permission-mode", "bypassPermissions",
        "--no-session-persistence",
        "--model", model,
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout_secs, env=env)
    except subprocess.TimeoutExpired:
        return None, f"claude CLI timeout after {timeout_secs}s"
    finally:
        Path(cfg_path).unlink(missing_ok=True)
    if proc.returncode != 0:
        return None, f"claude CLI exit {proc.returncode}: {proc.stderr[:300]}"
    try:
        envelope = json.loads(proc.stdout)
        result_text = envelope.get("result", "")
    except json.JSONDecodeError:
        result_text = proc.stdout
    answer = core.extract_answer(result_text)
    if answer is None:
        return None, "no JSON parsed"
    return answer, None
```

- [ ] **Step 2: Commit**

```bash
cd ~/ssdf-eval-runner
git add ssdf_runner/claude_adapter.py
git commit -q -m "feat(claude): CLI-driven adapter (MCP owned by claude CLI)"
```

---

### Task 6: run.py CLI

**Files:**
- Create: `~/ssdf-eval-runner/ssdf_runner/run.py`

- [ ] **Step 1: Implement the CLI**

`ssdf_runner/run.py`:
```python
"""CLI: run one model x tier over the corpus, write a contract-v1 manifest.
Serial by construction — one question at a time; never run two tiers under one
principal with overlapping audit windows (run them strictly sequentially)."""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import core

MODELS = {
    "claude": {"model": "claude-sonnet-4-6", "principal": "eval-claude",
               "runner": "ssdf-eval-runner/claude", "token_prefix": "EVAL_CLAUDE"},
    "qwen": {"model": "qwen2.5-coder:7b", "principal": "eval-qwen",
             "runner": "ssdf-eval-runner/qwen", "token_prefix": "EVAL_QWEN"},
}
URLS = {"sovereign": "https://198.51.100.152:30032/mcp",
        "public": "https://198.51.100.154:30033/mcp"}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="ssdf-eval-run")
    ap.add_argument("--model", choices=MODELS, required=True)
    ap.add_argument("--tier", choices=URLS, required=True)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args(argv)

    root = Path(os.environ.get("SSDF_ROOT", "/home/mharman/SSDF"))
    corpus = root / "services" / "evals" / "golden" / "core.yaml"
    schema = root / "services" / "evals" / "schemas" / "manifest.schema.json"
    ca_file = str(root / "infra" / "tls-local" / "ssdf-ca.crt")
    spec = MODELS[args.model]
    token_var = f"{spec['token_prefix']}_{args.tier.upper()}_TOKEN"
    token = os.environ.get(token_var)
    if not token:
        print(f"missing token env {token_var}", file=sys.stderr)
        return 2

    corpus_version = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        capture_output=True, text=True).stdout.strip() or "unknown"

    if args.model == "claude":
        from .claude_adapter import run_question
    else:
        from .qwen_adapter import run_question

    questions = core.filter_tier(core.load_corpus(corpus), args.tier)
    results = []
    for q in questions:
        prompt = core.build_prompt(q)
        started = _now()
        answer, error = run_question(prompt, url=URLS[args.tier], token=token,
                                     ca_file=ca_file, model=spec["model"])
        finished = _now()
        results.append({"id": q["id"], "started": started, "finished": finished,
                        "answer": answer, "error": error})
        print(f"  {q['id']}: {'ANSWER' if answer else 'ERR ' + str(error)}",
              file=sys.stderr)

    run_id = f"{spec['model']}-{args.tier}-{_now()}"
    manifest = core.assemble_manifest(
        model=spec["model"], runner=spec["runner"], tier=args.tier,
        principal=spec["principal"], corpus_version=corpus_version,
        run_id=run_id, results=results)
    core.validate_manifest(manifest, schema)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    import json
    args.out.write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"wrote {args.out} ({len(results)} questions)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 2: Smoke-test arg parsing (no network)**

```bash
cd ~/ssdf-eval-runner && uv run ssdf-eval-run --help
```
Expected: usage shows `--model {claude,qwen} --tier {sovereign,public} --out`.

- [ ] **Step 3: Commit**

```bash
cd ~/ssdf-eval-runner
git add ssdf_runner/run.py
git commit -q -m "feat(run): model x tier CLI -> contract-v1 manifest"
```

---

### Task 7: PROVING RUN — claude × sovereign → manifest → score → inspect

This is the first live integration test of the whole chain. Pin the exact CLI behavior here.

- [ ] **Step 1: Source tokens and do a single-question CLI sanity check**

```bash
cd ~/ssdf-eval-runner
set -a; . /home/mharman/SSDF/services/evals/infra/ENV.local; set +a
export SSDF_ROOT=/home/mharman/SSDF
NODE_EXTRA_CA_CERTS=$SSDF_ROOT/infra/tls-local/ssdf-ca.crt \
claude -p 'Which devices in the topology are firewalls? Answer with JSON: {"firewalls": ["<name>", ...]}' \
  --output-format json --strict-mcp-config \
  --mcp-config "{\"mcpServers\":{\"ssdf\":{\"type\":\"http\",\"url\":\"https://198.51.100.152:30032/mcp\",\"headers\":{\"Authorization\":\"Bearer $EVAL_CLAUDE_SOVEREIGN_TOKEN\"}}}}" \
  --allowedTools "mcp__ssdf__*" --permission-mode bypassPermissions \
  --no-session-persistence --model claude-sonnet-4-6 | python3 -c "import sys,json;print(json.load(sys.stdin)['result'])"
```
Expected: a JSON object naming firewalls (e.g. `{"firewalls": ["panosvm", "vSRX-test10"]}`).
**If the CLI prompts for permission or the tool is blocked:** adjust the allow flag — try `--allowedTools "mcp__ssdf"` (server-prefix) or list explicit tool names `mcp__ssdf__topology_snapshot ...`; update `claude_adapter.py` to match, then re-run. Record the working flag in the README.

- [ ] **Step 2: Run the full sovereign manifest**

```bash
cd ~/ssdf-eval-runner
uv run ssdf-eval-run --model claude --tier sovereign \
  --out manifests/claude-sovereign.json
```
Expected: per-question lines on stderr (17 questions: `tier ∈ {sovereign, both}`), then `wrote manifests/claude-sovereign.json`. Most questions print `ANSWER`.

- [ ] **Step 3: Retrieve the ssdf_ro password for scoring**

```bash
ssh root@pve3.example.com "pct exec 106 -- grep -E '^CH_PASSWORD=' /etc/ssdf-mcp/secrets.env" | cut -d= -f2-
```
Save the value as `$SSDF_RO_PW` in your shell. (This is the `ssdf_ro` query password the scorer needs.)

- [ ] **Step 4: Score the manifest**

```bash
cd /home/mharman/SSDF/services/evals
set -a; . infra/ENV.local 2>/dev/null; . ../mcp-query/infra/ENV.local; set +a
CH_HOST=198.51.100.151 CH_PORT=8443 CH_SECURE=1 \
  CH_CA_FILE=/home/mharman/SSDF/infra/tls-local/ssdf-ca.crt \
  CH_PASSWORD="$SSDF_RO_PW" \
  CH_AUDIT_VERIFY_PASSWORD="$CH_AUDIT_VERIFY_PASSWORD" \
  uv run python -m ssdf_evals.score ~/ssdf-eval-runner/manifests/claude-sovereign.json
```
Expected: `scored N/17 -> results/2026-06-12-claude-sonnet-4-6-...json`, exit 0.

- [ ] **Step 5: Inspect the scorecard — confirm tool-checks joined audit**

```bash
cd /home/mharman/SSDF/services/evals
ls -t results/*.json | head -1 | xargs python3 -m json.tool | \
  grep -E '"id"|"pass"|tools_observed' | head -60
```
Expected: questions with `required_tools` show non-empty `tools_observed` (proves the `eval-claude` audit window joined). If `tools_observed` is empty on tool-required questions, the audit join window is off — check that the principal in the manifest is exactly `eval-claude` and that ct106 audited the calls (`EVAL_AUDIT_SLOP_SECS` can be raised if clock skew). Resolve before proceeding.

- [ ] **Step 6: Commit the proving scorecard + note**

```bash
cd /home/mharman/SSDF
git add services/evals/results/*.json
git commit -q -m "eval(m8): claude-sonnet-4-6 sovereign scorecard (first live run)"
```

---

### Task 8: claude × public run → score → commit

Run AFTER Task 7 fully completes (same principal `eval-claude` — serial, non-overlapping audit windows).

- [ ] **Step 1: Run the public manifest**

```bash
cd ~/ssdf-eval-runner
set -a; . /home/mharman/SSDF/services/evals/infra/ENV.local; set +a
export SSDF_ROOT=/home/mharman/SSDF
uv run ssdf-eval-run --model claude --tier public --out manifests/claude-public.json
```
Expected: 6 questions (`tier ∈ {public, both}`), `wrote manifests/claude-public.json`.

- [ ] **Step 2: Score it**

```bash
cd /home/mharman/SSDF/services/evals
set -a; . ../mcp-query/infra/ENV.local; set +a
CH_HOST=198.51.100.151 CH_PORT=8443 CH_SECURE=1 \
  CH_CA_FILE=/home/mharman/SSDF/infra/tls-local/ssdf-ca.crt \
  CH_PASSWORD="$SSDF_RO_PW" CH_AUDIT_VERIFY_PASSWORD="$CH_AUDIT_VERIFY_PASSWORD" \
  uv run python -m ssdf_evals.score ~/ssdf-eval-runner/manifests/claude-public.json
```
Expected: `scored N/6 -> results/...`, exit 0. Public-containment is enforced by the scorer (any non-public tool in a question's window fails it).

- [ ] **Step 3: Commit the scorecard**

```bash
cd /home/mharman/SSDF
git add services/evals/results/*.json
git commit -q -m "eval(m8): claude-sonnet-4-6 public scorecard"
```

---

### Task 9: qwen adapter (live) — MCP client + Ollama tool loop

**Files:**
- Create: `~/ssdf-eval-runner/ssdf_runner/qwen_adapter.py`

Live by nature; exercised in Task 10.

- [ ] **Step 1: Implement the adapter**

`ssdf_runner/qwen_adapter.py`:
```python
"""Qwen adapter: drive MCP directly (streamable-HTTP, bearer + CA) and run an
Ollama tool-calling loop against qwen2.5-coder:7b. Sync entrypoint wraps an
async MCP session."""
from __future__ import annotations

import asyncio
import json
import ssl

import httpx
import ollama
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

from . import core

OLLAMA_HOST = "http://127.0.0.1:11434"
MAX_TURNS = 8


def _ollama_tools(mcp_tools) -> list[dict]:
    out = []
    for t in mcp_tools:
        out.append({"type": "function", "function": {
            "name": t.name, "description": t.description or "",
            "parameters": t.inputSchema or {"type": "object", "properties": {}}}})
    return out


def _ssl_ctx(ca_file: str) -> ssl.SSLContext:
    return ssl.create_default_context(cafile=ca_file)


async def _run(prompt: str, url: str, token: str, ca_file: str,
               model: str) -> tuple[dict | None, str | None]:
    headers = {"Authorization": f"Bearer {token}"}

    def factory(*a, **k):  # trust the local CA for the streamable-http client
        return httpx.AsyncClient(*a, verify=_ssl_ctx(ca_file), **k)

    try:
        async with streamablehttp_client(
                url, headers=headers, httpx_client_factory=factory) as (r, w, _):
            async with ClientSession(r, w) as session:
                await session.initialize()
                tools = (await session.list_tools()).tools
                otools = _ollama_tools(tools)
                client = ollama.AsyncClient(host=OLLAMA_HOST)
                messages = [{"role": "user", "content": prompt}]
                for _turn in range(MAX_TURNS):
                    resp = await client.chat(model=model, messages=messages,
                                             tools=otools)
                    msg = resp["message"]
                    messages.append(msg)
                    calls = msg.get("tool_calls") or []
                    if not calls:
                        ans = core.extract_answer(msg.get("content", ""))
                        return (ans, None) if ans else (None, "no JSON parsed")
                    for call in calls:
                        fn = call["function"]
                        args = fn["arguments"]
                        if isinstance(args, str):
                            args = json.loads(args or "{}")
                        try:
                            tr = await session.call_tool(fn["name"], args)
                            content = "".join(
                                getattr(c, "text", "") for c in tr.content)
                        except Exception as exc:  # tool error -> tell the model
                            content = f"tool error: {exc}"
                        messages.append({"role": "tool", "content": content[:4000]})
                return None, f"no final answer within {MAX_TURNS} turns"
    except Exception as exc:
        return None, f"qwen adapter error: {exc}"


def run_question(prompt: str, *, url: str, token: str, ca_file: str,
                 model: str = "qwen2.5-coder:7b") -> tuple[dict | None, str | None]:
    return asyncio.run(_run(prompt, url, token, ca_file, model))
```

- [ ] **Step 2: Verify imports resolve**

```bash
cd ~/ssdf-eval-runner && uv run python -c "import ssdf_runner.qwen_adapter; print('import OK')"
```
Expected: `import OK`. If `httpx_client_factory` is not accepted by `streamablehttp_client` in the installed `mcp` version, check the signature (`uv run python -c "import inspect,mcp.client.streamable_http as m; print(inspect.signature(m.streamablehttp_client))"`) and switch to the supported TLS-injection param (older versions accept an `httpx.AsyncClient`-compatible kwarg or an `ssl` context via the transport); update accordingly.

- [ ] **Step 3: Commit**

```bash
cd ~/ssdf-eval-runner
git add ssdf_runner/qwen_adapter.py
git commit -q -m "feat(qwen): MCP streamable-HTTP client + ollama tool loop"
```

---

### Task 10: qwen × sovereign and × public runs → score → commit

Run AFTER Tasks 7–8 (different principal, but keep strictly serial to be safe). Within qwen, run sovereign fully, THEN public (same `eval-qwen` principal — non-overlapping windows).

- [ ] **Step 1: One-question qwen smoke test**

```bash
cd ~/ssdf-eval-runner
set -a; . /home/mharman/SSDF/services/evals/infra/ENV.local; set +a
uv run python -c "
from ssdf_runner.qwen_adapter import run_question
import os
a,e = run_question('Which devices in the topology are firewalls? Answer with JSON: {\"firewalls\": [\"<name>\", ...]}',
  url='https://198.51.100.152:30032/mcp', token=os.environ['EVAL_QWEN_SOVEREIGN_TOKEN'],
  ca_file='/home/mharman/SSDF/infra/tls-local/ssdf-ca.crt')
print('answer', a, 'error', e)"
```
Expected: a parsed answer or a clear error (7B may need the loop). If the MCP handshake fails on TLS, fix per Task 9 Step 2 before the full run.

- [ ] **Step 2: Full qwen sovereign + public manifests**

```bash
cd ~/ssdf-eval-runner
export SSDF_ROOT=/home/mharman/SSDF
uv run ssdf-eval-run --model qwen --tier sovereign --out manifests/qwen-sovereign.json
uv run ssdf-eval-run --model qwen --tier public   --out manifests/qwen-public.json
```
Expected: two manifests written (17 and 6 questions). Lower `ANSWER` rate than Claude is expected and fine — honest result.

- [ ] **Step 3: Score both**

```bash
cd /home/mharman/SSDF/services/evals
set -a; . ../mcp-query/infra/ENV.local; set +a
for m in qwen-sovereign qwen-public; do
  CH_HOST=198.51.100.151 CH_PORT=8443 CH_SECURE=1 \
    CH_CA_FILE=/home/mharman/SSDF/infra/tls-local/ssdf-ca.crt \
    CH_PASSWORD="$SSDF_RO_PW" CH_AUDIT_VERIFY_PASSWORD="$CH_AUDIT_VERIFY_PASSWORD" \
    uv run python -m ssdf_evals.score ~/ssdf-eval-runner/manifests/$m.json
done
```
Expected: two `scored N/.. -> results/...` lines, exit 0 each.

- [ ] **Step 4: Commit the scorecards**

```bash
cd /home/mharman/SSDF
git add services/evals/results/*.json
git commit -q -m "eval(m8): qwen2.5-coder:7b sovereign + public scorecards"
```

---

### Task 11: regression gate, runner README, SSDF docs/memory

**Files:**
- Create: `~/ssdf-eval-runner/README.md`
- Modify: `/home/mharman/SSDF/docs/superpowers/STATUS.md`
- Modify: `/home/mharman/SSDF/CLAUDE.md` (M8 section — add the live-run note)

- [ ] **Step 1: Run the regression gate on each new scorecard**

```bash
cd /home/mharman/SSDF/services/evals
for sc in results/*claude-sonnet-4-6* results/*qwen2.5-coder*; do
  echo "== $sc =="; uv run python -m ssdf_evals.regress "$sc"; echo "exit $?"
done
```
Expected: exit 0 for each (first scorecard per model ⇒ no prior baseline ⇒ no regression). Non-zero ⇒ read the stderr regression list and investigate before claiming done.

- [ ] **Step 2: Write the runner README**

`~/ssdf-eval-runner/README.md`:
```markdown
# ssdf-eval-runner

External M8 eval runner for SSDF. Binds to the live SSDF MCP edges, runs the
golden corpus, and emits run-manifests (contract v1). **Not part of the SSDF
repo** — SSDF owns the corpus/contract/scorer; this owns the MCP client harness.

## Run

    set -a; . $SSDF_ROOT/services/evals/infra/ENV.local; set +a
    export SSDF_ROOT=/home/mharman/SSDF
    uv run ssdf-eval-run --model claude --tier sovereign --out manifests/claude-sovereign.json
    uv run ssdf-eval-run --model qwen   --tier public    --out manifests/qwen-public.json

Models: `claude` (`claude-sonnet-4-6`, principal `eval-claude`, via the
authenticated `claude` CLI) and `qwen` (`qwen2.5-coder:7b`, principal
`eval-qwen`, via local Ollama + MCP). Tokens come from
`$SSDF_ROOT/services/evals/infra/ENV.local`; CA from
`$SSDF_ROOT/infra/tls-local/ssdf-ca.crt`.

## Audit integrity

Runs are SERIAL. Never run two tiers under the same principal with overlapping
audit windows. Score+commit from the SSDF checkout
(`python -m ssdf_evals.score <manifest>`); scorecards land in
`SSDF/services/evals/results/`.

## Working claude allow-tools flag

`--allowedTools "mcp__ssdf__*"` (pinned from the Task 7 proving run).
```
(Update the last line if Task 7 Step 1 found a different working flag.)

- [ ] **Step 3: Commit the runner repo**

```bash
cd ~/ssdf-eval-runner
git add README.md
git commit -q -m "docs: runner README (run, audit integrity, pinned allow-tools)"
```

- [ ] **Step 4: Update SSDF STATUS.md + CLAUDE.md M8 section**

Add a short "M8 live-proven end-to-end" note to `docs/superpowers/STATUS.md` and a bullet to the `CLAUDE.md` M8 section recording: external runner `~/ssdf-eval-runner` (sibling repo), 4 scorecards committed (claude+qwen × sovereign+public), `ssdf_ro` scoring pw sourced from ct106 secrets, principals `eval-claude`/`eval-qwen`. Keep to a few lines, matching the existing terse style.

- [ ] **Step 5: Commit the SSDF docs**

```bash
cd /home/mharman/SSDF
git add docs/superpowers/STATUS.md CLAUDE.md
git commit -q -m "docs(m8): record external runner + 4 live scorecards (M8 end-to-end)"
```

---

## Self-Review notes

- **Spec coverage:** §2 components → Tasks 1–6,9; §3 run flow → run.py (Task 6) + filter (Task 2); §4 adapters → Tasks 5,9 (+ live pins in 7,10); §5 models/principals/endpoints → run.py `MODELS`/`URLS`; §6 scoring & commit → Tasks 7–8,10–11; §7 testing → Tasks 2–4 (core) + live proving runs; §8 risks → iteration cap (Task 9 `MAX_TURNS`), serial ordering (Tasks 7→8→10), read-only principals.
- **Audit-window integrity** (contract requirement) is enforced by the strict task ordering 7→8 and the sovereign-then-public ordering within Task 10, plus the README note.
- **Single source of truth:** corpus + schema + CA + tokens all read from `$SSDF_ROOT`; nothing duplicated into the runner repo.
- **Known live-pin points** (resolved during execution, not guessed): exact `--allowedTools` spelling (Task 7 Step 1); `streamablehttp_client` TLS-injection kwarg (Task 9 Step 2). Both have explicit fallback instructions.
