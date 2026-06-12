"""Scorer CLI: manifest in, scorecard out.

Usage:
    uv run python -m ssdf_evals.score <manifest.json> \
        [--corpus golden/core.yaml] [--results-dir results/]

Exit codes: 0 = scored (any pass rate), 2 = config/schema error or CH unreachable.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import clickhouse_connect

from .auditcheck import check_tools, fetch_tools
from .config import Config, client_kwargs, load_config
from .corpus import Question, load_corpus, questions_for_tier
from .predicates import evaluate
from .schemas import validate_manifest, validate_scorecard

PACKAGE_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CORPUS = PACKAGE_ROOT / "golden" / "core.yaml"
DEFAULT_RESULTS = PACKAGE_ROOT / "results"


def _parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _sanitize(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", value)


def _connect(config: Config):
    """(query client as ssdf_ro-style user, audit client as ssdf_audit_verify)."""
    query_client = clickhouse_connect.get_client(**client_kwargs(config))
    audit_client = clickhouse_connect.get_client(**client_kwargs(
        config, username="ssdf_audit_verify",
        password=config.audit_verify_password))
    return query_client, audit_client


def _load_questions(path: Path) -> list[Question]:
    return load_corpus(path)


def _rollup(results: list[tuple[Question, bool]], key_fn) -> dict:
    buckets: dict[str, dict] = {}
    for question, passed in results:
        bucket = buckets.setdefault(key_fn(question), {"total": 0, "passed": 0})
        bucket["total"] += 1
        bucket["passed"] += int(passed)
    return buckets


def score_run(manifest: dict, questions: list[Question], query_client,
              audit_client, slop_secs: int) -> dict:
    """Pure scoring core: corpus tier-subset vs manifest, fail-closed."""
    tier = manifest["tier"]
    subset = questions_for_tier(questions, tier)
    by_id = {entry["id"]: entry for entry in manifest["questions"]}
    unknown = set(by_id) - {q.id for q in subset}
    if unknown:
        print(f"warning: manifest ids not in corpus tier subset, ignored: "
              f"{sorted(unknown)}", file=sys.stderr)

    scored: list[dict] = []
    outcomes: list[tuple[Question, bool]] = []
    for question in subset:
        entry = by_id.get(question.id)
        reasons: list[str] = []
        predicate_detail: dict = {}
        tools_observed: list[str] = []
        if entry is None:
            passed = False
            reasons.append("question not in manifest (fail-closed)")
        elif entry["error"]:
            passed = False
            reasons.append(f"runner error: {entry['error']}")
        else:
            tools_observed = fetch_tools(
                audit_client, manifest["principal"],
                _parse_ts(entry["started"]), _parse_ts(entry["finished"]),
                slop_secs)
            tool_result = check_tools(question, tools_observed, tier)
            predicate_result = evaluate(question, entry["answer"], query_client)
            predicate_detail = predicate_result.detail
            passed = tool_result.passed and predicate_result.passed
            if not predicate_result.passed:
                reasons.append(f"predicate: {predicate_result.reason}")
            if not tool_result.passed:
                reasons.append(f"tools: {tool_result.reason}")
        scored.append({"id": question.id, "pass": passed, "reasons": reasons,
                       "predicate_detail": predicate_detail,
                       "tools_observed": tools_observed})
        outcomes.append((question, passed))

    scorecard = {
        "schema_version": 1,
        "run_id": manifest["run_id"], "model": manifest["model"],
        "runner": manifest["runner"], "tier": tier,
        "principal": manifest["principal"],
        "corpus_version": manifest["corpus_version"],
        "scored_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "questions": scored,
        "rollups": {
            "total": len(outcomes),
            "passed": sum(passed for _, passed in outcomes),
            "by_category": _rollup(outcomes, lambda q: q.category),
            "by_difficulty": _rollup(outcomes, lambda q: q.difficulty),
            "by_tier": _rollup(outcomes, lambda q: q.tier),
        },
    }
    validate_scorecard(scorecard)
    return scorecard


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ssdf_evals.score")
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    parser.add_argument("--results-dir", type=Path, default=DEFAULT_RESULTS)
    args = parser.parse_args(argv)

    try:
        manifest = json.loads(args.manifest.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        print(f"cannot read manifest: {exc}", file=sys.stderr)
        return 2
    try:
        validate_manifest(manifest)
        questions = _load_questions(args.corpus)
        config = load_config()
        query_client, audit_client = _connect(config)
    except Exception as exc:  # SchemaError, ConfigError, CH unreachable — all exit 2
        print(f"config/contract error: {exc}", file=sys.stderr)
        return 2

    scorecard = score_run(manifest, questions, query_client, audit_client,
                          config.audit_slop_secs)
    date = scorecard["scored_at"][:10]
    out_path = (args.results_dir /
                f"{date}-{_sanitize(manifest['model'])}-"
                f"{_sanitize(manifest['run_id'])}.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(scorecard, indent=2) + "\n")
    rollups = scorecard["rollups"]
    print(f"scored {rollups['passed']}/{rollups['total']} -> {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
