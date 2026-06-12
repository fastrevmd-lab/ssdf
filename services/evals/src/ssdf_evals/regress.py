"""Regression gate: no question that ever passed (per model) may silently fail.

Usage:
    uv run python -m ssdf_evals.regress <new-scorecard.json> \
        [--results-dir results/]

Exit codes: 0 = no regression, 1 = regression(s) listed, 2 = config error.
History is the committed results/ directory — no other storage. Pass-rate
thresholds are runner-project policy and deliberately NOT implemented here.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .schemas import SchemaError, validate_scorecard

DEFAULT_RESULTS = Path(__file__).resolve().parents[2] / "results"


def _ever_passed(model: str, results_dir: Path, exclude: Path) -> set[str]:
    passed: set[str] = set()
    for path in sorted(results_dir.glob("*.json")):
        if path.resolve() == exclude.resolve():
            continue
        try:
            scorecard = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            print(f"warning: skipping unreadable scorecard {path}", file=sys.stderr)
            continue
        if scorecard.get("model") != model:
            continue
        passed.update(q["id"] for q in scorecard.get("questions", []) if q.get("pass"))
    return passed


def find_regressions(new_scorecard: dict, results_dir: Path,
                     exclude: Path = Path("/nonexistent")) -> list[str]:
    history = _ever_passed(new_scorecard["model"], results_dir, exclude)
    now_failing = {q["id"] for q in new_scorecard["questions"] if not q["pass"]}
    return sorted(history & now_failing)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ssdf_evals.regress")
    parser.add_argument("scorecard", type=Path)
    parser.add_argument("--results-dir", type=Path, default=DEFAULT_RESULTS)
    args = parser.parse_args(argv)

    try:
        new_scorecard = json.loads(args.scorecard.read_text())
        validate_scorecard(new_scorecard)
    except (OSError, json.JSONDecodeError, SchemaError) as exc:
        print(f"cannot read scorecard: {exc}", file=sys.stderr)
        return 2

    regressions = find_regressions(new_scorecard, args.results_dir,
                                   exclude=args.scorecard)
    if regressions:
        print(f"REGRESSION: previously-passing questions now failing for "
              f"model {new_scorecard['model']}: {regressions}", file=sys.stderr)
        return 1
    print(f"no regressions for model {new_scorecard['model']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
