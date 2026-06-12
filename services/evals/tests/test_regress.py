"""Regression gate: 'no question that ever passed (per model) may silently fail'."""

import json
from pathlib import Path

from ssdf_evals.regress import find_regressions, main


def card(model, run_id, results: dict[str, bool]):
    return {
        "schema_version": 1, "run_id": run_id, "model": model, "runner": "t@1",
        "tier": "sovereign", "principal": "eval-test", "corpus_version": "v1",
        "scored_at": "2026-06-12T19:00:00Z",
        "questions": [{"id": qid, "pass": passed, "reasons": [],
                       "predicate_detail": {}, "tools_observed": []}
                      for qid, passed in results.items()],
        "rollups": {"total": len(results),
                    "passed": sum(results.values()),
                    "by_category": {}, "by_difficulty": {}, "by_tier": {}},
    }


def write(path: Path, scorecard: dict) -> Path:
    path.write_text(json.dumps(scorecard))
    return path


def test_regression_detected(tmp_path):
    write(tmp_path / "old.json", card("m1", "r1", {"q1": True, "q2": False}))
    new = card("m1", "r2", {"q1": False, "q2": False})
    assert find_regressions(new, tmp_path) == ["q1"]  # q2 never passed


def test_other_models_history_ignored(tmp_path):
    write(tmp_path / "other.json", card("m2", "r1", {"q1": True}))
    new = card("m1", "r2", {"q1": False})
    assert find_regressions(new, tmp_path) == []


def test_removed_question_is_not_a_regression(tmp_path):
    write(tmp_path / "old.json", card("m1", "r1", {"q-removed": True}))
    new = card("m1", "r2", {"q1": True})
    assert find_regressions(new, tmp_path) == []


def test_new_scorecard_file_excluded_from_history(tmp_path):
    # the new card may already be saved in results/ when regress runs
    new = card("m1", "r2", {"q1": False})
    new_path = write(tmp_path / "new.json", new)
    assert main([str(new_path), "--results-dir", str(tmp_path)]) == 0


def test_main_exit_codes(tmp_path):
    write(tmp_path / "old.json", card("m1", "r1", {"q1": True}))
    ok = write(tmp_path / "ok.json", card("m1", "r2", {"q1": True}))
    bad = write(tmp_path / "bad.json", card("m1", "r3", {"q1": False}))
    assert main([str(ok), "--results-dir", str(tmp_path)]) == 0
    assert main([str(bad), "--results-dir", str(tmp_path)]) == 1
    garbage = tmp_path / "g.json"
    garbage.write_text("{nope")
    assert main([str(garbage), "--results-dir", str(tmp_path)]) == 2
