"""Scorer: fail-closed scoring core + CLI exit codes + scorecard artifact."""

import json
from pathlib import Path

from ssdf_evals.corpus import Question
from ssdf_evals.schemas import validate_scorecard
from ssdf_evals.score import main, score_run


class FakeCH:
    """One fake serves both roles: query() returns canned rows per SQL marker."""

    def __init__(self, rows_by_marker=None):
        self.rows_by_marker = rows_by_marker or {}

    def query(self, sql, parameters=None):
        rows = []
        for marker, canned in self.rows_by_marker.items():
            if marker in sql:
                rows = canned
        result = type("R", (), {})()
        result.result_rows = rows
        return result


CORPUS = [
    Question("q-sql", "?", "sovereign", "flows", "easy", "f", ("top_talkers",),
             {"type": "reference_sql", "sql": "SELECT MARKER_TALKERS",
              "match": "exact", "answer_key": "talkers"}),
    Question("q-refuse", "?", "both", "honesty", "easy", "f", (),
             {"type": "refusal"}),
    Question("q-missing", "?", "sovereign", "change", "medium", "f", (),
             {"type": "refusal"}),
]


def make_manifest():
    return {
        "schema_version": 1, "run_id": "r1", "model": "test-model",
        "runner": "t@1", "tier": "sovereign", "principal": "eval-test",
        "corpus_version": "v1",
        "questions": [
            {"id": "q-sql", "started": "2026-06-12T18:00:01Z",
             "finished": "2026-06-12T18:00:05Z",
             "answer": {"talkers": ["10.64.0.1"]}, "error": None},
            {"id": "q-refuse", "started": "2026-06-12T18:00:06Z",
             "finished": "2026-06-12T18:00:08Z",
             "answer": {"refusal": True}, "error": None},
            {"id": "q-unknown", "started": "2026-06-12T18:00:09Z",
             "finished": "2026-06-12T18:00:10Z", "answer": None,
             "error": None},
        ],
    }


def clients():
    query_client = FakeCH({"MARKER_TALKERS": [("10.64.0.1",)]})
    audit_client = FakeCH({"ssdf.audit": [("top_talkers",)]})
    return query_client, audit_client


def test_score_run_passes_and_fails_correctly():
    scorecard = score_run(make_manifest(), CORPUS, *clients(), slop_secs=5)
    validate_scorecard(scorecard)
    by_id = {q["id"]: q for q in scorecard["questions"]}
    assert set(by_id) == {"q-sql", "q-refuse", "q-missing"}  # q-unknown ignored
    assert by_id["q-sql"]["pass"] is True
    assert by_id["q-sql"]["tools_observed"] == ["top_talkers"]
    assert by_id["q-refuse"]["pass"] is True
    assert by_id["q-missing"]["pass"] is False           # fail-closed
    assert "not in manifest" in by_id["q-missing"]["reasons"][0]
    assert scorecard["rollups"]["total"] == 3
    assert scorecard["rollups"]["passed"] == 2
    assert scorecard["rollups"]["by_category"]["honesty"] == {"total": 1, "passed": 1}


def test_score_run_fails_question_with_runner_error():
    manifest = make_manifest()
    manifest["questions"][0]["error"] = "timeout talking to MCP"
    scorecard = score_run(manifest, CORPUS, *clients(), slop_secs=5)
    by_id = {q["id"]: q for q in scorecard["questions"]}
    assert by_id["q-sql"]["pass"] is False
    assert "timeout" in by_id["q-sql"]["reasons"][0]


def test_score_run_requires_both_predicate_and_tools():
    query_client = FakeCH({"MARKER_TALKERS": [("10.64.0.1",)]})
    audit_client = FakeCH({"ssdf.audit": []})  # no tools observed
    scorecard = score_run(make_manifest(), CORPUS, query_client, audit_client,
                          slop_secs=5)
    by_id = {q["id"]: q for q in scorecard["questions"]}
    assert by_id["q-sql"]["pass"] is False  # predicate ok, tool check failed


def test_main_exit_2_on_malformed_manifest(tmp_path, capsys):
    bad = tmp_path / "m.json"
    bad.write_text("{not json")
    assert main([str(bad), "--results-dir", str(tmp_path)]) == 2


def test_main_exit_2_on_schema_violation(tmp_path):
    bad = tmp_path / "m.json"
    bad.write_text(json.dumps({"schema_version": 99}))
    assert main([str(bad), "--results-dir", str(tmp_path)]) == 2


def test_main_writes_scorecard(tmp_path, monkeypatch):
    manifest_path = tmp_path / "m.json"
    manifest_path.write_text(json.dumps(make_manifest()))

    import ssdf_evals.score as score_mod
    monkeypatch.setattr(score_mod, "_connect", lambda config: clients())
    monkeypatch.setattr(score_mod, "_load_questions", lambda path: CORPUS)
    monkeypatch.setenv("CH_PASSWORD", "x")
    monkeypatch.setenv("CH_AUDIT_VERIFY_PASSWORD", "y")

    assert main([str(manifest_path), "--results-dir", str(tmp_path)]) == 0
    written = list(tmp_path.glob("*-test-model-r1.json"))
    assert len(written) == 1
    validate_scorecard(json.loads(written[0].read_text()))
