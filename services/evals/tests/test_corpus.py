"""Corpus loader + the corpus lint test (spec: 'Corpus constraints')."""

import re
from pathlib import Path

import pytest

from ssdf_evals.corpus import (
    PUBLIC_TOOLS, SOVEREIGN_TOOLS, CorpusError, Question, load_corpus,
    questions_for_tier,
)

GOLDEN = Path(__file__).resolve().parents[1] / "golden" / "core.yaml"


def make_question(**overrides) -> dict:
    question = {
        "id": "test-q", "question": "What?", "tier": "sovereign",
        "category": "flows", "difficulty": "easy",
        "answer_format": 'Answer with JSON: {"x": 1}',
        "required_tools": [],
        "predicate": {"type": "refusal"},
    }
    question.update(overrides)
    return question


def write_corpus(tmp_path, questions):
    import yaml
    path = tmp_path / "c.yaml"
    path.write_text(yaml.safe_dump(questions))
    return path


def test_load_minimal_corpus(tmp_path):
    questions = load_corpus(write_corpus(tmp_path, [make_question()]))
    assert questions == [Question(
        id="test-q", question="What?", tier="sovereign", category="flows",
        difficulty="easy", answer_format='Answer with JSON: {"x": 1}',
        required_tools=(), predicate={"type": "refusal"},
    )]


def test_duplicate_ids_rejected(tmp_path):
    with pytest.raises(CorpusError):
        load_corpus(write_corpus(tmp_path, [make_question(), make_question()]))


def test_bad_tier_rejected(tmp_path):
    with pytest.raises(CorpusError):
        load_corpus(write_corpus(tmp_path, [make_question(tier="secret")]))


def test_public_question_with_sovereign_tool_rejected(tmp_path):
    bad = make_question(tier="both", required_tools=["top_talkers"])
    with pytest.raises(CorpusError):
        load_corpus(write_corpus(tmp_path, [bad]))


def test_non_select_reference_sql_rejected(tmp_path):
    bad = make_question(predicate={
        "type": "reference_sql", "sql": "ALTER TABLE ssdf.events DELETE WHERE 1",
        "match": "exact", "answer_key": "x"})
    with pytest.raises(CorpusError):
        load_corpus(write_corpus(tmp_path, [bad]))


def test_questions_for_tier():
    questions = [
        Question("a", "?", "sovereign", "flows", "easy", "f", (), {"type": "refusal"}),
        Question("b", "?", "public", "topology", "easy", "f", (), {"type": "refusal"}),
        Question("c", "?", "both", "topology", "easy", "f", (), {"type": "refusal"}),
    ]
    assert [q.id for q in questions_for_tier(questions, "sovereign")] == ["a", "c"]
    assert [q.id for q in questions_for_tier(questions, "public")] == ["b", "c"]


# ---- the corpus lint: golden/core.yaml itself must satisfy every constraint ----

def test_golden_corpus_lints():
    questions = load_corpus(GOLDEN)  # raises CorpusError on any violation
    assert len(questions) >= 20
    categories = {q.category for q in questions}
    assert categories == {"reachability", "flows", "topology", "change", "honesty"}
    # every category has at least 3 questions
    for category in categories:
        assert sum(1 for q in questions if q.category == category) >= 3
    # at least one public-or-both question exists (the public-tier subset is real)
    assert any(q.tier in ("public", "both") for q in questions)
    # refusal questions never carry SQL
    for q in questions:
        if q.predicate["type"] == "refusal":
            assert "sql" not in q.predicate
