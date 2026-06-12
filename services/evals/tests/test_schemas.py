"""Manifest/scorecard JSON-Schema validation (the contract)."""

import pytest

from ssdf_evals.schemas import SchemaError, validate_manifest, validate_scorecard


def make_manifest(**overrides):
    manifest = {
        "schema_version": 1,
        "run_id": "2026-06-12-test-001",
        "model": "test-model",
        "runner": "test-runner@abc123",
        "tier": "sovereign",
        "principal": "eval-test",
        "corpus_version": "deadbeef",
        "questions": [
            {"id": "flows-top-talkers-24h",
             "started": "2026-06-12T18:00:01Z",
             "finished": "2026-06-12T18:00:14Z",
             "answer": {"talkers": [{"ip": "10.74.11.20", "bytes": 1}]},
             "error": None},
        ],
    }
    manifest.update(overrides)
    return manifest


def test_valid_manifest_passes():
    validate_manifest(make_manifest())  # must not raise


def test_unknown_schema_version_rejected():
    with pytest.raises(SchemaError):
        validate_manifest(make_manifest(schema_version=2))


def test_missing_principal_rejected():
    manifest = make_manifest()
    del manifest["principal"]
    with pytest.raises(SchemaError):
        validate_manifest(manifest)


def test_bad_tier_rejected():
    with pytest.raises(SchemaError):
        validate_manifest(make_manifest(tier="both"))  # 'both' is a corpus tier, not a run tier


def test_question_missing_times_rejected():
    manifest = make_manifest()
    del manifest["questions"][0]["started"]
    with pytest.raises(SchemaError):
        validate_manifest(manifest)


def test_extra_top_level_key_rejected():
    with pytest.raises(SchemaError):
        validate_manifest(make_manifest(extra_field="nope"))


def test_valid_scorecard_passes():
    validate_scorecard({
        "schema_version": 1, "run_id": "r", "model": "m", "runner": "x",
        "tier": "sovereign", "principal": "eval-test", "corpus_version": "v",
        "scored_at": "2026-06-12T19:00:00Z",
        "questions": [{"id": "q1", "pass": True, "reasons": [],
                       "predicate_detail": {}, "tools_observed": ["top_talkers"]}],
        "rollups": {"total": 1, "passed": 1,
                    "by_category": {"flows": {"total": 1, "passed": 1}},
                    "by_difficulty": {"medium": {"total": 1, "passed": 1}},
                    "by_tier": {"sovereign": {"total": 1, "passed": 1}}},
    })  # must not raise


def test_scorecard_missing_rollups_rejected():
    with pytest.raises(SchemaError):
        validate_scorecard({"schema_version": 1})


def test_malformed_timestamp_rejected():
    manifest = make_manifest()
    manifest["questions"][0]["started"] = "yesterday-ish"
    with pytest.raises(SchemaError):
        validate_manifest(manifest)
