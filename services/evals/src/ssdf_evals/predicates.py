"""Deterministic predicate engine. evaluate() never raises (fail-closed)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .corpus import Question


@dataclass
class PredicateResult:
    passed: bool
    reason: str
    detail: dict = field(default_factory=dict)


def _normalize(value: Any) -> Any:
    """Recursively sort scalar-only lists; recurse into dict values. Leave mixed lists."""
    if isinstance(value, dict):
        return {k: _normalize(v) for k, v in value.items()}
    if isinstance(value, list):
        normalized = [_normalize(item) for item in value]
        # only sort if every element is a scalar (sortable, not dict/list)
        if all(isinstance(item, (str, int, float, bool, type(None)))
               for item in normalized):
            return sorted(normalized, key=lambda x: (x is None, str(x)))
        return normalized
    return value


def _agent_values(answer: dict, predicate: dict) -> list[Any]:
    value = answer[predicate["answer_key"]]
    if not isinstance(value, list):
        value = [value]
    item_key = predicate.get("item_key")
    if item_key:
        value = [item[item_key] for item in value]
    return value


def _eval_reference_sql(question: Question, answer: dict, ch_client) -> PredicateResult:
    predicate = question.predicate
    rows = ch_client.query(predicate["sql"]).result_rows
    reference = [str(row[0]) for row in rows]
    match = predicate["match"]
    params = predicate.get("params", {})

    if match == "numeric_tolerance":
        if not reference:
            return PredicateResult(False, "reference query returned no rows")
        agent = float(answer[predicate["answer_key"]])
        ref = float(reference[0])
        if "tolerance" in params:
            allowed = float(params["tolerance"])
        else:
            allowed = abs(ref) * float(params["tolerance_pct"]) / 100.0
        passed = abs(agent - ref) <= allowed
        return PredicateResult(
            passed, "" if passed else f"|{agent}-{ref}| > {allowed}",
            {"agent": agent, "reference": ref, "allowed": allowed})

    agent_set = {str(v) for v in _agent_values(answer, predicate)}
    reference_set = set(reference)
    detail = {"agent": sorted(agent_set), "reference": sorted(reference_set)}
    if match == "exact":
        passed = agent_set == reference_set
        return PredicateResult(passed, "" if passed else "exact set mismatch", detail)
    # set_overlap
    overlap = len(agent_set & reference_set)
    needed = int(params["min_overlap"])
    passed = overlap >= needed
    return PredicateResult(
        passed, "" if passed else f"overlap {overlap} < required {needed}",
        {**detail, "overlap": overlap})


def evaluate(question: Question, answer: dict | None, ch_client) -> PredicateResult:
    """Evaluate one question's predicate against the agent's structured answer."""
    predicate = question.predicate
    ptype = predicate["type"]
    try:
        if ptype == "refusal":
            passed = isinstance(answer, dict) and answer.get("refusal") is True
            return PredicateResult(passed, "" if passed else "expected refusal=true")
        if answer is None:
            return PredicateResult(False, "no answer provided")
        if ptype == "expected_json":
            passed = _normalize(answer) == _normalize(predicate["expected"])
            return PredicateResult(
                passed, "" if passed else "answer != expected",
                {"expected": predicate["expected"], "agent": answer})
        return _eval_reference_sql(question, answer, ch_client)
    except Exception as exc:  # fail-closed: any predicate error = question fails
        return PredicateResult(False, f"predicate error: {exc}")
