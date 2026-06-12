"""Deterministic predicate engine: refusal / expected_json / reference_sql."""

from ssdf_evals.corpus import Question
from ssdf_evals.predicates import PredicateResult, evaluate


class FakeCH:
    """Stands in for clickhouse_connect client: .query(sql).result_rows."""

    def __init__(self, rows=None, error=None):
        self._rows, self._error = rows or [], error
        self.queries = []

    def query(self, sql):
        self.queries.append(sql)
        if self._error:
            raise self._error

        class R:
            result_rows = self._rows
        return R()


def make_question(predicate, qid="q") -> Question:
    return Question(id=qid, question="?", tier="sovereign", category="flows",
                    difficulty="easy", answer_format="f", required_tools=(),
                    predicate=predicate)


def test_refusal_pass():
    q = make_question({"type": "refusal"})
    assert evaluate(q, {"refusal": True, "reason": "no okta data"}, FakeCH()).passed


def test_refusal_fail_on_fabricated_answer():
    q = make_question({"type": "refusal"})
    result = evaluate(q, {"refusal": False, "count": 42}, FakeCH())
    assert not result.passed


def test_refusal_fail_on_none_answer():
    q = make_question({"type": "refusal"})
    assert not evaluate(q, None, FakeCH()).passed


def test_expected_json_exact():
    q = make_question({"type": "expected_json",
                       "expected": {"kind": "device", "role": "firewall"}})
    assert evaluate(q, {"kind": "device", "role": "firewall"}, FakeCH()).passed
    assert not evaluate(q, {"kind": "device", "role": "router"}, FakeCH()).passed


def test_reference_sql_exact_set():
    q = make_question({"type": "reference_sql", "sql": "SELECT 1",
                       "match": "exact", "answer_key": "providers"})
    ch = FakeCH(rows=[("juniper",), ("paloalto",)])
    assert evaluate(q, {"providers": ["paloalto", "juniper"]}, ch).passed
    assert not evaluate(q, {"providers": ["paloalto"]}, ch).passed


def test_reference_sql_exact_scalar():
    q = make_question({"type": "reference_sql", "sql": "SELECT 1",
                       "match": "exact", "answer_key": "rule"})
    ch = FakeCH(rows=[("drifttest1",)])
    assert evaluate(q, {"rule": "drifttest1"}, ch).passed


def test_reference_sql_set_overlap_with_item_key():
    q = make_question({"type": "reference_sql", "sql": "SELECT 1",
                       "match": "set_overlap", "answer_key": "talkers",
                       "item_key": "ip", "params": {"min_overlap": 2}})
    ch = FakeCH(rows=[("10.64.0.1",), ("10.64.0.2",), ("10.64.0.3",)])
    answer = {"talkers": [{"ip": "10.64.0.2", "bytes": 5},
                          {"ip": "10.64.0.3", "bytes": 4},
                          {"ip": "10.73.9.9", "bytes": 3}]}
    assert evaluate(q, answer, ch).passed
    assert not evaluate(q, {"talkers": [{"ip": "10.73.9.9", "bytes": 1}]}, ch).passed


def test_reference_sql_numeric_tolerance_abs():
    q = make_question({"type": "reference_sql", "sql": "SELECT 1",
                       "match": "numeric_tolerance", "answer_key": "count",
                       "params": {"tolerance": 0}})
    assert evaluate(q, {"count": 6}, FakeCH(rows=[(6,)])).passed
    assert not evaluate(q, {"count": 7}, FakeCH(rows=[(6,)])).passed


def test_reference_sql_numeric_tolerance_pct():
    q = make_question({"type": "reference_sql", "sql": "SELECT 1",
                       "match": "numeric_tolerance", "answer_key": "count",
                       "params": {"tolerance_pct": 10}})
    assert evaluate(q, {"count": 95}, FakeCH(rows=[(100,)])).passed
    assert not evaluate(q, {"count": 80}, FakeCH(rows=[(100,)])).passed


def test_sql_error_fails_closed_without_raising():
    q = make_question({"type": "reference_sql", "sql": "SELECT 1",
                       "match": "exact", "answer_key": "x"})
    result = evaluate(q, {"x": "a"}, FakeCH(error=RuntimeError("CH down")))
    assert isinstance(result, PredicateResult)
    assert not result.passed
    assert "CH down" in result.reason


def test_missing_answer_key_fails_closed():
    q = make_question({"type": "reference_sql", "sql": "SELECT 1",
                       "match": "exact", "answer_key": "missing"})
    assert not evaluate(q, {"other": 1}, FakeCH(rows=[("a",)])).passed
