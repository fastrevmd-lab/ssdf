"""ssdf.audit tool-usage checks: required ⊆ observed; public-tier surface guard."""

from datetime import datetime, timezone

from ssdf_evals.auditcheck import ToolCheckResult, check_tools, fetch_tools
from ssdf_evals.corpus import Question


class FakeCH:
    def __init__(self, rows):
        self._rows = rows
        self.last = None

    def query(self, sql, parameters=None):
        self.last = (sql, parameters)

        class R:
            result_rows = self._rows
        return R()


def make_question(required_tools=()) -> Question:
    return Question(id="q", question="?", tier="sovereign", category="flows",
                    difficulty="easy", answer_format="f",
                    required_tools=tuple(required_tools),
                    predicate={"type": "refusal"})


def test_fetch_tools_windows_by_principal_and_slop():
    ch = FakeCH(rows=[("top_talkers",), ("locate",)])
    started = datetime(2026, 6, 12, 18, 0, 1, tzinfo=timezone.utc)
    finished = datetime(2026, 6, 12, 18, 0, 14, tzinfo=timezone.utc)
    tools = fetch_tools(ch, "eval-claude", started, finished, slop_secs=5)
    assert tools == ["locate", "top_talkers"]  # sorted
    sql, parameters = ch.last
    assert "principal" in sql and "ts" in sql
    assert parameters["principal"] == "eval-claude"
    assert parameters["start"] == "2026-06-12 17:59:56"   # started - 5s
    assert parameters["end"] == "2026-06-12 18:00:19"     # finished + 5s


def test_required_subset_passes():
    result = check_tools(make_question(["top_talkers"]),
                         ["top_talkers", "run_sql"], tier="sovereign")
    assert result == ToolCheckResult(True, ["top_talkers", "run_sql"], "")


def test_missing_required_tool_fails():
    result = check_tools(make_question(["explain_access"]), ["run_sql"],
                         tier="sovereign")
    assert not result.passed
    assert "explain_access" in result.reason


def test_no_required_tools_always_passes():
    assert check_tools(make_question([]), [], tier="sovereign").passed


def test_public_tier_rejects_sovereign_tool_observed():
    result = check_tools(make_question([]), ["locate", "run_sql"], tier="public")
    assert not result.passed
    assert "run_sql" in result.reason


def test_public_tier_with_public_tools_passes():
    assert check_tools(make_question(["locate"]), ["locate"], tier="public").passed
