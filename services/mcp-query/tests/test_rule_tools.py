"""RuleTools tests (MEC-566). The disagreement->unknown case is the safety-critical
one: unused_rules must never report "unused" (or "used") when the log rollup and
the device hit-counter give conflicting or incomplete signals."""

from ssdf_mcp_query.rule_tools import RuleTools


class FakeChClient:
    """Routes .run(sql, params) by table, mirroring tests/test_tools.py's FakeClient."""

    def __init__(self, usage_by_rule=None, log_coverage_count=1):
        self._usage_by_rule = usage_by_rule or {}
        self._log_coverage_count = log_coverage_count
        self.calls: list[tuple[str, dict]] = []

    def run(self, sql, params=None):
        params = params or {}
        self.calls.append((sql, params))
        if "rule_usage_hourly" in sql:
            rows = self._usage_by_rule.get(params.get("rule"), [])
            return {"columns": [], "rows": rows, "row_count": len(rows)}
        if "policy_versions" in sql:
            return {"columns": [], "rows": [], "row_count": 0}
        if "FROM ssdf.events" in sql:
            return {"columns": ["c"], "rows": [{"c": self._log_coverage_count}], "row_count": 1}
        raise AssertionError(f"unexpected sql: {sql}")


class FakeEntityStore:
    def __init__(self, policies):
        self._policies = policies

    def configured_policies_for_firewalls(self, firewall_names):
        return [{"firewall": firewall_names[0], "policy": p} for p in self._policies]


def _policy(name, hit_count=None, action="allow"):
    attrs = {
        "provider": "juniper",
        "device_name": "vsrx-ci",
        "action": action,
        "from_zone": "trust",
        "to_zone": "untrust",
        "enabled": "true",
        "position": "0",
    }
    if hit_count is not None:
        attrs["hit_count"] = hit_count
    return {"entity_id": f"pol-{name}", "name": name, "attrs": attrs}


def _usage_row(sessions, bucket="2026-09-28T10:00:00"):
    return {
        "bucket_start": bucket,
        "provider": "juniper",
        "observer_hostname": "vsrx-ci",
        "rule_name": "r",
        "sessions": sessions,
        "bytes": sessions * 100,
    }


# ---- unused_rules: the hard requirement ----


def test_unused_rules_disagreement_log_used_counter_zero_is_unknown():
    """Log rollup shows traffic; device counter shows zero. Must be unknown, not
    "used" and definitely not "unused" -- disagreement is the exact scenario
    where a wrong 'unused' verdict could get a live rule deleted."""
    policies = [_policy("RULE-A", hit_count="0")]
    ch = FakeChClient(usage_by_rule={"RULE-A": [_usage_row(sessions=10)]}, log_coverage_count=5)
    tools = RuleTools(ch, FakeEntityStore(policies))

    out = tools.unused_rules("vsrx-ci")
    assert out["rules"][0]["status"] == "unknown"
    assert "disagree" in out["rules"][0]["reason"]


def test_unused_rules_disagreement_log_unused_counter_positive_is_unknown():
    """Opposite disagreement direction: device counter positive, no log rollup rows."""
    policies = [_policy("RULE-B", hit_count="5")]
    ch = FakeChClient(usage_by_rule={"RULE-B": []}, log_coverage_count=5)
    tools = RuleTools(ch, FakeEntityStore(policies))

    out = tools.unused_rules("vsrx-ci")
    assert out["rules"][0]["status"] == "unknown"


def test_unused_rules_missing_counter_is_unknown_not_unused():
    """No hit_count was ever collected for this rule (device unreachable at
    collection time, or hit-count command failed) -- must not default to
    'unused' just because the log rollup found nothing either."""
    policies = [_policy("RULE-C", hit_count=None)]
    ch = FakeChClient(usage_by_rule={"RULE-C": []}, log_coverage_count=5)
    tools = RuleTools(ch, FakeEntityStore(policies))

    out = tools.unused_rules("vsrx-ci")
    assert out["rules"][0]["status"] == "unknown"
    assert "not collected" in out["rules"][0]["reason"]


def test_unused_rules_no_log_coverage_is_unknown():
    """Device isn't logging at all in the window -- zero usage rows are not
    evidence of "unused", they're evidence of "we can't see this device"."""
    policies = [_policy("RULE-D", hit_count="0")]
    ch = FakeChClient(usage_by_rule={"RULE-D": []}, log_coverage_count=0)
    tools = RuleTools(ch, FakeEntityStore(policies))

    out = tools.unused_rules("vsrx-ci")
    assert out["rules"][0]["status"] == "unknown"
    assert "log ingest" in out["rules"][0]["reason"]


def test_unused_rules_agreement_used():
    policies = [_policy("RULE-E", hit_count="42")]
    ch = FakeChClient(usage_by_rule={"RULE-E": [_usage_row(sessions=3)]}, log_coverage_count=5)
    tools = RuleTools(ch, FakeEntityStore(policies))

    out = tools.unused_rules("vsrx-ci")
    assert out["rules"][0]["status"] == "used"


def test_unused_rules_agreement_unused():
    policies = [_policy("RULE-F", hit_count="0")]
    ch = FakeChClient(usage_by_rule={"RULE-F": []}, log_coverage_count=5)
    tools = RuleTools(ch, FakeEntityStore(policies))

    out = tools.unused_rules("vsrx-ci")
    assert out["rules"][0]["status"] == "unused"


def test_unused_rules_evaluates_every_configured_rule():
    policies = [_policy("R1", hit_count="0"), _policy("R2", hit_count="9")]
    ch = FakeChClient(
        usage_by_rule={"R1": [], "R2": [_usage_row(sessions=1)]}, log_coverage_count=5
    )
    tools = RuleTools(ch, FakeEntityStore(policies))

    out = tools.unused_rules("vsrx-ci")
    assert out["row_count"] == 2
    statuses = {r["rule_name"]: r["status"] for r in out["rules"]}
    assert statuses == {"R1": "unused", "R2": "used"}


# ---- rule_usage ----


def test_rule_usage_totals_and_device_hit_count():
    policies = [_policy("ALLOW-WEB", hit_count="7")]
    ch = FakeChClient(usage_by_rule={"ALLOW-WEB": [_usage_row(5), _usage_row(3)]})
    tools = RuleTools(ch, FakeEntityStore(policies))

    out = tools.rule_usage("vsrx-ci", "ALLOW-WEB")
    assert out["total_sessions"] == 8
    assert out["total_bytes"] == 800
    assert out["device_hit_count"] == 7


def test_rule_usage_no_policy_match_leaves_hit_count_none():
    ch = FakeChClient(usage_by_rule={"GHOST": []})
    tools = RuleTools(ch, FakeEntityStore([]))

    out = tools.rule_usage("vsrx-ci", "GHOST")
    assert out["device_hit_count"] is None
    assert out["total_sessions"] == 0


# ---- rule_history ----


def test_rule_history_returns_row_count():
    ch = FakeChClient()
    tools = RuleTools(ch, FakeEntityStore([]))
    out = tools.rule_history("vsrx-ci", "ALLOW-WEB")
    assert out["row_count"] == 0
    assert out["versions"] == []


# ---- explain_rule ----


def test_explain_rule_not_found_returns_structured_error():
    ch = FakeChClient()
    tools = RuleTools(ch, FakeEntityStore([]))
    out = tools.explain_rule("vsrx-ci", "GHOST")
    assert out["error"] == "not_found"


def test_explain_rule_cites_unused_verdict_and_usage_data():
    policies = [_policy("ALLOW-WEB", hit_count="0", action="allow")]
    ch = FakeChClient(usage_by_rule={"ALLOW-WEB": []}, log_coverage_count=5)
    tools = RuleTools(ch, FakeEntityStore(policies))

    out = tools.explain_rule("vsrx-ci", "ALLOW-WEB")
    assert out["unused_verdict"]["status"] == "unused"
    assert out["config"]["action"] == "allow"
    assert "usage_status=unused" in out["summary"]
    assert "ALLOW-WEB" in out["summary"] and "vsrx-ci" in out["summary"]


def test_explain_rule_summary_reflects_unknown_on_disagreement():
    policies = [_policy("ALLOW-WEB", hit_count="0")]
    ch = FakeChClient(usage_by_rule={"ALLOW-WEB": [_usage_row(10)]}, log_coverage_count=5)
    tools = RuleTools(ch, FakeEntityStore(policies))

    out = tools.explain_rule("vsrx-ci", "ALLOW-WEB")
    assert out["unused_verdict"]["status"] == "unknown"
    assert "usage_status=unknown" in out["summary"]
