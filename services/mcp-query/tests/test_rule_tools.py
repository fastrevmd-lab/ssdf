"""RuleTools tests (MEC-566). The disagreement->unknown case is the safety-critical
one: unused_rules must never report "unused" (or "used") when the log rollup and
the device hit-counter give conflicting or incomplete signals -- neither may the
rollup's own coverage of the window, or the counter's own freshness, be assumed."""

from datetime import datetime, timezone

from ssdf_mcp_query.rule_tools import RuleTools
from ssdf_mcp_query.timeparse import parse_time

_FRESH_COLLECTED_AT = "__default__"


class FakeChClient:
    """Routes .run(sql, params) by table, mirroring tests/test_tools.py's FakeClient.

    `coverage_rows`, when given, is returned verbatim for the device-wide
    rollup-coverage query (letting tests force an empty/stale rollup). Otherwise
    the coverage query reports the rollup as spanning exactly [since, until]
    with `log_coverage_count` buckets -- "the rollup covers this window" by
    construction, for tests that only care about the per-rule usage/counter
    signals.
    """

    def __init__(self, usage_by_rule=None, log_coverage_count=1, coverage_rows=None):
        self._usage_by_rule = usage_by_rule or {}
        self._log_coverage_count = log_coverage_count
        self._coverage_rows = coverage_rows
        self.calls: list[tuple[str, dict]] = []

    def run(self, sql, params=None):
        params = params or {}
        self.calls.append((sql, params))
        if "min(bucket_start)" in sql:
            if self._coverage_rows is not None:
                rows = self._coverage_rows
            else:
                since_dt = parse_time(params["since"])
                until_dt = parse_time(params["until"])
                rows = [
                    {
                        "min_bucket": since_dt.isoformat(),
                        "max_bucket": until_dt.isoformat(),
                        "c": self._log_coverage_count,
                    }
                ]
            return {"columns": [], "rows": rows, "row_count": len(rows)}
        if "rule_usage_hourly" in sql:
            rows = self._usage_by_rule.get(params.get("rule"), [])
            return {"columns": [], "rows": rows, "row_count": len(rows)}
        if "policy_versions" in sql:
            return {"columns": [], "rows": [], "row_count": 0}
        raise AssertionError(f"unexpected sql: {sql}")


class FakeEntityStore:
    def __init__(self, policies):
        self._policies = policies

    def configured_policies_for_firewalls(self, firewall_names):
        return [{"firewall": firewall_names[0], "policy": p} for p in self._policies]


def _policy(name, hit_count=None, action="allow", hit_count_collected_at=_FRESH_COLLECTED_AT):
    """`hit_count_collected_at` defaults to "now" whenever `hit_count` is set, so
    tests that only care about the usage/counter agreement don't also have to
    reason about counter freshness. Pass an explicit ISO timestamp to test
    staleness, or `None` to simulate a counter value with no collection time."""
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
        if hit_count_collected_at == _FRESH_COLLECTED_AT:
            attrs["hit_count_collected_at"] = datetime.now(timezone.utc).isoformat()
        elif hit_count_collected_at is not None:
            attrs["hit_count_collected_at"] = hit_count_collected_at
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
    assert "does not cover the window" in out["rules"][0]["reason"]


def test_unused_rules_stale_counter_is_unknown():
    """The device hit-counter agrees with the log rollup (both say "no traffic"),
    but it was collected long before this window (device unreachable, collector
    broken) -- a fresh "unused" read off a stale counter is exactly the
    false-negative unused_rules exists to refuse. Repro (973284d): this policy
    currently comes back "unused" because nothing ever checked the counter's age."""
    policies = [
        _policy("RULE-STALE", hit_count="0", hit_count_collected_at="2026-01-01T00:00:00+00:00")
    ]
    ch = FakeChClient(usage_by_rule={"RULE-STALE": []})
    tools = RuleTools(ch, FakeEntityStore(policies))

    out = tools.unused_rules("vsrx-ci")
    assert out["rules"][0]["status"] == "unknown"
    assert "stale" in out["rules"][0]["reason"]
    assert "2026-01-01" in out["rules"][0]["reason"]
    assert out["rules"][0]["evidence"]["hit_count_collected_at"] == "2026-01-01T00:00:00+00:00"


def test_unused_rules_empty_rollup_with_device_events_is_unknown():
    """The device is genuinely logging (ssdf.events has rows) but the hourly
    rollup itself has no buckets for this window -- e.g. the rollup timer is
    down. unused_rules must trust the rollup's OWN coverage, not infer coverage
    from raw event volume it never queries. Repro (973284d): with an empty
    rollup and a fresh zero counter this used to read as "unused"."""
    policies = [_policy("RULE-EMPTY-ROLLUP", hit_count="0")]
    ch = FakeChClient(
        usage_by_rule={"RULE-EMPTY-ROLLUP": []},
        coverage_rows=[{"min_bucket": None, "max_bucket": None, "c": 0}],
    )
    tools = RuleTools(ch, FakeEntityStore(policies))

    out = tools.unused_rules("vsrx-ci")
    assert out["rules"][0]["status"] == "unknown"
    assert "does not cover the window" in out["rules"][0]["reason"]


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
