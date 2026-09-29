"""rule_history / rule_usage / unused_rules / explain_rule (MEC-566, Firewall Memory v1).

unused_rules is the safety-critical tool here: it cross-checks two INDEPENDENT,
deterministic signals for "has this rule matched traffic" --

  * log coverage: ssdf.rule_usage_hourly, rolled up from ssdf.events.rule_name
    (RT_FLOW for Junos, TRAFFIC/THREAT for PAN-OS)
  * counter coverage: the device's own cumulative hit-count counter, collected
    read-only by services/policy's collectors into the configured-policy
    entity's attrs

When the two signals disagree, or either one's coverage is itself uncertain
(no log ingest observed for the device, or the counter was never collected),
the verdict is "unknown" -- NEVER "unused". A SOC engineer acting on a false
"unused" verdict could delete a rule that is genuinely live. See
tests/test_rule_tools.py for the disagreement case.

Every call here reaches ssdf.audit through server.py's `audited_tool` wrapper
like any other tool (tier="sovereign", data_classes from classification.py) --
that is the "join to the audit evidence tier" this feature needs: these tools
never read ssdf.audit directly (ssdf_ro is deliberately never granted SELECT
on it, see infra/clickhouse/007_audit.sql), they just become audit rows like
everything else, under the SAME `tier` column MEC-565's checkpoint anchoring
already chains on.
"""

from __future__ import annotations

from .rule_builders import (
    build_device_log_coverage_sql,
    build_rule_history_sql,
    build_rule_usage_sql,
)
from .timeparse import parse_time

DEFAULT_UNUSED_WINDOW_HOURS = 24 * 7


def _verdict(
    log_coverage_ok: bool, log_used: bool, counter_known: bool, counter_used: bool
) -> tuple[str, str]:
    if not log_coverage_ok:
        return "unknown", "no log ingest observed for this device in the window"
    if not counter_known:
        return "unknown", "device hit-counter was not collected for this rule"
    if log_used != counter_used:
        return "unknown", "log rollup and device hit-counter disagree"
    return ("used" if log_used else "unused"), "log rollup and device hit-counter agree"


class RuleTools:
    """Stateless rule-memory tool surface bound to a ClickHouse client + EntityStore."""

    def __init__(self, ch_client, entity_store):
        self._ch = ch_client
        self._store = entity_store

    def _policy_for(self, device_name: str, rule_name: str) -> dict | None:
        for item in self._store.configured_policies_for_firewalls([device_name]):
            if item["policy"].get("name") == rule_name:
                return item["policy"]
        return None

    def rule_history(self, device_name: str, rule_name: str, limit: int = 50) -> dict:
        sql, params = build_rule_history_sql(device_name, rule_name, limit=limit)
        result = self._ch.run(sql, params)
        return {
            "device_name": device_name,
            "rule_name": rule_name,
            "versions": result["rows"],
            "row_count": result["row_count"],
        }

    def rule_usage(self, device_name: str, rule_name: str, since=None, until=None) -> dict:
        sql, params = build_rule_usage_sql(device_name, rule_name, since=since, until=until)
        result = self._ch.run(sql, params)
        buckets = result["rows"]
        total_sessions = sum(int(b["sessions"]) for b in buckets)
        total_bytes = sum(int(b["bytes"]) for b in buckets)
        policy = self._policy_for(device_name, rule_name)
        hit_count = None
        if policy is not None:
            raw = policy.get("attrs", {}).get("hit_count")
            if raw not in (None, ""):
                hit_count = int(raw)
        return {
            "device_name": device_name,
            "rule_name": rule_name,
            "buckets": buckets,
            "total_sessions": total_sessions,
            "total_bytes": total_bytes,
            "device_hit_count": hit_count,
        }

    def _log_coverage(self, device_name: str, since, until) -> bool:
        sql, params = build_device_log_coverage_sql(device_name, since, until)
        rows = self._ch.run(sql, params)["rows"]
        return bool(rows) and int(rows[0]["c"]) > 0

    def unused_rules(self, device_name: str, since=None, until=None) -> dict:
        since_dt = parse_time(since) if since else parse_time(f"now-{DEFAULT_UNUSED_WINDOW_HOURS}h")
        until_dt = parse_time(until) if until else parse_time("now")
        since_iso, until_iso = since_dt.isoformat(), until_dt.isoformat()

        policies = [
            item["policy"] for item in self._store.configured_policies_for_firewalls([device_name])
        ]
        log_coverage_ok = self._log_coverage(device_name, since_iso, until_iso)

        results = []
        for policy in policies:
            rule_name = policy.get("name", "")
            usage_sql, usage_params = build_rule_usage_sql(
                device_name, rule_name, since=since_iso, until=until_iso
            )
            usage_rows = self._ch.run(usage_sql, usage_params)["rows"]
            log_used = any(int(row["sessions"]) > 0 for row in usage_rows)

            raw_hit = policy.get("attrs", {}).get("hit_count")
            counter_known = raw_hit not in (None, "")
            counter_used = counter_known and int(raw_hit) > 0

            status, reason = _verdict(log_coverage_ok, log_used, counter_known, counter_used)
            results.append(
                {
                    "rule_name": rule_name,
                    "status": status,
                    "reason": reason,
                    "evidence": {
                        "log_coverage": log_coverage_ok,
                        "log_used": log_used,
                        "device_hit_count": int(raw_hit) if counter_known else None,
                    },
                }
            )
        return {
            "device_name": device_name,
            "since": since_iso,
            "until": until_iso,
            "rules": results,
            "row_count": len(results),
        }

    def explain_rule(self, device_name: str, rule_name: str, since=None, until=None) -> dict:
        policy = self._policy_for(device_name, rule_name)
        if policy is None:
            return {
                "error": "not_found",
                "detail": f"no configured rule '{rule_name}' on '{device_name}'",
            }
        usage = self.rule_usage(device_name, rule_name, since=since, until=until)
        history = self.rule_history(device_name, rule_name, limit=5)
        unused = self.unused_rules(device_name, since=since, until=until)
        verdict = next((r for r in unused["rules"] if r["rule_name"] == rule_name), None)
        attrs = policy.get("attrs", {})

        # Deterministic string assembly ONLY -- every value here is cited straight
        # from the query results above. No model call, no inferred claim about
        # whether the rule is "safe" to remove; the house rule is deterministic
        # code decides, the model explains, and this tool's job stops at citing
        # the data a downstream model would explain.
        status = verdict["status"] if verdict else "unknown"
        summary = (
            f"{rule_name} on {device_name}: action={attrs.get('action', '')}, "
            f"enabled={attrs.get('enabled', '')}, "
            f"sessions_in_window={usage['total_sessions']}, "
            f"device_hit_count={usage['device_hit_count']}, "
            f"usage_status={status}."
        )
        return {
            "device_name": device_name,
            "rule_name": rule_name,
            "config": {
                "action": attrs.get("action", ""),
                "from_zone": attrs.get("from_zone", ""),
                "to_zone": attrs.get("to_zone", ""),
                "enabled": attrs.get("enabled", "") == "true",
                "position": attrs.get("position", ""),
            },
            "usage": usage,
            "recent_versions": history["versions"],
            "unused_verdict": verdict,
            "summary": summary,
        }
