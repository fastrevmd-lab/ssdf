"""Hourly rollup of ssdf.events.rule_name into ssdf.rule_usage_hourly (MEC-566).

Deterministic aggregation only -- no model involvement, matches the house rule
that deterministic code decides while a model may later narrate the result
(explain_rule). Run periodically (e.g. an hourly systemd timer) as the
least-privilege `ssdf_ruleusage` identity created by
infra/clickhouse/019_rule_usage_hourly.sql -- separate from the `ssdf_entity`
resolver identity, matching the split already used for
`ssdf_entity_maint` (011_entity_maint_user.sql):

    CH_USER=ssdf_ruleusage python -m ssdf_policy.rule_usage_rollup
"""

from __future__ import annotations

import datetime
import logging
import os

import clickhouse_connect

from .chwriter import client_kwargs
from .config import load_config

log = logging.getLogger("ssdf_policy.rule_usage_rollup")

ROLLUP_COLUMNS = [
    "tenant_id",
    "bucket_start",
    "provider",
    "observer_hostname",
    "rule_name",
    "sessions",
    "bytes",
]

# rule_name == '' covers every event kind that never carries a policy match
# (system syslog, non-flow records); excluding it keeps this table scoped to
# actual rule usage instead of one giant "" bucket.
_SELECT_SQL = """
SELECT
    tenant_id,
    toStartOfHour(timestamp) AS bucket_start,
    event_provider AS provider,
    observer_hostname,
    rule_name,
    count() AS sessions,
    sum(coalesce(network_bytes, 0)) AS bytes
FROM ssdf.events
WHERE rule_name != ''
  AND timestamp >= {since:DateTime64(3,'UTC')}
  AND timestamp < {until:DateTime64(3,'UTC')}
GROUP BY tenant_id, bucket_start, provider, observer_hostname, rule_name
"""


def compute_window(
    now: datetime.datetime, lookback_hours: int
) -> tuple[datetime.datetime, datetime.datetime]:
    """Whole-hour window ending at the current top of hour.

    Recomputing the last `lookback_hours` COMPLETE hours (not just the newest
    one) means a late-arriving event that lands after the previous run still
    gets rolled up on the next pass; ssdf.rule_usage_hourly is a
    ReplacingMergeTree keyed through bucket_start, so re-emitting an
    already-seen bucket overwrites it rather than double-counting.
    """
    until = now.replace(minute=0, second=0, microsecond=0)
    since = until - datetime.timedelta(hours=lookback_hours)
    return since, until


def run_once(client, now: datetime.datetime, lookback_hours: int = 3) -> int:
    since, until = compute_window(now, lookback_hours)
    result = client.query(
        _SELECT_SQL,
        parameters={"since": since.isoformat(), "until": until.isoformat()},
    )
    rows = [list(row) for row in result.result_rows]
    if not rows:
        return 0
    client.insert("rule_usage_hourly", rows, column_names=ROLLUP_COLUMNS)
    return len(rows)


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    config = load_config()
    client = clickhouse_connect.get_client(**client_kwargs(config))
    lookback_hours = int(os.environ.get("RULE_USAGE_LOOKBACK_HOURS", "3"))
    n = run_once(client, datetime.datetime.now(datetime.timezone.utc), lookback_hours)
    log.info("rule_usage_rollup: %d bucket rows upserted", n)


if __name__ == "__main__":
    main()
