"""Public-metrics resolver: aggregate ssdf.events into the de-identified tables.

Sovereign process (runs on ct109). Holds PUBLIC_PSEUDONYM_KEY; emits only
surrogates to the public schema. Real<->surrogate stays in ssdf.pseudonym_map.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from .chreader import EventsReader
from .chwriter import MetricsWriter
from .config import load_config
from .measures import enabled_measures, ratio_to_baseline
from .pseudonym import mint_surrogate

# Per-entity source IPs map to 'host' surrogates. This is the PSEUDONYM kind
# (see pseudonym.PREFIXES) — distinct from Measure.kind ('aggregate'|'index').
_PSEUDONYM_KIND = "host"


@dataclass
class WritePlan:
    metric_rows: list[dict] = field(default_factory=list)
    entity_rows: list[dict] = field(default_factory=list)
    map_rows: list[dict] = field(default_factory=list)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def plan_writes(
    reader, pmap, key, since_iso, baseline_since_iso, bucket_secs, top_n, key_version, tenant_id
) -> WritePlan:
    plan = WritePlan()
    now_iso = _now_iso()
    for measure in enabled_measures():
        if measure.kind == "index":
            if measure.metric == "deny_rate_index":
                cur = reader.deny_counts(since_iso)
                base = reader.deny_counts(baseline_since_iso)
                cur_ratio = ratio_to_baseline(cur["deny"], cur["total"])
                base_ratio = ratio_to_baseline(base["deny"], base["total"])
            else:  # ips_volume_index
                cur_ratio = reader.alert_count(since_iso)
                base_ratio = reader.alert_count(baseline_since_iso)
            value = ratio_to_baseline(cur_ratio, base_ratio)
            plan.metric_rows.append(
                {
                    "bucket_start": since_iso,
                    "metric": measure.metric,
                    "dim": "",
                    "value": value,
                    "tenant_id": tenant_id,
                }
            )
            continue

        # per_entity measures ALSO emit a top-N entity_series breakdown (in
        # addition to the aggregate series emitted below — never instead of it).
        if measure.per_entity:
            rows = reader.entity_bucket_series(measure.metric, since_iso, bucket_secs)
            totals: dict[str, float] = {}
            for row in rows:
                totals[row["ip"]] = totals.get(row["ip"], 0.0) + float(row["value"])
            top_ips = [
                ip for ip, _ in sorted(totals.items(), key=lambda kv: kv[1], reverse=True)[:top_n]
            ]
            top = set(top_ips)
            for row in rows:
                ip = row["ip"]
                if ip not in top:
                    continue
                surrogate = mint_surrogate(pmap, key, _PSEUDONYM_KIND, ip)
                if (_PSEUDONYM_KIND, ip) not in {
                    (m["kind"], m["real_value"]) for m in plan.map_rows
                }:
                    plan.map_rows.append(
                        {
                            "kind": _PSEUDONYM_KIND,
                            "real_value": ip,
                            "surrogate": surrogate,
                            "key_version": key_version,
                            "first_seen": now_iso,
                            "last_seen": now_iso,
                        }
                    )
                plan.entity_rows.append(
                    {
                        "bucket_start": row["bucket_start"],
                        "surrogate": surrogate,
                        "metric": measure.metric,
                        "value": float(row["value"]),
                        "tenant_id": tenant_id,
                    }
                )

        # every non-index measure (per_entity or not) emits its aggregate series
        for row in reader.aggregate_series(measure.metric, since_iso, bucket_secs):
            plan.metric_rows.append(
                {
                    "bucket_start": row["bucket_start"],
                    "metric": measure.metric,
                    "dim": "",
                    "value": float(row["value"]),
                    "tenant_id": tenant_id,
                }
            )
    return plan


def run() -> int:
    config = load_config()
    now = datetime.now(timezone.utc)
    since_iso = (now - timedelta(hours=config.lookback_hours)).isoformat()
    baseline_since_iso = (now - timedelta(days=config.baseline_days)).isoformat()

    reader = EventsReader(config)
    writer = MetricsWriter(config)
    pmap = reader.load_pseudonym_map(["host"])

    plan = plan_writes(
        reader,
        pmap,
        key=config.pseudonym_key,
        since_iso=since_iso,
        baseline_since_iso=baseline_since_iso,
        bucket_secs=config.bucket_secs,
        top_n=config.top_n,
        key_version=config.key_version,
        tenant_id=config.tenant_id,
    )
    m = writer.write_metric_timeseries(plan.metric_rows)
    e = writer.write_entity_series(plan.entity_rows)
    p = writer.write_pseudonym_map(plan.map_rows)
    print(f"public-metrics: wrote metric={m} entity={e} map={p}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
