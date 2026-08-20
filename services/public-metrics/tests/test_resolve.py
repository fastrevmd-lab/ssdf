from ssdf_pubmetrics.resolve import plan_writes


class _FakeReader:
    def __init__(self):
        self.tenant = "t_main"

    def aggregate_series(self, metric, since_iso, bucket_secs):
        return [{"bucket_start": "2026-06-19 00:00:00", "value": 100.0}]

    def entity_bucket_series(self, metric, since_iso, bucket_secs):
        return [
            {"bucket_start": "2026-06-19 00:00:00", "ip": "10.74.11.20", "value": 80.0},
            {"bucket_start": "2026-06-19 00:00:00", "ip": "10.74.11.21", "value": 20.0},
        ]

    def deny_counts(self, since_iso):
        return {"deny": 5.0, "total": 50.0}

    def alert_count(self, since_iso):
        return 12.0


def test_plan_writes_aggregate_and_index_and_entity():
    reader = _FakeReader()
    pmap = {}  # empty -> everything minted fresh
    plan = plan_writes(
        reader,
        pmap,
        key=b"\x00" * 16,
        since_iso="2026-06-19T00:00:00+00:00",
        baseline_since_iso="2026-05-20T00:00:00+00:00",
        bucket_secs=300,
        top_n=1,
        key_version=1,
        tenant_id="t_main",
    )
    # aggregate metrics carry dim='' and a value
    agg = [r for r in plan.metric_rows if r["dim"] == "" and r["metric"] == "bytes"]
    assert agg and agg[0]["value"] == 100.0
    # index metric emitted as a single ratio row (deny 5/50 = 0.1 over baseline)
    idx = [r for r in plan.metric_rows if r["metric"] == "deny_rate_index"]
    assert len(idx) == 1
    # entity series limited to top_n=1 surrogate, never the raw IP
    assert len(plan.entity_rows) == 1
    assert plan.entity_rows[0]["surrogate"].startswith("h_")
    assert "10.74.11.20" not in plan.entity_rows[0]["surrogate"]
    # a pseudonym-map upsert was minted for the surfaced IP
    assert plan.map_rows and plan.map_rows[0]["kind"] == "host"
    assert plan.map_rows[0]["real_value"] == "10.74.11.20"
