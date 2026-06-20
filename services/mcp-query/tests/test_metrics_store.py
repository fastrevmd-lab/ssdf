from ssdf_mcp_query.metrics_store import MetricsStore


class _FakeClient:
    def __init__(self, rows):
        self._rows = rows
        self.calls = []

    def run(self, sql, params=None):
        self.calls.append((sql, params))
        return {"rows": self._rows, "row_count": len(self._rows),
                "elapsed_ms": 1, "truncated": False}


def test_metric_timeseries_reads_aggregate_table():
    fake = _FakeClient([{"bucket_start": "2026-06-19 00:00:00", "value": 12.0}])
    store = MetricsStore(fake)
    out = store.metric_timeseries("bytes", since="now-1h", until=None)
    assert out["rows"][0]["value"] == 12.0
    sql = fake.calls[0][0]
    assert "ssdf_public.metric_timeseries" in sql and "FINAL" in sql
    assert "dim = ''" in sql


def test_top_series_groups_by_surrogate():
    fake = _FakeClient([{"surrogate": "h_abc", "value": 99.0}])
    store = MetricsStore(fake)
    out = store.top_series("bytes", since="now-1h", limit=5)
    sql = fake.calls[0][0]
    assert "ssdf_public.entity_series" in sql and "surrogate" in sql
    assert out["rows"][0]["surrogate"] == "h_abc"


def test_reidentify_reads_sovereign_map():
    fake = _FakeClient([{"kind": "host", "real_value": "10.74.11.20"}])
    store = MetricsStore(fake)
    out = store.reidentify("h_abc")
    sql = fake.calls[0][0]
    assert "ssdf.pseudonym_map" in sql and "FINAL" in sql
    assert out["entity"]["real_value"] == "10.74.11.20"


def test_reidentify_unknown_surrogate_returns_null_entity():
    fake = _FakeClient([])
    store = MetricsStore(fake)
    out = store.reidentify("h_nope")
    assert out["entity"] is None


def test_relative_since_resolved_to_absolute_iso():
    # parseDateTimeBestEffort can't read 'now-...'; the store must resolve
    # relative/default windows to an absolute ISO timestamp before binding.
    fake = _FakeClient([])
    store = MetricsStore(fake)
    store.metric_timeseries("bytes", since="now-1h", until=None)
    params = fake.calls[0][1]
    assert not params["since"].startswith("now")
    assert params["since"].startswith("20")  # ISO-8601 absolute
    assert params["until"] == ""             # unset upper bound stays empty


def test_default_since_resolved_not_passed_through():
    fake = _FakeClient([])
    store = MetricsStore(fake)
    store.top_series("bytes")  # since defaults internally
    params = fake.calls[0][1]
    assert not params["since"].startswith("now")
    assert params["since"].startswith("20")


def test_unset_until_uses_or_null_to_avoid_empty_string_parse():
    # ClickHouse constant-folds BOTH sides of the OR, so the empty-until guard
    # must use parseDateTimeBestEffortOrNull — parseDateTimeBestEffort('') throws
    # CANNOT_PARSE_DATETIME even when {until} = '' short-circuits logically.
    fake = _FakeClient([])
    store = MetricsStore(fake)
    store.metric_timeseries("bytes", since="now-1h", until=None)
    sql = fake.calls[0][0]
    assert "parseDateTimeBestEffortOrNull({until:String})" in sql
    store.entity_metric_timeseries("h_abc", "bytes", since="now-1h", until=None)
    assert "parseDateTimeBestEffortOrNull({until:String})" in fake.calls[1][0]
