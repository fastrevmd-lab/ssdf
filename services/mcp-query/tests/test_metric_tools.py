from ssdf_mcp_query.metric_tools import MetricTools


class _FakeStore:
    def __init__(self):
        self.calls = []

    def metric_timeseries(self, metric, since=None, until=None):
        self.calls.append(("metric_timeseries", metric, since, until))
        return {"rows": [{"bucket_start": "b", "value": 1.0}]}

    def top_series(self, metric, since=None, limit=10):
        self.calls.append(("top_series", metric, since, limit))
        return {"rows": [{"surrogate": "h_a", "value": 9.0}]}

    def entity_metric_timeseries(self, surrogate, metric, since=None, until=None):
        self.calls.append(("entity_metric_timeseries", surrogate, metric))
        return {"rows": []}

    def reidentify(self, surrogate):
        self.calls.append(("reidentify", surrogate))
        return {"surrogate": surrogate, "entity": {"kind": "host", "real_value": "x"}}


def test_metric_tools_delegate_to_store():
    store = _FakeStore()
    tools = MetricTools(store)
    assert tools.metric_timeseries("bytes")["rows"][0]["value"] == 1.0
    assert tools.top_series("bytes", limit=3)["rows"][0]["surrogate"] == "h_a"
    assert tools.entity_metric_timeseries("h_a", "bytes")["rows"] == []
    assert tools.reidentify("h_a")["entity"]["real_value"] == "x"
    assert [c[0] for c in store.calls] == [
        "metric_timeseries", "top_series", "entity_metric_timeseries", "reidentify",
    ]
