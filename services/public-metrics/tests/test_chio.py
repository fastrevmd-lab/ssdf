from ssdf_pubmetrics.chreader import EventsReader
from ssdf_pubmetrics.chwriter import (
    MetricsWriter, METRIC_COLUMNS, ENTITY_COLUMNS, MAP_COLUMNS,
)


class _FakeClient:
    def __init__(self, rows):
        self._rows = rows
        self.queries = []
        self.inserts = []

    def query(self, sql, parameters=None, settings=None):
        self.queries.append((sql, parameters))

        class _R:
            pass

        r = _R()
        r.column_names = self._rows["cols"]
        r.result_rows = self._rows["rows"]
        return r

    def insert(self, table, rows, column_names=None):
        self.inserts.append((table, rows, column_names))


def test_reader_aggregate_series_returns_rows():
    fake = _FakeClient({"cols": ["bucket_start", "value"],
                        "rows": [["2026-06-19 00:00:00", 1234.0]]})
    reader = EventsReader.__new__(EventsReader)
    reader._client = fake
    reader._tenant = "t_main"
    out = reader.aggregate_series("bytes", "2026-06-19T00:00:00+00:00", 300)
    assert out == [{"bucket_start": "2026-06-19 00:00:00", "value": 1234.0}]


def test_reader_load_pseudonym_map_keys_by_kind_value():
    fake = _FakeClient({"cols": ["kind", "real_value", "surrogate"],
                        "rows": [["host", "10.74.11.20", "h_abc"]]})
    reader = EventsReader.__new__(EventsReader)
    reader._client = fake
    reader._tenant = "t_main"
    out = reader.load_pseudonym_map(["host"])
    assert out == {("host", "10.74.11.20"): "h_abc"}


def test_writer_insert_metric_rows_uses_columns():
    fake = _FakeClient({"cols": [], "rows": []})
    writer = MetricsWriter.__new__(MetricsWriter)
    writer._client = fake
    n = writer.write_metric_timeseries(
        [{c: v for c, v in zip(METRIC_COLUMNS, ["2026-06-19 00:00:00", "bytes", "", 1.0, "t_main"])}])
    assert n == 1
    table, rows, cols = fake.inserts[0]
    assert table == "ssdf_public.metric_timeseries"
    assert cols == METRIC_COLUMNS


def test_writer_skips_empty():
    fake = _FakeClient({"cols": [], "rows": []})
    writer = MetricsWriter.__new__(MetricsWriter)
    writer._client = fake
    assert writer.write_entity_series([]) == 0
    assert writer.write_pseudonym_map([]) == 0
    assert fake.inserts == []
