import datetime

from ssdf_policy.rule_usage_rollup import ROLLUP_COLUMNS, compute_window, run_once


def test_compute_window_truncates_to_whole_hours():
    now = datetime.datetime(2026, 9, 28, 14, 37, 12, tzinfo=datetime.timezone.utc)
    since, until = compute_window(now, lookback_hours=3)
    assert until == datetime.datetime(2026, 9, 28, 14, 0, 0, tzinfo=datetime.timezone.utc)
    assert since == datetime.datetime(2026, 9, 28, 11, 0, 0, tzinfo=datetime.timezone.utc)


class _FakeQueryResult:
    def __init__(self, rows):
        self.result_rows = rows


class _FakeChClient:
    def __init__(self, rows):
        self._rows = rows
        self.inserted = None
        self.insert_table = None
        self.last_params = None

    def query(self, sql, parameters=None):
        self.last_params = parameters
        return _FakeQueryResult(self._rows)

    def insert(self, table, rows, column_names):
        self.insert_table = table
        self.inserted = (rows, column_names)


def test_run_once_inserts_rolled_up_rows():
    rows = [("t_main", "2026-09-28T11:00:00", "juniper", "vsrx-ci", "ALLOW-WEB", 5, 1500)]
    client = _FakeChClient(rows)
    n = run_once(client, datetime.datetime(2026, 9, 28, 14, 0, 0, tzinfo=datetime.timezone.utc))
    assert n == 1
    assert client.insert_table == "rule_usage_hourly"
    inserted_rows, columns = client.inserted
    assert columns == ROLLUP_COLUMNS
    assert inserted_rows == [list(rows[0])]


def test_run_once_no_rows_skips_insert():
    client = _FakeChClient([])
    n = run_once(client, datetime.datetime(2026, 9, 28, 14, 0, 0, tzinfo=datetime.timezone.utc))
    assert n == 0
    assert client.inserted is None
