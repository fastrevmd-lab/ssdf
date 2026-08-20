# tests/test_clickhouse.py
import datetime as dt
import ipaddress
import threading
from ssdf_mcp_query.clickhouse import jsonify


def test_jsonify_datetime_to_iso():
    value = dt.datetime(2026, 6, 6, 12, 0, 0, tzinfo=dt.timezone.utc)
    assert jsonify(value) == "2026-06-06T12:00:00+00:00"


def test_jsonify_ipv4_to_str():
    assert jsonify(ipaddress.IPv4Address("10.65.1.10")) == "10.65.1.10"


def test_jsonify_passthrough_and_none():
    assert jsonify(None) is None
    assert jsonify(443) == 443
    assert jsonify("x") == "x"


def test_jsonify_nested_collections():
    assert jsonify({"a": ipaddress.IPv4Address("1.2.3.4")}) == {"a": "1.2.3.4"}
    assert jsonify([dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)]) == [
        "2026-01-01T00:00:00+00:00"
    ]


from ssdf_mcp_query.clickhouse import ClickHouseClient
from ssdf_mcp_query.config import Config


class _FakeResult:
    column_names = ["x"]
    result_rows = [[1]]


class _FakeClient:
    def __init__(self):
        self.calls = []

    def query(self, sql, parameters=None, settings=None):
        self.calls.append({"sql": sql, "parameters": parameters, "settings": settings})
        return _FakeResult()


def _config(**over):
    base = dict(
        ch_host="h",
        ch_port=8123,
        ch_user="u",
        ch_password="p",
        ch_database="ssdf",
        mcp_bind="0.0.0.0",
        mcp_port=30032,
        tokens={},
        max_execution_time=7,
        max_result_rows=222,
        max_memory_usage=333,
    )
    base.update(over)
    return Config(**base)


def test_run_passes_query_settings(monkeypatch):
    fake = _FakeClient()
    monkeypatch.setattr(
        "ssdf_mcp_query.clickhouse.clickhouse_connect.get_client",
        lambda **kw: fake,
    )
    client = ClickHouseClient(_config())
    client.run("SELECT 1")
    settings = fake.calls[0]["settings"]
    assert settings["max_execution_time"] == 7
    assert settings["max_result_rows"] == 222
    assert settings["max_memory_usage"] == 333
    assert settings["result_overflow_mode"] == "throw"


class _ThreadTrackingClient:
    """Fake driver client that records the thread id of each query call."""

    def __init__(self):
        self.thread_ids = []

    def query(self, sql, parameters=None, settings=None):
        self.thread_ids.append(threading.get_ident())
        return _FakeResult()


def test_no_underlying_client_shared_across_threads(monkeypatch):
    """clickhouse_connect clients hold a single session and reject concurrent
    queries across threads; ClickHouseClient must hand each thread its own."""
    created = []
    lock = threading.Lock()

    def fake_get_client(**kw):
        with lock:
            inst = _ThreadTrackingClient()
            created.append(inst)
        return inst

    monkeypatch.setattr("ssdf_mcp_query.clickhouse.clickhouse_connect.get_client", fake_get_client)
    client = ClickHouseClient(_config())

    barrier = threading.Barrier(2)

    def worker():
        barrier.wait()  # release both threads together to force contention
        for _ in range(5):
            client.run("SELECT 1")

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    # No single underlying client may be touched by more than one thread.
    for inst in created:
        assert len(set(inst.thread_ids)) <= 1
    # The two worker threads must have used two distinct underlying clients.
    worker_clients = [inst for inst in created if inst.thread_ids]
    assert len({inst.thread_ids[0] for inst in worker_clients}) == 2


def test_reuses_one_client_within_a_thread(monkeypatch):
    created = []

    def fake_get_client(**kw):
        inst = _ThreadTrackingClient()
        created.append(inst)
        return inst

    monkeypatch.setattr("ssdf_mcp_query.clickhouse.clickhouse_connect.get_client", fake_get_client)
    client = ClickHouseClient(_config())
    client.run("SELECT 1")
    client.run("SELECT 2")
    # Constructing thread reuses a single underlying client across calls.
    assert len(created) == 1
