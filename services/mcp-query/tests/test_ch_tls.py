# tests/test_ch_tls.py
"""L1: CH TLS client support — get_client kwargs across all three connect paths."""

from ssdf_mcp_query.config import Config
from ssdf_mcp_query.clickhouse import ClickHouseClient
from ssdf_mcp_query.audit import make_ch_auditor
from ssdf_mcp_query.verify_audit import _fetch_rows


def _config(**over):
    base = dict(
        ch_host="h",
        ch_port=8443,
        ch_user="u",
        ch_password="p",
        ch_database="ssdf",
        mcp_bind="0.0.0.0",
        mcp_port=30032,
        tokens={},
    )
    base.update(over)
    return Config(**base)


class _FakeResult:
    column_names = ["x"]
    result_rows = []


class _FakeClient:
    def query(self, sql, parameters=None, settings=None):
        return _FakeResult()

    def insert(self, *a, **k):
        pass


def _capture_get_client(monkeypatch):
    captured = []

    def fake_get_client(**kwargs):
        captured.append(kwargs)
        return _FakeClient()

    # clickhouse.py imports the module at top level; audit/verify_audit import
    # it inside the function — patching the module attribute covers all three.
    monkeypatch.setattr("clickhouse_connect.get_client", fake_get_client)
    return captured


def test_clickhouse_client_secure_with_ca(monkeypatch):
    captured = _capture_get_client(monkeypatch)
    ClickHouseClient(_config(ch_secure=True, ch_ca_file="/etc/ssdf/ssdf-ca.crt"))
    assert captured[0]["interface"] == "https"
    assert captured[0]["ca_cert"] == "/etc/ssdf/ssdf-ca.crt"


def test_clickhouse_client_secure_without_ca(monkeypatch):
    captured = _capture_get_client(monkeypatch)
    ClickHouseClient(_config(ch_secure=True))
    assert captured[0]["interface"] == "https"
    assert "ca_cert" not in captured[0]


def test_clickhouse_client_insecure_default(monkeypatch):
    captured = _capture_get_client(monkeypatch)
    ClickHouseClient(_config())
    assert "interface" not in captured[0]
    assert "ca_cert" not in captured[0]


def test_make_ch_auditor_secure(monkeypatch):
    captured = _capture_get_client(monkeypatch)
    make_ch_auditor(
        _config(
            ch_secure=True,
            ch_ca_file="/ca.crt",
            ch_audit_password="apw",
            ch_audit_verify_password="vpw",
        ),
        tier="sovereign",
    )
    # both the insert connection and the chain-seed connection are secure
    assert len(captured) == 2
    for kwargs in captured:
        assert kwargs["interface"] == "https"
        assert kwargs["ca_cert"] == "/ca.crt"


def test_make_ch_auditor_insecure(monkeypatch):
    captured = _capture_get_client(monkeypatch)
    make_ch_auditor(_config(ch_audit_password="apw"), tier="sovereign")
    assert len(captured) == 1
    assert "interface" not in captured[0]
    assert "ca_cert" not in captured[0]


def test_verify_audit_fetch_rows_secure(monkeypatch):
    captured = _capture_get_client(monkeypatch)
    _fetch_rows(_config(ch_secure=True, ch_ca_file="/ca.crt", ch_audit_verify_password="vpw"))
    assert captured[0]["interface"] == "https"
    assert captured[0]["ca_cert"] == "/ca.crt"


def test_verify_audit_fetch_rows_insecure(monkeypatch):
    captured = _capture_get_client(monkeypatch)
    _fetch_rows(_config(ch_audit_verify_password="vpw"))
    assert "interface" not in captured[0]
