from ssdf_policy import chwriter
from ssdf_policy.chwriter import entity_rows, edge_rows, ENTITY_COLUMNS, ENTITY_EDGE_COLUMNS
from ssdf_policy.config import Config


def _config(**overrides):
    base = dict(
        ch_host="10.64.0.151",
        ch_port=8123,
        ch_user="ssdf_entity",
        ch_password="pw",
        ch_database="ssdf",
        tenant_id="t_main",
        enabled_collectors=("panos", "junos"),
        junos_devices=("vSRX-test10",),
        panos_device="panosvm",
    )
    base.update(overrides)
    return Config(**base)


def test_writer_default_is_plain_http(monkeypatch):
    captured = {}
    monkeypatch.setattr(
        chwriter.clickhouse_connect,
        "get_client",
        lambda **kwargs: captured.update(kwargs) or object(),
    )
    chwriter.ClickHouseEntityWriter(_config())
    assert captured["host"] == "10.64.0.151"
    assert captured["port"] == 8123
    assert "interface" not in captured
    assert "ca_cert" not in captured


def test_writer_secure_passes_https_and_ca(monkeypatch):
    captured = {}
    monkeypatch.setattr(
        chwriter.clickhouse_connect,
        "get_client",
        lambda **kwargs: captured.update(kwargs) or object(),
    )
    chwriter.ClickHouseEntityWriter(
        _config(ch_port=8443, ch_secure=True, ch_ca_file="/etc/ssdf/ssdf-ca.crt")
    )
    assert captured["interface"] == "https"
    assert captured["port"] == 8443
    assert captured["ca_cert"] == "/etc/ssdf/ssdf-ca.crt"


def test_writer_secure_without_ca_file_omits_ca_cert(monkeypatch):
    captured = {}
    monkeypatch.setattr(
        chwriter.clickhouse_connect,
        "get_client",
        lambda **kwargs: captured.update(kwargs) or object(),
    )
    chwriter.ClickHouseEntityWriter(_config(ch_secure=True))
    assert captured["interface"] == "https"
    assert "ca_cert" not in captured


def test_entity_rows_match_m6a_column_order():
    # Must equal services/entity ENTITY_COLUMNS so inserts target the shared table layout.
    assert ENTITY_COLUMNS == [
        "entity_id",
        "tenant_id",
        "kind",
        "name",
        "identifiers",
        "source",
        "identity_basis",
        "confidence",
        "attrs",
        "first_seen",
        "last_seen",
    ]
    assert ENTITY_EDGE_COLUMNS == [
        "edge_id",
        "tenant_id",
        "src_id",
        "dst_id",
        "edge_type",
        "source",
        "confidence",
        "attrs",
        "first_seen",
        "last_seen",
    ]
    ent = {c: c for c in ENTITY_COLUMNS}
    assert entity_rows([ent]) == [[c for c in ENTITY_COLUMNS]]
    edge = {c: c for c in ENTITY_EDGE_COLUMNS}
    assert edge_rows([edge]) == [[c for c in ENTITY_EDGE_COLUMNS]]
