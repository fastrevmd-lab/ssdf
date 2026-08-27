"""Unit tests for ssdf_common.clickhouse."""

from dataclasses import dataclass


from ssdf_common.clickhouse import client_kwargs, client_kwargs_from_config


def test_client_kwargs_plaintext():
    """client_kwargs builds a plain HTTP connection dict."""
    kwargs = client_kwargs(
        host="127.0.0.1",
        port=8123,
        user="ssdf_ro",
        password="pw",
        database="ssdf",
    )
    assert kwargs == {
        "host": "127.0.0.1",
        "port": 8123,
        "username": "ssdf_ro",
        "password": "pw",
        "database": "ssdf",
    }


def test_client_kwargs_secure_no_ca():
    """client_kwargs adds interface=https when secure=True, no ca_cert if empty."""
    kwargs = client_kwargs(
        host="198.51.100.152",
        port=8443,
        user="ssdf_ro",
        password="pw",
        database="ssdf",
        secure=True,
    )
    assert kwargs["interface"] == "https"
    assert "ca_cert" not in kwargs


def test_client_kwargs_secure_with_ca():
    """client_kwargs adds ca_cert when secure=True and ca_file is set."""
    kwargs = client_kwargs(
        host="198.51.100.152",
        port=8443,
        user="ssdf_ro",
        password="pw",
        database="ssdf",
        secure=True,
        ca_file="/path/to/ca.crt",
    )
    assert kwargs["interface"] == "https"
    assert kwargs["ca_cert"] == "/path/to/ca.crt"


def test_client_kwargs_from_config():
    """client_kwargs_from_config extracts from a Config-like object."""

    @dataclass
    class FakeConfig:
        ch_host: str
        ch_port: int
        ch_user: str
        ch_password: str
        ch_database: str
        ch_secure: bool
        ch_ca_file: str

    config = FakeConfig(
        ch_host="ct104",
        ch_port=8443,
        ch_user="ssdf_topo",
        ch_password="secret",
        ch_database="ssdf",
        ch_secure=True,
        ch_ca_file="/etc/ca.crt",
    )
    kwargs = client_kwargs_from_config(config)
    assert kwargs["host"] == "ct104"
    assert kwargs["port"] == 8443
    assert kwargs["username"] == "ssdf_topo"
    assert kwargs["password"] == "secret"
    assert kwargs["database"] == "ssdf"
    assert kwargs["interface"] == "https"
    assert kwargs["ca_cert"] == "/etc/ca.crt"
