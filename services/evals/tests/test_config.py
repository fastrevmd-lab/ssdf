"""Config loading: required secrets, env defaults, TLS knobs."""

import pytest

from ssdf_evals.config import Config, ConfigError, client_kwargs, load_config

REQUIRED = {"CH_PASSWORD": "ro-pw", "CH_AUDIT_VERIFY_PASSWORD": "av-pw"}


def _set_required(monkeypatch):
    for key, value in REQUIRED.items():
        monkeypatch.setenv(key, value)


def test_missing_ch_password_raises(monkeypatch):
    monkeypatch.delenv("CH_PASSWORD", raising=False)
    monkeypatch.setenv("CH_AUDIT_VERIFY_PASSWORD", "av-pw")
    with pytest.raises(ConfigError):
        load_config()


def test_missing_audit_verify_password_raises(monkeypatch):
    monkeypatch.setenv("CH_PASSWORD", "ro-pw")
    monkeypatch.delenv("CH_AUDIT_VERIFY_PASSWORD", raising=False)
    with pytest.raises(ConfigError):
        load_config()


def test_defaults(monkeypatch):
    _set_required(monkeypatch)
    for key in (
        "CH_HOST",
        "CH_PORT",
        "CH_USER",
        "CH_DATABASE",
        "CH_SECURE",
        "CH_CA_FILE",
        "EVAL_AUDIT_SLOP_SECS",
    ):
        monkeypatch.delenv(key, raising=False)
    config = load_config()
    assert config == Config(
        ch_host="127.0.0.1",
        ch_port=8123,
        ch_user="ssdf_ro",
        ch_password="ro-pw",
        ch_database="ssdf",
        ch_secure=False,
        ch_ca_file="",
        audit_verify_password="av-pw",
        audit_slop_secs=5,
    )


def test_tls_and_slop_overrides(monkeypatch):
    _set_required(monkeypatch)
    monkeypatch.setenv("CH_PORT", "8443")
    monkeypatch.setenv("CH_SECURE", "1")
    monkeypatch.setenv("CH_CA_FILE", "/etc/ssdf/ssdf-ca.crt")
    monkeypatch.setenv("EVAL_AUDIT_SLOP_SECS", "10")
    config = load_config()
    assert config.ch_port == 8443
    assert config.ch_secure is True
    assert config.ch_ca_file == "/etc/ssdf/ssdf-ca.crt"
    assert config.audit_slop_secs == 10


def test_client_kwargs_tls_shape(monkeypatch):
    _set_required(monkeypatch)
    monkeypatch.setenv("CH_PORT", "8443")
    monkeypatch.setenv("CH_SECURE", "1")
    monkeypatch.setenv("CH_CA_FILE", "/etc/ssdf/ssdf-ca.crt")
    kwargs = client_kwargs(load_config())
    assert kwargs["interface"] == "https"
    assert kwargs["ca_cert"] == "/etc/ssdf/ssdf-ca.crt"
    assert kwargs["port"] == 8443


def test_client_kwargs_identity_override(monkeypatch):
    _set_required(monkeypatch)
    kwargs = client_kwargs(load_config(), username="ssdf_audit_verify", password="av-pw2")
    assert kwargs["username"] == "ssdf_audit_verify"
    assert kwargs["password"] == "av-pw2"
