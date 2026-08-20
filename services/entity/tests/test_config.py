import pytest
from ssdf_entity.config import load_config, ConfigError


def test_load_config_requires_password(monkeypatch):
    monkeypatch.delenv("CH_PASSWORD", raising=False)
    with pytest.raises(ConfigError):
        load_config()


def test_load_config_defaults(monkeypatch):
    monkeypatch.setenv("CH_PASSWORD", "secret")
    monkeypatch.delenv("CH_HOST", raising=False)
    monkeypatch.delenv("CH_USER", raising=False)
    monkeypatch.delenv("ENTITY_WINDOW_HOURS", raising=False)
    config = load_config()
    assert config.ch_host == "127.0.0.1"
    assert config.ch_user == "ssdf_entity"
    assert config.tenant_id == "t_main"
    assert config.window_hours == 24


def test_load_config_ch_secure_defaults_off(monkeypatch):
    monkeypatch.setenv("CH_PASSWORD", "secret")
    monkeypatch.delenv("CH_SECURE", raising=False)
    monkeypatch.delenv("CH_CA_FILE", raising=False)
    config = load_config()
    assert config.ch_secure is False
    assert config.ch_ca_file == ""


def test_load_config_ch_secure_parses_truthy(monkeypatch):
    monkeypatch.setenv("CH_PASSWORD", "secret")
    monkeypatch.setenv("CH_SECURE", "true")
    monkeypatch.setenv("CH_CA_FILE", "/etc/ssdf/ssdf-ca.crt")
    config = load_config()
    assert config.ch_secure is True
    assert config.ch_ca_file == "/etc/ssdf/ssdf-ca.crt"
    monkeypatch.setenv("CH_SECURE", "1")
    assert load_config().ch_secure is True
    monkeypatch.setenv("CH_SECURE", "0")
    assert load_config().ch_secure is False


def test_load_config_default_binding_lookback(monkeypatch):
    monkeypatch.setenv("CH_PASSWORD", "x")
    monkeypatch.delenv("TOPO_BINDING_LOOKBACK_HOURS", raising=False)
    from ssdf_entity.config import load_config

    assert load_config().binding_lookback_hours == 168
