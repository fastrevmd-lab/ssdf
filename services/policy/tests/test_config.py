import pytest
from ssdf_policy.config import load_config, ConfigError


def test_load_config_requires_password(monkeypatch):
    monkeypatch.delenv("CH_PASSWORD", raising=False)
    with pytest.raises(ConfigError):
        load_config()


def test_load_config_defaults_and_devices(monkeypatch):
    monkeypatch.setenv("CH_PASSWORD", "pw")
    monkeypatch.setenv("POLICY_COLLECTORS", "panos,junos")
    monkeypatch.setenv("JUNOS_DEVICES", "vSRX-test10, vSRX-test11")
    cfg = load_config()
    assert cfg.ch_user == "ssdf_entity"          # reuses the M6a writer user
    assert cfg.enabled_collectors == ("panos", "junos")
    assert cfg.junos_devices == ("vSRX-test10", "vSRX-test11")
    assert cfg.panos_device == "panosvm"


def test_load_config_ch_secure_defaults_off(monkeypatch):
    monkeypatch.setenv("CH_PASSWORD", "pw")
    monkeypatch.delenv("CH_SECURE", raising=False)
    monkeypatch.delenv("CH_CA_FILE", raising=False)
    cfg = load_config()
    assert cfg.ch_secure is False
    assert cfg.ch_ca_file == ""


def test_load_config_ch_secure_parses_truthy(monkeypatch):
    monkeypatch.setenv("CH_PASSWORD", "pw")
    monkeypatch.setenv("CH_SECURE", "true")
    monkeypatch.setenv("CH_CA_FILE", "/etc/ssdf/ssdf-ca.crt")
    cfg = load_config()
    assert cfg.ch_secure is True
    assert cfg.ch_ca_file == "/etc/ssdf/ssdf-ca.crt"
    monkeypatch.setenv("CH_SECURE", "1")
    assert load_config().ch_secure is True
    monkeypatch.setenv("CH_SECURE", "0")
    assert load_config().ch_secure is False


def test_mcp_endpoint_requires_url(monkeypatch):
    monkeypatch.setenv("CH_PASSWORD", "pw")
    monkeypatch.delenv("PANOS_MCP_URL", raising=False)
    with pytest.raises(ConfigError):
        load_config().mcp_endpoint("panos")
