import pytest

from ssdf_health.config import Config, ConfigError, load_config


def test_load_config_requires_ch_password(monkeypatch):
    monkeypatch.delenv("CH_PASSWORD", raising=False)
    with pytest.raises(ConfigError):
        load_config()


def test_load_config_defaults_and_device_lists(monkeypatch):
    monkeypatch.setenv("CH_PASSWORD", "secret")
    monkeypatch.setenv("JUNOS_DEVICES", "vSRX-test10, vSRX-Production")
    monkeypatch.setenv("UNIFI_DEVICE_MACS", "aa:bb:cc:dd:ee:ff")
    monkeypatch.delenv("HEALTH_COLLECTORS", raising=False)
    config = load_config()
    assert config.ch_user == "ssdf_health"
    assert config.ch_port == 8123
    assert config.junos_devices == ["vSRX-test10", "vSRX-Production"]
    assert config.unifi_macs == ["aa:bb:cc:dd:ee:ff"]
    assert config.enabled_collectors == ("proxmox", "junos", "panos", "unifi")


def test_mcp_endpoint_requires_url(monkeypatch):
    monkeypatch.setenv("CH_PASSWORD", "secret")
    monkeypatch.delenv("JUNOS_MCP_URL", raising=False)
    config = load_config()
    with pytest.raises(ConfigError):
        config.mcp_endpoint("junos")


def test_ch_secure_parsed(monkeypatch):
    monkeypatch.setenv("CH_PASSWORD", "secret")
    monkeypatch.setenv("CH_SECURE", "1")
    monkeypatch.setenv("CH_CA_FILE", "/etc/ca.crt")
    config = load_config()
    assert config.ch_secure is True
    assert config.ch_ca_file == "/etc/ca.crt"
