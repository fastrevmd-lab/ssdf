# tests/test_config.py
import pytest
from ssdf_topo.config import load_config, ConfigError, McpEndpoint

def _base_env(monkeypatch):
    monkeypatch.setenv("CH_PASSWORD", "secret")
    monkeypatch.setenv("CH_HOST", "10.64.0.151")

def test_requires_ch_password(monkeypatch):
    monkeypatch.delenv("CH_PASSWORD", raising=False)
    with pytest.raises(ConfigError):
        load_config()

def test_defaults_and_writer_user(monkeypatch):
    _base_env(monkeypatch)
    cfg = load_config()
    assert cfg.ch_user == "ssdf_topo"     # writer, not ssdf_ro
    assert cfg.ch_host == "10.64.0.151"
    assert cfg.tenant_id == "t_main"
    assert cfg.window_hours == 24

def test_enabled_collectors_parsed(monkeypatch):
    _base_env(monkeypatch)
    monkeypatch.setenv("TOPO_COLLECTORS", "junos,unifi")
    cfg = load_config()
    assert cfg.enabled_collectors == ("junos", "unifi")

def test_mcp_endpoint_lookup(monkeypatch):
    _base_env(monkeypatch)
    monkeypatch.setenv("JUNOS_MCP_URL", "http://198.51.100.194:30031/mcp")
    monkeypatch.setenv("JUNOS_MCP_TOKEN", "tok123")
    cfg = load_config()
    ep = cfg.mcp_endpoint("junos")
    assert ep == McpEndpoint(url="http://198.51.100.194:30031/mcp", token="tok123")

def test_mcp_endpoint_missing_raises(monkeypatch):
    _base_env(monkeypatch)
    cfg = load_config()
    with pytest.raises(ConfigError):
        cfg.mcp_endpoint("junos")
