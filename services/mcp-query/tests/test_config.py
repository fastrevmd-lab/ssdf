import pytest
from ssdf_mcp_query.config import load_config, ConfigError

def test_load_config_from_env(monkeypatch, tmp_path):
    token_file = tmp_path / "token"
    token_file.write_text("secret-token\n")
    monkeypatch.setenv("CH_HOST", "10.64.0.9")
    monkeypatch.setenv("CH_USER", "ssdf_ro")
    monkeypatch.setenv("CH_PASSWORD", "pw")
    monkeypatch.setenv("MCP_TOKEN_FILE", str(token_file))
    monkeypatch.delenv("MCP_AUTH_TOKEN", raising=False)
    cfg = load_config()
    assert cfg.ch_host == "10.64.0.9"
    assert cfg.ch_port == 8123
    assert cfg.ch_user == "ssdf_ro"
    assert cfg.mcp_port == 30032
    assert cfg.auth_token == "secret-token"

def test_inline_token_env_wins(monkeypatch):
    monkeypatch.setenv("CH_PASSWORD", "pw")
    monkeypatch.setenv("MCP_AUTH_TOKEN", "inline")
    monkeypatch.delenv("MCP_TOKEN_FILE", raising=False)
    assert load_config().auth_token == "inline"

def test_missing_token_raises(monkeypatch):
    monkeypatch.setenv("CH_PASSWORD", "pw")
    monkeypatch.delenv("MCP_AUTH_TOKEN", raising=False)
    monkeypatch.delenv("MCP_TOKEN_FILE", raising=False)
    with pytest.raises(ConfigError):
        load_config()

def test_whitespace_only_token_raises(monkeypatch, tmp_path):
    token_file = tmp_path / "token"
    token_file.write_text("   \n")
    monkeypatch.setenv("CH_PASSWORD", "pw")
    monkeypatch.setenv("MCP_TOKEN_FILE", str(token_file))
    monkeypatch.delenv("MCP_AUTH_TOKEN", raising=False)
    with pytest.raises(ConfigError):
        load_config()
