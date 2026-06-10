import json
import pytest
from ssdf_mcp_query.config import load_config, load_token_map, ConfigError


def test_single_token_fallback_from_file(monkeypatch, tmp_path):
    token_file = tmp_path / "token"
    token_file.write_text("secret-token\n")
    monkeypatch.setenv("CH_HOST", "10.64.0.9")
    monkeypatch.setenv("CH_USER", "ssdf_ro")
    monkeypatch.setenv("CH_PASSWORD", "pw")
    monkeypatch.setenv("MCP_TOKEN_FILE", str(token_file))
    monkeypatch.delenv("MCP_AUTH_TOKEN", raising=False)
    monkeypatch.delenv("MCP_TOKENS_FILE", raising=False)
    cfg = load_config()
    assert cfg.ch_host == "10.64.0.9"
    assert cfg.mcp_port == 30032
    assert set(cfg.tokens) == {"secret-token"}
    principal = cfg.tokens["secret-token"]
    assert principal.principal == "agent"
    assert principal.allowed_tools is None


def test_inline_token_env_wins(monkeypatch):
    monkeypatch.setenv("CH_PASSWORD", "pw")
    monkeypatch.setenv("MCP_AUTH_TOKEN", "inline")
    monkeypatch.delenv("MCP_TOKEN_FILE", raising=False)
    monkeypatch.delenv("MCP_TOKENS_FILE", raising=False)
    cfg = load_config()
    assert set(cfg.tokens) == {"inline"}
    assert cfg.tokens["inline"].principal == "agent"


def test_missing_token_raises(monkeypatch):
    monkeypatch.setenv("CH_PASSWORD", "pw")
    monkeypatch.delenv("MCP_AUTH_TOKEN", raising=False)
    monkeypatch.delenv("MCP_TOKEN_FILE", raising=False)
    monkeypatch.delenv("MCP_TOKENS_FILE", raising=False)
    with pytest.raises(ConfigError):
        load_config()


def test_token_map_multi_principal(monkeypatch, tmp_path):
    f = tmp_path / "tokens.json"
    f.write_text(json.dumps({
        "tok-triage": {"principal": "triage-agent",
                       "allowed_tools": ["query_flows", "top_talkers"]},
        "tok-admin": {"principal": "admin-agent"},
    }))
    monkeypatch.setenv("MCP_TOKENS_FILE", str(f))
    tokens = load_token_map()
    assert tokens["tok-triage"].principal == "triage-agent"
    assert tokens["tok-triage"].allowed_tools == frozenset({"query_flows", "top_talkers"})
    assert tokens["tok-admin"].allowed_tools is None


def test_token_map_empty_object_raises(monkeypatch, tmp_path):
    f = tmp_path / "tokens.json"
    f.write_text("{}")
    monkeypatch.setenv("MCP_TOKENS_FILE", str(f))
    with pytest.raises(ConfigError):
        load_token_map()


def test_token_map_entry_missing_principal_raises(monkeypatch, tmp_path):
    f = tmp_path / "tokens.json"
    f.write_text(json.dumps({"tok": {"allowed_tools": ["query_flows"]}}))
    monkeypatch.setenv("MCP_TOKENS_FILE", str(f))
    with pytest.raises(ConfigError):
        load_token_map()


def test_audit_conn_fields(monkeypatch):
    monkeypatch.setenv("CH_PASSWORD", "pw")
    monkeypatch.setenv("MCP_AUTH_TOKEN", "inline")
    monkeypatch.setenv("CH_AUDIT_PASSWORD", "apw")
    monkeypatch.delenv("MCP_TOKENS_FILE", raising=False)
    monkeypatch.delenv("MCP_TOKEN_FILE", raising=False)
    cfg = load_config()
    assert cfg.ch_audit_user == "ssdf_audit"
    assert cfg.ch_audit_password == "apw"


def test_load_config_reads_query_limit_envs(monkeypatch):
    from ssdf_mcp_query.config import load_config
    monkeypatch.setenv("CH_PASSWORD", "x")
    monkeypatch.setenv("MCP_AUTH_TOKEN", "t")
    monkeypatch.setenv("MCP_MAX_RESULT_ROWS", "5")
    monkeypatch.setenv("MCP_MAX_MEMORY_BYTES", "9")
    cfg = load_config()
    assert cfg.max_result_rows == 5
    assert cfg.max_memory_usage == 9


def test_load_config_query_limit_defaults(monkeypatch):
    from ssdf_mcp_query.config import load_config
    monkeypatch.setenv("CH_PASSWORD", "x")
    monkeypatch.setenv("MCP_AUTH_TOKEN", "t")
    monkeypatch.delenv("MCP_MAX_RESULT_ROWS", raising=False)
    monkeypatch.delenv("MCP_MAX_MEMORY_BYTES", raising=False)
    cfg = load_config()
    assert cfg.max_result_rows == 100000
    assert cfg.max_memory_usage == 1_000_000_000
