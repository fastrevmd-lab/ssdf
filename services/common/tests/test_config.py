"""Unit tests for ssdf_common.config."""

import pytest

from ssdf_common.config import ConfigError, McpEndpoint, env_bool, load_mcp_endpoint


def test_config_error():
    """ConfigError is a RuntimeError."""
    exc = ConfigError("missing foo")
    assert isinstance(exc, RuntimeError)
    assert str(exc) == "missing foo"


def test_mcp_endpoint():
    """McpEndpoint is a frozen dataclass with url and token."""
    ep = McpEndpoint(url="http://example.com", token="abc")
    assert ep.url == "http://example.com"
    assert ep.token == "abc"
    with pytest.raises(AttributeError):
        ep.url = "other"  # frozen


def test_env_bool_default():
    """env_bool returns default when the var is unset."""
    assert env_bool("NONEXISTENT") is False
    assert env_bool("NONEXISTENT", default=True) is True


def test_env_bool_truthiness():
    """env_bool recognizes "1" and "true" (case-insensitive) as True."""
    assert env_bool("FOO", default=False) is False  # unset
    env = {"FOO": "1"}
    # We need to mock os.environ; for simplicity, pass the env explicitly
    # (though env_bool doesn't accept env yet — this is a limitation).
    # Since env_bool uses os.environ, we'll test via the real environment.
    import os

    old = os.environ.get("TEST_ENV_BOOL")
    try:
        os.environ["TEST_ENV_BOOL"] = "1"
        assert env_bool("TEST_ENV_BOOL") is True
        os.environ["TEST_ENV_BOOL"] = "true"
        assert env_bool("TEST_ENV_BOOL") is True
        os.environ["TEST_ENV_BOOL"] = "TRUE"
        assert env_bool("TEST_ENV_BOOL") is True
        os.environ["TEST_ENV_BOOL"] = "0"
        assert env_bool("TEST_ENV_BOOL") is False
        os.environ["TEST_ENV_BOOL"] = "false"
        assert env_bool("TEST_ENV_BOOL") is False
    finally:
        if old is None:
            os.environ.pop("TEST_ENV_BOOL", None)
        else:
            os.environ["TEST_ENV_BOOL"] = old


def test_load_mcp_endpoint_success():
    """load_mcp_endpoint reads <NAME>_MCP_URL and <NAME>_MCP_TOKEN."""
    env = {
        "JUNOS_MCP_URL": "http://junos.local",
        "JUNOS_MCP_TOKEN": "secret",
    }
    ep = load_mcp_endpoint("junos", env=env)
    assert ep.url == "http://junos.local"
    assert ep.token == "secret"


def test_load_mcp_endpoint_missing_url():
    """load_mcp_endpoint raises ConfigError when URL is missing."""
    env = {"JUNOS_MCP_TOKEN": "secret"}
    with pytest.raises(ConfigError, match="missing JUNOS_MCP_URL"):
        load_mcp_endpoint("junos", env=env)


def test_load_mcp_endpoint_token_defaults():
    """load_mcp_endpoint defaults token to empty string if absent."""
    env = {"UNIFI_MCP_URL": "http://unifi.local"}
    ep = load_mcp_endpoint("unifi", env=env)
    assert ep.url == "http://unifi.local"
    assert ep.token == ""
