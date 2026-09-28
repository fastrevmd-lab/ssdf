"""Unit tests for ssdf_common.config."""

import pytest

from ssdf_common.config import (
    ConfigError,
    McpEndpoint,
    Secret,
    env_bool,
    load_mcp_endpoint,
    require_tls_or_loopback,
)


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
    # env_bool reads os.environ directly rather than taking a mapping, so this
    # exercises the real environment and restores it afterwards.
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


def test_secret_get_returns_the_wrapped_value():
    assert Secret("hunter2").get() == "hunter2"


def test_secret_repr_and_str_never_show_the_value():
    secret = Secret("hunter2")
    assert "hunter2" not in repr(secret)
    assert "hunter2" not in str(secret)


def test_secret_equality_is_by_value():
    assert Secret("hunter2") == Secret("hunter2")
    assert Secret("hunter2") != Secret("other")
    assert Secret("hunter2") != "hunter2"  # not equal to a plain str


def test_secret_wraps_bytes():
    key = bytes.fromhex("00112233")
    secret = Secret(key)
    assert secret.get() == key
    assert "00112233" not in repr(secret)
    assert Secret(key) == Secret(bytes.fromhex("00112233"))
    assert Secret(key) != Secret(bytes.fromhex("44556677"))


def test_secret_bytes_and_str_of_equal_content_are_not_equal():
    assert Secret("ab") != Secret(b"ab")


def test_secret_bool_reflects_wrapped_value_truthiness():
    assert not Secret("")
    assert not Secret(b"")
    assert Secret("x")
    assert Secret(b"x")


def test_require_tls_or_loopback_allows_loopback_plaintext():
    require_tls_or_loopback("127.0.0.1", secure=False)
    require_tls_or_loopback("localhost", secure=False)
    require_tls_or_loopback("::1", secure=False)


def test_require_tls_or_loopback_allows_any_host_when_secure():
    require_tls_or_loopback("198.51.100.152", secure=True)
    require_tls_or_loopback("ct104.example.net", secure=True)


def test_require_tls_or_loopback_rejects_plaintext_to_remote_host():
    with pytest.raises(ConfigError, match="198.51.100.152"):
        require_tls_or_loopback("198.51.100.152", secure=False)
