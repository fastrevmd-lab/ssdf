"""Shared configuration helpers — exception, MCP endpoint loader, env bool parser."""

from __future__ import annotations

import hmac
import os
from dataclasses import dataclass


class ConfigError(RuntimeError):
    """Raised when required configuration is missing."""


@dataclass(frozen=True)
class McpEndpoint:
    """An MCP server endpoint — URL + bearer token."""

    url: str
    token: str


class Secret:
    """Wraps a sensitive string or byte string so it can't leak through repr/str/logging by accident.

    Config dataclasses hold their password (and key material) fields as
    ``Secret`` instead of ``str``/``bytes`` so a traceback or debug
    ``repr(config)`` never prints the value. Call ``.get()`` to unwrap it at
    the point of use (building connection kwargs, keying an HMAC).
    """

    __slots__ = ("_value",)

    def __init__(self, value: str | bytes) -> None:
        self._value = value

    def get(self) -> str | bytes:
        return self._value

    def __repr__(self) -> str:
        return "Secret('***')"

    def __str__(self) -> str:
        return "***"

    def __bool__(self) -> bool:
        return bool(self._value)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Secret):
            return NotImplemented
        a, b = self._value, other._value
        if type(a) is not type(b):
            return False
        if isinstance(a, str):
            a, b = a.encode("utf-8"), b.encode("utf-8")
        return hmac.compare_digest(a, b)

    def __hash__(self) -> int:
        return hash(self._value)


_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


def require_tls_or_loopback(host: str, secure: bool) -> None:
    """Raise ConfigError for a plaintext ClickHouse connection to a non-loopback host.

    A plain-HTTP connection to anything but the local machine sends the
    ClickHouse password (and every row read/written) in the clear. TLS
    (``secure=True``) is required for any other host.
    """
    if secure:
        return
    if host.strip().lower() in _LOOPBACK_HOSTS:
        return
    raise ConfigError(
        f"refusing a plaintext ClickHouse connection to non-loopback host {host!r}: "
        "set ch_secure=True (CH_SECURE=1) or connect to 127.0.0.1/localhost/::1"
    )


def env_bool(name: str, default: bool = False) -> bool:
    """Parse an env var as a boolean (truthiness: "1" or "true", case-insensitive)."""
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true")


def load_mcp_endpoint(name: str, env: dict | None = None) -> McpEndpoint:
    """Load an MCP endpoint from environment: <NAME>_MCP_URL (required) + <NAME>_MCP_TOKEN.

    Raises ConfigError if the URL is missing.
    """
    if env is None:
        env = os.environ
    prefix = name.upper()
    url = env.get(f"{prefix}_MCP_URL")
    token = env.get(f"{prefix}_MCP_TOKEN", "")
    if not url:
        raise ConfigError(f"missing {prefix}_MCP_URL for endpoint '{name}'")
    return McpEndpoint(url=url, token=token)
