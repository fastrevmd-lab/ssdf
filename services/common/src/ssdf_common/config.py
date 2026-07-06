"""Shared configuration helpers — exception, MCP endpoint loader, env bool parser."""

from __future__ import annotations

import os
from dataclasses import dataclass


class ConfigError(RuntimeError):
    """Raised when required configuration is missing."""


@dataclass(frozen=True)
class McpEndpoint:
    """An MCP server endpoint — URL + bearer token."""
    url: str
    token: str


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
