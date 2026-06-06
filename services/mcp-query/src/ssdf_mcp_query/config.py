"""Runtime configuration loaded from environment + token file."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


class ConfigError(RuntimeError):
    """Raised when required configuration is missing."""


@dataclass(frozen=True)
class Config:
    ch_host: str
    ch_port: int
    ch_user: str
    ch_password: str
    ch_database: str
    mcp_bind: str
    mcp_port: int
    auth_token: str
    max_execution_time: int = 10


def _read_token() -> str:
    inline = os.environ.get("MCP_AUTH_TOKEN")
    if inline:
        token = inline.strip()
        if not token:
            raise ConfigError("auth token is empty")
        return token
    token_file = os.environ.get("MCP_TOKEN_FILE")
    if token_file and Path(token_file).is_file():
        token = Path(token_file).read_text(encoding="utf-8").strip()
        if not token:
            raise ConfigError("auth token is empty")
        return token
    raise ConfigError("no bearer token: set MCP_AUTH_TOKEN or MCP_TOKEN_FILE")


def load_config() -> Config:
    password = os.environ.get("CH_PASSWORD")
    if password is None:
        raise ConfigError("CH_PASSWORD is required")
    return Config(
        ch_host=os.environ.get("CH_HOST", "127.0.0.1"),
        ch_port=int(os.environ.get("CH_PORT", "8123")),
        ch_user=os.environ.get("CH_USER", "ssdf_ro"),
        ch_password=password,
        ch_database=os.environ.get("CH_DATABASE", "ssdf"),
        mcp_bind=os.environ.get("MCP_BIND", "0.0.0.0"),
        mcp_port=int(os.environ.get("MCP_PORT", "30032")),
        auth_token=_read_token(),
        max_execution_time=int(os.environ.get("MCP_MAX_EXEC_SECS", "10")),
    )
