# src/ssdf_topo/config.py
"""Runtime configuration for the topo collectors + resolver (env-driven)."""

from __future__ import annotations

import os
from dataclasses import dataclass

ALL_COLLECTORS = ("junos", "unifi", "panos", "proxmox")


class ConfigError(RuntimeError):
    """Raised when required configuration is missing."""


@dataclass(frozen=True)
class McpEndpoint:
    url: str
    token: str


@dataclass(frozen=True)
class Config:
    ch_host: str
    ch_port: int
    ch_user: str
    ch_password: str
    ch_database: str
    tenant_id: str
    window_hours: int
    enabled_collectors: tuple[str, ...]

    def mcp_endpoint(self, name: str) -> McpEndpoint:
        prefix = name.upper()
        url = os.environ.get(f"{prefix}_MCP_URL")
        token = os.environ.get(f"{prefix}_MCP_TOKEN", "")
        if not url:
            raise ConfigError(f"missing {prefix}_MCP_URL for collector '{name}'")
        return McpEndpoint(url=url, token=token)


def load_config() -> Config:
    password = os.environ.get("CH_PASSWORD")
    if password is None:
        raise ConfigError("CH_PASSWORD is required")
    raw = os.environ.get("TOPO_COLLECTORS", ",".join(ALL_COLLECTORS))
    enabled = tuple(c.strip() for c in raw.split(",") if c.strip())
    return Config(
        ch_host=os.environ.get("CH_HOST", "127.0.0.1"),
        ch_port=int(os.environ.get("CH_PORT", "8123")),
        ch_user=os.environ.get("CH_USER", "ssdf_topo"),
        ch_password=password,
        ch_database=os.environ.get("CH_DATABASE", "ssdf"),
        tenant_id=os.environ.get("TOPO_TENANT", "t_main"),
        window_hours=int(os.environ.get("TOPO_WINDOW_HOURS", "24")),
        enabled_collectors=enabled,
    )
