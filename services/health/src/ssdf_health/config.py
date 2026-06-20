"""Runtime configuration for the M13a health poller (env-driven).

Writes ClickHouse as the ssdf_health user. Device lists name the same devices
topo/policy use so health rows bridge to topology identity later.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

ALL_COLLECTORS = ("proxmox", "junos", "panos", "unifi")


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
    enabled_collectors: tuple[str, ...]
    junos_devices: list[str]
    panos_device: str
    unifi_macs: list[str]
    unifi_site_id: str
    ch_secure: bool = False
    ch_ca_file: str = ""

    def mcp_endpoint(self, name: str) -> McpEndpoint:
        prefix = name.upper()
        url = os.environ.get(f"{prefix}_MCP_URL")
        token = os.environ.get(f"{prefix}_MCP_TOKEN", "")
        if not url:
            raise ConfigError(f"missing {prefix}_MCP_URL for collector '{name}'")
        return McpEndpoint(url=url, token=token)


def _csv(name: str) -> list[str]:
    return [item.strip() for item in os.environ.get(name, "").split(",") if item.strip()]


def load_config() -> Config:
    password = os.environ.get("CH_PASSWORD")
    if password is None:
        raise ConfigError("CH_PASSWORD is required")
    raw = os.environ.get("HEALTH_COLLECTORS", ",".join(ALL_COLLECTORS))
    enabled = tuple(c.strip() for c in raw.split(",") if c.strip())
    return Config(
        ch_host=os.environ.get("CH_HOST", "127.0.0.1"),
        ch_port=int(os.environ.get("CH_PORT", "8123")),
        ch_user=os.environ.get("CH_USER", "ssdf_health"),
        ch_password=password,
        ch_database=os.environ.get("CH_DATABASE", "ssdf"),
        tenant_id=os.environ.get("HEALTH_TENANT", "t_main"),
        enabled_collectors=enabled,
        junos_devices=_csv("JUNOS_DEVICES"),
        panos_device=os.environ.get("PANOS_DEVICE", "panosvm"),
        unifi_macs=_csv("UNIFI_DEVICE_MACS"),
        unifi_site_id=os.environ.get("UNIFI_SITE_ID", "default"),
        ch_secure=os.environ.get("CH_SECURE", "0").strip().lower() in ("1", "true"),
        ch_ca_file=os.environ.get("CH_CA_FILE", ""),
    )
