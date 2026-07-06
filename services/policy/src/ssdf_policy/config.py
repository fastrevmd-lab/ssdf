"""Runtime config for the configured-policy collector + resolver (env-driven).

Mirrors ssdf_topo.config (mcp_endpoint) and ssdf_entity.config (ClickHouse). Writes
ClickHouse as the existing M6a `ssdf_entity` user into the shared entity tables.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from ssdf_common.config import ConfigError, McpEndpoint, load_mcp_endpoint

ALL_COLLECTORS = ("panos", "junos")


@dataclass(frozen=True)
class Config:
    ch_host: str
    ch_port: int
    ch_user: str
    ch_password: str
    ch_database: str
    tenant_id: str
    enabled_collectors: tuple[str, ...]
    junos_devices: tuple[str, ...]
    panos_device: str
    ch_secure: bool = False
    ch_ca_file: str = ""

    def mcp_endpoint(self, name: str) -> McpEndpoint:
        return load_mcp_endpoint(name)


def _csv(name: str, default: str = "") -> tuple[str, ...]:
    raw = os.environ.get(name, default)
    return tuple(item.strip() for item in raw.split(",") if item.strip())


def load_config() -> Config:
    password = os.environ.get("CH_PASSWORD")
    if password is None:
        raise ConfigError("CH_PASSWORD is required")
    enabled = _csv("POLICY_COLLECTORS", ",".join(ALL_COLLECTORS))
    return Config(
        ch_host=os.environ.get("CH_HOST", "127.0.0.1"),
        ch_port=int(os.environ.get("CH_PORT", "8123")),
        ch_user=os.environ.get("CH_USER", "ssdf_entity"),
        ch_password=password,
        ch_database=os.environ.get("CH_DATABASE", "ssdf"),
        tenant_id=os.environ.get("POLICY_TENANT", "t_main"),
        enabled_collectors=enabled,
        junos_devices=_csv("JUNOS_DEVICES"),
        panos_device=os.environ.get("PANOS_DEVICE", "panosvm"),
        ch_secure=os.environ.get("CH_SECURE", "0").strip().lower() in ("1", "true"),
        ch_ca_file=os.environ.get("CH_CA_FILE", ""),
    )
