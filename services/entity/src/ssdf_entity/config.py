"""Env-driven runtime config for the entity resolver (mirrors ssdf_topo.config)."""

from __future__ import annotations

import os
from dataclasses import dataclass


class ConfigError(RuntimeError):
    """Raised when required configuration is missing."""


@dataclass(frozen=True)
class Config:
    ch_host: str
    ch_port: int
    ch_user: str
    ch_password: str
    ch_database: str
    tenant_id: str
    window_hours: int


def load_config() -> Config:
    password = os.environ.get("CH_PASSWORD")
    if password is None:
        raise ConfigError("CH_PASSWORD is required")
    return Config(
        ch_host=os.environ.get("CH_HOST", "127.0.0.1"),
        ch_port=int(os.environ.get("CH_PORT", "8123")),
        ch_user=os.environ.get("CH_USER", "ssdf_entity"),
        ch_password=password,
        ch_database=os.environ.get("CH_DATABASE", "ssdf"),
        tenant_id=os.environ.get("ENTITY_TENANT", "t_main"),
        window_hours=int(os.environ.get("ENTITY_WINDOW_HOURS", "24")),
    )
