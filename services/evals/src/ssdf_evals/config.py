"""Env-driven runtime config for the eval scorer (mirrors ssdf_entity.config).

Reads the query path as ssdf_ro and the audit trail as ssdf_audit_verify —
the same identities/envs the rest of SSDF already uses (CH_PORT=8443,
CH_SECURE=1, CH_CA_FILE for the TLS edge).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

from ssdf_common.config import ConfigError
from ssdf_common.clickhouse import client_kwargs as _shared_client_kwargs


@dataclass(frozen=True)
class Config:
    ch_host: str
    ch_port: int
    ch_user: str
    ch_password: str
    ch_database: str
    ch_secure: bool
    ch_ca_file: str
    audit_verify_password: str
    audit_slop_secs: int


def load_config() -> Config:
    password = os.environ.get("CH_PASSWORD")
    if password is None:
        raise ConfigError("CH_PASSWORD is required")
    audit_verify_password = os.environ.get("CH_AUDIT_VERIFY_PASSWORD")
    if audit_verify_password is None:
        raise ConfigError("CH_AUDIT_VERIFY_PASSWORD is required")
    return Config(
        ch_host=os.environ.get("CH_HOST", "127.0.0.1"),
        ch_port=int(os.environ.get("CH_PORT", "8123")),
        ch_user=os.environ.get("CH_USER", "ssdf_ro"),
        ch_password=password,
        ch_database=os.environ.get("CH_DATABASE", "ssdf"),
        ch_secure=os.environ.get("CH_SECURE", "0").strip().lower() in ("1", "true"),
        ch_ca_file=os.environ.get("CH_CA_FILE", ""),
        audit_verify_password=audit_verify_password,
        audit_slop_secs=int(os.environ.get("EVAL_AUDIT_SLOP_SECS", "5")),
    )


def client_kwargs(config: Config, *, username: str | None = None,
                  password: str | None = None) -> dict[str, Any]:
    """clickhouse_connect.get_client kwargs; adds TLS when ch_secure.

    Pass username/password to connect as a different identity
    (ssdf_audit_verify for the audit read path).
    """
    # Delegate to the shared client_kwargs; override user/password if given
    return _shared_client_kwargs(
        host=config.ch_host,
        port=config.ch_port,
        user=username or config.ch_user,
        password=config.ch_password if password is None else password,
        database=config.ch_database,
        secure=config.ch_secure,
        ca_file=config.ch_ca_file,
    )
