"""Runtime config for the public-metrics resolver (env-driven).

Writes ClickHouse as the ssdf_pubmetrics user. The sovereign PUBLIC_PSEUDONYM_KEY
is a hex string (e.g. `openssl rand -hex 16`), held ONLY on ct109.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from ssdf_common.config import ConfigError


@dataclass(frozen=True)
class Config:
    ch_host: str
    ch_port: int
    ch_user: str
    ch_password: str
    ch_database: str
    tenant_id: str
    pseudonym_key: bytes
    key_version: int
    bucket_secs: int
    lookback_hours: int
    baseline_days: int
    top_n: int
    ch_secure: bool = False
    ch_ca_file: str = ""


def load_config() -> Config:
    password = os.environ.get("CH_PASSWORD")
    if password is None:
        raise ConfigError("CH_PASSWORD is required")
    raw_key = os.environ.get("PUBLIC_PSEUDONYM_KEY")
    key_file = os.environ.get("PUBLIC_PSEUDONYM_KEY_FILE")
    if not raw_key and key_file:
        with open(key_file, "r", encoding="utf-8") as handle:
            raw_key = handle.read().strip()
    if not raw_key:
        raise ConfigError("PUBLIC_PSEUDONYM_KEY or PUBLIC_PSEUDONYM_KEY_FILE is required")
    try:
        key = bytes.fromhex(raw_key)
    except ValueError as exc:
        raise ConfigError(f"PUBLIC_PSEUDONYM_KEY must be hex: {exc}") from exc
    return Config(
        ch_host=os.environ.get("CH_HOST", "127.0.0.1"),
        ch_port=int(os.environ.get("CH_PORT", "8123")),
        ch_user=os.environ.get("CH_USER", "ssdf_pubmetrics"),
        ch_password=password,
        ch_database=os.environ.get("CH_DATABASE", "ssdf"),
        tenant_id=os.environ.get("PUBMETRICS_TENANT_ID", "t_main"),
        pseudonym_key=key,
        key_version=int(os.environ.get("PUBMETRICS_KEY_VERSION", "1")),
        bucket_secs=int(os.environ.get("PUBMETRICS_BUCKET_SECS", "300")),
        lookback_hours=int(os.environ.get("PUBMETRICS_LOOKBACK_HOURS", "1")),
        baseline_days=int(os.environ.get("PUBMETRICS_BASELINE_DAYS", "30")),
        top_n=int(os.environ.get("PUBMETRICS_TOP_N", "20")),
        ch_secure=os.environ.get("CH_SECURE", "0").strip().lower() in ("1", "true"),
        ch_ca_file=os.environ.get("CH_CA_FILE", ""),
    )
