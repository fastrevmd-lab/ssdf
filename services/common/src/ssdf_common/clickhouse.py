"""Shared ClickHouse connection helpers — TLS-aware client kwargs builder."""

from __future__ import annotations

from typing import Any

import clickhouse_connect


def client_kwargs(
    *,
    host: str,
    port: int,
    user: str,
    password: str,
    database: str,
    secure: bool = False,
    ca_file: str = "",
) -> dict[str, Any]:
    """Build clickhouse_connect.get_client kwargs; adds TLS (interface/ca_cert) when secure.

    Args:
        host: ClickHouse host (IP or hostname).
        port: ClickHouse HTTP port (8123 plaintext, 8443 HTTPS).
        user: ClickHouse username.
        password: ClickHouse password.
        database: Default database.
        secure: Enable TLS (sets interface="https").
        ca_file: Optional path to a CA cert file (for self-signed local CA).

    Returns:
        dict suitable for **unpacking into get_client.
    """
    kwargs: dict[str, Any] = dict(
        host=host,
        port=port,
        username=user,
        password=password,
        database=database,
    )
    if secure:
        kwargs["interface"] = "https"
        if ca_file:
            kwargs["ca_cert"] = ca_file
    return kwargs


def get_client(**kwargs: Any):
    """Thin wrapper over clickhouse_connect.get_client; pass result of client_kwargs."""
    return clickhouse_connect.get_client(**kwargs)


def client_kwargs_from_config(config) -> dict[str, Any]:
    """Adapter: extract client_kwargs from a Config with ch_* attributes.

    Assumes the config has: ch_host, ch_port, ch_user, ch_password, ch_database,
    ch_secure (bool), ch_ca_file (str).
    """
    return client_kwargs(
        host=config.ch_host,
        port=config.ch_port,
        user=config.ch_user,
        password=config.ch_password,
        database=config.ch_database,
        secure=config.ch_secure,
        ca_file=config.ch_ca_file,
    )
