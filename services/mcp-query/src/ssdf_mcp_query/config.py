"""Runtime configuration loaded from environment + token file."""

from __future__ import annotations

import datetime as _dt
import json
import os
from dataclasses import dataclass
from pathlib import Path


class ConfigError(RuntimeError):
    """Raised when required configuration is missing."""


@dataclass(frozen=True)
class TokenPrincipal:
    """A bearer token's identity. ``allowed_tools=None`` means all tools allowed.

    ``not_after=None`` means the token never expires; otherwise it is a
    timezone-aware UTC datetime after which the token is denied per call.
    """

    principal: str
    allowed_tools: frozenset[str] | None
    not_after: _dt.datetime | None = None


@dataclass(frozen=True)
class Config:
    ch_host: str
    ch_port: int
    ch_user: str
    ch_password: str
    ch_database: str
    mcp_bind: str
    mcp_port: int
    tokens: dict[str, "TokenPrincipal"]
    ch_audit_user: str = "ssdf_audit"
    ch_audit_password: str | None = None
    ch_audit_verify_password: str | None = None
    max_execution_time: int = 10
    max_result_rows: int = 100000
    max_memory_usage: int = 1_000_000_000
    ch_secure: bool = False
    ch_ca_file: str | None = None


def ch_tls_kwargs(config: "Config") -> dict:
    """Extra ``clickhouse_connect.get_client`` kwargs for TLS (empty when off).

    When ``ch_secure`` is set, connect over HTTPS; ``ca_cert`` is passed only
    when ``ch_ca_file`` is configured (self-signed local CA per the L1 design).
    """
    if not config.ch_secure:
        return {}
    kwargs: dict = {"interface": "https"}
    if config.ch_ca_file:
        kwargs["ca_cert"] = config.ch_ca_file
    return kwargs


def parse_not_after(value: object) -> _dt.datetime | None:
    """Parse a tokens-file ``not_after`` ISO-8601 string (naive ⇒ UTC).

    Raises ``ConfigError`` on any non-string or unparseable value (fail closed).
    """
    if value is None:
        return None
    if not isinstance(value, str):
        raise ConfigError(f"not_after must be an ISO-8601 string, got {type(value).__name__}")
    try:
        parsed = _dt.datetime.fromisoformat(value)
    except ValueError as exc:
        raise ConfigError(f"invalid not_after {value!r}: {exc}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=_dt.timezone.utc)
    return parsed


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


def load_token_map() -> dict[str, TokenPrincipal]:
    """Load the multi-principal token map (env ``MCP_TOKENS_FILE``).

    Falls back to the single-token path (``MCP_AUTH_TOKEN``/``MCP_TOKEN_FILE``)
    mapped to principal ``agent`` with all tools allowed, preserving the existing
    deploy. Raises ``ConfigError`` if neither is configured (fail closed).
    """
    tokens_file = os.environ.get("MCP_TOKENS_FILE")
    if not tokens_file:
        single = _read_token()
        return {single: TokenPrincipal(principal="agent", allowed_tools=None)}
    path = Path(tokens_file)
    if not path.is_file():
        raise ConfigError(f"MCP_TOKENS_FILE not found: {tokens_file}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigError(f"invalid token map JSON: {exc}") from exc
    if not isinstance(data, dict) or not data:
        raise ConfigError("token map must be a non-empty JSON object")
    tokens: dict[str, TokenPrincipal] = {}
    for token, meta in data.items():
        if not token or not isinstance(meta, dict):
            raise ConfigError("each token must map to an object with a 'principal'")
        principal = meta.get("principal")
        if not principal:
            raise ConfigError("token entry missing 'principal'")
        allowed = meta.get("allowed_tools")
        allowed_set = None if allowed is None else frozenset(allowed)
        tokens[token] = TokenPrincipal(
            principal=principal,
            allowed_tools=allowed_set,
            not_after=parse_not_after(meta.get("not_after")),
        )
    return tokens


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
        tokens=load_token_map(),
        ch_audit_user=os.environ.get("CH_AUDIT_USER", "ssdf_audit"),
        ch_audit_password=os.environ.get("CH_AUDIT_PASSWORD"),
        ch_audit_verify_password=os.environ.get("CH_AUDIT_VERIFY_PASSWORD"),
        max_execution_time=int(os.environ.get("MCP_MAX_EXEC_SECS", "10")),
        max_result_rows=int(os.environ.get("MCP_MAX_RESULT_ROWS", "100000")),
        max_memory_usage=int(os.environ.get("MCP_MAX_MEMORY_BYTES", "1000000000")),
        ch_secure=os.environ.get("CH_SECURE", "").strip().lower() in ("1", "true"),
        ch_ca_file=os.environ.get("CH_CA_FILE") or None,
    )
