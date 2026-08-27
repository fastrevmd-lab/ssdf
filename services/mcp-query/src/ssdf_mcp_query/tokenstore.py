"""Bearer tokens held as digests, never as recoverable secrets (issue #7).

The token file used to be keyed by the bearer token itself, so anyone who could
read it obtained working credentials for the sovereign tier -- a stray backup, a
container snapshot, a token pasted into a ticket. Worse, a leaked token is
indistinguishable from a live one, so there is no signal that rotation is due.

FastMCP's own ``StaticTokenVerifier`` says as much in its docstring: "Never use
this in production - tokens are stored in plain text!". It matches the presented
bearer against a dict keyed by the plaintext, so it cannot be given digests.
``DigestTokenVerifier`` below hashes what the caller presented and compares that,
which is what lets the file hold only digests.

The sibling Rust servers (``mecmcp-auth``) have always done this. This is the
same model reimplemented in Python -- deliberately NOT a dependency on those
crates, which are Rust-only and built for config-mutating vendor servers.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import stat
import sys
from pathlib import Path

from fastmcp.server.auth import TokenVerifier
from mcp.server.auth.provider import AccessToken

DIGEST_PREFIX = "sha256:"

# A minted token: 32 random bytes, URL-safe. Long enough that guessing is not a
# threat model, short enough to paste into a client config.
TOKEN_BYTES = 32


def mint_token() -> str:
    """Return a new bearer token. The only time the plaintext ever exists."""
    return secrets.token_urlsafe(TOKEN_BYTES)


def digest_for(token: str) -> str:
    """Return the stored form of a token: ``sha256:<hex>``."""
    return DIGEST_PREFIX + hashlib.sha256(token.encode("utf-8")).hexdigest()


def is_digest(key: str) -> bool:
    """True when a token-file key is already a digest rather than a secret."""
    return key.startswith(DIGEST_PREFIX)


class InsecureTokenFileError(Exception):
    """Raised when the token file is readable by anyone but its owner."""


def assert_file_mode_private(path: Path) -> None:
    """Refuse a token file that group or others can read.

    Fail closed at startup, matching the Rust servers, which refuse to start on
    a token file that is not 0600. A readable secrets file is not a warning
    condition: by the time the process is serving, the exposure has happened.
    """
    mode = path.stat().st_mode
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise InsecureTokenFileError(
            f"{path} is accessible beyond its owner (mode {stat.S_IMODE(mode):04o}); "
            "chmod 600 it. Tokens are credentials for the sovereign MCP tier."
        )


def normalize_token_keys(raw: dict[str, dict], source: str) -> tuple[dict[str, dict], list[str]]:
    """Map a token file's keys to digests, accepting a legacy plaintext key.

    Returns ``(by_digest, legacy_principals)``. A legacy key is hashed here so
    the deployment keeps working, but it is reported so the operator can re-mint:
    the file still holds a usable secret until they do.

    Rejects a file that mixes two entries resolving to the same digest, which
    would silently drop one principal's grants.
    """
    by_digest: dict[str, dict] = {}
    legacy: list[str] = []
    for key, entry in raw.items():
        if is_digest(key):
            key_digest = key
        else:
            key_digest = digest_for(key)
            legacy.append(str(entry.get("principal", "<unnamed>")))
        if key_digest in by_digest:
            raise ValueError(
                f"{source}: two entries resolve to the same token digest "
                f"({key_digest[:16]}...); one would shadow the other"
            )
        by_digest[key_digest] = entry
    return by_digest, legacy


def warn_about_legacy_tokens(legacy_principals: list[str], source: str) -> None:
    """Say plainly, once at startup, that the file still holds live secrets."""
    if not legacy_principals:
        return
    names = ", ".join(sorted(legacy_principals))
    print(
        f"[auth] WARNING: {source} stores plaintext tokens for: {names}. "
        f"Anyone who reads that file holds working credentials, and a leaked "
        f"token cannot be told apart from a live one. Re-mint with "
        f"`python -m ssdf_mcp_query.mint_token --principal <name>` and replace "
        f"each key with its sha256: digest.",
        file=sys.stderr,
    )


def verify_against(digests: dict[str, dict], presented: str) -> dict | None:
    """Return the entry a presented token authenticates to, or None.

    Compares with ``hmac.compare_digest`` over every candidate rather than a
    dict lookup. A dict lookup leaks nothing useful here (the key is already a
    hash), but comparing digests in constant time keeps the property true if the
    stored form ever changes, and costs nothing at this token count.
    """
    candidate = digest_for(presented)
    matched: dict | None = None
    for stored_digest, entry in digests.items():
        if hmac.compare_digest(stored_digest, candidate):
            matched = entry
    return matched


class DigestTokenVerifier(TokenVerifier):
    """Authenticate a bearer by its digest, so no secret is held in memory or file.

    FastMCP's ``StaticTokenVerifier`` looks the presented token up in a dict
    keyed by the plaintext, which requires holding every secret. This hashes
    what was presented and matches that instead, so the server never possesses a
    token it could leak -- only values derived from one.

    ``claims`` is the entry from the token map, so everything downstream
    (``auth.current_caller_claims``) keeps reading ``principal`` /
    ``allowed_tools`` / ``not_after`` exactly as before.
    """

    def __init__(self, tokens_by_digest: dict[str, dict], required_scopes: list[str] | None = None):
        super().__init__(required_scopes=required_scopes)
        self._by_digest = dict(tokens_by_digest)

    async def verify_token(self, token: str) -> AccessToken | None:
        entry = verify_against(self._by_digest, token)
        if entry is None:
            return None
        return AccessToken(
            token=token,
            client_id=entry.get("client_id", "ssdf"),
            scopes=entry.get("scopes", []),
            expires_at=None,
            claims=entry,
        )
