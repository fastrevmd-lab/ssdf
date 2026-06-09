"""Runtime reader of the caller principal from the FastMCP access-token claims (M7a)."""

from __future__ import annotations

from fastmcp.server.dependencies import get_access_token


def current_caller() -> tuple[str, frozenset[str] | None]:
    """Return ``(principal, allowed_tools)`` for the in-flight request.

    ``allowed_tools`` is ``None`` when the token grants all tools. Falls back to
    ``sub`` then ``"unknown"`` when ``principal`` is absent.
    """
    token = get_access_token()
    claims = token.claims if token is not None and token.claims else {}
    principal = claims.get("principal") or claims.get("sub") or "unknown"
    allowed = claims.get("allowed_tools")
    allowed_set = None if allowed is None else frozenset(allowed)
    return principal, allowed_set
