"""Who, beyond the token, made a tool call (issue #9).

``ssdf.audit`` is meant to be the one place to ask "who did what" across SSDF's
own MCP servers and the ``rust*mcp`` family alike. For SSDF's own rows, "who"
was a single string -- the token's ``principal``. The rows produced by the Rust
control plane, writing into this same table, carried client, model and actor
type. The steward's own rows were the less informative ones.

Provenance is the whole design here, so it is explicit in the field names' own
documentation rather than left to be inferred:

- ``client_name`` is **client-asserted**. It comes from the MCP ``clientInfo``
  sent at initialize. A client can put anything there. It is worth recording and
  must never be read as verified.
- ``model_id`` and ``actor_type`` are **operator-declared**: they come from the
  token entry, which only someone with write access to the token file can set.
  MCP has no model field, so a client-supplied model would be pure assertion;
  binding it to the token instead makes it as trustworthy as the token itself.

The audit trail must not imply it verified something it cannot. Two trust levels
in one row is fine; pretending there is one is not.
"""

from __future__ import annotations

from typing import Any

# What an absent value looks like in the table. Empty rather than NULL: the
# hash chain serialises these, and "" round-trips through ClickHouse String
# columns unambiguously where NULL would need its own encoding rule.
UNKNOWN = ""

ACTOR_TYPES = frozenset({"human", "agent", "unknown"})


def normalize_actor_type(value: Any) -> str:
    """Constrain actor_type to the known set; anything else reads as unknown.

    An unrecognised value must not be stored verbatim: it would look like an
    assertion the system stands behind, when in fact nobody validated it.
    """
    if not isinstance(value, str):
        return "unknown"
    lowered = value.strip().lower()
    return lowered if lowered in ACTOR_TYPES else "unknown"


def client_name_from_session(session: Any) -> str:
    """Best-effort MCP ``clientInfo.name``; empty when unavailable.

    Deliberately defensive. This reaches through FastMCP into the MCP session to
    read something optional, and the exact path has changed across versions.
    An audit row that loses its client label is a smaller loss than a tool call
    that fails because attribution could not be gathered.
    """
    try:
        params = getattr(session, "client_params", None)
        info = getattr(params, "clientInfo", None)
        name = getattr(info, "name", None)
        return name if isinstance(name, str) and name else UNKNOWN
    except Exception:
        return UNKNOWN


def attribution_from(claims: dict | None, session: Any) -> dict[str, str]:
    """Return the three attribution fields for the in-flight call.

    ``claims`` is the token entry (operator-declared); ``session`` is the live
    MCP session (client-asserted).
    """
    claims = claims or {}
    return {
        "client_name": client_name_from_session(session),
        "model_id": str(claims.get("model_id") or UNKNOWN),
        "actor_type": normalize_actor_type(claims.get("actor_type")),
    }


def current_attribution() -> dict[str, str]:
    """Attribution for the request being served, or blanks off-request.

    Never raises: attribution is context for an audit row, not a precondition
    for serving a tool.
    """
    session: Any = None
    claims: dict | None = None
    try:
        from fastmcp.server.dependencies import get_access_token, get_context

        try:
            session = get_context().session
        except Exception:
            session = None
        try:
            token = get_access_token()
            claims = token.claims if token is not None else None
        except Exception:
            claims = None
    except Exception:
        pass
    return attribution_from(claims, session)
