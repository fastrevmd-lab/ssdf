"""Unwrap vendor MCP tool response envelopes.

Vendor MCP servers wrap a tool's payload in a JSON envelope whose shape is not
stable across releases: rust-panosmcp moved from a flat ``{"result": "<xml>"}``
to a nested ``{"output": {"content": "<xml>", "truncated": false}}`` when it was
renamed to its prod identity. Each collector used to carry its own unwrapper, so
a shape change broke them independently and silently — the JSON reached an XML
parser, failed, and the collector logged a parse warning while emitting nothing.

Keeping one unwrapper here means the next envelope change is a single edit.
"""

from __future__ import annotations

import json
from typing import Any

__all__ = ["unwrap_mcp_text", "envelope_truncated"]


def _envelope(text: str) -> dict[str, Any] | None:
    """Return the decoded JSON envelope, or None if the text is not a JSON object."""
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return None
    return data if isinstance(data, dict) else None


def unwrap_mcp_text(text: str) -> str:
    """Return the payload carried by an MCP tool response.

    Accepts the nested ``output.content`` envelope, a plain-string ``output``,
    the legacy flat ``result``, and a bare JSON string. Anything unrecognised —
    including a JSON object with no known payload key — is returned unchanged so
    the caller sees the real response instead of an empty string.
    """
    stripped = text.strip()
    try:
        data = json.loads(stripped)
    except (json.JSONDecodeError, TypeError):
        return stripped
    if isinstance(data, str):
        return data
    if isinstance(data, dict):
        output = data.get("output")
        if isinstance(output, dict) and isinstance(output.get("content"), str):
            return output["content"]
        if isinstance(output, str):
            return output
        if isinstance(data.get("result"), str):
            return data["result"]
    return stripped


def envelope_truncated(text: str) -> bool:
    """True if the envelope reports that it cut the payload short.

    A truncated payload is not a parse problem to be retried blindly — it is
    incomplete data, and treating it as complete silently under-reports.
    """
    data = _envelope(text)
    if data is None:
        return False
    output = data.get("output")
    if isinstance(output, dict):
        return bool(output.get("truncated", False))
    return bool(data.get("truncated", False))
