"""Per-tool authz + audit wrapper (M7a).

Wraps each registered tool so that, per call: (1) the caller principal +
allowed_tools are resolved, (2) per-tool authorization is enforced (deny ->
structured ``{"error": "forbidden"}``, audited), (3) the underlying tool runs
unchanged, (4) one audit row is recorded. ``functools.wraps`` preserves the
tool's signature + docstring so FastMCP builds the correct schema.
"""

from __future__ import annotations

import datetime as _dt
import functools
from typing import Any, Callable

from .auth import current_caller_claims
from .classification import classes_for_tool
from .ratelimit import ConcurrencyExceeded, PrincipalLimiter, RateLimitExceeded


def row_count_of(result: Any) -> int:
    """Best-effort row count: explicit ``row_count``, else ``len(rows)``, else 0."""
    if isinstance(result, dict):
        explicit = result.get("row_count")
        if isinstance(explicit, int):
            return explicit
        rows = result.get("rows")
        if isinstance(rows, list):
            return len(rows)
    return 0


def audited_tool(
    tool_name: str,
    fn: Callable[..., Any],
    auditor: Any,
    *,
    tier: str = "sovereign",
    caller: Callable[[], tuple] = current_caller_claims,
    limiter: PrincipalLimiter | None = None,
) -> Callable[..., Any]:
    """Return ``fn`` wrapped with per-call authz + audit for ``tool_name``.

    ``caller`` may return ``(principal, allowed_tools)`` (legacy) or
    ``(principal, allowed_tools, not_after)``; an expired ``not_after`` is
    denied exactly like a disallowed tool (M2 token expiry).

    ``limiter`` applies per-principal rate and concurrency limits (issue #8).
    It is checked AFTER authorization: a principal that may not call a tool
    should be told that, not have its refusal attributed to load. A limited
    call is audited as a deny like any other, so "was it throttled" is a
    question ``ssdf.audit`` can answer.
    """
    data_classes = sorted(classes_for_tool(tool_name))

    def _deny(principal: str, kwargs: dict, detail: str, error: str = "forbidden") -> dict:
        auditor.record(
            principal=principal,
            tier=tier,
            tool=tool_name,
            args=kwargs,
            data_classes=data_classes,
            decision="deny",
            row_count=0,
            error=error,
        )
        return {"error": error, "detail": detail}

    @functools.wraps(fn)
    def wrapped(*args: Any, **kwargs: Any) -> Any:
        # FastMCP dispatches tools by keyword, so the audited args are kwargs.
        # If a caller ever invokes positionally, those args run but aren't recorded.
        info = caller()
        principal, allowed = info[0], info[1]
        not_after = info[2] if len(info) > 2 else None
        if not_after is not None and _dt.datetime.now(_dt.timezone.utc) >= not_after:
            return _deny(principal, kwargs, f"token for principal '{principal}' has expired")
        if allowed is not None and tool_name not in allowed:
            return _deny(
                principal, kwargs, f"tool '{tool_name}' not permitted for principal '{principal}'"
            )
        if limiter is not None and limiter.enabled:
            try:
                limiter.acquire(principal)
            except (RateLimitExceeded, ConcurrencyExceeded) as exc:
                # A distinct error code from "forbidden": throttling is
                # transient and the caller should retry, where an authz denial
                # never will succeed. Conflating them tells an agent to give up
                # on a tool it is entitled to use.
                return _deny(principal, kwargs, str(exc), error="rate_limited")
            try:
                result = fn(*args, **kwargs)
            finally:
                # Release even when the tool raises, or one failing call would
                # permanently consume a concurrency slot.
                limiter.release(principal)
        else:
            result = fn(*args, **kwargs)

        error = result.get("error", "") if isinstance(result, dict) else ""
        auditor.record(
            principal=principal,
            tier=tier,
            tool=tool_name,
            args=kwargs,
            data_classes=data_classes,
            decision="allow",
            row_count=row_count_of(result),
            error=error,
        )
        return result

    return wrapped
