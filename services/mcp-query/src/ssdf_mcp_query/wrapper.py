"""Per-tool authz + audit wrapper (M7a).

Wraps each registered tool so that, per call: (1) the caller principal +
allowed_tools are resolved, (2) per-tool authorization is enforced (deny ->
structured ``{"error": "forbidden"}``, audited), (3) the underlying tool runs
unchanged, (4) one audit row is recorded. ``functools.wraps`` preserves the
tool's signature + docstring so FastMCP builds the correct schema.
"""

from __future__ import annotations

import functools
from typing import Any, Callable

from .auth import current_caller
from .classification import classes_for_tool


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
    caller: Callable[[], tuple[str, frozenset[str] | None]] = current_caller,
) -> Callable[..., Any]:
    """Return ``fn`` wrapped with per-call authz + audit for ``tool_name``."""
    data_classes = sorted(classes_for_tool(tool_name))

    @functools.wraps(fn)
    def wrapped(*args: Any, **kwargs: Any) -> Any:
        principal, allowed = caller()
        if allowed is not None and tool_name not in allowed:
            auditor.record(
                principal=principal, tier=tier, tool=tool_name, args=kwargs,
                data_classes=data_classes, decision="deny", row_count=0,
                error="forbidden",
            )
            return {
                "error": "forbidden",
                "detail": f"tool '{tool_name}' not permitted for principal '{principal}'",
            }
        result = fn(*args, **kwargs)
        error = result.get("error", "") if isinstance(result, dict) else ""
        auditor.record(
            principal=principal, tier=tier, tool=tool_name, args=kwargs,
            data_classes=data_classes, decision="allow",
            row_count=row_count_of(result), error=error,
        )
        return result

    return wrapped
