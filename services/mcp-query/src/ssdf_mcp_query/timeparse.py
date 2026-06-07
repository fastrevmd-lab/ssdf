"""Parse absolute (ISO-8601) and relative ("now-1h") time expressions to UTC datetimes."""

from __future__ import annotations

import re
from datetime import datetime, timezone, timedelta

_REL_RE = re.compile(r"^now(?:-(\d+)([smhd]))?$")
_UNIT_TO_KW = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}


class TimeParseError(ValueError):
    """Raised when a time expression cannot be parsed."""


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def parse_time(value: str) -> datetime:
    """Return a timezone-aware UTC datetime for an ISO-8601 or relative expression."""
    text = value.strip()
    match = _REL_RE.match(text)
    if match:
        now = _utcnow()
        amount, unit = match.group(1), match.group(2)
        if amount is None:
            return now
        return now - timedelta(**{_UNIT_TO_KW[unit]: int(amount)})
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise TimeParseError(f"unrecognized time expression: {value!r}") from exc
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)
