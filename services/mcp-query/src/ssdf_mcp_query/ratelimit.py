"""Per-principal rate and concurrency limits (issue #8).

Every limit SSDF enforced lived in nginx and was keyed on ``$binary_remote_addr``:
10r/s burst 30, 32 connections per IP. Two consequences followed. Agents sharing
an address shared a bucket, so a busy one degraded the others; and a *principal*
could not be throttled at all, even though the token is the unit of identity
everywhere else in the system -- ``allowed_tools``, ``not_after``, and the audit
``principal`` column.

These limits are enforced in ``wrapper.audited_tool`` instead, where the
principal has already been resolved and where the refusal can be audited beside
every other allow/deny decision. The nginx limits stay: they are the cheap
per-address defence against a flood that never reaches Python, and this is the
per-identity fairness control that sits behind it.

Both limits are per-process. The two tiers run as separate services, so a
principal's budget is per-tier, which is the intent -- the public and sovereign
surfaces are different resources.
"""

from __future__ import annotations

import threading
import time
from collections import deque


class RateLimitExceeded(Exception):
    """Raised when a principal has spent its request budget."""


class ConcurrencyExceeded(Exception):
    """Raised when a principal already has its maximum calls in flight."""


class PrincipalLimiter:
    """Sliding-window request limit plus an in-flight cap, keyed by principal.

    A sliding window rather than a token bucket: the question an operator asks
    after an incident is "how many calls did that principal make in the last
    minute", and a window answers it directly with the timestamps it already
    keeps. At these rates the memory is a few hundred floats per principal.

    ``max_per_window <= 0`` or ``max_concurrent <= 0`` disables that limit, so
    an unconfigured deployment behaves exactly as before.
    """

    def __init__(
        self,
        max_per_window: int,
        window_seconds: float = 60.0,
        max_concurrent: int = 0,
        clock=time.monotonic,
    ):
        self._max = int(max_per_window)
        self._window = float(window_seconds)
        self._max_concurrent = int(max_concurrent)
        self._clock = clock
        # FastMCP dispatches sync tools on a worker thread pool, so sibling
        # calls for one principal genuinely race here. Under CPython the GIL
        # usually hides that -- removing this lock does not fail the threaded
        # test -- but "the GIL happened to serialise it" is a property of one
        # runtime, not of this code.
        self._lock = threading.Lock()
        self._calls: dict[str, deque[float]] = {}
        self._in_flight: dict[str, int] = {}

    @property
    def enabled(self) -> bool:
        return self._max > 0 or self._max_concurrent > 0

    def _trim(self, principal: str, now: float) -> deque[float]:
        calls = self._calls.setdefault(principal, deque())
        cutoff = now - self._window
        while calls and calls[0] <= cutoff:
            calls.popleft()
        return calls

    def observed(self, principal: str) -> int:
        """Calls by this principal inside the current window (for diagnostics)."""
        with self._lock:
            return len(self._trim(principal, self._clock()))

    def in_flight(self, principal: str) -> int:
        with self._lock:
            return self._in_flight.get(principal, 0)

    def acquire(self, principal: str) -> None:
        """Admit one call, or raise.

        Checks concurrency BEFORE recording the call. A rejected call must not
        consume window budget, or a principal already at its concurrency ceiling
        would also burn through its rate allowance while achieving nothing.
        """
        with self._lock:
            now = self._clock()
            if self._max_concurrent > 0:
                current = self._in_flight.get(principal, 0)
                if current >= self._max_concurrent:
                    raise ConcurrencyExceeded(
                        f"principal '{principal}' already has {current} calls in flight "
                        f"(limit {self._max_concurrent})"
                    )
            if self._max > 0:
                calls = self._trim(principal, now)
                if len(calls) >= self._max:
                    raise RateLimitExceeded(
                        f"principal '{principal}' exceeded {self._max} calls per {self._window:g}s"
                    )
                calls.append(now)
            self._in_flight[principal] = self._in_flight.get(principal, 0) + 1

    def release(self, principal: str) -> None:
        """Return one in-flight slot. Never drops below zero."""
        with self._lock:
            current = self._in_flight.get(principal, 0)
            if current <= 1:
                self._in_flight.pop(principal, None)
            else:
                self._in_flight[principal] = current - 1
