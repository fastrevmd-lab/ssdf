"""Per-principal rate and concurrency limits (issue #8)."""

from __future__ import annotations

import threading

import pytest

from ssdf_mcp_query.ratelimit import (
    ConcurrencyExceeded,
    PrincipalLimiter,
    RateLimitExceeded,
)
from ssdf_mcp_query.wrapper import audited_tool


class _Clock:
    """Controllable time, so the window is tested by logic rather than sleeping."""

    def __init__(self):
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class _Auditor:
    def __init__(self):
        self.rows = []

    def record(self, **kw):
        self.rows.append(kw)


# --- disabled by default ----------------------------------------------------


def test_zero_limits_are_disabled():
    limiter = PrincipalLimiter(max_per_window=0, max_concurrent=0)
    assert not limiter.enabled
    for _ in range(1000):
        limiter.acquire("p")  # never raises


def test_enabled_when_either_limit_is_set():
    assert PrincipalLimiter(max_per_window=1, max_concurrent=0).enabled
    assert PrincipalLimiter(max_per_window=0, max_concurrent=1).enabled


# --- the rate window --------------------------------------------------------


def test_calls_up_to_the_limit_are_admitted():
    limiter = PrincipalLimiter(max_per_window=3, window_seconds=60, clock=_Clock())
    for _ in range(3):
        limiter.acquire("p")
        limiter.release("p")


def test_the_call_past_the_limit_is_refused():
    limiter = PrincipalLimiter(max_per_window=2, window_seconds=60, clock=_Clock())
    for _ in range(2):
        limiter.acquire("p")
        limiter.release("p")
    with pytest.raises(RateLimitExceeded, match="exceeded 2 calls"):
        limiter.acquire("p")


def test_budget_returns_as_the_window_slides():
    clock = _Clock()
    limiter = PrincipalLimiter(max_per_window=2, window_seconds=60, clock=clock)
    limiter.acquire("p")
    limiter.release("p")
    limiter.acquire("p")
    limiter.release("p")
    with pytest.raises(RateLimitExceeded):
        limiter.acquire("p")

    clock.advance(61)  # both calls now fall outside the window
    limiter.acquire("p")
    assert limiter.observed("p") == 1


def test_partial_window_expiry_frees_exactly_one_slot():
    clock = _Clock()
    limiter = PrincipalLimiter(max_per_window=2, window_seconds=60, clock=clock)
    limiter.acquire("p")
    limiter.release("p")
    clock.advance(30)
    limiter.acquire("p")
    limiter.release("p")
    clock.advance(31)  # the first call aged out, the second has not
    limiter.acquire("p")
    limiter.release("p")
    with pytest.raises(RateLimitExceeded):
        limiter.acquire("p")


def test_principals_have_independent_budgets():
    """The whole point: one principal must not consume another's allowance."""
    limiter = PrincipalLimiter(max_per_window=1, window_seconds=60, clock=_Clock())
    limiter.acquire("noisy")
    with pytest.raises(RateLimitExceeded):
        limiter.acquire("noisy")
    limiter.acquire("quiet")  # unaffected


# --- concurrency ------------------------------------------------------------


def test_in_flight_calls_are_capped():
    limiter = PrincipalLimiter(max_per_window=0, max_concurrent=2)
    limiter.acquire("p")
    limiter.acquire("p")
    with pytest.raises(ConcurrencyExceeded, match="already has 2 calls in flight"):
        limiter.acquire("p")


def test_releasing_frees_a_slot():
    limiter = PrincipalLimiter(max_per_window=0, max_concurrent=1)
    limiter.acquire("p")
    limiter.release("p")
    limiter.acquire("p")


def test_concurrency_is_per_principal():
    limiter = PrincipalLimiter(max_per_window=0, max_concurrent=1)
    limiter.acquire("a")
    limiter.acquire("b")
    assert limiter.in_flight("a") == 1 and limiter.in_flight("b") == 1


def test_release_never_goes_negative():
    limiter = PrincipalLimiter(max_per_window=0, max_concurrent=1)
    limiter.release("never-acquired")
    assert limiter.in_flight("never-acquired") == 0
    limiter.acquire("never-acquired")  # still admits


def test_a_concurrency_refusal_does_not_spend_window_budget():
    """A call rejected on concurrency must not also burn rate allowance.

    Otherwise a principal sitting at its concurrency ceiling exhausts its
    per-minute budget while achieving nothing, and is then locked out of the
    window too.
    """
    limiter = PrincipalLimiter(max_per_window=10, window_seconds=60, max_concurrent=1)
    limiter.acquire("p")
    with pytest.raises(ConcurrencyExceeded):
        limiter.acquire("p")
    assert limiter.observed("p") == 1


def test_concurrent_threads_do_not_exceed_the_cap():
    """Sixteen threads contend for four slots; exactly four get in.

    Honest about what this proves: it is a smoke test, not proof the lock is
    load-bearing. Removing the lock does NOT fail it -- under CPython the
    check-and-increment is short enough that the GIL rarely lets it interleave.
    The lock is kept because that is an implementation detail of one runtime,
    not a property of the code, and FastMCP genuinely dispatches sync tools
    across a worker thread pool.
    """
    limiter = PrincipalLimiter(max_per_window=0, max_concurrent=4)
    admitted = []
    lock = threading.Lock()
    start = threading.Barrier(16)

    def worker():
        start.wait()
        try:
            limiter.acquire("p")
        except ConcurrencyExceeded:
            return
        with lock:
            admitted.append(1)

    threads = [threading.Thread(target=worker) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(admitted) == 4, f"cap of 4 admitted {len(admitted)} concurrent calls"


# --- through the wrapper, where it actually runs -----------------------------


def _wrapped(limiter, auditor, fn=None):
    return audited_tool(
        "query_flows",
        fn or (lambda: {"rows": [1], "row_count": 1}),
        auditor,
        caller=lambda: ("agent", None, None),
        limiter=limiter,
    )


def test_wrapper_throttles_and_audits_the_refusal():
    auditor = _Auditor()
    tool = _wrapped(PrincipalLimiter(max_per_window=1, window_seconds=60, clock=_Clock()), auditor)
    assert tool()["row_count"] == 1
    refused = tool()
    assert refused["error"] == "rate_limited"
    assert "exceeded 1 calls" in refused["detail"]

    denied = [r for r in auditor.rows if r["decision"] == "deny"]
    assert len(denied) == 1
    assert denied[0]["error"] == "rate_limited"
    assert denied[0]["principal"] == "agent"


def test_rate_limited_is_distinct_from_forbidden():
    """Throttling is transient; an authz denial never becomes permitted.

    An agent that reads one as the other either retries forever or gives up on
    a tool it is entitled to use.
    """
    auditor = _Auditor()
    limiter = PrincipalLimiter(max_per_window=1, window_seconds=60, clock=_Clock())
    tool = _wrapped(limiter, auditor)
    tool()
    assert tool()["error"] == "rate_limited"

    forbidden = audited_tool(
        "query_flows",
        lambda: {"rows": []},
        auditor,
        caller=lambda: ("agent", frozenset({"other_tool"}), None),
        limiter=limiter,
    )()
    assert forbidden["error"] == "forbidden"


def test_authorization_is_checked_before_throttling():
    """A principal that may not call a tool is told that, not blamed on load."""
    auditor = _Auditor()
    limiter = PrincipalLimiter(max_per_window=0, window_seconds=60, max_concurrent=1)
    limiter.acquire("agent")  # saturate concurrency
    result = audited_tool(
        "query_flows",
        lambda: {"rows": []},
        auditor,
        caller=lambda: ("agent", frozenset({"other_tool"}), None),
        limiter=limiter,
    )()
    assert result["error"] == "forbidden"


def test_a_raising_tool_still_releases_its_slot():
    """Otherwise one failure permanently consumes a concurrency slot."""
    auditor = _Auditor()
    limiter = PrincipalLimiter(max_per_window=0, max_concurrent=1)

    def boom():
        raise RuntimeError("tool exploded")

    tool = _wrapped(limiter, auditor, fn=boom)
    with pytest.raises(RuntimeError):
        tool()
    assert limiter.in_flight("agent") == 0
    _wrapped(limiter, auditor)()  # slot is usable again


def test_no_limiter_behaves_exactly_as_before():
    auditor = _Auditor()
    tool = audited_tool(
        "query_flows",
        lambda: {"rows": [1], "row_count": 1},
        auditor,
        caller=lambda: ("agent", None, None),
    )
    for _ in range(50):
        assert tool()["row_count"] == 1
    assert all(r["decision"] == "allow" for r in auditor.rows)
