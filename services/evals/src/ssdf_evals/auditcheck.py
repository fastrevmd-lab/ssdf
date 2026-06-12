"""Tool-usage verification against ssdf.audit (the only trusted tool trace).

Reads as ssdf_audit_verify (SELECT-only grant from 009_audit_hash_chain.sql).
Runner-self-reported tool calls are ignored by design.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from .corpus import PUBLIC_TOOLS, Question

_AUDIT_SQL = (
    "SELECT DISTINCT tool FROM ssdf.audit "
    "WHERE principal = {principal:String} "
    "AND ts >= parseDateTimeBestEffort({start:String}, 'UTC') "
    "AND ts <= parseDateTimeBestEffort({end:String}, 'UTC') "
    "AND decision = 'allow'"
)


@dataclass
class ToolCheckResult:
    passed: bool
    observed: list[str]
    reason: str


def _to_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def fetch_tools(client, principal: str, started: datetime, finished: datetime,
                slop_secs: int) -> list[str]:
    """Distinct tools the principal invoked in [started-slop, finished+slop] (UTC)."""
    slop = timedelta(seconds=slop_secs)
    start_dt = _to_utc(started) - slop
    end_dt = _to_utc(finished) + slop
    parameters = {
        "principal": principal,
        "start": start_dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
        "end": end_dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
    }
    rows = client.query(_AUDIT_SQL, parameters=parameters).result_rows
    return sorted(str(row[0]) for row in rows)


def check_tools(question: Question, observed: list[str], tier: str) -> ToolCheckResult:
    """required_tools ⊆ observed; public runs must stay inside PUBLIC_TOOLS."""
    missing = sorted(set(question.required_tools) - set(observed))
    if missing:
        return ToolCheckResult(False, list(observed),
                               f"required tools not observed in audit: {missing}")
    if tier == "public":
        outside = sorted(set(observed) - PUBLIC_TOOLS)
        if outside:
            return ToolCheckResult(False, list(observed),
                                   f"non-public tools observed on public run: {outside}")
    return ToolCheckResult(True, list(observed), "")
