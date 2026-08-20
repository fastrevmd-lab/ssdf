"""Offline tamper-evidence verifier for the ssdf.audit hash chain (M3).

Reads as the read-only ``ssdf_audit_verify`` identity, groups rows by
**(tier, server_id)**, and follows each chain's prev_hash -> row_hash linkage
from genesis (prev_hash == "").

Why per writer rather than per tier: the ``evidence`` tier has fifteen MCP
servers writing it. A single chain per tier would require every writer to
serialise against a shared head, and there is no such lock — so each seeds
``prev_hash=""`` and the tier acquires one accepted root per server. With many
roots, deleting an entire run removes a whole independent root and leaves
nothing unreachable, so the verifier reports clean on missing evidence. Grouped
by writer, each server has exactly one root, and a run that continues its
predecessor makes a wholesale deletion visible as ``missing_predecessor``
(ssdf#47). Rows without a ``server_id`` — every ``sovereign`` row — group by
tier alone and verify exactly as before.
Detects: content edits (recomputed hash != stored), deletions (a prev_hash naming
a missing row), and insertions/reorders (rows unreachable from genesis). Follows
the linkage, NOT ts ordering, so same-millisecond ts ties never false-positive.

Usage: python -m ssdf_mcp_query.verify_audit
Exit code 0 = all tiers clean; 1 = at least one issue (or 2 = config error).
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict

from .audit_chain import compute_row_hash
from .config import ch_tls_kwargs, load_config

_VERIFY_COLUMNS = [
    "ts",
    "principal",
    "tier",
    "tool",
    "args",
    "data_classes",
    "decision",
    "row_count",
    "error",
    "prev_hash",
    "row_hash",
]


def group_key(row: dict) -> tuple[str, str]:
    """The chain a row belongs to: its tier, and its writer when it names one.

    ``server_id`` lives inside the JSON ``args`` payload rather than in a
    column, so this parses defensively: a row whose args are absent, malformed
    or lack the field falls back to tier-only grouping, which is the historical
    behaviour and the right answer for sovereign rows.
    """
    raw = row.get("args") or ""
    server_id = ""
    if raw:
        try:
            parsed = json.loads(raw)
        except (TypeError, ValueError):
            parsed = None
        if isinstance(parsed, dict):
            value = parsed.get("server_id")
            if isinstance(value, str):
                server_id = value
    return (row["tier"], server_id)


def verify_tier(rows: list[dict]) -> list[dict]:
    """Verify one tier's rows. Returns a list of issue dicts (empty == clean).

    Rows written before migration 009 carry prev_hash='' / row_hash='' (column
    DEFAULT) and are excluded: the first hashed row per tier is that tier's
    chain start. A blanked-hash tamper on a chained row is still caught — its
    successor's prev_hash names a now-missing row_hash (missing_predecessor).
    """
    rows = [r for r in rows if r["row_hash"] != ""]
    issues: list[dict] = []
    by_hash = {r["row_hash"]: r for r in rows}

    # 1. Content integrity: each stored row_hash must equal H(prev_hash, fields).
    for r in rows:
        if compute_row_hash(r["prev_hash"], r) != r["row_hash"]:
            issues.append({"type": "content_edit", "row_hash": r["row_hash"]})

    # 2. Linkage: a non-genesis prev_hash must name a present row.
    for r in rows:
        if r["prev_hash"] != "" and r["prev_hash"] not in by_hash:
            issues.append({"type": "missing_predecessor", "row_hash": r["row_hash"]})

    # 3. Reachability from genesis (prev_hash == "").
    children: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        children[r["prev_hash"]].append(r)
    reachable: set[str] = set()
    stack = list(children.get("", []))
    while stack:
        r = stack.pop()
        if r["row_hash"] in reachable:
            continue
        reachable.add(r["row_hash"])
        stack.extend(children.get(r["row_hash"], []))
    for r in rows:
        if r["row_hash"] not in reachable:
            issues.append({"type": "unreachable", "row_hash": r["row_hash"]})

    return issues


def _fetch_rows(config) -> list[dict]:
    import clickhouse_connect

    client = clickhouse_connect.get_client(
        host=config.ch_host,
        port=config.ch_port,
        username="ssdf_audit_verify",
        password=config.ch_audit_verify_password,
        database=config.ch_database,
        **ch_tls_kwargs(config),
    )
    res = client.query(f"SELECT {', '.join(_VERIFY_COLUMNS)} FROM ssdf.audit ORDER BY ts ASC")
    return [dict(zip(_VERIFY_COLUMNS, row)) for row in res.result_rows]


def main() -> int:
    config = load_config()
    if not config.ch_audit_verify_password:
        print("CH_AUDIT_VERIFY_PASSWORD is required to verify the audit chain", file=sys.stderr)
        return 2
    rows = _fetch_rows(config)
    by_chain: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for r in rows:
        by_chain[group_key(r)].append(r)
    total = 0
    for (tier, server_id), chain_rows in sorted(by_chain.items()):
        issues = verify_tier(chain_rows)
        total += len(issues)
        legacy = sum(1 for r in chain_rows if r["row_hash"] == "")
        status = "OK" if not issues else f"{len(issues)} ISSUE(S)"
        writer = f" server={server_id}" if server_id else ""
        print(f"tier={tier}{writer} rows={len(chain_rows)} legacy_unhashed={legacy} {status}")
        for issue in issues:
            print(f"  {issue['type']}: row_hash={issue['row_hash'][:16]}…")
    return 0 if total == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
