"""Offline tamper-evidence verifier for the ssdf.audit hash chain (M3).

Reads as the read-only ``ssdf_audit_verify`` identity, groups rows by tier, and
follows each tier's prev_hash -> row_hash linkage from genesis (prev_hash == "").
Detects: content edits (recomputed hash != stored), deletions (a prev_hash naming
a missing row), and insertions/reorders (rows unreachable from genesis). Follows
the linkage, NOT ts ordering, so same-millisecond ts ties never false-positive.

Usage: python -m ssdf_mcp_query.verify_audit
Exit code 0 = all tiers clean; 1 = at least one issue (or 2 = config error).
"""

from __future__ import annotations

import sys
from collections import defaultdict

from .audit_chain import compute_row_hash
from .config import load_config

_VERIFY_COLUMNS = [
    "ts", "principal", "tier", "tool", "args", "data_classes",
    "decision", "row_count", "error", "prev_hash", "row_hash",
]


def verify_tier(rows: list[dict]) -> list[dict]:
    """Verify one tier's rows. Returns a list of issue dicts (empty == clean)."""
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
    )
    res = client.query(
        f"SELECT {', '.join(_VERIFY_COLUMNS)} FROM ssdf.audit ORDER BY ts ASC"
    )
    return [dict(zip(_VERIFY_COLUMNS, row)) for row in res.result_rows]


def main() -> int:
    config = load_config()
    if not config.ch_audit_verify_password:
        print("CH_AUDIT_VERIFY_PASSWORD is required to verify the audit chain",
              file=sys.stderr)
        return 2
    rows = _fetch_rows(config)
    by_tier: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        by_tier[r["tier"]].append(r)
    total = 0
    for tier, tier_rows in sorted(by_tier.items()):
        issues = verify_tier(tier_rows)
        total += len(issues)
        status = "OK" if not issues else f"{len(issues)} ISSUE(S)"
        print(f"tier={tier} rows={len(tier_rows)} {status}")
        for issue in issues:
            print(f"  {issue['type']}: row_hash={issue['row_hash'][:16]}…")
    return 0 if total == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
