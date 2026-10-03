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
from .checkpoint_verify import (
    Checkpoint,
    CheckpointVerificationError,
    verify_checkpoint_signature,
)
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
    # Attribution (issue #9). MUST be selected: canonical() folds these into the
    # hash when present, so a verifier that ignored them would recompute the
    # nine-field form for an attributed row and report a false mismatch.
    "client_name",
    "model_id",
    "actor_type",
    "prev_hash",
    "row_hash",
]


def group_key(row: dict) -> tuple[str, str]:
    """The chain a row belongs to: its tier, and its writer when it names one.

    ``server_id`` lives inside the JSON ``args`` payload rather than in a
    column, so this parses defensively: a row whose args are absent, malformed
    or lack the field falls back to tier-only grouping, which is the historical
    behaviour and the right answer for sovereign rows.

    For an **evidence** row that fallback is a defect rather than a default, and
    :func:`writer_issue` reports it — see the note there.
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


def writer_issue(row: dict) -> dict | None:
    """Report an evidence row that does not name the chain it belongs to.

    Evidence chains are keyed ``(tier, server_id)``. A row whose ``args`` are
    malformed, omit ``server_id``, or carry a non-string or empty one has no
    usable key, and grouping it under the tier alone is not harmless: several
    such rows share that bucket, each contributes its own root, and the whole
    set verifies as clean. That is precisely the deletion blind spot per-writer
    grouping was introduced to close, arrived at from the other direction.

    Only the evidence tier is held to this. Sovereign rows never carried a
    writer — all 20,193 of them predate the field — so requiring one there would
    turn every historical row into an issue over a rule that was never made
    about them.
    """
    if row.get("tier") != "evidence":
        return None
    _, server_id = group_key(row)
    if server_id:
        return None
    return {"type": "unidentified_writer", "row_hash": row.get("row_hash", "")}


def _select_checkpoint_anchor(
    checkpoints: list[Checkpoint],
    verifying_key: bytes | None,
) -> tuple[str | None, list[dict]]:
    """Pick a checkpoint's head hash to trust as a stand-in for an expired
    genesis row (MEC-565).

    The returned hash is deliberately NOT required to belong to a row still
    present in ``rows``: the entire reason a checkpoint exists is to anchor a
    chain whose genesis (and, after enough checkpoint cycles, whose earlier
    checkpointed heads too) has already aged out of ssdf.audit. A signed
    checkpoint is itself the durable proof that a row with this hash once
    existed at the stated position in the chain — ``verify_tier`` uses it as
    a trusted ``prev_hash`` value a surviving row may legitimately point to,
    exactly as it would trust ``prev_hash == ""`` for a real genesis row.

    Never trusts a checkpoint it cannot verify (fail closed): a missing
    verifying key or a bad signature both fall back to no anchor at all,
    which (via the normal missing_predecessor/unreachable checks) reports the
    chain exactly as it would have before this feature existed, rather than
    silently accepting an unproven anchor.
    """
    if not checkpoints:
        return None, []
    latest = max(checkpoints, key=lambda c: c.checkpoint_ts)
    if verifying_key is None:
        return None, [{"type": "unverifiable_checkpoint", "row_hash": latest.head_row_hash}]
    try:
        verify_checkpoint_signature(latest, verifying_key)
    except CheckpointVerificationError:
        return None, [{"type": "unverifiable_checkpoint", "row_hash": latest.head_row_hash}]
    return latest.head_row_hash, []


def verify_tier(
    rows: list[dict],
    checkpoints: list[Checkpoint] = (),
    verifying_key: bytes | None = None,
) -> list[dict]:
    """Verify one tier's rows. Returns a list of issue dicts (empty == clean).

    Rows written before migration 009 carry prev_hash='' / row_hash='' (column
    DEFAULT) and are excluded: the first hashed row per tier is that tier's
    chain start. A blanked-hash tamper on a chained row is still caught — its
    successor's prev_hash names a now-missing row_hash (missing_predecessor).

    ``checkpoints`` and ``verifying_key`` (MEC-565) are only consulted when
    this chain's genesis row is absent from ``rows`` -- i.e. it has expired
    past the 90-day TTL. Callers that never pass them get exactly today's
    behaviour: an expired genesis makes every surviving row ``unreachable``.
    """
    rows = [r for r in rows if r["row_hash"] != ""]
    issues: list[dict] = []
    by_hash = {r["row_hash"]: r for r in rows}

    # 0. Duplicates. A retry after an ambiguous INSERT timeout can land the same
    #    row twice: the sink cannot tell whether the timed-out request committed,
    #    its high-water read can answer "nothing landed", and the original then
    #    commits alongside the retry. The pair is invisible to every check below
    #    -- identical content means an identical row_hash, so `by_hash` collapses
    #    them into one entry and linkage and reachability both pass. Counting is
    #    the only thing that sees it.
    seen: dict[str, int] = defaultdict(int)
    for r in rows:
        seen[r["row_hash"]] += 1
    for row_hash, count in seen.items():
        if count > 1:
            issues.append({"type": "duplicate_row", "row_hash": row_hash})

    # 1. Content integrity: each stored row_hash must equal H(prev_hash, fields).
    for r in rows:
        if compute_row_hash(r["prev_hash"], r) != r["row_hash"]:
            issues.append({"type": "content_edit", "row_hash": r["row_hash"]})

    # Genesis-or-checkpoint anchor selection, done once up front so both the
    # linkage check (2) and reachability (3) below agree on what counts as a
    # legitimate root. A checkpoint is only consulted when this chain's own
    # genesis row (prev_hash == "") is absent -- a chain that still has its
    # genesis needs no anchor and MUST ignore any checkpoint it is handed
    # (stale or even malformed), since consulting one it does not need would
    # let a bad checkpoint affect a chain it has nothing to do with.
    has_genesis = any(r["prev_hash"] == "" for r in rows)
    anchor_hash: str | None = None
    if not has_genesis and rows:
        anchor_hash, anchor_issues = _select_checkpoint_anchor(list(checkpoints), verifying_key)
        issues.extend(anchor_issues)

    # 2. Linkage: a non-genesis prev_hash must name a present row, UNLESS it
    #    names the trusted checkpoint anchor (MEC-565) -- that hash stands in
    #    for a row that once existed but has since expired out of ssdf.audit.
    for r in rows:
        if r["prev_hash"] != "" and r["prev_hash"] not in by_hash and r["prev_hash"] != anchor_hash:
            issues.append({"type": "missing_predecessor", "row_hash": r["row_hash"]})

    # 3. Reachability from genesis (prev_hash == ""), extended by any row
    #    chaining directly from a verified checkpoint anchor (MEC-565).
    children: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        children[r["prev_hash"]].append(r)
    reachable: set[str] = set()
    stack = list(children.get("", []))
    if anchor_hash is not None:
        stack.extend(children.get(anchor_hash, []))
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


_CHECKPOINT_COLUMNS = [
    "tier",
    "server_id",
    "row_count",
    "head_row_hash",
    "checkpoint_ts",
    "signature",
    "key_id",
]


def _make_client(config):
    import clickhouse_connect

    return clickhouse_connect.get_client(
        host=config.ch_host,
        port=config.ch_port,
        username="ssdf_audit_verify",
        password=config.ch_audit_verify_password.get(),
        database=config.ch_database,
        **ch_tls_kwargs(config),
    )


def _fetch_rows(config) -> list[dict]:
    client = _make_client(config)
    res = client.query(f"SELECT {', '.join(_VERIFY_COLUMNS)} FROM ssdf.audit ORDER BY ts ASC")
    return [dict(zip(_VERIFY_COLUMNS, row)) for row in res.result_rows]


def _fetch_checkpoints(config) -> dict[tuple[str, str], list[Checkpoint]]:
    client = _make_client(config)
    res = client.query(
        f"SELECT {', '.join(_CHECKPOINT_COLUMNS)} FROM ssdf.audit_checkpoints "
        "ORDER BY checkpoint_ts ASC"
    )
    by_chain: dict[tuple[str, str], list[Checkpoint]] = defaultdict(list)
    for values in res.result_rows:
        row = dict(zip(_CHECKPOINT_COLUMNS, values))
        checkpoint = Checkpoint(
            tier=row["tier"],
            server_id=row["server_id"],
            row_count=int(row["row_count"]),
            head_row_hash=row["head_row_hash"],
            checkpoint_ts=row["checkpoint_ts"],
            signature=row["signature"],
            key_id=row["key_id"],
        )
        by_chain[(checkpoint.tier, checkpoint.server_id)].append(checkpoint)
    return by_chain


def _load_verifying_key(config) -> bytes | None:
    """Load the checkpoint verifying key, or None when checkpoint-based
    verification is not configured (fail closed to today's behaviour, not to
    an exception, since most deployments will not have rolled this out yet)."""
    if not config.ch_checkpoint_verify_key_path:
        return None
    from .checkpoint_verify import load_verifying_key

    try:
        return load_verifying_key(config.ch_checkpoint_verify_key_path)
    except CheckpointVerificationError as exc:
        print(f"warning: could not load checkpoint verifying key: {exc}", file=sys.stderr)
        return None


def main() -> int:
    config = load_config()
    if not config.ch_audit_verify_password:
        print("CH_AUDIT_VERIFY_PASSWORD is required to verify the audit chain", file=sys.stderr)
        return 2
    rows = _fetch_rows(config)
    checkpoints_by_chain = _fetch_checkpoints(config)
    verifying_key = _load_verifying_key(config)
    by_chain: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for r in rows:
        by_chain[group_key(r)].append(r)
    total = 0
    for (tier, server_id), chain_rows in sorted(by_chain.items()):
        issues = verify_tier(
            chain_rows,
            checkpoints=checkpoints_by_chain.get((tier, server_id), []),
            verifying_key=verifying_key,
        )
        # An evidence row with no usable writer cannot be chained to anything,
        # so it is reported rather than quietly folded into the tier bucket.
        issues.extend(issue for row in chain_rows if (issue := writer_issue(row)))
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
