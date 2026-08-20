#!/usr/bin/env python3
"""Round-trip verification for the audit evidence contract v1.0.

Exercises the high-water-mark ingestion protocol end to end:

1. read the writer's high-water mark as ``ssdf_audit_verify``
2. insert a hand-built evidence record as ``ssdf_audit``
3. replay the identical record, which the protocol must skip
4. insert again *without* consulting the mark, carrying the same dedup token,
   which the database must drop
5. read back and assert exactly one row landed

The replay step is the point. An earlier version of this script re-inserted
unconditionally and reported the resulting duplicate as expected, because the
contract then called for an ``INSERT ... WHERE NOT EXISTS`` guard that the
INSERT-only writer identity cannot execute. The guard is gone; idempotency now
comes from reading the high-water mark first, so the script has to perform that
read or it is testing nothing.

**This writes to the table it verifies.** Point it at a scratch ClickHouse, or
accept that it appends one evidence row to whatever it is aimed at. The cleanup
statement it prints needs an identity with DELETE rights, which neither of the
identities used here has.

Step 4 is what tests the *unknown-outcome* case -- a timed-out insert whose
fate the sink never learned, where the high-water read cannot help because it
may run before the original commits. That is the database's job, via migration
016; without it applied, step 4 fails and should.

This script requires:
- ClickHouse running with ssdf.audit table (migrations 007+009+016 applied)
- CH_HOST, CH_AUDIT_PASSWORD, CH_AUDIT_VERIFY_PASSWORD in environment
- Local ClickHouse OR lab instance accessible (read safety rules in CLAUDE.md)

Usage:
    export CH_HOST=localhost  # or 198.51.100.104 for lab ct104
    export CH_AUDIT_PASSWORD=<from-vault>
    export CH_AUDIT_VERIFY_PASSWORD=<from-vault>
    python scripts/verify_evidence_contract.py
"""

import hashlib
import json
import os
import sys
from datetime import datetime, timezone

try:
    import clickhouse_connect
except ImportError:
    print("ERROR: clickhouse-connect not installed", file=sys.stderr)
    print("Install: uv pip install clickhouse-connect", file=sys.stderr)
    sys.exit(1)


def compute_evidence_hash(ts: str, principal: str, tool: str, args: str, prev_hash: str) -> str:
    """Compute row_hash for an evidence record (matches audit_chain.py semantics)."""
    payload = f"{ts}|{principal}|{tool}|{args}|{prev_hash}"
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def dedup_token(server_id: str, run_id: str, segment_seq: int) -> str:
    """Injective identity for one segment, matching the sink's encoding.

    Length-prefixed because the identifiers are free-form: joining on a
    separator alone is not one-to-one when a field contains it, and two
    segments sharing a token means the database drops one while reporting
    success.
    """
    return f"{len(server_id)}:{server_id}:{len(run_id)}:{run_id}:{segment_seq}"


def high_water(verify_client, server_id: str, run_id: str) -> int | None:
    """Highest ``segment_seq`` already landed for this writer and run.

    ``None`` means nothing has landed, which is **not** the same as ``0``:
    ``max()`` over no rows returns ``0`` and ``segment_seq`` is 0-based, so a
    caller that cannot tell the two apart skips segment 0 of every new run --
    the first record a writer produces, and the root of its chain. The
    ``count()`` is what separates them.
    """
    landed, highest = verify_client.query(
        """
        SELECT count(),
               max(JSONExtractUInt(args, 'segment_seq'))
        FROM ssdf.audit
        WHERE tier = 'evidence'
          AND JSONExtractString(args, 'server_id') = {server_id:String}
          AND JSONExtractString(args, 'run_id')    = {run_id:String}
        """,
        parameters={"server_id": server_id, "run_id": run_id},
    ).result_rows[0]
    return int(highest) if landed else None


def main():
    ch_host = os.getenv("CH_HOST", "localhost")
    ch_port = int(os.getenv("CH_PORT", "8443"))
    ch_secure = os.getenv("CH_SECURE", "1") == "1"
    audit_password = os.getenv("CH_AUDIT_PASSWORD")
    verify_password = os.getenv("CH_AUDIT_VERIFY_PASSWORD")

    if not audit_password:
        print("ERROR: CH_AUDIT_PASSWORD not set", file=sys.stderr)
        sys.exit(1)
    if not verify_password:
        print("ERROR: CH_AUDIT_VERIFY_PASSWORD not set", file=sys.stderr)
        print("The write identity cannot SELECT; the high-water read needs", file=sys.stderr)
        print("ssdf_audit_verify. See migration 009.", file=sys.stderr)
        sys.exit(1)

    print(f"Connecting to ClickHouse: {ch_host}:{ch_port} (secure={ch_secure})")

    # Connect as ssdf_audit (INSERT-only writer)
    try:
        client = clickhouse_connect.get_client(
            host=ch_host,
            port=ch_port,
            username="ssdf_audit",
            password=audit_password,
            secure=ch_secure,
            verify=True if ch_secure else False,
        )
    except Exception as e:
        print(f"ERROR: Failed to connect: {e}", file=sys.stderr)
        print("Is ClickHouse running? Are migrations 007+009 applied?", file=sys.stderr)
        sys.exit(1)

    # Connect as ssdf_audit_verify (SELECT-only reader). Two identities, two
    # statements, each doing only what it is granted -- the boundary migration
    # 007 drew, and the reason the old INSERT guard was impossible.
    try:
        verify_client = clickhouse_connect.get_client(
            host=ch_host,
            port=ch_port,
            username="ssdf_audit_verify",
            password=verify_password,
            secure=ch_secure,
            verify=True if ch_secure else False,
        )
    except Exception as e:
        print(f"ERROR: Failed to connect as ssdf_audit_verify: {e}", file=sys.stderr)
        sys.exit(1)

    # Build a test evidence record
    test_run_id = f"test_run_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
    test_server_id = "verify-script-local"
    test_ts = datetime.now(timezone.utc).replace(microsecond=123000)
    test_ts_str = test_ts.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]  # millisecond precision

    evidence_payload = {
        "request_id": "req_verify_test_001",
        "changeset_id": "cs_verify_abc",
        "device_id": "test-device",
        "diff_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "run_id": test_run_id,
        "server_id": test_server_id,
        "segment_seq": 0,
        "prev_hash": "",  # First record in chain
        "metadata": {"test": True, "purpose": "contract verification"},
    }
    args_json = json.dumps(evidence_payload, separators=(",", ":"))

    # Compute row_hash (first record: prev_hash empty)
    row_hash = compute_evidence_hash(
        test_ts_str, "agent:verify-script", "evidence:proposal", args_json, ""
    )

    print("\n=== Test Evidence Record ===")
    print(f"run_id: {test_run_id}")
    print(f"server_id: {test_server_id}")
    print("segment_seq: 0")
    print(f"row_hash: {row_hash}")
    print(f"timestamp: {test_ts_str}")

    # Step 1: read the high-water mark BEFORE writing anything.
    print("\n[1/5] Reading the high-water mark as ssdf_audit_verify...")
    try:
        mark = high_water(verify_client, test_server_id, test_run_id)
    except Exception as e:
        print(f"✗ High-water read failed: {e}", file=sys.stderr)
        print("  A failed read is not 'nothing landed' -- stopping rather than", file=sys.stderr)
        print("  inserting blind, which is how a replay becomes a duplicate.", file=sys.stderr)
        sys.exit(1)
    print(f"✓ high_water = {mark!r} (None means the run is new)")

    insert_data = [
        (
            test_ts,
            "agent:verify-script",
            "evidence",
            "evidence:proposal",
            args_json,
            ["device:test-device"],
            "",
            1,
            "",
            "",  # prev_hash
            row_hash,
        )
    ]
    columns = [
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

    # Step 2: insert, exactly as a sink would -- only when the mark says to.
    print("\n[2/5] Inserting segment 0 as ssdf_audit...")
    if mark is not None and mark >= 0:
        print(f"✗ Expected a fresh run, but segment {mark} already landed", file=sys.stderr)
        sys.exit(1)
    try:
        client.insert(
            "ssdf.audit",
            insert_data,
            column_names=columns,
            settings={"insert_deduplication_token": dedup_token(test_server_id, test_run_id, 0)},
        )
        print("✓ Insert succeeded")
    except Exception as e:
        print(f"✗ Insert failed: {e}", file=sys.stderr)
        sys.exit(1)

    # Step 3: replay. The protocol must skip it, and the skip is the whole test.
    print("\n[3/5] Replaying the identical segment (idempotency)...")
    replay_mark = high_water(verify_client, test_server_id, test_run_id)
    print(f"  high_water is now {replay_mark!r}")
    if replay_mark is None:
        print("✗ The insert did not land, so the replay proves nothing", file=sys.stderr)
        sys.exit(1)
    if replay_mark >= 0:
        print("✓ Segment 0 is at or below the mark; a sink would skip it")
    else:
        print("✗ The mark did not advance; a sink would re-insert", file=sys.stderr)
        sys.exit(1)

    # Step 4: the unknown-outcome case. A sink whose insert timed out never
    # learns whether it committed, so it retries -- and its high-water read can
    # run before the original lands, meaning the read cannot save it. Only the
    # database can, by recognising the token. Insert deliberately WITHOUT
    # consulting the mark, exactly as that sink would.
    print("\n[4/5] Replaying with the same dedup token, ignoring the mark...")
    try:
        client.insert(
            "ssdf.audit",
            insert_data,
            column_names=columns,
            settings={"insert_deduplication_token": dedup_token(test_server_id, test_run_id, 0)},
        )
        print("✓ Insert accepted (the database must now drop it as a seen block)")
    except Exception as e:
        print(f"✗ Tokened insert failed: {e}", file=sys.stderr)
        sys.exit(1)

    # Step 5: prove it, by counting. A protocol that says "skip" and a table
    # that holds two rows would both be reported as success by the assertions
    # above alone.
    print("\n[5/5] Confirming exactly one row landed...")
    rows = verify_client.query(
        """
        SELECT count()
        FROM ssdf.audit
        WHERE tier = 'evidence'
          AND JSONExtractString(args, 'server_id') = {server_id:String}
          AND JSONExtractString(args, 'run_id')    = {run_id:String}
          AND JSONExtractUInt(args, 'segment_seq') = 0
        """,
        parameters={"server_id": test_server_id, "run_id": test_run_id},
    ).result_rows[0][0]
    if rows != 1:
        print(f"✗ Expected exactly 1 row for segment 0, found {rows}", file=sys.stderr)
        if rows > 1:
            print(
                "  If step 4 is what duplicated it, migration 016 is not applied:",
                file=sys.stderr,
            )
            print(
                "  non_replicated_deduplication_window must be set or the token is ignored.",
                file=sys.stderr,
            )
        sys.exit(1)
    print("✓ Exactly one row")

    print("\nVerification Summary")
    print("✓ The high-water read works as ssdf_audit_verify")
    print("✓ INSERT via ssdf_audit works, and the payload shape is accepted")
    print("✓ Hash chain fields (prev_hash, row_hash) populate")
    print("✓ A replay is skipped, and the table holds one row -- no guard needed")
    print("✓ A tokened insert of a settled segment is dropped by the database")

    print(f"\nTest run_id: {test_run_id}")
    print(
        f"Cleanup: DELETE FROM ssdf.audit WHERE JSONExtractString(args,'run_id')='{test_run_id}';"
    )
    print("(Requires an identity with DELETE rights; neither used here has it)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
