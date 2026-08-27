"""Caller attribution on audit rows, and its hash-chain compatibility (issue #9)."""

from __future__ import annotations

import datetime as dt

from ssdf_mcp_query.attribution import (
    ACTOR_TYPES,
    attribution_from,
    client_name_from_session,
    normalize_actor_type,
)
from ssdf_mcp_query.audit import (
    AUDIT_ATTRIBUTION_COLUMNS,
    AUDIT_COLUMNS,
    build_audit_row,
)
from ssdf_mcp_query.audit_chain import canonical, compute_row_hash
from ssdf_mcp_query.wrapper import audited_tool


class _Auditor:
    def __init__(self):
        self.rows = []

    def record(self, **kw):
        self.rows.append(kw)


class _Info:
    def __init__(self, name):
        self.name = name


class _Params:
    def __init__(self, name):
        self.clientInfo = _Info(name)


class _Session:
    def __init__(self, name):
        self.client_params = _Params(name)


def _row(**overrides):
    base = dict(
        principal="agent",
        tier="sovereign",
        tool="query_flows",
        args={"limit": 1},
        data_classes=["security_log"],
        decision="allow",
        row_count=1,
        error="",
        ts=dt.datetime(2026, 8, 27, 12, 0, 0, tzinfo=dt.timezone.utc),
    )
    base.update(overrides)
    return build_audit_row(**base)


# --- the chain must still verify for everything written before this ----------


def test_a_row_without_attribution_hashes_exactly_as_before():
    """The compatibility guarantee the whole design rests on.

    This literal is the nine-element canonical form as it was before the
    attribution columns existed. If this test fails, every audit row ever
    written stops verifying.
    """
    row = _row()
    assert canonical(row) == (
        '["2026-08-27T12:00:00.000Z","agent","sovereign","query_flows",'
        '"{\\"limit\\": 1}",["security_log"],"allow",1,""]'
    )


def test_empty_attribution_is_indistinguishable_from_absent():
    """A mecmcp evidence row sets none of these; it must hash the old way."""
    with_empties = _row(client_name="", model_id="", actor_type="")
    without = _row()
    assert canonical(with_empties) == canonical(without)


def test_a_legacy_row_dict_lacking_the_keys_entirely_still_hashes():
    """Rows read back from ClickHouse before migration 017 have no such keys."""
    row = _row()
    for key in AUDIT_ATTRIBUTION_COLUMNS:
        row.pop(key)
    assert canonical(row) == canonical(_row())


# --- attribution is inside the tamper-evidence, not beside it ----------------


def test_attribution_changes_the_hash():
    plain = _row()
    attributed = _row(client_name="claude-code", model_id="opus", actor_type="agent")
    assert compute_row_hash("", plain) != compute_row_hash("", attributed)


def test_rewriting_the_model_breaks_the_chain():
    """The attack the chain exists to expose: reattributing a call.

    Without folding attribution into the hash, someone able to write to the
    table could blame a different model and the verifier would report clean.
    """
    row = _row(client_name="claude-code", model_id="opus", actor_type="agent")
    stored = compute_row_hash("", row)
    row["model_id"] = "some-other-model"
    assert compute_row_hash("", row) != stored


def test_stripping_attribution_breaks_the_chain():
    row = _row(client_name="claude-code", model_id="opus", actor_type="agent")
    stored = compute_row_hash("", row)
    for key in AUDIT_ATTRIBUTION_COLUMNS:
        row[key] = ""
    assert compute_row_hash("", row) != stored


def test_adding_attribution_to_an_unattributed_row_breaks_the_chain():
    row = _row()
    stored = compute_row_hash("", row)
    row["model_id"] = "fabricated"
    assert compute_row_hash("", row) != stored


def test_any_single_attribution_field_is_enough_to_extend_the_form():
    for field in AUDIT_ATTRIBUTION_COLUMNS:
        assert canonical(_row(**{field: "x"})) != canonical(_row())


# --- column plumbing --------------------------------------------------------


def test_attribution_columns_are_in_the_insert_order_before_the_hashes():
    for name in AUDIT_ATTRIBUTION_COLUMNS:
        assert name in AUDIT_COLUMNS
    assert AUDIT_COLUMNS[-2:] == ["prev_hash", "row_hash"]


def test_build_audit_row_defaults_attribution_to_empty():
    row = _row()
    assert all(row[name] == "" for name in AUDIT_ATTRIBUTION_COLUMNS)


# --- trust levels -----------------------------------------------------------


def test_actor_type_is_constrained_to_the_known_set():
    for value in ACTOR_TYPES:
        assert normalize_actor_type(value) == value
    assert normalize_actor_type("AGENT") == "agent"
    assert normalize_actor_type("  Human  ") == "human"


def test_an_unrecognised_actor_type_reads_as_unknown():
    """Storing it verbatim would look like an assertion nobody validated."""
    for value in ["root", "", None, 42, "superuser"]:
        assert normalize_actor_type(value) == "unknown"


def test_client_name_comes_from_the_session_and_model_from_the_token():
    """Two trust levels: client-asserted vs operator-declared."""
    got = attribution_from({"model_id": "opus", "actor_type": "agent"}, _Session("claude-code"))
    assert got == {"client_name": "claude-code", "model_id": "opus", "actor_type": "agent"}


def test_a_client_cannot_assert_its_model_or_actor_type():
    """Only the token entry sets these; clientInfo must not be able to."""
    got = attribution_from({}, _Session("anything-it-likes"))
    assert got["model_id"] == ""
    assert got["actor_type"] == "unknown"


def test_missing_or_broken_session_degrades_to_empty():
    """Attribution is context for a row, never a precondition for serving."""
    assert client_name_from_session(None) == ""
    assert client_name_from_session(object()) == ""


# --- through the wrapper ----------------------------------------------------


def test_attribution_reaches_the_audit_row():
    auditor = _Auditor()
    tool = audited_tool(
        "query_flows",
        lambda: {"rows": [1], "row_count": 1},
        auditor,
        caller=lambda: ("agent", None, None),
        attribution=lambda: {
            "client_name": "claude-code",
            "model_id": "opus",
            "actor_type": "agent",
        },
    )
    tool()
    assert auditor.rows[0]["client_name"] == "claude-code"
    assert auditor.rows[0]["model_id"] == "opus"


def test_a_denied_call_is_attributed_too():
    """Who tried and was refused is the more interesting audit question."""
    auditor = _Auditor()
    tool = audited_tool(
        "query_flows",
        lambda: {"rows": []},
        auditor,
        caller=lambda: ("agent", frozenset({"other"}), None),
        attribution=lambda: {
            "client_name": "claude-code",
            "model_id": "opus",
            "actor_type": "agent",
        },
    )
    assert tool()["error"] == "forbidden"
    assert auditor.rows[0]["decision"] == "deny"
    assert auditor.rows[0]["client_name"] == "claude-code"
