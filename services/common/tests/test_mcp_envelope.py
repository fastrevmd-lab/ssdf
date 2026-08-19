"""Vendor MCP tool responses are wrapped; the envelope shape is not stable."""

import json

from ssdf_common.mcp_envelope import envelope_truncated, unwrap_mcp_text

XML = "<response status='success'><result><entry><ip>10.64.0.1</ip></entry></result></response>"


def test_unwraps_nested_output_content():
    """Current rust-panosmcp shape: {"output": {"content": "<xml>"}}."""
    payload = json.dumps({"device": "panosvm", "status": "success",
                          "output": {"content": XML, "truncated": False}})
    assert unwrap_mcp_text(payload) == XML


def test_unwraps_legacy_flat_result():
    """Older shape, still emitted by some tools: {"result": "<xml>"}."""
    assert unwrap_mcp_text(json.dumps({"result": XML})) == XML


def test_unwraps_output_as_plain_string():
    assert unwrap_mcp_text(json.dumps({"output": XML})) == XML


def test_bare_json_string_is_unwrapped():
    assert unwrap_mcp_text(json.dumps(XML)) == XML


def test_non_json_passes_through_unchanged():
    assert unwrap_mcp_text(XML) == XML


def test_json_without_a_known_payload_key_passes_through():
    """Never silently return an empty payload — the caller should see the text."""
    payload = json.dumps({"device": "panosvm", "status": "error"})
    assert unwrap_mcp_text(payload) == payload


def test_whitespace_is_stripped():
    assert unwrap_mcp_text(f"  {XML}  ") == XML


def test_envelope_truncated_reads_the_flag():
    assert envelope_truncated(json.dumps({"output": {"content": XML, "truncated": True}})) is True
    assert envelope_truncated(json.dumps({"output": {"content": XML, "truncated": False}})) is False


def test_envelope_truncated_defaults_false_when_absent():
    assert envelope_truncated(json.dumps({"result": XML})) is False
    assert envelope_truncated(XML) is False
