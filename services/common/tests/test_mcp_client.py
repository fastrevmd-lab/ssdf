"""Unit tests for ssdf_common.mcp_client."""

from dataclasses import dataclass

import pytest

from ssdf_common.config import McpEndpoint
from ssdf_common.mcp_client import extract_text, McpToolClient


def test_extract_text_structured():
    """extract_text returns JSON dump of structured_content when present."""

    @dataclass
    class FakeResult:
        structured_content: dict

    result = FakeResult(structured_content={"key": "value"})
    text = extract_text(result)
    assert '"key"' in text and '"value"' in text


def test_extract_text_content_blocks():
    """extract_text joins text from content blocks."""

    @dataclass
    class Block:
        text: str

    @dataclass
    class FakeResult:
        structured_content = None
        content: list

    result = FakeResult(content=[Block(text="line1"), Block(text="line2")])
    text = extract_text(result)
    assert text == "line1\nline2"


def test_extract_text_no_blocks():
    """extract_text returns empty when no content."""

    @dataclass
    class FakeResult:
        structured_content = None
        content = []

    result = FakeResult()
    assert extract_text(result) == ""


def test_mcp_tool_client_init():
    """McpToolClient accepts an McpEndpoint."""
    ep = McpEndpoint(url="http://example.com", token="abc")
    client = McpToolClient(ep)
    assert client is not None


def test_call_tool_times_out_instead_of_hanging_forever():
    """A vendor MCP that accepts the request and never answers must not wedge the
    caller. Live effect before this: one unanswered call left collect_all running
    91 minutes, and because the collector runs in ExecStartPre — bounded by
    TimeoutStartSec, which was infinity — systemd never killed it and the topology
    graph stopped updating entirely.
    """
    import asyncio

    from ssdf_common.config import McpEndpoint
    from ssdf_common.mcp_client import McpToolClient

    client = McpToolClient(
        McpEndpoint(url="http://example.invalid/mcp", token="t"), timeout_secs=0.05
    )

    async def _never_answers(name, args):
        await asyncio.sleep(30)

    client._call = _never_answers

    with pytest.raises(TimeoutError):
        client.call_tool("execute_junos_command", {"router_name": "x"})


def test_call_tool_returns_normally_within_the_timeout():
    async def _fast(name, args):
        return "ok"

    from ssdf_common.config import McpEndpoint
    from ssdf_common.mcp_client import McpToolClient

    client = McpToolClient(McpEndpoint(url="http://example.invalid/mcp", token="t"), timeout_secs=5)
    client._call = _fast
    assert client.call_tool("t", {}) == "ok"
