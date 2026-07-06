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
