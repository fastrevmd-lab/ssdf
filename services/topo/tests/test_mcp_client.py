# tests/test_mcp_client.py
from ssdf_topo.mcp_client import extract_text


def test_extract_text_joins_text_blocks():
    class Block:
        def __init__(self, text):
            self.text = text

    class Result:
        content = [Block("line1"), Block("line2")]
        structured_content = None

    assert extract_text(Result()) == "line1\nline2"


def test_extract_text_prefers_structured_content():
    class Result:
        content = []
        structured_content = {"result": [{"a": 1}]}

    out = extract_text(Result())
    assert '"a": 1' in out  # structured content serialized to JSON text
