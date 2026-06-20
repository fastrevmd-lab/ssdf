from ssdf_health.mcp_client import extract_text


class _Block:
    def __init__(self, text):
        self.text = text


class _Result:
    def __init__(self, structured=None, content=None):
        self.structured_content = structured
        self.content = content


def test_extract_text_prefers_structured_content():
    result = _Result(structured={"cpu": 12.5})
    assert extract_text(result) == '{"cpu": 12.5}'


def test_extract_text_joins_text_blocks():
    result = _Result(content=[_Block("line1"), _Block("line2")])
    assert extract_text(result) == "line1\nline2"


def test_extract_text_empty():
    result = _Result()
    assert extract_text(result) == ""
