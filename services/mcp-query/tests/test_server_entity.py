import asyncio
import os

os.environ.setdefault("CH_PASSWORD", "x")
os.environ.setdefault("MCP_AUTH_TOKEN", "t")


def _registered_tool_names(app):
    tools = asyncio.run(app.list_tools())
    return {t.name for t in tools}


def test_explain_access_tool_is_registered(monkeypatch):
    import ssdf_mcp_query.server as server

    class _Dummy:
        def __init__(self, *a, **k):
            pass

    monkeypatch.setattr(server, "ClickHouseClient", _Dummy)
    app = server.build_app()
    assert "explain_access" in _registered_tool_names(app)
