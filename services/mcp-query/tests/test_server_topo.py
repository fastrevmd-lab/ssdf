import asyncio
import os

os.environ.setdefault("CH_PASSWORD", "x")
os.environ.setdefault("MCP_AUTH_TOKEN", "t")

from ssdf_mcp_query.topo_tools import TopoTools


def test_topo_tools_constructs_with_store():
    # smoke: TopoTools binds to a store and exposes the six tool methods
    class S:
        def find_node(self, i): return None
        def load_subgraph(self, since, limit=5000): return [], []
    t = TopoTools(S())
    for name in ("get_entity", "locate", "neighbors", "find_path",
                 "enforcement_points", "topology_snapshot"):
        assert callable(getattr(t, name))


def test_server_topology_snapshot_passes_role(monkeypatch):
    import ssdf_mcp_query.server as server

    class _Dummy:
        def __init__(self, *a, **k):
            pass

    captured = {}

    class _FakeTopo:
        def __init__(self, *a, **k):
            pass

        def topology_snapshot(self, layer=None, since_hours=None, role=None, kind=None):
            captured["role"] = role
            return {"nodes": [], "edges": [], "node_count": 0, "edge_count": 0,
                    "truncated": False}

    monkeypatch.setattr(server, "ClickHouseClient", _Dummy)
    monkeypatch.setattr(server, "TopoTools", _FakeTopo)
    app = server.build_app()
    asyncio.run(app.call_tool("topology_snapshot", {"role": "firewall"}))
    assert captured["role"] == "firewall"
