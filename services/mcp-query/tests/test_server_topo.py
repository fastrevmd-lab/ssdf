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
