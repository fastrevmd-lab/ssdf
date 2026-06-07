from ssdf_mcp_query.graphstore import ClickHouseGraphStore, build_node_match_sql, build_subgraph_sql

class FakeCH:
    def __init__(self): self.calls = []
    def run(self, sql, params=None):
        self.calls.append((sql, params or {}))
        if "graph_nodes" in sql and "WHERE" in sql:
            return {"columns": [], "rows": [{
                "node_id": "n1", "kind": "host", "name": "h1",
                "identifiers": {"mac": "aa:bb", "ip": "10.64.0.5"},
                "first_seen": "x", "last_seen": "y", "attrs": {}}], "row_count": 1}
        if "graph_edges" in sql:
            return {"columns": [], "rows": [{
                "edge_id": "e1", "src_id": "n1", "dst_id": "n2",
                "edge_type": "attaches_to", "layer": "l2", "first_seen": "x",
                "last_seen": "y", "confidence": 1.0, "attrs": {"port": "3"}}], "row_count": 1}
        return {"columns": [], "rows": [], "row_count": 0}

def test_node_match_sql_uses_final_and_binds_value():
    sql, params = build_node_match_sql("10.64.0.5", tenant="t_main")
    assert "graph_nodes FINAL" in sql
    assert "{val:String}" in sql
    assert params["val"] == "10.64.0.5"

def test_subgraph_sql_filters_staleness():
    sql, params = build_subgraph_sql(since_iso="2026-06-06T00:00:00+00:00", tenant="t_main")
    assert "graph_edges FINAL" in sql
    assert "last_seen >=" in sql
    assert params["since"] == "2026-06-06T00:00:00+00:00"

def test_find_node_returns_match():
    store = ClickHouseGraphStore(FakeCH(), tenant="t_main")
    node = store.find_node("10.64.0.5")
    assert node["node_id"] == "n1" and node["identifiers"]["ip"] == "10.64.0.5"
