from ssdf_mcp_query.entitystore import (
    build_entity_match_sql, build_comm_edges_sql, build_governed_by_sql,
    build_entities_by_id_sql, ClickHouseEntityStore,
)


def test_entity_match_sql_lowercases_mac_and_matches_values():
    sql, params = build_entity_match_sql("AA:BB:CC:DD:EE:FF", tenant="t_main")
    assert "ssdf.entities FINAL" in sql
    assert "has(mapValues(identifiers), {val:String})" in sql
    assert params["val"] == "aa:bb:cc:dd:ee:ff"
    assert params["tenant"] == "t_main"


def test_entity_match_sql_preserves_non_mac():
    _, params = build_entity_match_sql("10.64.0.5", tenant="t_main")
    assert params["val"] == "10.64.0.5"


def test_comm_edges_sql_is_bidirectional_and_windowed():
    sql, params = build_comm_edges_sql("A", "B", "2026-06-07T00:00:00", tenant="t_main")
    assert "edge_type = 'communicated_with'" in sql
    assert "last_seen >= {since:String}" in sql
    assert params["a"] == "A" and params["b"] == "B"


def test_governed_by_sql_filters_by_comm_edge_ids():
    sql, params = build_governed_by_sql(["e1", "e2"], tenant="t_main")
    assert "edge_type = 'governed_by'" in sql
    assert "src_id IN {ids:Array(String)}" in sql
    assert params["ids"] == ["e1", "e2"]


class _FakeCH:
    def __init__(self, rows):
        self._rows = rows
        self.calls = []

    def run(self, sql, params=None):
        self.calls.append((sql, params))
        return {"rows": self._rows.pop(0)}


def test_store_find_entity_returns_first_row_or_none():
    ch = _FakeCH([[{"entity_id": "x"}]])
    store = ClickHouseEntityStore(ch, tenant="t_main")
    assert store.find_entity("10.64.0.5") == {"entity_id": "x"}
    ch2 = _FakeCH([[]])
    assert ClickHouseEntityStore(ch2, tenant="t_main").find_entity("nope") is None
