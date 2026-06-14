from ssdf_mcp_query.entitystore import (
    build_entity_match_sql, build_comm_edges_sql, build_governed_by_sql,
    build_entities_by_id_sql, ClickHouseEntityStore,
)
from ssdf_mcp_query.entitystore import build_alerts_for_pair_sql


def test_build_alerts_for_pair_sql_filters_provider_kind_ips_and_window():
    sql, params = build_alerts_for_pair_sql(
        ["198.51.100.50", "198.51.100.20"], "2026-06-13T00:00:00.000", "t_main")
    assert "event_provider = 'unifi'" in sql
    assert "event_kind = 'alert'" in sql
    assert "timestamp >= {since:String}" in sql
    assert "toString(source_ip) IN {ips:Array(String)}" in sql
    assert "toString(destination_ip) IN {ips:Array(String)}" in sql
    assert "LIMIT 200" in sql
    assert params["ips"] == ["198.51.100.50", "198.51.100.20"]
    assert params["since"] == "2026-06-13T00:00:00.000"
    assert params["tenant"] == "t_main"


def test_entity_match_sql_lowercases_mac_and_matches_values():
    sql, params = build_entity_match_sql("AA:BB:CC:DD:EE:FF", tenant="t_main")
    assert "ssdf.entities FINAL" in sql
    assert "has(mapValues(identifiers), {val:String})" in sql
    assert params["val"] == "aa:bb:cc:dd:ee:ff"
    assert params["tenant"] == "t_main"


def test_entity_match_sql_preserves_non_mac():
    _, params = build_entity_match_sql("10.64.0.5", tenant="t_main")
    assert params["val"] == "10.64.0.5"


def test_entity_match_sql_orders_by_qualified_column():
    # Must qualify so the toString(last_seen) alias doesn't make "most recent"
    # a lexical string sort instead of a real DateTime64 sort.
    sql, _ = build_entity_match_sql("10.64.0.5", tenant="t_main")
    assert "entities.last_seen DESC" in sql


def test_entity_match_sql_orders_by_confidence_then_last_seen():
    # A by-IP lookup can match both a MAC asset (confidence 1.0) and a stale
    # ip_only twin (0.5); confidence-first ordering makes the MAC asset win so
    # its observer_hosts-bearing edge is the one explain_access reads.
    sql, params = build_entity_match_sql("198.51.100.150", tenant="t_main")
    assert "ORDER BY confidence DESC, entities.last_seen DESC LIMIT 1" in sql
    assert params["tenant"] == "t_main"


def test_comm_edges_sql_is_bidirectional_and_windowed():
    sql, params = build_comm_edges_sql("A", "B", "2026-06-07T00:00:00", tenant="t_main")
    assert "edge_type = 'communicated_with'" in sql
    # Must qualify the column so the toString(last_seen) alias doesn't turn the
    # window filter into a lexical string compare that drops every row.
    assert "entity_edges.last_seen >= {since:String}" in sql
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


from ssdf_mcp_query.entitystore import (
    build_firewall_match_sql, build_configured_governed_sql,
)


def test_firewall_match_sql_filters_kind_and_device_names():
    sql, params = build_firewall_match_sql(["panosvm", "vSRX-test10"], tenant="t_main")
    assert "ssdf.entities FINAL" in sql
    assert "kind = 'firewall'" in sql
    assert "identifiers['device_name'] IN {names:Array(String)}" in sql
    assert params["names"] == ["panosvm", "vSRX-test10"]
    assert params["tenant"] == "t_main"


def test_configured_governed_sql_filters_source_and_src_ids():
    sql, params = build_configured_governed_sql(["fw1"], tenant="t_main")
    assert "edge_type = 'governed_by'" in sql
    assert "source = 'configured'" in sql
    assert "src_id IN {ids:Array(String)}" in sql
    assert params["ids"] == ["fw1"]


def test_configured_policies_for_firewalls_joins_fw_edge_policy():
    # rows popped in call order: firewalls, governed edges, policies
    ch = _FakeCH([
        [{"entity_id": "fwid", "identifiers": {"device_name": "panosvm"}, "name": "panosvm"}],
        [{"edge_id": "g1", "src_id": "fwid", "dst_id": "polid", "attrs": {}}],
        [{"entity_id": "polid", "name": "allow-web", "attrs": {"action": "allow"}}],
    ])
    store = ClickHouseEntityStore(ch, tenant="t_main")
    result = store.configured_policies_for_firewalls(["panosvm"])
    assert result == [{"firewall": "panosvm",
                       "policy": {"entity_id": "polid", "name": "allow-web",
                                  "attrs": {"action": "allow"}}}]


def test_configured_policies_for_firewalls_empty_input():
    store = ClickHouseEntityStore(_FakeCH([]), tenant="t_main")
    assert store.configured_policies_for_firewalls([]) == []
