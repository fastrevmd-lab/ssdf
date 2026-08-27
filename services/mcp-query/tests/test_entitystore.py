from ssdf_mcp_query.entitystore import (
    build_entity_match_sql,
    build_comm_edges_sql,
    build_governed_by_sql,
    ClickHouseEntityStore,
    build_entities_match_sql,
    build_comm_edges_multi_sql,
)
from ssdf_mcp_query.entitystore import (
    build_alerts_for_pair_sql,
    build_firewall_match_sql,
    build_configured_governed_sql,
)


def test_build_alerts_for_pair_sql_filters_provider_kind_ips_and_window():
    sql, params = build_alerts_for_pair_sql(
        ["198.51.100.50", "198.51.100.20"], "2026-06-13T00:00:00.000", "t_main"
    )
    assert "event_provider = 'unifi'" in sql
    assert "event_kind = 'alert'" in sql
    assert "events.timestamp >= parseDateTimeBestEffort({since:String})" in sql
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
    ch = _FakeCH(
        [
            [{"entity_id": "fwid", "identifiers": {"device_name": "panosvm"}, "name": "panosvm"}],
            [{"edge_id": "g1", "src_id": "fwid", "dst_id": "polid", "attrs": {}}],
            [{"entity_id": "polid", "name": "allow-web", "attrs": {"action": "allow"}}],
        ]
    )
    store = ClickHouseEntityStore(ch, tenant="t_main")
    result = store.configured_policies_for_firewalls(["panosvm"])
    assert result == [
        {
            "firewall": "panosvm",
            "policy": {"entity_id": "polid", "name": "allow-web", "attrs": {"action": "allow"}},
        }
    ]


def test_configured_policies_for_firewalls_empty_input():
    store = ClickHouseEntityStore(_FakeCH([]), tenant="t_main")
    assert store.configured_policies_for_firewalls([]) == []


def test_build_entities_match_sql_omits_limit_keeps_order():
    # Same match as build_entity_match_sql but returns ALL twins (no LIMIT 1),
    # keeping confidence-first order so row 0 == what find_entity returns today.
    sql, params = build_entities_match_sql("198.51.100.150", tenant="t_main")
    assert "ssdf.entities FINAL" in sql
    assert "LIMIT 1" not in sql
    assert "ORDER BY confidence DESC, entities.last_seen DESC" in sql
    assert "has(mapValues(identifiers), {val:String})" in sql
    assert params["val"] == "198.51.100.150"
    assert params["tenant"] == "t_main"


def test_build_entities_match_sql_lowercases_mac():
    _, params = build_entities_match_sql("AA:BB:CC:DD:EE:FF", tenant="t_main")
    assert params["val"] == "aa:bb:cc:dd:ee:ff"


def test_build_comm_edges_multi_sql_in_lists_both_directions():
    sql, params = build_comm_edges_multi_sql(
        ["A1", "A2"], ["B1"], "2026-06-15T00:00:00.000", tenant="t_main"
    )
    assert "edge_type = 'communicated_with'" in sql
    # qualified column so the toString(last_seen) alias doesn't lexically drop rows
    assert "entity_edges.last_seen >= {since:String}" in sql
    assert "src_id IN {a:Array(String)} AND dst_id IN {b:Array(String)}" in sql
    assert "src_id IN {b:Array(String)} AND dst_id IN {a:Array(String)}" in sql
    assert params["a"] == ["A1", "A2"]
    assert params["b"] == ["B1"]
    assert params["since"] == "2026-06-15T00:00:00.000"
    assert params["tenant"] == "t_main"


def test_store_find_entities_returns_all_rows():
    ch = _FakeCH([[{"entity_id": "x"}, {"entity_id": "y"}]])
    store = ClickHouseEntityStore(ch, tenant="t_main")
    assert store.find_entities("8.8.8.8") == [{"entity_id": "x"}, {"entity_id": "y"}]


def test_store_find_entities_empty_when_none():
    store = ClickHouseEntityStore(_FakeCH([[]]), tenant="t_main")
    assert store.find_entities("nope") == []


def test_store_communicated_edges_multi_skips_query_when_either_list_empty():
    ch = _FakeCH([])  # no batches queued: any run() call would IndexError
    store = ClickHouseEntityStore(ch, tenant="t_main")
    assert store.communicated_edges_multi([], ["B"], "2026-06-15T00:00:00.000") == []
    assert store.communicated_edges_multi(["A"], [], "2026-06-15T00:00:00.000") == []
    assert ch.calls == []


def test_store_communicated_edges_multi_runs_query():
    ch = _FakeCH([[{"edge_id": "E1"}]])
    store = ClickHouseEntityStore(ch, tenant="t_main")
    assert store.communicated_edges_multi(["A"], ["B"], "2026-06-15T00:00:00.000") == [
        {"edge_id": "E1"}
    ]
    assert len(ch.calls) == 1


def test_build_observers_for_ips_sql():
    from ssdf_mcp_query.entitystore import build_observers_for_ips_sql

    sql, params = build_observers_for_ips_sql(
        ["10.74.11.20", "198.51.100.1"], "2026-06-18T00:00:00.000+00:00", "t_main"
    )
    assert "observer_hostname" in sql
    assert "ssdf.events" in sql
    assert "observer_hostname != ''" in sql
    assert "toString(source_ip) IN {ips:Array(String)}" in sql
    assert "toString(destination_ip) IN {ips:Array(String)}" in sql
    # events.timestamp is DateTime64(3,'UTC') and rejects a raw ISO +00:00 String
    # cast, so the window bound must be parsed explicitly (live-found 2026-06-19).
    assert "timestamp >= parseDateTimeBestEffort({since:String})" in sql
    assert params == {
        "tenant": "t_main",
        "ips": ["10.74.11.20", "198.51.100.1"],
        "since": "2026-06-18T00:00:00.000+00:00",
    }


def test_observers_for_ips_method_runs_builder_and_returns_rows():
    from ssdf_mcp_query.entitystore import ClickHouseEntityStore

    class _FakeCH:
        def __init__(self):
            self.calls = []

        def run(self, sql, params):
            self.calls.append((sql, params))
            return {"rows": [{"observer_hostname": "panosvm.example.com"}]}

    ch = _FakeCH()
    store = ClickHouseEntityStore(ch, tenant="t_main")
    rows = store.observers_for_ips(["10.74.11.20"], "2026-06-18T00:00:00.000+00:00")
    assert rows == [{"observer_hostname": "panosvm.example.com"}]
    assert ch.calls and ch.calls[0][1]["ips"] == ["10.74.11.20"]


def test_observers_for_ips_empty_ips_short_circuits():
    from ssdf_mcp_query.entitystore import ClickHouseEntityStore

    class _BoomCH:
        def run(self, sql, params):
            raise AssertionError("must not query CH with no IPs")

    store = ClickHouseEntityStore(_BoomCH(), tenant="t_main")
    assert store.observers_for_ips([], "2026-06-18T00:00:00.000+00:00") == []


# --- Regression: detections dropped on a same-day window ---------------------
#
# `build_alerts_for_pair_sql` aliases `toString(timestamp) AS timestamp`, so an
# unqualified `timestamp` in WHERE/ORDER BY bound to that String alias and the
# window became a lexical compare against the caller's isoformat bound. Same
# defect class as build_subgraph_sql (see tests/test_graphstore.py), reached
# through explain_access's `detections` field.


def test_alerts_for_pair_window_is_parsed_not_string_compared():
    sql, _ = build_alerts_for_pair_sql(["198.51.100.50"], "2026-08-26T12:00:00.000+00:00", "t_main")
    assert "events.timestamp >= parseDateTimeBestEffort({since:String})" in sql
    # The bare form binds to the `toString(timestamp) AS timestamp` alias.
    assert "AND timestamp >=" not in sql


def test_alerts_for_pair_ordering_uses_the_datetime_column_not_the_alias():
    sql, _ = build_alerts_for_pair_sql(["198.51.100.50"], "2026-08-26T12:00:00.000+00:00", "t_main")
    assert "ORDER BY events.timestamp DESC" in sql
