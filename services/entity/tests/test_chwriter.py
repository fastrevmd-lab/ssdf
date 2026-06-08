from ssdf_entity.chwriter import (
    build_flow_agg_sql, build_topo_hosts_sql, entity_rows, edge_rows,
    ENTITY_COLUMNS, ENTITY_EDGE_COLUMNS,
)


def test_flow_agg_sql_is_parameterized_and_groups_by_pair():
    sql, params = build_flow_agg_sql(window_hours=24, tenant="t_main")
    assert "{tenant:String}" in sql
    assert "{window_hours:UInt32}" in sql
    assert "GROUP BY src_ip, dst_ip" in sql
    assert "groupUniqArray(destination_port)" in sql
    assert params == {"tenant": "t_main", "window_hours": 24}


def test_flow_agg_sql_selects_observer_hosts():
    sql, _ = build_flow_agg_sql(window_hours=24, tenant="t_main")
    assert "groupUniqArray(observer_hostname) AS observer_hosts" in sql


def test_topo_hosts_sql_filters_to_host_kind():
    sql, params = build_topo_hosts_sql(tenant="t_main")
    assert "ssdf.graph_nodes FINAL" in sql
    assert "kind = 'host'" in sql
    assert params == {"tenant": "t_main"}


def test_entity_rows_follow_column_order():
    entity = {c: c for c in ENTITY_COLUMNS}
    assert entity_rows([entity]) == [[c for c in ENTITY_COLUMNS]]


def test_edge_rows_follow_column_order():
    edge = {c: c for c in ENTITY_EDGE_COLUMNS}
    assert edge_rows([edge]) == [[c for c in ENTITY_EDGE_COLUMNS]]
