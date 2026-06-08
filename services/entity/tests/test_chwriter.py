from ssdf_entity.chwriter import (
    build_flow_agg_sql, build_binding_sql,
    entity_rows, edge_rows, ENTITY_COLUMNS, ENTITY_EDGE_COLUMNS,
)


def test_flow_agg_sql_is_parameterized_and_groups_by_pair():
    sql, params = build_flow_agg_sql(window_hours=24, tenant="t_main")
    assert "{tenant:String}" in sql
    assert "{window_hours:UInt32}" in sql
    assert "GROUP BY src_ip, dst_ip, observer_hostname" in sql
    assert "groupUniqArray(destination_port)" in sql
    assert params == {"tenant": "t_main", "window_hours": 24}


def test_flow_agg_sql_selects_observer_hostname_per_row():
    sql, _ = build_flow_agg_sql(window_hours=24, tenant="t_main")
    assert "toString(observer_hostname) AS observer_hostname" in sql


def test_binding_sql_reads_arp_entries_with_source_device():
    sql, params = build_binding_sql(lookback_hours=168, tenant="t_main")
    assert "ssdf.topo_observations" in sql
    assert "observation_type = 'arp_entry'" in sql
    assert "source_device" in sql
    assert "replaceOne(subj_id, 'ip:', '') AS ip" in sql
    assert "replaceOne(obj_id, 'mac:', '') AS mac" in sql
    assert "{lookback_hours:UInt32}" in sql
    # Must qualify the column: the toString(observed_at) alias otherwise shadows
    # the DateTime column, making the window filter a String/DateTime compare
    # (NO_COMMON_TYPE) that fails the read outright.
    assert "topo_observations.observed_at >= now() - INTERVAL {lookback_hours:UInt32} HOUR" in sql
    assert params == {"tenant": "t_main", "lookback_hours": 168}



def test_entity_rows_follow_column_order():
    entity = {c: c for c in ENTITY_COLUMNS}
    assert entity_rows([entity]) == [[c for c in ENTITY_COLUMNS]]


def test_edge_rows_follow_column_order():
    edge = {c: c for c in ENTITY_EDGE_COLUMNS}
    assert edge_rows([edge]) == [[c for c in ENTITY_EDGE_COLUMNS]]


def test_assets_by_basis_sql_filters_basis():
    from ssdf_entity.chwriter import build_assets_by_basis_sql
    sql, params = build_assets_by_basis_sql("ip_only", tenant="t_main")
    assert "ssdf.entities FINAL" in sql
    assert "identity_basis = {basis:String}" in sql
    assert "kind = 'asset'" in sql
    assert params == {"tenant": "t_main", "basis": "ip_only"}


def test_all_edges_by_type_sql():
    from ssdf_entity.chwriter import build_all_edges_by_type_sql
    sql, params = build_all_edges_by_type_sql("communicated_with", tenant="t_main")
    assert "ssdf.entity_edges FINAL" in sql
    assert "edge_type = {etype:String}" in sql
    assert params == {"tenant": "t_main", "etype": "communicated_with"}
