from ssdf_topo.resolver.flows import build_flow_agg_sql, flow_to_edges

def test_flow_agg_sql_groups_and_windows():
    sql, params = build_flow_agg_sql(window_hours=24, tenant="t_main")
    assert "FROM ssdf.events" in sql
    assert "GROUP BY" in sql
    assert "source_ip" in sql and "destination_ip" in sql
    assert "sum(network_bytes)" in sql
    assert params["tenant"] == "t_main"
    assert "{window_hours:UInt32}" in sql or "INTERVAL" in sql

def test_flow_to_edges_emits_talked_to_and_governed_by():
    agg = [{
        "src_ip": "10.64.0.5", "dst_ip": "10.64.0.9", "bytes": 4096, "flows": 3,
        "rule_name": "allow-web", "ingress_zone": "trust", "egress_zone": "untrust",
        "provider": "juniper", "first_seen": "2026-06-07T00:00:00+00:00",
        "last_seen": "2026-06-07T01:00:00+00:00",
    }]
    edges = flow_to_edges(agg, tenant="t_main")
    types = {e["edge_type"] for e in edges}
    assert "talked_to" in types and "governed_by" in types and "in_zone" in types
    talked = next(e for e in edges if e["edge_type"] == "talked_to")
    assert talked["attrs"]["bytes"] == "4096" and talked["layer"] == "flow"
