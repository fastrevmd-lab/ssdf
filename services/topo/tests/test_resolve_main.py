from ssdf_topo.resolve_main import OBS_SQL, run_resolver


def test_obs_sql_filters_before_aliasing_observed_at():
    """The observed_at time filter must bind to the DateTime column, not the
    String alias. ClickHouse resolves a SELECT alias of the same name in WHERE,
    which made `observed_at >= now() - INTERVAL ...` compare String vs DateTime
    (error 386). Keep the filter inside a subquery so the alias cannot shadow it.
    """
    where_pos = OBS_SQL.index("observed_at >= now()")
    subquery_pos = OBS_SQL.index("FROM (")
    assert subquery_pos < where_pos, "time filter must live inside the subquery"


class FakeWriter:
    def __init__(self, obs_rows, flow_rows):
        self._obs, self._flows = obs_rows, flow_rows
        self.nodes = None
        self.edges = None

    def query(self, sql, params=None):
        return self._flows if "FROM ssdf.events" in sql else self._obs

    def replace_nodes(self, nodes):
        self.nodes = nodes
        return len(nodes)

    def replace_edges(self, edges):
        self.edges = edges
        return len(edges)


def test_run_resolver_reads_resolves_and_upserts():
    obs_rows = [
        {
            "observed_at": "2026-06-07T00:00:00+00:00",
            "collector": "junos",
            "source_device": "sw1",
            "tenant_id": "t_main",
            "layer": "l3",
            "observation_type": "arp_entry",
            "subj_kind": "host",
            "subj_id": "ip:10.64.0.5",
            "obj_kind": "host",
            "obj_id": "mac:aa:bb",
            "attrs": {},
            "raw": "",
        }
    ]
    flow_rows = [
        {
            "src_ip": "10.64.0.5",
            "dst_ip": "10.64.0.9",
            "bytes": 10,
            "flows": 1,
            "rule_name": "allow",
            "ingress_zone": "trust",
            "egress_zone": "untrust",
            "provider": "juniper",
            "first_seen": "2026-06-07T00:00:00+00:00",
            "last_seen": "2026-06-07T00:30:00+00:00",
        }
    ]
    writer = FakeWriter(obs_rows, flow_rows)
    n_nodes, n_edges = run_resolver(writer, tenant="t_main", window_hours=24)
    assert n_nodes >= 1 and n_edges >= 1
    assert any(e["edge_type"] == "has_address" for e in writer.edges)
    assert any(e["edge_type"] == "talked_to" for e in writer.edges)
