from ssdf_mcp_query.graphstore import ClickHouseGraphStore, build_node_match_sql, build_subgraph_sql


class FakeCH:
    def __init__(self):
        self.calls = []

    def run(self, sql, params=None):
        self.calls.append((sql, params or {}))
        if "graph_nodes" in sql and "WHERE" in sql:
            return {
                "columns": [],
                "rows": [
                    {
                        "node_id": "n1",
                        "kind": "host",
                        "name": "h1",
                        "identifiers": {"mac": "aa:bb", "ip": "10.64.0.5"},
                        "first_seen": "x",
                        "last_seen": "y",
                        "attrs": {},
                    }
                ],
                "row_count": 1,
            }
        if "graph_edges" in sql:
            return {
                "columns": [],
                "rows": [
                    {
                        "edge_id": "e1",
                        "src_id": "n1",
                        "dst_id": "n2",
                        "edge_type": "attaches_to",
                        "layer": "l2",
                        "first_seen": "x",
                        "last_seen": "y",
                        "confidence": 1.0,
                        "attrs": {"port": "3"},
                    }
                ],
                "row_count": 1,
            }
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


def test_node_match_sql_lowercases_mac_shaped_value():
    """MACs are stored lowercase; an uppercase MAC-shaped lookup must match."""
    _, params = build_node_match_sql("AA:BB:CC:DD:EE:FF", tenant="t_main")
    assert params["val"] == "aa:bb:cc:dd:ee:ff"


def test_node_match_sql_preserves_non_mac_case():
    """Names/IPs are not MAC-shaped and must pass through verbatim."""
    _, params = build_node_match_sql("Switch-A", tenant="t_main")
    assert params["val"] == "Switch-A"


from ssdf_mcp_query.graphstore import build_nodes_by_id_sql


def test_builders_default_to_ssdf_schema():
    node_sql, _ = build_node_match_sql("10.64.0.5", tenant="t_main")
    edge_sql, _ = build_subgraph_sql(since_iso="2026-06-06T00:00:00+00:00", tenant="t_main")
    ids_sql, _ = build_nodes_by_id_sql(["n1"], tenant="t_main")
    assert "ssdf.graph_nodes FINAL" in node_sql
    assert "ssdf.graph_edges FINAL" in edge_sql
    assert "ssdf.graph_nodes FINAL" in ids_sql


def test_builders_honor_public_schema():
    node_sql, _ = build_node_match_sql("10.64.0.5", tenant="t_main", schema="ssdf_public")
    edge_sql, _ = build_subgraph_sql(
        since_iso="2026-06-06T00:00:00+00:00", tenant="t_main", schema="ssdf_public"
    )
    ids_sql, _ = build_nodes_by_id_sql(["n1"], tenant="t_main", schema="ssdf_public")
    assert "ssdf_public.graph_nodes FINAL" in node_sql
    assert "ssdf_public.graph_edges FINAL" in edge_sql
    assert "ssdf_public.graph_nodes FINAL" in ids_sql
    # base schema must NOT appear when the public schema is requested
    assert "ssdf.graph_nodes" not in node_sql
    assert "ssdf.graph_edges" not in edge_sql


def test_store_threads_schema_into_queries():
    fake = FakeCH()
    store = ClickHouseGraphStore(fake, tenant="t_main", schema="ssdf_public")
    store.find_node("10.64.0.5")
    assert any("ssdf_public.graph_nodes" in sql for sql, _ in fake.calls)


def test_nodes_by_attr_sql_selects_directly_by_role_no_window():
    from ssdf_mcp_query.graphstore import build_nodes_by_attr_sql

    sql, params = build_nodes_by_attr_sql(role="firewall", kind=None, tenant="t_main")
    assert "ssdf.graph_nodes FINAL" in sql  # latest version per node_id
    assert "attrs['role'] = {role:String}" in sql
    assert "last_seen >=" not in sql  # inventory = current-state, unwindowed
    assert params == {"tenant": "t_main", "role": "firewall"}


def test_nodes_by_attr_sql_combines_role_and_kind():
    from ssdf_mcp_query.graphstore import build_nodes_by_attr_sql

    sql, params = build_nodes_by_attr_sql(
        role="firewall", kind="device", tenant="t_main", schema="ssdf_public"
    )
    assert "ssdf_public.graph_nodes FINAL" in sql
    assert "attrs['role'] = {role:String}" in sql
    assert "kind = {kind:String}" in sql
    assert params == {"tenant": "t_main", "role": "firewall", "kind": "device"}


def test_nodes_by_attr_collapses_superseded_rows_for_one_device():
    """graph_nodes keys on node_id, so a device that changes identity leaves its
    previous row behind until TTL — both rows carry the same name and both match.

    The fix is dedupe by identity, NOT a staleness filter: a node lingering stale
    during a collector lull is still part of the inventory, and hiding it would
    defeat ingest_status, whose whole job is to surface a device that stopped
    reporting. Age is the wrong axis; identity is the right one.
    """
    from ssdf_mcp_query.graphstore import ClickHouseGraphStore

    rows = [
        {
            "node_id": "old",
            "kind": "device",
            "name": "Gateway Max",
            "identifiers": {"mac": "02:00:01:27:fb:2b"},
            "attrs": {"role": "gateway"},
            "first_seen": "2026-08-01T00:00:00Z",
            "last_seen": "2026-08-20T14:11:25Z",
        },
        {
            "node_id": "new",
            "kind": "device",
            "name": "Gateway Max",
            "identifiers": {"mac": "02:00:01:27:fb:2b"},
            "attrs": {"role": "gateway"},
            "first_seen": "2026-08-01T00:00:00Z",
            "last_seen": "2026-08-20T14:16:43Z",
        },
        {
            "node_id": "other",
            "kind": "device",
            "name": "vsrx-prod",
            "identifiers": {},
            "attrs": {"role": "firewall"},
            "first_seen": "2026-08-01T00:00:00Z",
            "last_seen": "2026-08-20T14:16:43Z",
        },
    ]

    class _CH:
        def run(self, sql, params=None):
            return {"rows": rows}

    out = ClickHouseGraphStore(_CH()).nodes_by_attr(kind="device")

    assert len(out) == 2, [n["name"] for n in out]
    gateway = next(n for n in out if n["name"] == "Gateway Max")
    assert gateway["node_id"] == "new", "the freshest row must win"


def test_nodes_by_attr_keeps_distinct_devices_that_share_no_name():
    from ssdf_mcp_query.graphstore import ClickHouseGraphStore

    rows = [
        {
            "node_id": "a",
            "kind": "device",
            "name": "vsrx-prod",
            "identifiers": {},
            "attrs": {"role": "firewall"},
            "first_seen": "x",
            "last_seen": "2026-08-20T10:00:00Z",
        },
        {
            "node_id": "b",
            "kind": "device",
            "name": "vsrx-ci",
            "identifiers": {},
            "attrs": {"role": "firewall"},
            "first_seen": "x",
            "last_seen": "2026-08-20T10:00:00Z",
        },
    ]

    class _CH:
        def run(self, sql, params=None):
            return {"rows": rows}

    assert len(ClickHouseGraphStore(_CH()).nodes_by_attr(kind="device")) == 2
