from ssdf_mcp_query.access_tools import AccessTools


class _FakeStore:
    def __init__(self, entities, comm, policies):
        self._entities = entities
        self._comm = comm
        self._policies = policies

    def find_entity(self, identifier):
        return self._entities.get(identifier)

    def communicated_edges(self, a_id, b_id, since_iso):
        return self._comm

    def governed_policies(self, comm_edge_ids):
        return self._policies


class _FakeTopo:
    def __init__(self, firewalls, path):
        self._firewalls = firewalls
        self._path = path

    def enforcement_points(self, src, dst):
        return {"firewalls": self._firewalls, "rules": [], "zones": []}

    def find_path(self, src, dst, layer="any"):
        return self._path


def _client_server():
    # keyed by the identifier strings explain_access() looks up
    return {"10.64.0.5": {"entity_id": "C", "name": "10.64.0.5", "identity_basis": "ip_only"},
            "8.8.8.8": {"entity_id": "S", "name": "8.8.8.8", "identity_basis": "ip_only"}}


def test_not_found_when_endpoint_unresolved():
    store = _FakeStore({}, [], [])
    topo = _FakeTopo([], {"found": False})
    out = AccessTools(store, topo).explain_access("nope", "8.8.8.8")
    assert out["error"] == "not_found"


def test_observed_flow_with_controls_and_coverage():
    ents = _client_server()
    comm = [{"edge_id": "E1", "attrs": {"sessions": "42", "bytes": "1000",
                                        "ports": "443", "providers": "juniper",
                                        "transports": "tcp"}}]
    policies = [{"policy": {"name": "trust-to-untrust",
                            "identifiers": {"provider": "juniper", "rule": "trust-to-untrust"},
                            "source": "observed"},
                 "edge_attrs": {"rule": "trust-to-untrust", "provider": "juniper"}}]
    store = _FakeStore(ents, comm, policies)
    topo = _FakeTopo(["vSRX-test10"], {"found": True, "hops": 3, "path_nodes": ["C", "X", "S"]})
    out = AccessTools(store, topo).explain_access("10.64.0.5", "8.8.8.8")
    assert out["observed_flows"]["sessions"] == 42
    assert out["observed_flows"]["providers"] == ["juniper"]
    assert out["controls"][0]["rule"] == "trust-to-untrust"
    assert out["controls"][0]["source"] == "observed"
    assert out["controls"][0]["firewall"] == "vSRX-test10"
    assert out["controls"][0]["firewall_basis"] == "topology"
    assert out["coverage"] == {"observed": True, "configured": "pending_m6b"}
    assert out["topology_path"]["found"] is True


def test_observed_flow_without_resolved_rule_is_a_finding():
    ents = _client_server()
    comm = [{"edge_id": "E1", "attrs": {"sessions": "5", "bytes": "10",
                                        "ports": "", "providers": "paloalto", "transports": "tcp"}}]
    store = _FakeStore(ents, comm, [])    # no governed_by policies
    topo = _FakeTopo([], {"found": False})
    out = AccessTools(store, topo).explain_access("10.64.0.5", "8.8.8.8")
    assert out["controls"] == []
    assert out["observed_flows"]["sessions"] == 5
    assert out["coverage"]["observed"] is True


def test_firewall_omitted_when_topology_ambiguous():
    ents = _client_server()
    comm = [{"edge_id": "E1", "attrs": {"sessions": "1", "bytes": "1",
                                        "ports": "443", "providers": "juniper", "transports": "tcp"}}]
    policies = [{"policy": {"name": "r", "identifiers": {"provider": "juniper", "rule": "r"},
                            "source": "observed"},
                 "edge_attrs": {"rule": "r", "provider": "juniper"}}]
    store = _FakeStore(ents, comm, policies)
    topo = _FakeTopo(["fw1", "fw2"], {"found": True, "hops": 4})   # two firewalls -> ambiguous
    out = AccessTools(store, topo).explain_access("10.64.0.5", "8.8.8.8")
    assert out["controls"][0]["firewall"] is None
    assert out["firewalls"] == ["fw1", "fw2"]
