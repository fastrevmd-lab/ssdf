from ssdf_entity.resolve_main import run_resolver


class _FakeWriter:
    def __init__(self):
        self.entities = None
        self.edges = None

    def query(self, sql, params=None):
        if "topo_observations" in sql:
            return [
                {
                    "source_device": "fw1",
                    "ip": "10.64.0.5",
                    "mac": "aa:aa:aa:aa:aa:aa",
                    "observed_at": "2026-06-07 00:00:00.000",
                }
            ]
        return [
            {
                "src_ip": "10.64.0.5",
                "dst_ip": "8.8.8.8",
                "observer_hostname": "fw1",
                "bytes": 100,
                "flows": 1,
                "ports": [443],
                "rule_name": "r1",
                "provider": "juniper",
                "transport": "tcp",
                "first_seen": "2026-06-07 00:00:00.000",
                "last_seen": "2026-06-07 00:00:00.000",
            }
        ]

    def replace_entities(self, entities):
        self.entities = entities
        return len(entities)

    def replace_edges(self, edges):
        self.edges = edges
        return len(edges)


def test_run_resolver_reads_both_inputs_and_writes():
    writer = _FakeWriter()
    n_entities, n_edges = run_resolver(
        writer, tenant="t_main", window_hours=24, binding_lookback_hours=168
    )
    assert n_entities == 3  # mac-anchored src + ip-only dst + policy r1
    assert n_edges == 2  # communicated_with + governed_by
    src = next(e for e in writer.entities if e["identifiers"].get("mac"))
    assert src["identity_basis"] == "mac"
