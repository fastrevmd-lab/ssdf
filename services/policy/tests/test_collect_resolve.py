from ssdf_policy.collect_resolve import run_once


class _FakeCollector:
    def __init__(self, rules):
        self._rules = rules

    def collect(self, client, now):
        return self._rules


class _FakeWriter:
    def __init__(self):
        self.entities = None
        self.edges = None

    def replace_entities(self, entities):
        self.entities = entities
        return len(entities)

    def replace_edges(self, edges):
        self.edges = edges
        return len(edges)


def _rule(device, name):
    return {
        "provider": "paloalto",
        "device_name": device,
        "rule_name": name,
        "action": "allow",
        "from_zone": ["trust"],
        "to_zone": ["untrust"],
        "source_addresses": ["any"],
        "dest_addresses": ["any"],
        "application": ["any"],
        "service": ["any"],
        "position": 0,
        "enabled": True,
        "vendor_extras": {},
        "collected_at": "2026-06-08T00:00:00",
    }


def test_run_once_collects_resolves_writes():
    writer = _FakeWriter()
    n_ent, n_edge = run_once(
        enabled=["panos"],
        collector_factory=lambda name: _FakeCollector([_rule("panosvm", "allow-web")]),
        client_factory=lambda name: object(),
        writer=writer,
        tenant="t_main",
        now="2026-06-08T00:00:00",
    )
    assert n_ent == 2 and n_edge == 1  # firewall + policy, 1 governed_by
    assert {e["kind"] for e in writer.entities} == {"firewall", "policy"}


def test_run_once_skips_failing_collector():
    class _Boom:
        def collect(self, client, now):
            raise RuntimeError("mcp down")

    writer = _FakeWriter()
    n_ent, _ = run_once(
        enabled=["panos", "junos"],
        collector_factory=lambda name: (
            _Boom() if name == "panos" else _FakeCollector([_rule("vSRX-test10", "P1")])
        ),
        client_factory=lambda name: object(),
        writer=writer,
        tenant="t_main",
        now="2026-06-08T00:00:00",
    )
    assert n_ent == 2  # only junos's firewall+policy survived
