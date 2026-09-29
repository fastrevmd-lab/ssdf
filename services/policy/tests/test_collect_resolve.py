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


def test_run_once_calls_version_writer_with_policy_entities_only():
    class _VersionWriter:
        def __init__(self):
            self.seen = None

        def append_policy_versions(self, policies):
            self.seen = policies
            return len(policies)

    version_writer = _VersionWriter()
    run_once(
        enabled=["panos"],
        collector_factory=lambda name: _FakeCollector([_rule("panosvm", "allow-web")]),
        client_factory=lambda name: object(),
        writer=_FakeWriter(),
        tenant="t_main",
        now="2026-06-08T00:00:00",
        version_writer=version_writer,
    )
    assert version_writer.seen is not None
    assert {e["kind"] for e in version_writer.seen} == {"policy"}  # firewall excluded


def test_run_once_without_version_writer_is_unaffected():
    # Backward-compatible default: existing callers that never pass version_writer.
    n_ent, n_edge = run_once(
        enabled=["panos"],
        collector_factory=lambda name: _FakeCollector([_rule("panosvm", "allow-web")]),
        client_factory=lambda name: object(),
        writer=_FakeWriter(),
        tenant="t_main",
        now="2026-06-08T00:00:00",
    )
    assert n_ent == 2 and n_edge == 1


def test_run_once_survives_version_writer_failure():
    class _BoomVersionWriter:
        def append_policy_versions(self, policies):
            raise RuntimeError("clickhouse down")

    n_ent, n_edge = run_once(
        enabled=["panos"],
        collector_factory=lambda name: _FakeCollector([_rule("panosvm", "allow-web")]),
        client_factory=lambda name: object(),
        writer=_FakeWriter(),
        tenant="t_main",
        now="2026-06-08T00:00:00",
        version_writer=_BoomVersionWriter(),
    )
    assert n_ent == 2 and n_edge == 1  # primary write path unaffected
