import datetime as _dt
import pytest

from ssdf_mcp_query.liveness_tools import (
    LivenessTools,
    _short_host,
    build_recent_observer_hostnames_sql,
)


class _FakeGraphStore:
    def __init__(self, nodes):
        self._nodes = nodes

    def nodes_by_attr(self, role=None, kind=None, limit=5000):
        result = self._nodes
        if role:
            result = [n for n in result if n.get("attrs", {}).get("role") == role]
        if kind:
            result = [n for n in result if n.get("kind") == kind]
        return result


class _FakeCHClient:
    def __init__(self, rows):
        self._rows = rows

    def run(self, sql, params):
        return {"rows": self._rows}


class _FakeEntityStore:
    def __init__(self, ch_client):
        self._ch = ch_client


def test_short_host_strips_fqdn_suffix():
    assert _short_host("panosvm.example.com") == "panosvm"
    assert _short_host("vSRX-test10") == "vSRX-test10"


def test_short_host_preserves_case():
    assert _short_host("vSRX-Production.lab") == "vSRX-Production"


def test_short_host_preserves_ipv4():
    assert _short_host("198.51.100.1") == "198.51.100.1"


def test_short_host_preserves_ipv6():
    assert _short_host("2001:db8::1") == "2001:db8::1"


def test_recent_observer_hostnames_sql_shape():
    sql, params = build_recent_observer_hostnames_sql("2026-07-05T00:00:00+00:00", "t_main")
    assert "observer_hostname" in sql
    assert "event_provider AS provider" in sql
    assert "max(timestamp) AS max_timestamp" in sql
    assert "dateDiff('second', max(timestamp), now()) / 3600.0 AS hours_since" in sql
    assert "observer_hostname != ''" in sql
    assert "parseDateTimeBestEffort({since:String})" in sql
    assert "GROUP BY observer_hostname, provider" in sql
    assert params == {"tenant": "t_main", "since": "2026-07-05T00:00:00+00:00"}


def test_ingest_status_fresh_firewall():
    # Use tz-aware datetime to match real clickhouse-connect behavior
    now = _dt.datetime.now(_dt.timezone.utc)
    recent = (now - _dt.timedelta(minutes=30)).isoformat()
    hours_since = 0.5

    topo_nodes = [
        {
            "name": "panosvm",
            "kind": "device",
            "attrs": {"role": "firewall"},
            "identifiers": {"provider": "paloalto"},
        }
    ]
    event_rows = [
        {
            "observer_hostname": "panosvm.example.com",
            "provider": "paloalto",
            "max_timestamp": recent,
            "hours_since": hours_since,
        }
    ]

    graph = _FakeGraphStore(topo_nodes)
    entity = _FakeEntityStore(_FakeCHClient(event_rows))
    tools = LivenessTools(graph, entity, default_staleness_hours=2)

    result = tools.ingest_status()

    assert len(result["firewalls"]) == 1
    fw = result["firewalls"][0]
    assert fw["name"] == "panosvm"
    assert fw["provider"] == "paloalto"
    assert fw["stale"] is False
    assert fw["last_event"] == recent
    assert fw["hours_since"] == hours_since
    assert result["summary"] == {"total": 1, "stale": 0, "fresh": 1}


def test_ingest_status_stale_firewall():
    now = _dt.datetime.now(_dt.timezone.utc)
    stale_ts = (now - _dt.timedelta(hours=5)).isoformat()
    hours_since = 5.0

    topo_nodes = [
        {
            "name": "vSRX-test10",
            "kind": "device",
            "attrs": {"role": "firewall"},
            "identifiers": {"provider": "juniper"},
        }
    ]
    event_rows = [
        {
            "observer_hostname": "vSRX-test10",
            "provider": "juniper",
            "max_timestamp": stale_ts,
            "hours_since": hours_since,
        }
    ]

    graph = _FakeGraphStore(topo_nodes)
    entity = _FakeEntityStore(_FakeCHClient(event_rows))
    tools = LivenessTools(graph, entity, default_staleness_hours=2)

    result = tools.ingest_status()

    assert len(result["firewalls"]) == 1
    fw = result["firewalls"][0]
    assert fw["name"] == "vSRX-test10"
    assert fw["stale"] is True
    assert fw["hours_since"] == hours_since
    assert result["summary"] == {"total": 1, "stale": 1, "fresh": 0}


def test_ingest_status_missing_entirely():
    # A topology firewall with NO events in the 7d window
    topo_nodes = [
        {"name": "vSRX-silent", "kind": "device", "attrs": {"role": "firewall"}, "identifiers": {}}
    ]
    event_rows = []  # no events for this device

    graph = _FakeGraphStore(topo_nodes)
    entity = _FakeEntityStore(_FakeCHClient(event_rows))
    tools = LivenessTools(graph, entity, default_staleness_hours=2)

    result = tools.ingest_status()

    assert len(result["firewalls"]) == 1
    fw = result["firewalls"][0]
    assert fw["name"] == "vSRX-silent"
    assert fw["last_event"] is None
    assert fw["hours_since"] is None
    assert fw["stale"] is True
    assert result["summary"] == {"total": 1, "stale": 1, "fresh": 0}


def test_ingest_status_panosvm_fqdn_short_label_join():
    now = _dt.datetime.now(_dt.timezone.utc)
    recent = (now - _dt.timedelta(minutes=10)).isoformat()

    topo_nodes = [
        {
            "name": "panosvm",
            "kind": "device",
            "attrs": {"role": "firewall"},
            "identifiers": {"provider": "paloalto"},
        }
    ]
    event_rows = [
        {
            "observer_hostname": "panosvm.example.com",
            "provider": "paloalto",
            "max_timestamp": recent,
            "hours_since": 0.17,
        }
    ]

    graph = _FakeGraphStore(topo_nodes)
    entity = _FakeEntityStore(_FakeCHClient(event_rows))
    tools = LivenessTools(graph, entity)

    result = tools.ingest_status()

    # The FQDN event should join to the short-name topology node
    assert len(result["firewalls"]) == 1
    fw = result["firewalls"][0]
    assert fw["name"] == "panosvm"
    assert fw["stale"] is False


def test_ingest_status_summary_counts():
    now = _dt.datetime.now(_dt.timezone.utc)
    fresh_ts = (now - _dt.timedelta(minutes=10)).isoformat()
    stale_ts = (now - _dt.timedelta(hours=4)).isoformat()

    topo_nodes = [
        {"name": "fw1", "kind": "device", "attrs": {"role": "firewall"}, "identifiers": {}},
        {"name": "fw2", "kind": "device", "attrs": {"role": "firewall"}, "identifiers": {}},
        {"name": "fw3", "kind": "device", "attrs": {"role": "firewall"}, "identifiers": {}},
    ]
    event_rows = [
        {
            "observer_hostname": "fw1",
            "provider": "juniper",
            "max_timestamp": fresh_ts,
            "hours_since": 0.17,
        },
        {
            "observer_hostname": "fw2",
            "provider": "paloalto",
            "max_timestamp": stale_ts,
            "hours_since": 4.0,
        },
    ]
    # fw3 has no events

    graph = _FakeGraphStore(topo_nodes)
    entity = _FakeEntityStore(_FakeCHClient(event_rows))
    tools = LivenessTools(graph, entity, default_staleness_hours=2)

    result = tools.ingest_status()

    assert result["summary"] == {"total": 3, "stale": 2, "fresh": 1}


def test_ingest_status_sorts_stale_first_then_name():
    now = _dt.datetime.now(_dt.timezone.utc)
    fresh_ts = (now - _dt.timedelta(minutes=10)).isoformat()
    stale_ts = (now - _dt.timedelta(hours=3)).isoformat()

    topo_nodes = [
        {"name": "alpha", "kind": "device", "attrs": {"role": "firewall"}, "identifiers": {}},
        {"name": "bravo", "kind": "device", "attrs": {"role": "firewall"}, "identifiers": {}},
        {"name": "charlie", "kind": "device", "attrs": {"role": "firewall"}, "identifiers": {}},
    ]
    event_rows = [
        {
            "observer_hostname": "alpha",
            "provider": "juniper",
            "max_timestamp": fresh_ts,
            "hours_since": 0.17,
        },
        {
            "observer_hostname": "bravo",
            "provider": "juniper",
            "max_timestamp": stale_ts,
            "hours_since": 3.0,
        },
        {
            "observer_hostname": "charlie",
            "provider": "paloalto",
            "max_timestamp": fresh_ts,
            "hours_since": 0.17,
        },
    ]

    graph = _FakeGraphStore(topo_nodes)
    entity = _FakeEntityStore(_FakeCHClient(event_rows))
    tools = LivenessTools(graph, entity, default_staleness_hours=2)

    result = tools.ingest_status()

    # stale devices first (bravo), then fresh sorted by name (alpha, charlie)
    names = [fw["name"] for fw in result["firewalls"]]
    assert names == ["bravo", "alpha", "charlie"]


def test_ingest_status_event_only_device():
    # A device that appears in events but NOT in topology
    now = _dt.datetime.now(_dt.timezone.utc)
    recent = (now - _dt.timedelta(minutes=20)).isoformat()

    topo_nodes = []  # no topology nodes
    event_rows = [
        {
            "observer_hostname": "rogue-fw",
            "provider": "juniper",
            "max_timestamp": recent,
            "hours_since": 0.33,
        }
    ]

    graph = _FakeGraphStore(topo_nodes)
    entity = _FakeEntityStore(_FakeCHClient(event_rows))
    tools = LivenessTools(graph, entity)

    result = tools.ingest_status()

    assert len(result["firewalls"]) == 1
    fw = result["firewalls"][0]
    assert fw["name"] == "rogue-fw"
    assert fw["stale"] is False
    assert result["summary"] == {"total": 1, "stale": 0, "fresh": 1}
