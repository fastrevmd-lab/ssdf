# services/mcp-query/tests/test_fabric_tools.py
from ssdf_mcp_query.fabric_manifest import Subject
from ssdf_mcp_query.fabric_tools import FabricTools

FRESH = Subject(
    name="juniper",
    kind="source",
    table="ssdf.events",
    ts_column="timestamp",
    filter_column="event_provider",
    filter_value="juniper",
    budget_hours=1.0,
    note="n",
)
SLOW = Subject(
    name="ssdf-policy",
    kind="resolver",
    table="ssdf.entities",
    ts_column="last_seen",
    filter_column="source",
    filter_value="configured",
    budget_hours=2.0,
    note="n",
)


class _FakeCH:
    """Returns a canned row per table, or raises if the value is an Exception."""

    def __init__(self, by_table):
        self._by_table = by_table
        self.calls = []

    def run(self, sql, params=None):
        table = next(t for t in self._by_table if f"FROM {t}" in sql)
        self.calls.append((table, params))
        row = self._by_table[table]
        if isinstance(row, Exception):
            raise row
        return {"rows": [row]}


def test_fresh_subject_is_not_stale():
    ch = _FakeCH({"ssdf.events": {"n": 5, "last_seen": "2026-08-19T12:00:00Z", "hours_since": 0.5}})
    result = FabricTools(ch, manifest=(FRESH,)).fabric_status()

    assert result["healthy"] is True
    subject = result["subjects"][0]
    assert subject["name"] == "juniper"
    assert subject["stale"] is False
    assert subject["hours_since"] == 0.5
    assert subject["budget_hours"] == 1.0
    assert subject["signal"] == "ssdf.events(event_provider=juniper)"


def test_subject_past_its_budget_is_stale_and_makes_the_fabric_unhealthy():
    ch = _FakeCH(
        {"ssdf.entities": {"n": 22, "last_seen": "2026-08-15T18:00:00Z", "hours_since": 97.3}}
    )
    result = FabricTools(ch, manifest=(SLOW,)).fabric_status()

    assert result["subjects"][0]["stale"] is True
    assert result["healthy"] is False
    assert result["summary"] == {"total": 1, "stale": 1, "fresh": 0, "errored": 0}


def test_exactly_at_budget_is_not_stale():
    """Boundary: stale means strictly past budget, so a 0.25h timer checked at
    exactly 0.25h does not flap."""
    ch = _FakeCH({"ssdf.events": {"n": 1, "last_seen": "x", "hours_since": 1.0}})
    result = FabricTools(ch, manifest=(FRESH,)).fabric_status()
    assert result["subjects"][0]["stale"] is False


def test_never_observed_is_stale_not_absent():
    """UniFi went unnoticed for 30 days because nothing was there to age.
    Absence must be loud."""
    ch = _FakeCH({"ssdf.events": {"n": 0, "last_seen": None, "hours_since": None}})
    result = FabricTools(ch, manifest=(FRESH,)).fabric_status()

    subject = result["subjects"][0]
    assert subject["stale"] is True
    assert subject["last_seen"] is None
    assert subject["hours_since"] is None
    assert result["healthy"] is False


def test_a_failing_subject_is_surfaced_not_swallowed():
    """run_collectors catching errors and continuing SILENTLY is what hid every
    bug on 2026-08-19. The tool built to detect that must not repeat it."""
    ch = _FakeCH(
        {
            "ssdf.events": {"n": 5, "last_seen": "2026-08-19T12:00:00Z", "hours_since": 0.5},
            "ssdf.entities": RuntimeError("table does not exist"),
        }
    )
    result = FabricTools(ch, manifest=(FRESH, SLOW)).fabric_status()

    by_name = {s["name"]: s for s in result["subjects"]}
    assert "table does not exist" in by_name["ssdf-policy"]["error"]
    # the healthy subject still reported
    assert by_name["juniper"]["stale"] is False
    assert result["healthy"] is False
    assert result["summary"]["errored"] == 1


def test_subjects_sort_stale_first():
    ch = _FakeCH(
        {
            "ssdf.events": {"n": 5, "last_seen": "x", "hours_since": 0.1},
            "ssdf.entities": {"n": 1, "last_seen": "y", "hours_since": 99.0},
        }
    )
    result = FabricTools(ch, manifest=(FRESH, SLOW)).fabric_status()
    assert [s["name"] for s in result["subjects"]] == ["ssdf-policy", "juniper"]


def test_devices_rollup_delegates_to_ingest_status():
    class _FakeLiveness:
        def ingest_status(self):
            return {"firewalls": [{}, {}, {}], "summary": {"total": 3, "stale": 1, "fresh": 2}}

    ch = _FakeCH({"ssdf.events": {"n": 5, "last_seen": "x", "hours_since": 0.1}})
    result = FabricTools(ch, liveness=_FakeLiveness(), manifest=(FRESH,)).fabric_status()

    assert result["devices"] == {"total": 3, "stale": 1, "fresh": 2}


def test_devices_is_null_when_no_liveness_store_is_wired():
    ch = _FakeCH({"ssdf.events": {"n": 5, "last_seen": "x", "hours_since": 0.1}})
    result = FabricTools(ch, manifest=(FRESH,)).fabric_status()
    assert result["devices"] is None


def test_device_rollup_failure_does_not_lose_subject_results():
    class _BrokenLiveness:
        def ingest_status(self):
            raise RuntimeError("graph unavailable")

    ch = _FakeCH({"ssdf.events": {"n": 5, "last_seen": "x", "hours_since": 0.1}})
    result = FabricTools(ch, liveness=_BrokenLiveness(), manifest=(FRESH,)).fabric_status()

    assert result["subjects"][0]["name"] == "juniper"
    assert "graph unavailable" in result["devices_error"]
    assert result["healthy"] is False
