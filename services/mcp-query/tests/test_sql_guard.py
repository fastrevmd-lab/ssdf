import pytest
from ssdf_mcp_query.sql_guard import guard_sql, GuardError

ALLOWED = [
    "SELECT * FROM ssdf.events LIMIT 10",
    "SELECT event_action, count() FROM ssdf.events GROUP BY event_action",
    "SELECT * FROM ssdf.events WHERE event_outcome = 'failure' ORDER BY timestamp DESC",
    "SELECT s.source_ip FROM ssdf.events AS s WHERE s.destination_port = 443",
]

DENIED = [
    "INSERT INTO ssdf.events VALUES (1)",
    "ALTER TABLE ssdf.events DELETE WHERE 1=1",
    "DROP TABLE ssdf.events",
    "SELECT * FROM ssdf.events; DELETE FROM ssdf.events",
    "SELECT * FROM system.tables",
    "SELECT * FROM url('http://evil/x', CSV, 'a String')",
    "SELECT * FROM ssdf.events SETTINGS readonly=0",
    "SELECT * FROM events",
    "SELECT * FROM other.secrets",
    "TRUNCATE TABLE ssdf.events",
]

@pytest.mark.parametrize("query", ALLOWED)
def test_allowed_queries_pass(query):
    out = guard_sql(query, max_limit=1000)
    assert "ssdf" in out.lower()
    assert "limit" in out.lower()

@pytest.mark.parametrize("query", DENIED)
def test_denied_queries_rejected(query):
    with pytest.raises(GuardError):
        guard_sql(query, max_limit=1000)

def test_missing_limit_is_injected():
    out = guard_sql("SELECT * FROM ssdf.events", max_limit=500)
    assert out.lower().rstrip().endswith("limit 500")

def test_oversized_limit_is_clamped():
    out = guard_sql("SELECT * FROM ssdf.events LIMIT 999999", max_limit=1000)
    assert "1000" in out
    assert "999999" not in out
