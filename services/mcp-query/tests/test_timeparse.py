from datetime import datetime, timezone, timedelta
import pytest
from ssdf_mcp_query.timeparse import parse_time, TimeParseError


def test_iso_8601_parsed_as_utc():
    dt = parse_time("2026-06-06T12:00:00Z")
    assert dt == datetime(2026, 6, 6, 12, 0, 0, tzinfo=timezone.utc)


def test_now_returns_utc(monkeypatch):
    fixed = datetime(2026, 6, 6, 12, 0, 0, tzinfo=timezone.utc)
    monkeypatch.setattr("ssdf_mcp_query.timeparse._utcnow", lambda: fixed)
    assert parse_time("now") == fixed


def test_relative_hours(monkeypatch):
    fixed = datetime(2026, 6, 6, 12, 0, 0, tzinfo=timezone.utc)
    monkeypatch.setattr("ssdf_mcp_query.timeparse._utcnow", lambda: fixed)
    assert parse_time("now-1h") == fixed - timedelta(hours=1)


def test_relative_days_and_minutes(monkeypatch):
    fixed = datetime(2026, 6, 6, 12, 0, 0, tzinfo=timezone.utc)
    monkeypatch.setattr("ssdf_mcp_query.timeparse._utcnow", lambda: fixed)
    assert parse_time("now-2d") == fixed - timedelta(days=2)
    assert parse_time("now-30m") == fixed - timedelta(minutes=30)


def test_invalid_raises():
    with pytest.raises(TimeParseError):
        parse_time("yesterday")
