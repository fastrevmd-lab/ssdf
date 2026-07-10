# tests/test_alerts.py
import pytest
from ssdf_mcp_query.alerts import normalize_severity, build_recent_alerts_sql


def test_suricata_severity_inverted():
    assert normalize_severity("unifi", "alert", {"unifi.ips.severity": "1"}) == ("critical", 4)
    assert normalize_severity("unifi", "alert", {"unifi.ips.severity": "2"}) == ("high", 3)
    assert normalize_severity("unifi", "alert", {"unifi.ips.severity": "3"}) == ("medium", 2)


def test_pan_threat_severity_strings():
    # PAN severity key: panw.panos.severity (pinned from vector.toml line 342)
    assert normalize_severity("paloalto", "alert", {"panw.panos.severity": "critical"}) == ("critical", 4)
    assert normalize_severity("paloalto", "alert", {"panw.panos.severity": "informational"}) == ("low", 1)


def test_syslog_numeric_severity():
    assert normalize_severity("juniper", "event", {"syslog.severity": "2"}) == ("critical", 4)
    assert normalize_severity("juniper", "event", {"syslog.severity": "4"}) == ("medium", 2)


def test_non_alert_row_is_none():
    assert normalize_severity("proxmox", "event", {}) is None


def test_sql_filters_min_severity_and_providers():
    sql, params = build_recent_alerts_sql(since="now-24h", min_severity="high",
                                          providers="unifi,paloalto", limit=10)
    assert "LIMIT" in sql and params["limit"] == 10
    assert "event_provider IN" in sql
