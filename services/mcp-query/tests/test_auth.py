from types import SimpleNamespace
import ssdf_mcp_query.auth as auth


def _fake_token(claims):
    return SimpleNamespace(claims=claims)


def test_principal_and_allowed_tools(monkeypatch):
    monkeypatch.setattr(auth, "get_access_token", lambda: _fake_token(
        {"principal": "triage-agent", "allowed_tools": ["query_flows"]}))
    principal, allowed = auth.current_caller()
    assert principal == "triage-agent"
    assert allowed == frozenset({"query_flows"})


def test_allowed_tools_absent_means_none(monkeypatch):
    monkeypatch.setattr(auth, "get_access_token", lambda: _fake_token(
        {"principal": "admin-agent"}))
    principal, allowed = auth.current_caller()
    assert principal == "admin-agent"
    assert allowed is None


def test_falls_back_to_sub(monkeypatch):
    monkeypatch.setattr(auth, "get_access_token", lambda: _fake_token({"sub": "agent"}))
    assert auth.current_caller() == ("agent", None)


def test_no_token_returns_unknown(monkeypatch):
    monkeypatch.setattr(auth, "get_access_token", lambda: None)
    assert auth.current_caller() == ("unknown", None)
