import asyncio
import json
import os

os.environ.setdefault("CH_PASSWORD", "x")
os.environ.setdefault("MCP_AUTH_TOKEN", "t")

EXPECTED_TOOLS = {
    "query_flows",
    "describe_schema",
    "top_talkers",
    "run_sql",
    "get_entity",
    "locate",
    "neighbors",
    "find_path",
    "enforcement_points",
    "topology_snapshot",
    "explain_access",
    "configured_policies",
    "observed_by",
    "ingest_status",
    "recent_alerts",
    "metric_timeseries",
    "top_series",
    "entity_metric_timeseries",
    "reidentify",
}


def _names(app):
    return {t.name for t in asyncio.run(app.list_tools())}


def _patch_ch(monkeypatch, server):
    class _Dummy:
        def __init__(self, *a, **k):
            pass

    monkeypatch.setattr(server, "ClickHouseClient", _Dummy)
    monkeypatch.setattr(
        server, "make_ch_auditor", lambda config, tier="sovereign": server.Auditor(lambda row: None)
    )


def test_all_tools_registered_single_token(monkeypatch):
    import ssdf_mcp_query.server as server

    _patch_ch(monkeypatch, server)
    app = server.build_app()
    assert _names(app) == EXPECTED_TOOLS


def test_multi_principal_tokens_register(monkeypatch, tmp_path):
    import ssdf_mcp_query.server as server

    f = tmp_path / "tokens.json"
    f.write_text(
        json.dumps(
            {
                "tok-a": {"principal": "triage-agent", "allowed_tools": ["query_flows"]},
                "tok-b": {"principal": "admin-agent"},
            }
        )
    )
    monkeypatch.setenv("MCP_TOKENS_FILE", str(f))
    _patch_ch(monkeypatch, server)
    app = server.build_app()
    assert _names(app) == EXPECTED_TOOLS


def test_not_after_lands_in_verifier_claims(monkeypatch, tmp_path):
    import ssdf_mcp_query.server as server

    f = tmp_path / "tokens.json"
    f.write_text(
        json.dumps(
            {
                "tok-exp": {"principal": "expiring", "not_after": "2026-09-09T12:00:00+00:00"},
                "tok-forever": {"principal": "forever"},
            }
        )
    )
    monkeypatch.setenv("MCP_TOKENS_FILE", str(f))
    _patch_ch(monkeypatch, server)
    captured = {}
    real_verifier = server.StaticTokenVerifier

    def _spy(tokens):
        captured.update(tokens)
        return real_verifier(tokens=tokens)

    monkeypatch.setattr(server, "StaticTokenVerifier", lambda tokens: _spy(tokens))
    server.build_app()
    assert captured["tok-exp"]["not_after"] == "2026-09-09T12:00:00+00:00"
    assert "not_after" not in captured["tok-forever"]
