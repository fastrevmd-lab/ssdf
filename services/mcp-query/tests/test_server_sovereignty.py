"""Sovereign tier must refuse a token lacking the local_only attestation (M16e)."""

import asyncio
import json
import os

os.environ.setdefault("CH_PASSWORD", "x")
os.environ.setdefault("MCP_AUTH_TOKEN", "t")

from ssdf_mcp_query.tokenstore import digest_for


def _patch_ch(monkeypatch, server):
    class _Dummy:
        def __init__(self, *a, **k):
            pass

    monkeypatch.setattr(server, "ClickHouseClient", _Dummy)
    monkeypatch.setattr(
        server, "make_ch_auditor", lambda config, tier="sovereign": server.Auditor(lambda row: None)
    )


def _tokens_file(tmp_path, payload):
    f = tmp_path / "tokens.json"
    f.write_text(json.dumps(payload))
    f.chmod(0o600)
    return f


def test_sovereign_build_refuses_token_without_local_only(monkeypatch, tmp_path):
    import ssdf_mcp_query.server as server

    _patch_ch(monkeypatch, server)
    monkeypatch.setenv(
        "MCP_TOKENS_FILE",
        str(
            _tokens_file(
                tmp_path,
                {
                    digest_for("hosted-runner-tok"): {"principal": "eval-hosted"},
                    digest_for("local-runner-tok"): {
                        "principal": "eval-local",
                        "local_only": True,
                    },
                },
            )
        ),
    )
    app = server.build_app(tier="sovereign")
    assert asyncio.run(app.auth.verify_token("hosted-runner-tok")) is None
    assert asyncio.run(app.auth.verify_token("local-runner-tok")) is not None


def test_public_build_ignores_local_only(monkeypatch, tmp_path):
    import ssdf_mcp_query.server as server

    _patch_ch(monkeypatch, server)
    monkeypatch.setenv(
        "MCP_TOKENS_FILE",
        str(_tokens_file(tmp_path, {digest_for("public-tok"): {"principal": "eval-hosted"}})),
    )
    app = server.build_app(tier="public")
    assert asyncio.run(app.auth.verify_token("public-tok")) is not None
