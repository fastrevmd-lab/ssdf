import os

import pytest

pytestmark = pytest.mark.integration


def _env(name):
    val = os.environ.get(name)
    if not val:
        pytest.skip(f"{name} not set")
    return val


def test_panos_collector_returns_rules_live():
    from ssdf_policy.config import McpEndpoint
    from ssdf_policy.mcp_client import McpToolClient
    from ssdf_policy.collectors.panos import PanosPolicyCollector

    ep = McpEndpoint(_env("PANOS_MCP_URL"), os.environ.get("PANOS_MCP_TOKEN", ""))
    rules = PanosPolicyCollector(os.environ.get("PANOS_DEVICE", "panosvm")).collect(
        McpToolClient(ep), "2026-06-08T00:00:00"
    )
    assert rules, "expected at least one configured PAN-OS rule"
    assert all(r["rule_name"] and r["device_name"] for r in rules)


def test_resolve_and_write_live():
    from ssdf_policy.config import load_config
    from ssdf_policy.chwriter import ClickHouseEntityWriter
    from ssdf_policy.collect_resolve import run_once, _build_collector
    from ssdf_policy.mcp_client import McpToolClient

    cfg = load_config()
    writer = ClickHouseEntityWriter(cfg)
    n_ent, n_edge = run_once(
        enabled=cfg.enabled_collectors,
        collector_factory=_build_collector,
        client_factory=lambda name: McpToolClient(cfg.mcp_endpoint(name)),
        writer=writer,
        tenant=cfg.tenant_id,
        now="2026-06-08T00:00:00",
    )
    assert n_ent >= 2 and n_edge >= 1
