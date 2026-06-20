"""Live integration: a real poll cycle writes valid rows to ssdf.health_metrics.

Run: cd services/health && CH_HOST=<ip> CH_PORT=8443 CH_SECURE=1 CH_CA_FILE=... \
  CH_USER=ssdf_health CH_PASSWORD=<pw> \
  JUNOS_MCP_URL=... JUNOS_MCP_TOKEN=... JUNOS_DEVICES=vSRX-test10 \
  PANOS_MCP_URL=... PANOS_MCP_TOKEN=... PANOS_DEVICE=panosvm \
  PROXMOX_MCP_URL=... PROXMOX_MCP_TOKEN=... \
  UNIFI_MCP_URL=... UNIFI_MCP_TOKEN=... UNIFI_DEVICE_MACS=<mac> \
  uv run pytest tests/test_health_metrics_integration.py -m integration -v
"""

from __future__ import annotations

import os

import pytest

from ssdf_health.chwriter import HealthWriter, client_kwargs
from ssdf_health.collect_main import _now, build_collector, run
from ssdf_health.config import load_config
from ssdf_health.mcp_client import McpToolClient

import clickhouse_connect

pytestmark = pytest.mark.integration


def _require(*names):
    missing = [n for n in names if not os.environ.get(n)]
    if missing:
        pytest.skip(f"missing env: {', '.join(missing)}")


def test_live_poll_writes_valid_rows():
    _require("CH_HOST", "CH_PASSWORD")
    config = load_config()
    writer = HealthWriter(config)
    total = run(
        config,
        client_factory=lambda name: McpToolClient(config.mcp_endpoint(name)),
        collector_factory=lambda name: build_collector(name, config),
        writer=writer,
        now=_now(),
    )
    assert total > 0, "expected at least one gauge from a live poll"

    ro = clickhouse_connect.get_client(**client_kwargs(config))
    result = ro.query(
        "SELECT metric_name, unit, metric_value FROM ssdf.health_metrics "
        "WHERE metric_name = 'cpu_util_pct' ORDER BY timestamp DESC LIMIT 5"
    )
    assert result.result_rows, "no cpu_util_pct rows landed"
    for _name, unit, value in result.result_rows:
        assert unit == "percent"
        assert 0.0 <= float(value) <= 100.0
