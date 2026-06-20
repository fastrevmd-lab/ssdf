"""Entrypoint: run all enabled health collectors and insert gauges into ClickHouse."""

from __future__ import annotations

import datetime
import logging

from .chwriter import HealthWriter
from . import collectors  # noqa: F401 — triggers @register for all collectors
from .collectors.base import REGISTRY, run_collectors
from .config import Config, load_config
from .mcp_client import McpToolClient

logger = logging.getLogger(__name__)


def _now() -> datetime.datetime:
    """Current UTC time as a timezone-aware datetime (for the DateTime64 column)."""
    return datetime.datetime.now(datetime.timezone.utc)


def build_collector(name: str, config: Config):
    """Instantiate the named collector, passing device config from `config`."""
    cls = REGISTRY[name]
    if name == "junos":
        return cls(devices=config.junos_devices)
    if name == "panos":
        return cls(device=config.panos_device)
    if name == "unifi":
        return cls(macs=config.unifi_macs, site_id=config.unifi_site_id)
    return cls()


def run(config: Config, client_factory, collector_factory, writer, now) -> int:
    """Run all enabled collectors against the given factories/writer; return total written."""
    return run_collectors(
        enabled=config.enabled_collectors,
        client_factory=client_factory,
        collector_factory=collector_factory,
        writer=writer,
        now=now,
    )


def main() -> None:
    """Load config, run all enabled collectors, log the total inserted count."""
    logging.basicConfig(level=logging.INFO)
    config = load_config()
    writer = HealthWriter(config)
    total = run(
        config,
        client_factory=lambda name: McpToolClient(config.mcp_endpoint(name)),
        collector_factory=lambda name: build_collector(name, config),
        writer=writer,
        now=_now(),
    )
    logger.info("collect_main: inserted %d health gauges", total)


if __name__ == "__main__":
    main()
