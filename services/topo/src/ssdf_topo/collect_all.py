# src/ssdf_topo/collect_all.py
"""Entrypoint that runs all enabled collectors and inserts observations into ClickHouse."""

from __future__ import annotations

import datetime
import logging
import os

from .chwriter import ClickHouseWriter
from . import collectors  # noqa: F401 — importing the package triggers __init__, which registers all collectors
from .collectors.base import REGISTRY
from .config import load_config
from .mcp_client import McpToolClient

logger = logging.getLogger(__name__)


def _now() -> str:
    """Return the current UTC time as an ISO-8601 string with millisecond precision."""
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds")


def _build_collector(name: str):
    """Instantiate the named collector from the registry, passing device config from env if needed."""
    cls = REGISTRY[name]
    if name == "junos":
        raw = os.environ.get("JUNOS_DEVICES", "")
        devices = [d.strip() for d in raw.split(",") if d.strip()]
        return cls(devices=devices)
    if name == "panos":
        return cls(device=os.environ.get("PANOS_DEVICE", "panosvm"))
    return cls()


def run_collectors(enabled, client_factory, collector_factory, writer, now: str) -> int:
    """Run each enabled collector; skip any that raise, log a warning, and continue.

    Returns the total number of observations inserted.
    """
    total = 0
    for name in enabled:
        try:
            collector = collector_factory(name)
            client = client_factory(name)
            obs = collector.collect(client, now)
            total += writer.insert_observations(obs)
        except Exception:
            logger.warning("collector %r failed; skipping", name, exc_info=True)
    return total


def main() -> None:
    """Load config, run all enabled collectors, and log the total inserted count."""
    logging.basicConfig(level=logging.INFO)
    config = load_config()
    writer = ClickHouseWriter(config)
    now = _now()
    total = run_collectors(
        enabled=config.enabled_collectors,
        client_factory=lambda name: McpToolClient(config.mcp_endpoint(name)),
        collector_factory=_build_collector,
        writer=writer,
        now=now,
    )
    logger.info("collect_all: inserted %d observations", total)


if __name__ == "__main__":
    main()
