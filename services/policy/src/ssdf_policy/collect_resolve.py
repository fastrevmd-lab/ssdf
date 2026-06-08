"""Entrypoint: collect configured rules from each firewall, resolve, upsert entities/edges."""

from __future__ import annotations

import datetime
import logging
import os

from . import collectors  # noqa: F401 — triggers @register for panos+junos
from .chwriter import ClickHouseEntityWriter
from .collectors.base import REGISTRY
from .config import Config, load_config
from .mcp_client import McpToolClient
from .resolve_policies import resolve_policies

log = logging.getLogger("ssdf_policy.collect_resolve")


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds")


def _build_collector(name: str):
    cls = REGISTRY[name]
    if name == "junos":
        raw = os.environ.get("JUNOS_DEVICES", "")
        return cls(devices=[d.strip() for d in raw.split(",") if d.strip()])
    if name == "panos":
        return cls(device=os.environ.get("PANOS_DEVICE", "panosvm"))
    return cls()


def run_once(enabled, collector_factory, client_factory, writer, tenant: str,
             now: str) -> tuple[int, int]:
    """Collect rules from each enabled firewall (skipping failures), resolve, write."""
    all_rules: list[dict] = []
    for name in enabled:
        try:
            collector = collector_factory(name)
            client = client_factory(name)
            all_rules.extend(collector.collect(client, now))
        except Exception:
            log.warning("policy collector %r failed; skipping", name, exc_info=True)
    entities, edges = resolve_policies(all_rules, tenant)
    n_ent = writer.replace_entities(entities)
    n_edge = writer.replace_edges(edges)
    log.info("policy resolver: %d entities, %d edges upserted", n_ent, n_edge)
    return n_ent, n_edge


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    config: Config = load_config()
    writer = ClickHouseEntityWriter(config)
    run_once(
        enabled=config.enabled_collectors,
        collector_factory=_build_collector,
        client_factory=lambda name: McpToolClient(config.mcp_endpoint(name)),
        writer=writer,
        tenant=config.tenant_id,
        now=_now(),
    )


if __name__ == "__main__":
    main()
