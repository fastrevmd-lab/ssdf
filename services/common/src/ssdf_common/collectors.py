"""Collector protocol, a name->class registry, and the fault-isolated runner."""

from __future__ import annotations

import logging
from typing import Callable, Protocol

logger = logging.getLogger(__name__)

REGISTRY: dict[str, type] = {}


class Collector(Protocol):
    """Protocol for a collector that pulls read-only telemetry via MCP.

    Each collector is instantiated per-run and has a `collect` method that returns
    a list of observations/gauges. The exact return type varies by service (Observation
    for topo/policy, Gauge for health), so this protocol doesn't enforce it — services
    adapt run_collectors to their specific types.
    """

    name: str

    def collect(self, client, now: str) -> list:
        """Pull read-only state via the MCP client; return normalized observations/gauges."""
        ...


def register(name: str) -> Callable[[type], type]:
    """Decorator: register a collector class under `name`.

    INVARIANT: `REGISTRY` is a module-level dict shared by every importer. Services
    reuse collector names (`junos`, `panos`, `proxmox`, `unifi`) with DIFFERENT
    classes, so this is only safe because each service runs as its own process
    (separate systemd unit / venv). Do NOT import two services' collector packages
    into one process — the later registration would silently shadow the earlier.
    If SSDF ever consolidates services into one process, switch to per-service
    registries or namespaced names (`topo:junos`).
    """

    def _wrap(cls: type) -> type:
        REGISTRY[name] = cls
        return cls

    return _wrap


def get_collector(name: str) -> type:
    """Look up a collector class by name; raises KeyError if unknown."""
    if name not in REGISTRY:
        raise KeyError(f"unknown collector: {name}")
    return REGISTRY[name]


def run_collectors(enabled, client_factory, collector_factory, writer, now: str) -> int:
    """Run each enabled collector; skip any that raise, log a warning, and continue.

    Args:
        enabled: Iterable of collector names to run.
        client_factory: Callable(name) -> MCP client.
        collector_factory: Callable(name) -> Collector instance.
        writer: Object with an insert method (insert_observations or insert_gauges).
        now: ISO-8601 timestamp string for observations.

    Returns:
        The total number of items written (observations or gauges).
    """
    total = 0
    for name in enabled:
        try:
            collector = collector_factory(name)
            client = client_factory(name)
            items = collector.collect(client, now)
            if not items:
                logger.warning("collector %r returned 0 items", name)
            # The writer method signature varies: topo/policy use insert_observations,
            # health uses insert_gauges. Both take (items, now) or just (items).
            # Try the health signature first (insert_gauges(items, now)), fall back
            # to topo/policy (insert_observations(items)).
            if hasattr(writer, "insert_gauges"):
                total += writer.insert_gauges(items, now)
            elif hasattr(writer, "insert_observations"):
                total += writer.insert_observations(items)
            else:
                raise AttributeError(f"writer has no insert_observations or insert_gauges method")
        except Exception:
            logger.warning("collector %r failed; skipping", name, exc_info=True)
    return total
