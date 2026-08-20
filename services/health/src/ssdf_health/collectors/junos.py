"""Junos health collector: routing-engine CPU%/mem% + chassis-environment temps."""

from __future__ import annotations

import logging

import re

from ..gauge import Gauge
from .base import register

logger = logging.getLogger(__name__)

_MEM_RE = re.compile(r"Memory utilization\s+(\d+)\s+percent", re.IGNORECASE)
_IDLE_RE = re.compile(r"Idle\s+(\d+)\s+percent", re.IGNORECASE)
# "Temp  <name...>  <STATUS>  NN degrees C ..."
_TEMP_RE = re.compile(r"^Temp\s+(?P<name>.+?)\s+\S+\s+(?P<c>-?\d+)\s+degrees C", re.IGNORECASE)


def parse_routing_engine(text: str, device: str, now: str) -> list[Gauge]:
    """Build device-scope CPU/mem gauges from 'show chassis routing-engine'."""
    gauges: list[Gauge] = []
    mem = _MEM_RE.search(text)
    if mem:
        gauges.append(
            Gauge(
                provider="juniper",
                device=device,
                scope="device",
                metric_class="memory",
                sensor="",
                metric_name="mem_util_pct",
                value=float(mem.group(1)),
                unit="percent",
                raw=mem.group(0),
            )
        )
    idle = _IDLE_RE.search(text)
    if idle:
        gauges.append(
            Gauge(
                provider="juniper",
                device=device,
                scope="device",
                metric_class="cpu",
                sensor="",
                metric_name="cpu_util_pct",
                value=max(0.0, 100.0 - float(idle.group(1))),
                unit="percent",
                raw=idle.group(0),
            )
        )
    return gauges


def parse_environment(text: str, device: str, now: str) -> list[Gauge]:
    """Build per-sensor temperature gauges from 'show chassis environment'."""
    gauges: list[Gauge] = []
    for line in text.splitlines():
        match = _TEMP_RE.match(line.strip())
        if not match:
            continue
        gauges.append(
            Gauge(
                provider="juniper",
                device=device,
                scope="device",
                metric_class="temperature",
                sensor=match.group("name").strip(),
                metric_name="temp_celsius",
                value=float(match.group("c")),
                unit="celsius",
                raw=line.strip(),
            )
        )
    return gauges


# Substrings that mean "this device is not answering", as opposed to "this
# command is not supported here". rust-junosmcp usually prefixes reachability
# problems with "transport error", but a powered-off device commonly surfaces as
# a bare timeout, and a stale known_hosts entry as a bare host-key mismatch.
_UNREACHABLE_MARKERS = (
    "transport error",
    "connection failed",
    "connection refused",
    "no route to host",
    "host key mismatch",
    "timed out",
    "timeout",
)


# "2026-08-18 23:05:33 UTC  Minor  AAMWD control channel down, ..."
# Junos prints a banner ("N alarms currently active" / "No alarms currently
# active") and a column header before the rows; anchoring on a leading timestamp
# is what distinguishes a real alarm line from both.
_ALARM_RE = re.compile(
    r"^(?P<raised>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?: \w+)?)\s+"
    r"(?P<cls>\S+)\s+(?P<desc>.+?)\s*$"
)


def parse_alarms(text: str, device: str, now: str) -> list[Gauge]:
    """Parse `show system alarms` / `show chassis alarms` into alarm gauges.

    Emits one `active_alarm_count` gauge plus one `alarm` gauge per active alarm.
    The count is emitted even when zero: a device with no alarms must be
    distinguishable from a collector that stopped running, and absence of rows
    cannot make that distinction.

    Severity rides the `sensor` axis and the raise time and description ride
    `raw`, so no schema change is needed — M13a designed metric_class + sensor as
    the discovery axes precisely so a new signal lands as new rows.
    """
    lines = [ln.rstrip() for ln in text.splitlines() if ln.strip()]
    if not lines:
        return []

    banner = any(
        "alarms currently active" in ln.lower() or "no alarms" in ln.lower() for ln in lines
    )
    if not banner:
        return []  # not alarm output at all

    gauges: list[Gauge] = []
    for line in lines:
        m = _ALARM_RE.match(line)
        if not m:
            continue
        gauges.append(
            Gauge(
                provider="juniper",
                device=device,
                scope="device",
                metric_class="alarm",
                sensor=m.group("cls").strip().lower(),
                metric_name="alarm",
                value=1.0,
                unit="count",
                raw=f"{m.group('raised')} | {m.group('desc').strip()}",
            )
        )

    gauges.insert(
        0,
        Gauge(
            provider="juniper",
            device=device,
            scope="device",
            metric_class="alarm",
            sensor="",
            metric_name="active_alarm_count",
            value=float(len(gauges)),
            unit="count",
            raw=lines[0],
        ),
    )
    return gauges


def _is_unreachable(exc: Exception) -> bool:
    """True if the error means the device is down rather than the command bad.

    Short-circuiting matters for cost, not just tidiness: most of the lab fleet is
    powered off, and probing every command against every dead device can exhaust
    the unit's RuntimeMaxSec=600 before later devices or collectors run. A command
    the platform simply does not support is NOT unreachable — the device's other
    probes may still answer.
    """
    text = str(exc).lower()
    return any(marker in text for marker in _UNREACHABLE_MARKERS)


@register("junos")
class JunosCollector:
    """Collects CPU/mem + temps from one or more Junos devices via rust-junosmcp."""

    name = "junos"

    def __init__(self, devices: list[str] | None = None):
        self.devices = devices or []

    def collect(self, client, now: str) -> list[Gauge]:
        """Poll each device, skipping only the probes that actually fail.

        Per-device resilient: run_collectors catches at collector granularity, so
        an uncaught error here would discard every other device's gauges too.
        The two commands are independent and are attempted independently — a
        platform that rejects one still yields the other's gauges, so neither is
        treated as a reachability gate for the device.
        """
        gauges: list[Gauge] = []
        for dev in self.devices:
            for command, parser in (
                ("show chassis routing-engine", parse_routing_engine),
                ("show chassis environment", parse_environment),
            ):
                try:
                    text = client.call_tool(
                        "execute_junos_command", {"router_name": dev, "command": command}
                    )
                    gauges.extend(parser(text, dev, now))
                except Exception as exc:
                    if _is_unreachable(exc):
                        logger.warning("junos device %r unreachable; skipping", dev, exc_info=True)
                        break
                    logger.warning(
                        "junos %r: command %r failed; continuing", dev, command, exc_info=True
                    )
            else:
                gauges.extend(self._collect_alarms(client, dev, now))
        return gauges

    def _collect_alarms(self, client, dev: str, now: str) -> list[Gauge]:
        """Collect active alarms, deduped across the two commands that report them.

        A vSRX returns the same alarm from BOTH `show system alarms` and
        `show chassis alarms`, so counting each command's output independently
        would double every device's alarm total.
        """
        seen: dict[tuple[str, str], Gauge] = {}
        saw_alarm_output = False
        for command in ("show system alarms", "show chassis alarms"):
            try:
                text = client.call_tool(
                    "execute_junos_command", {"router_name": dev, "command": command}
                )
            except Exception:
                logger.warning("junos %r: %r failed; continuing", dev, command, exc_info=True)
                continue
            parsed = parse_alarms(text, dev, now)
            if not parsed:
                continue  # not alarm output; do not infer a count from it
            saw_alarm_output = True
            for g in parsed:
                if g.metric_name == "alarm":
                    seen.setdefault((g.sensor, g.raw), g)

        # Report a count ONLY when a command actually answered with alarm output.
        # "No alarms currently active" parses to a real zero; unparseable output
        # must not be reported as zero, which would look identical to a healthy
        # device while actually meaning we learned nothing.
        if not saw_alarm_output:
            return []
        alarms = list(seen.values())
        count = Gauge(
            provider="juniper",
            device=dev,
            scope="device",
            metric_class="alarm",
            sensor="",
            metric_name="active_alarm_count",
            value=float(len(alarms)),
            unit="count",
            raw=f"{len(alarms)} active",
        )
        return [count, *alarms]
