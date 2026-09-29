"""vSRX configured-policy collector: security policies via `| display set` text parser.

Handles both zone-pair policies (`... from-zone X to-zone Y policy NAME ...`) and global
policies (`... global policy NAME ...`, whose zones appear as `match from-zone/to-zone`).
"""

from __future__ import annotations

import logging

import re

from .base import register

logger = logging.getLogger(__name__)

PROVIDER = "juniper"
_ACTION_MAP = {"permit": "allow", "deny": "deny", "reject": "reject"}
_ZONE_RE = re.compile(r"security policies from-zone (\S+) to-zone (\S+) policy (\S+) (.*)$")
_GLOBAL_RE = re.compile(r"security policies global policy (\S+) (.*)$")

# `show security policies hit-count` (verified live against vsrx-ci, 2026-09-28):
#   Index   From zone        To zone           Name           Policy count  Action
#   1       all-zone         all-zone          default-policy 0             Deny
# Header/banner lines ("Logical system: ...", "Number of policy: N") never start
# with a digit, so they fail this match harmlessly.
_HITCOUNT_RE = re.compile(r"^\s*\d+\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)\s+\S+\s*$")


def _new_rule(name, device_name, from_zone, to_zone, now, order):
    return {
        "provider": PROVIDER,
        "device_name": device_name,
        "rule_name": name,
        "action": "",
        "from_zone": list(from_zone),
        "to_zone": list(to_zone),
        "source_addresses": [],
        "dest_addresses": [],
        "application": [],
        "service": [],
        "position": order,
        "enabled": True,
        "vendor_extras": {},
        "collected_at": now,
    }


def parse_security_policies(text: str, device_name: str, now: str) -> list[dict]:
    """Parse Junos `set security policies … | display set` output into rule dicts.

    Terms for the same policy accumulate into one rule. Lines prefixed `inactive:`
    mark the rule disabled. `position` follows first appearance.
    """
    rules: dict[tuple, dict] = {}
    order = 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        inactive = line.startswith("inactive:")
        if inactive:
            line = line[len("inactive:") :].strip()
        if not line.startswith("set "):
            continue
        zone_match = _ZONE_RE.search(line)
        if zone_match:
            from_zone, to_zone, name, remainder = zone_match.groups()
            key = ("zonepair", from_zone, to_zone, name)
            seed_from, seed_to = [from_zone], [to_zone]
        else:
            global_match = _GLOBAL_RE.search(line)
            if not global_match:
                continue
            name, remainder = global_match.groups()
            key = ("global", name)
            seed_from, seed_to = [], []
        rule = rules.get(key)
        if rule is None:
            rule = _new_rule(name, device_name, seed_from, seed_to, now, order)
            rules[key] = rule
            order += 1
        if inactive:
            rule["enabled"] = False
        tokens = remainder.split()
        if tokens[:2] == ["match", "source-address"] and len(tokens) > 2:
            rule["source_addresses"].append(tokens[2])
        elif tokens[:2] == ["match", "destination-address"] and len(tokens) > 2:
            rule["dest_addresses"].append(tokens[2])
        elif tokens[:2] == ["match", "application"] and len(tokens) > 2:
            rule["application"].append(tokens[2])
            rule["service"].append(tokens[2])
        elif tokens[:2] == ["match", "from-zone"] and len(tokens) > 2:
            rule["from_zone"].append(tokens[2])
        elif tokens[:2] == ["match", "to-zone"] and len(tokens) > 2:
            rule["to_zone"].append(tokens[2])
        elif tokens[:1] == ["then"] and len(tokens) > 1:
            mapped = _ACTION_MAP.get(tokens[1])
            if mapped:
                rule["action"] = mapped
    for key, rule in rules.items():
        if key[0] == "global":
            if not rule["from_zone"]:
                rule["from_zone"] = ["any"]
            if not rule["to_zone"]:
                rule["to_zone"] = ["any"]
    return list(rules.values())


def parse_hit_counts(text: str) -> dict[str, int]:
    """Parse `show security policies hit-count` into {rule_name: count}.

    Matched by policy name only: Junos policy names are unique across a device's
    zone-pair + global policy set in the overwhelming common case, and the hit-count
    table (unlike `| display set`) carries no from-zone/to-zone linkage back to a
    rule's own match clauses to key on instead. A name reused across two distinct
    zone-pairs collapses to whichever row is seen last -- a known limitation for a
    first version (MEC-566), not a data-loss bug: session/byte usage still tracks
    correctly via ssdf.rule_usage_hourly, which is keyed by rule_name and does not
    share this ambiguity.
    """
    counts: dict[str, int] = {}
    for line in text.splitlines():
        match = _HITCOUNT_RE.match(line)
        if not match:
            continue
        _from_zone, _to_zone, name, count = match.groups()
        counts[name] = int(count)
    return counts


@register("junos")
class JunosPolicyCollector:
    """Collects configured security policies from one or more vSRX devices."""

    name = "junos"

    def __init__(self, devices: list[str] | None = None):
        self.devices = devices or []

    def collect(self, client, now: str) -> list[dict]:
        """Read each device's configured policy, skipping ones that fail.

        Per-device resilient: run_collectors catches at collector granularity, so
        an uncaught error here would discard every other device's rules too.
        """
        rules: list[dict] = []
        for dev in self.devices:
            try:
                text = client.call_tool(
                    "execute_junos_command",
                    {
                        "router_name": dev,
                        "command": "show configuration security policies | display set",
                    },
                )
            except Exception:
                logger.warning("junos device %r unreachable; skipping", dev, exc_info=True)
                continue
            try:
                dev_rules = parse_security_policies(text, dev, now)
            except Exception:
                logger.warning("junos %r: policy parse failed; continuing", dev, exc_info=True)
                continue
            # MEC-566: read-only hit-count enrichment via the same execute_junos_command
            # tool/token already used above -- no new device write path. A failure here
            # must not drop the device's configured rules, only leave hit_count unset
            # (downstream tools treat a missing hit_count as "unknown", never "unused").
            try:
                hc_text = client.call_tool(
                    "execute_junos_command",
                    {"router_name": dev, "command": "show security policies hit-count"},
                )
                hit_counts = parse_hit_counts(hc_text)
                for rule in dev_rules:
                    count = hit_counts.get(rule["rule_name"])
                    if count is not None:
                        rule["vendor_extras"]["hit_count"] = str(count)
                        rule["vendor_extras"]["hit_count_collected_at"] = now
            except Exception:
                logger.warning(
                    "junos %r: hit-count collection failed; continuing without counters",
                    dev,
                    exc_info=True,
                )
            rules.extend(dev_rules)
        return rules
