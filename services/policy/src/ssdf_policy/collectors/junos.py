"""vSRX configured-policy collector: security policies via `| display set` text parser.

Handles both zone-pair policies (`... from-zone X to-zone Y policy NAME ...`) and global
policies (`... global policy NAME ...`, whose zones appear as `match from-zone/to-zone`).
"""

from __future__ import annotations

import re

from .base import register

PROVIDER = "juniper"
_ACTION_MAP = {"permit": "allow", "deny": "deny", "reject": "reject"}
_ZONE_RE = re.compile(
    r"security policies from-zone (\S+) to-zone (\S+) policy (\S+) (.*)$"
)
_GLOBAL_RE = re.compile(r"security policies global policy (\S+) (.*)$")


def _new_rule(name, device_name, from_zone, to_zone, now, order):
    return {
        "provider": PROVIDER, "device_name": device_name, "rule_name": name,
        "action": "", "from_zone": list(from_zone), "to_zone": list(to_zone),
        "source_addresses": [], "dest_addresses": [], "application": [],
        "service": [], "position": order, "enabled": True,
        "vendor_extras": {}, "collected_at": now,
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
            line = line[len("inactive:"):].strip()
        if not line.startswith("set ") and not line.startswith("deactivate "):
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
    return list(rules.values())


@register("junos")
class JunosPolicyCollector:
    """Collects configured security policies from one or more vSRX devices."""

    name = "junos"

    def __init__(self, devices: list[str] | None = None):
        self.devices = devices or []

    def collect(self, client, now: str) -> list[dict]:
        rules: list[dict] = []
        for dev in self.devices:
            text = client.call_tool(
                "execute_junos_command",
                {"router_name": dev,
                 "command": "show configuration security policies | display set"},
            )
            rules.extend(parse_security_policies(text, dev, now))
        return rules
