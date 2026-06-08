"""PAN-OS configured-policy collector: security rulebase via get_pan_config (XML/JSON)."""

from __future__ import annotations

import json
import logging
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)

from .base import register

PROVIDER = "paloalto"


def _root(text: str) -> ET.Element | None:
    """Unwrap an optional JSON envelope and parse to an XML root element."""
    xml_text = text
    try:
        data = json.loads(text)
        if isinstance(data, dict) and isinstance(data.get("result"), str):
            xml_text = data["result"]
        elif isinstance(data, str):
            xml_text = data
    except json.JSONDecodeError:
        pass
    try:
        return ET.fromstring(xml_text)
    except ET.ParseError as exc:
        logger.warning("panos: failed to parse config XML: %s", exc)
        return None


def _rule_entries(root: ET.Element) -> list[ET.Element]:
    """Locate the vsys security rulebase rule entries, regardless of envelope.

    Handles the full running-config (`.//rulebase/security/rules`) and a bare
    `<rules>` root. Deliberately scoped so zone/address/user `<entry>` elements
    elsewhere in the config are never mistaken for security rules.
    """
    rules_el = root.find(".//rulebase/security/rules")
    if rules_el is None:
        if root.tag == "rules":
            rules_el = root
        else:
            rules_el = root.find(".//security/rules")
            if rules_el is None:
                rules_el = root.find(".//rules")
    return rules_el.findall("entry") if rules_el is not None else []


def _members(entry: ET.Element, tag: str) -> list[str]:
    el = entry.find(tag)
    if el is None:
        return []
    return [m.text.strip() for m in el.findall("member") if m.text and m.text.strip()]


def _text(entry: ET.Element, tag: str) -> str:
    el = entry.find(tag)
    return el.text.strip() if el is not None and el.text else ""


def parse_security_rules(text: str, device_name: str, now: str) -> list[dict]:
    """Parse a PAN-OS security rulebase into normalized rule dicts (order preserved)."""
    root = _root(text)
    if root is None:
        return []
    rules: list[dict] = []
    for position, entry in enumerate(_rule_entries(root)):
        name = entry.get("name", "").strip()
        if not name:
            continue
        rules.append({
            "provider": PROVIDER,
            "device_name": device_name,
            "rule_name": name,
            "action": _text(entry, "action"),
            "from_zone": _members(entry, "from"),
            "to_zone": _members(entry, "to"),
            "source_addresses": _members(entry, "source"),
            "dest_addresses": _members(entry, "destination"),
            "application": _members(entry, "application"),
            "service": _members(entry, "service"),
            "position": position,
            "enabled": _text(entry, "disabled").lower() != "yes",
            "vendor_extras": {"panw.panos.uuid": entry.get("uuid", "")},
            "collected_at": now,
        })
    return rules


@register("panos")
class PanosPolicyCollector:
    """Collects the configured security rulebase from one PAN-OS firewall."""

    name = "panos"

    def __init__(self, device: str = "panosvm"):
        self.device = device

    def collect(self, client, now: str) -> list[dict]:
        # Real get_pan_config(host, fmt, location) returns the full running config;
        # parse_security_rules scopes to the security rulebase itself.
        text = client.call_tool("get_pan_config", {"host": self.device})
        return parse_security_rules(text, self.device, now)
