"""CI guard: committed scorecards must never carry a live-looking IPv4 address.

MEC-811 follow-up to ssdf#24 (which hand-scrubbed the existing files but did
not stop the scorer from writing new ones). Only RFC 5737 documentation
addresses (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) are allowed in
results/*.json -- those are the synthetic addresses the M8 README and test
fixtures already use for the sovereign/public MCP endpoints.
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path

RESULTS_DIR = Path(__file__).resolve().parents[1] / "results"

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

_DOC_NETWORKS = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
]


def _is_documentation_address(addr: ipaddress.IPv4Address) -> bool:
    return any(addr in net for net in _DOC_NETWORKS)


def _live_looking_addresses(text: str) -> list[str]:
    found = []
    for match in _IPV4_RE.findall(text):
        try:
            addr = ipaddress.IPv4Address(match)
        except ValueError:
            continue  # not a real IPv4 address (e.g. a version-looking number)
        if not _is_documentation_address(addr):
            found.append(match)
    return found


def test_no_live_ipv4_addresses_in_committed_scorecards():
    offenders: dict[str, list[str]] = {}
    for path in sorted(RESULTS_DIR.glob("*.json")):
        addresses = _live_looking_addresses(path.read_text())
        if addresses:
            offenders[path.name] = addresses
    assert not offenders, f"live-looking IPv4 addresses in committed scorecards: {offenders}"


def test_guard_itself_flags_rfc1918_and_allows_rfc5737():
    assert _live_looking_addresses("reference: 10.0.0.1") == ["10.0.0.1"]
    assert _live_looking_addresses("reference: 172.16.5.9") == ["172.16.5.9"]
    assert _live_looking_addresses("reference: 192.168.1.1") == ["192.168.1.1"]
    assert _live_looking_addresses("endpoint: 198.51.100.152") == []
    assert _live_looking_addresses("endpoint: 192.0.2.1 and 203.0.113.7") == []
