# tests/test_collector_panos.py
"""Tests for the PAN-OS topology collector (ARP + LLDP, XML-in-JSON envelope)."""

import pathlib

from ssdf_topo.collectors.panos import parse_arp_xml, parse_lldp_xml

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
NOW = "2026-06-07T00:00:00+00:00"
SOURCE = "panosvm"

_INLINE_LLDP = (
    '{"result":"<response status=\\"success\\"><result>'
    '<entry><local-port>ethernet1/1</local-port>'
    '<system-name>sw1</system-name>'
    '<port-id>ge-0/0/1</port-id></entry>'
    '</result></response>"}'
)


def _load(name: str) -> str:
    return (FIXTURES / name).read_text()


def test_parse_arp_xml():
    obs = parse_arp_xml(_load("panos_arp.json"), SOURCE, NOW)
    assert len(obs) == 3, f"expected 3 arp entries, got {len(obs)}"
    first = obs[0]
    assert first.observation_type == "arp_entry"
    assert first.subj_id.startswith("ip:")
    assert first.obj_id.startswith("mac:")
    assert "interface" in first.attrs


def test_parse_lldp_xml():
    obs = parse_lldp_xml(_INLINE_LLDP, SOURCE, NOW)
    assert len(obs) > 0
    first = obs[0]
    assert first.observation_type == "lldp_neighbor"
    assert "local_port" in first.attrs


def test_collect_emits_firewall_inventory():
    from ssdf_topo.collectors.panos import PanosCollector

    empty_envelope = (
        '{"result":"<response status=\\"success\\"><result></result></response>"}'
    )

    class _EmptyClient:
        def call_tool(self, name, args=None):
            return empty_envelope

    obs = PanosCollector("panosvm").collect(_EmptyClient(), NOW)

    inv = [o for o in obs if o.observation_type == "device_inventory"]
    assert len(inv) == 1
    assert inv[0].source_device == "panosvm"
    assert inv[0].attrs["role"] == "firewall"
    assert inv[0].collector == "panos"


_BILLION_LAUGHS = """<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<response><result><entry><ip>&lol3;</ip><mac>00:11:22:33:44:55</mac></entry></result></response>"""


def test_parse_arp_xml_rejects_entity_expansion():
    assert parse_arp_xml(_BILLION_LAUGHS, "panosvm", "2026-06-10T00:00:00Z") == []
