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


def test_collect_uses_current_panos_mcp_tool_contract():
    """Pin the panos-mcp tool + argument names the collector depends on.

    The MCP server renamed these (execute_pan_op/host/cmd ->
    execute_panos_op/device/command). A stub that ignores name/args hides the
    drift, because run_collectors swallows the resulting error and skips.
    """
    from ssdf_topo.collectors.panos import PanosCollector

    empty_envelope = (
        '{"result":"<response status=\\"success\\"><result></result></response>"}'
    )
    calls: list[tuple[str, dict]] = []

    class _RecordingClient:
        def call_tool(self, name, args=None):
            calls.append((name, args or {}))
            return empty_envelope

    PanosCollector("panosvm").collect(_RecordingClient(), NOW)

    assert [c[0] for c in calls] == ["execute_panos_op", "execute_panos_op"]
    for _, args in calls:
        assert set(args) == {"device", "command", "max_bytes"}
        assert args["device"] == "panosvm"


_ARP_XML = ("<response status='success'><result>"
            "<entry><ip>10.64.0.9</ip><mac>aa:bb:cc:dd:ee:ff</mac>"
            "<interface>ethernet1/1</interface></entry></result></response>")


def _envelope(content: str, truncated: bool = False) -> str:
    import json
    return json.dumps({"device": "panosvm", "status": "success",
                       "output": {"content": content, "truncated": truncated}})


def test_collect_requests_a_generous_output_cap():
    """execute_panos_op caps output at 512 KiB by default; an ARP table on a
    real firewall can exceed that, and a cut-off table parses as fewer hosts."""
    from ssdf_topo.collectors.panos import PanosCollector

    calls: list[dict] = []

    class _RecordingClient:
        def call_tool(self, name, args=None):
            calls.append(args or {})
            return _envelope("<response status='success'><result></result></response>")

    PanosCollector("panosvm").collect(_RecordingClient(), NOW)

    assert all(c.get("max_bytes", 0) > 512 * 1024 for c in calls)


def test_collect_drops_truncated_observations_but_keeps_the_inventory_node():
    """A truncated response must not become a quietly short ARP table.

    The firewall_inventory item is emitted unconditionally, so a collector that
    swallowed truncation would still look healthy while under-reporting hosts.
    Dropping the inventory node instead would age the firewall out of the graph,
    so keep it and refuse only the incomplete payload.
    """
    from ssdf_topo.collectors.panos import PanosCollector

    class _TruncatingClient:
        def call_tool(self, name, args=None):
            return _envelope(_ARP_XML, truncated=True)

    obs = PanosCollector("panosvm").collect(_TruncatingClient(), NOW)

    assert [o.observation_type for o in obs] == ["device_inventory"]


def test_collect_keeps_observations_when_not_truncated():
    from ssdf_topo.collectors.panos import PanosCollector

    class _CompleteClient:
        def call_tool(self, name, args=None):
            return _envelope(_ARP_XML, truncated=False)

    obs = PanosCollector("panosvm").collect(_CompleteClient(), NOW)

    assert "arp_entry" in {o.observation_type for o in obs}
