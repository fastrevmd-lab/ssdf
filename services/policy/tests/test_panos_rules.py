from pathlib import Path
from ssdf_policy.collectors.panos import parse_security_rules

FIXTURE = Path(__file__).parent / "fixtures" / "panos_running_config.xml"


def _sample() -> str:
    # Minimal representative bare <rules> payload.
    return (
        "<rules>"
        "<entry name='allow-web' uuid='u-1'>"
        "<from><member>trust</member></from>"
        "<to><member>untrust</member></to>"
        "<source><member>any</member></source>"
        "<destination><member>any</member></destination>"
        "<application><member>web-browsing</member></application>"
        "<service><member>application-default</member></service>"
        "<action>allow</action>"
        "</entry>"
        "<entry name='deny-all' uuid='u-2'>"
        "<from><member>any</member></from><to><member>any</member></to>"
        "<source><member>any</member></source><destination><member>any</member></destination>"
        "<application><member>any</member></application><service><member>any</member></service>"
        "<action>deny</action><disabled>yes</disabled>"
        "</entry>"
        "</rules>"
    )


def test_parses_rules_with_position_and_enabled():
    rules = parse_security_rules(_sample(), "panosvm", "2026-06-08T00:00:00")
    assert [r["rule_name"] for r in rules] == ["allow-web", "deny-all"]
    first = rules[0]
    assert first["provider"] == "paloalto"
    assert first["device_name"] == "panosvm"
    assert first["action"] == "allow"
    assert first["from_zone"] == ["trust"] and first["to_zone"] == ["untrust"]
    assert first["application"] == ["web-browsing"]
    assert first["position"] == 0 and first["enabled"] is True
    assert first["vendor_extras"]["panw.panos.uuid"] == "u-1"
    assert rules[1]["enabled"] is False and rules[1]["position"] == 1


def test_handles_json_wrapped_payload():
    import json
    wrapped = json.dumps({"result": _sample()})
    rules = parse_security_rules(wrapped, "panosvm", "2026-06-08T00:00:00")
    assert len(rules) == 2


def test_real_fixture_parses_only_security_rules():
    rules = parse_security_rules(FIXTURE.read_text(), "panosvm", "2026-06-08T00:00:00")
    # the fixture has exactly 5 security rules; must NOT pick up zone/address entries
    assert [r["rule_name"] for r in rules] == [
        "drifttest1", "allow-trust-to-dmz", "allow-corp-to-internet",
        "allow-untrust-to-trust", "allow-trust-to-untrust",
    ]
    assert all(r["rule_name"] and r["action"] for r in rules)
    assert rules[0]["position"] == 0


from ssdf_policy.collectors.panos import _root

_BILLION_LAUGHS = """<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
]>
<response><result><rules><entry name="&lol2;"/></rules></response>"""


def test_root_rejects_entity_expansion():
    assert _root(_BILLION_LAUGHS) is None


def test_collect_uses_current_panos_mcp_tool_contract():
    """Pin the panos-mcp tool + argument names the collector depends on.

    The MCP server renamed these (get_pan_config/host -> get_panos_config/device);
    the collector silently collected nothing until the names were realigned.
    """
    from ssdf_policy.collectors.panos import PanosPolicyCollector

    calls: list[tuple[str, dict]] = []

    class _RecordingClient:
        def call_tool(self, name, args=None):
            calls.append((name, args or {}))
            return "<rules></rules>"

    PanosPolicyCollector("panosvm").collect(_RecordingClient(), "2026-08-19T00:00:00Z")

    assert [c[0] for c in calls] == ["get_panos_config"]
    assert calls[0][1] == {"device": "panosvm"}


def test_root_unwraps_panos_mcp_output_content_envelope():
    """get_panos_config wraps the XML in {"output": {"content": ...}}.

    The older get_pan_config used a flat {"result": ...} envelope; only that
    shape was unwrapped, so every live pass parsed the JSON as XML and failed.
    """
    import json as _json
    from ssdf_policy.collectors.panos import _root

    xml = (
        "<response status='success'><result><config>"
        "<rulebase><security><rules>"
        "<entry name='r1'><action>allow</action></entry>"
        "</rules></security></rulebase>"
        "</config></result></response>"
    )
    envelope = _json.dumps(
        {"device": "panosvm", "source": "running", "status": "success", "output": {"content": xml}}
    )

    root = _root(envelope)
    assert root is not None
    assert root.find(".//rulebase/security/rules") is not None


def test_parse_security_rules_reads_output_content_envelope():
    import json as _json
    from ssdf_policy.collectors.panos import parse_security_rules

    xml = (
        "<response status='success'><result><config>"
        "<rulebase><security><rules>"
        "<entry name='allow-web'>"
        "<from><member>trust</member></from>"
        "<to><member>untrust</member></to>"
        "<source><member>any</member></source>"
        "<destination><member>any</member></destination>"
        "<application><member>web-browsing</member></application>"
        "<service><member>application-default</member></service>"
        "<action>allow</action>"
        "</entry>"
        "</rules></security></rulebase>"
        "</config></result></response>"
    )
    envelope = _json.dumps({"device": "panosvm", "output": {"content": xml}})

    rules = parse_security_rules(envelope, "panosvm", "2026-08-19T00:00:00Z")
    assert len(rules) == 1
    assert rules[0]["rule_name"] == "allow-web"
