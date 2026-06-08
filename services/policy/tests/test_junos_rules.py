from pathlib import Path
from ssdf_policy.collectors.junos import parse_security_policies

GLOBAL_FIXTURE = Path(__file__).parent / "fixtures" / "junos_security_set_global.txt"
ZONEPAIR_FIXTURE = Path(__file__).parent / "fixtures" / "junos_security_set_zonepair.txt"

SAMPLE = """
set security policies from-zone trust to-zone untrust policy ALLOW-WEB match source-address any
set security policies from-zone trust to-zone untrust policy ALLOW-WEB match destination-address any
set security policies from-zone trust to-zone untrust policy ALLOW-WEB match application junos-http
set security policies from-zone trust to-zone untrust policy ALLOW-WEB then permit
set security policies from-zone trust to-zone untrust policy DENY-ALL match source-address any
set security policies from-zone trust to-zone untrust policy DENY-ALL match destination-address any
set security policies from-zone trust to-zone untrust policy DENY-ALL match application any
set security policies from-zone trust to-zone untrust policy DENY-ALL then deny
""".strip()


def test_groups_terms_into_rules_with_action_and_zones():
    rules = parse_security_policies(SAMPLE, "vSRX-test10", "2026-06-08T00:00:00")
    by_name = {r["rule_name"]: r for r in rules}
    assert set(by_name) == {"ALLOW-WEB", "DENY-ALL"}
    web = by_name["ALLOW-WEB"]
    assert web["provider"] == "juniper"
    assert web["device_name"] == "vSRX-test10"
    assert web["action"] == "allow"            # permit -> allow
    assert web["from_zone"] == ["trust"] and web["to_zone"] == ["untrust"]
    assert web["application"] == ["junos-http"]
    assert web["enabled"] is True
    assert by_name["DENY-ALL"]["action"] == "deny"


def test_position_follows_first_appearance_order():
    rules = parse_security_policies(SAMPLE, "vSRX-test10", "2026-06-08T00:00:00")
    assert [r["rule_name"] for r in sorted(rules, key=lambda r: r["position"])] == \
        ["ALLOW-WEB", "DENY-ALL"]


def test_parses_global_policy_fixture():
    # Live lab device emits a global baseline-permit policy (XML-wrapped set lines).
    rules = parse_security_policies(GLOBAL_FIXTURE.read_text(), "vSRX-test10", "2026-06-08T00:00:00")
    by_name = {r["rule_name"]: r for r in rules}
    assert "baseline-permit" in by_name
    perm = by_name["baseline-permit"]
    assert perm["action"] == "allow"
    assert perm["from_zone"] == ["any"] and perm["to_zone"] == ["any"]
    # the pre-id-default-policy line is not a real policy and must be skipped
    assert "pre-id-default-policy" not in by_name


def test_parses_zonepair_fixture_actions():
    rules = parse_security_policies(ZONEPAIR_FIXTURE.read_text(), "vSRX-test11", "2026-06-08T00:00:00")
    by_name = {r["rule_name"]: r for r in rules}
    assert by_name["allow-web"]["action"] == "allow"
    assert by_name["deny-telnet"]["action"] == "deny"
    assert by_name["block-all"]["action"] == "reject"
    assert all(r["rule_name"] and r["action"] for r in rules)
