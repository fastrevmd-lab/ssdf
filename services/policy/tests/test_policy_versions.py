from ssdf_policy.policy_versions import content_hash, diff_new_versions, version_key


def _policy(action="allow", enabled="true", position="0", from_zone="trust", to_zone="untrust"):
    return {
        "entity_id": "pol1",
        "tenant_id": "t_main",
        "kind": "policy",
        "name": "ALLOW-WEB",
        "attrs": {
            "provider": "juniper",
            "device_name": "vSRX-test10",
            "action": action,
            "from_zone": from_zone,
            "to_zone": to_zone,
            "enabled": enabled,
            "position": position,
        },
        "last_seen": "2026-09-28T00:00:00.000Z",
    }


def test_version_key_is_provider_device_rule():
    assert version_key(_policy()) == ("juniper", "vSRX-test10", "ALLOW-WEB")


def test_content_hash_stable_for_identical_attrs():
    assert content_hash(_policy()) == content_hash(_policy())


def test_content_hash_changes_when_action_changes():
    assert content_hash(_policy(action="allow")) != content_hash(_policy(action="deny"))


def test_content_hash_ignores_non_version_attrs():
    a = _policy()
    b = _policy()
    a["attrs"]["source_addresses"] = "10.0.0.0/8"
    b["attrs"]["source_addresses"] = "192.168.0.0/16"
    assert content_hash(a) == content_hash(b)


def test_diff_new_versions_emits_row_for_never_seen_rule():
    versions = diff_new_versions([_policy()], last_hash_by_key={})
    assert len(versions) == 1
    row = versions[0]
    assert row["rule_name"] == "ALLOW-WEB"
    assert row["provider"] == "juniper"
    assert row["device_name"] == "vSRX-test10"
    assert row["enabled"] is True
    assert row["content_hash"] == content_hash(_policy())


def test_diff_new_versions_skips_unchanged_rule():
    policy = _policy()
    known = {version_key(policy): content_hash(policy)}
    assert diff_new_versions([policy], known) == []


def test_diff_new_versions_emits_row_when_action_changes():
    old = _policy(action="allow")
    new = _policy(action="deny")
    known = {version_key(old): content_hash(old)}
    versions = diff_new_versions([new], known)
    assert len(versions) == 1
    assert versions[0]["action"] == "deny"


def test_diff_new_versions_ignores_non_policy_entities():
    firewall = {"kind": "firewall", "attrs": {}, "name": "fw1"}
    assert diff_new_versions([firewall], {}) == []
