import json
import pytest
from ssdf_mcp_query.classification import (
    classes_for_tool,
    load_classification,
    TOOL_DATA_CLASSES,
)
from ssdf_mcp_query.config import ConfigError

EXPECTED = {
    "query_flows": {"security_log"},
    "describe_schema": {"security_log"},
    "top_talkers": {"security_log"},
    "run_sql": {"security_log"},
    "get_entity": {"identity"},
    "locate": {"topology"},
    "neighbors": {"topology"},
    "find_path": {"topology"},
    "enforcement_points": {"topology", "firewall_config"},
    "topology_snapshot": {"topology"},
    "explain_access": {"security_log", "topology", "identity", "firewall_config"},
}


def test_tool_class_map_matches_spec():
    assert set(TOOL_DATA_CLASSES) == set(EXPECTED)
    for tool, classes in EXPECTED.items():
        assert set(classes_for_tool(tool)) == classes


def test_unknown_tool_returns_empty():
    assert classes_for_tool("does_not_exist") == frozenset()


def test_defaults_all_sovereign():
    c = load_classification(None)
    for cls in ("security_log", "firewall_config", "topology", "identity"):
        assert c.label_for_class(cls) == "sovereign"


def test_override_topology_shareable(tmp_path):
    f = tmp_path / "cls.json"
    f.write_text(json.dumps({"topology": "shareable"}))
    c = load_classification(str(f))
    assert c.label_for_class("topology") == "shareable"
    assert c.label_for_class("identity") == "sovereign"


def test_override_identity_sovereign_is_noop(tmp_path):
    f = tmp_path / "cls.json"
    f.write_text(json.dumps({"identity": "sovereign"}))
    assert load_classification(str(f)).label_for_class("identity") == "sovereign"


@pytest.mark.parametrize("cls", ["security_log", "firewall_config"])
def test_reject_non_configurable_override(tmp_path, cls):
    f = tmp_path / "cls.json"
    f.write_text(json.dumps({cls: "shareable"}))
    with pytest.raises(ConfigError):
        load_classification(str(f))


def test_reject_unknown_class(tmp_path):
    f = tmp_path / "cls.json"
    f.write_text(json.dumps({"bogus": "shareable"}))
    with pytest.raises(ConfigError):
        load_classification(str(f))


def test_reject_bad_value(tmp_path):
    f = tmp_path / "cls.json"
    f.write_text(json.dumps({"topology": "public"}))
    with pytest.raises(ConfigError):
        load_classification(str(f))


def test_reject_non_object_json(tmp_path):
    f = tmp_path / "cls.json"
    f.write_text(json.dumps(["topology"]))
    with pytest.raises(ConfigError):
        load_classification(str(f))


def test_label_for_unknown_class_raises():
    with pytest.raises(ConfigError):
        load_classification(None).label_for_class("bogus")
