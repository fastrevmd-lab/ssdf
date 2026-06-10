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


def test_missing_file_raises(tmp_path):
    missing = tmp_path / "does-not-exist.json"
    with pytest.raises(ConfigError):
        load_classification(str(missing))


from ssdf_mcp_query.classification import (
    PUBLIC_EXCLUDED_TOOLS,
    is_tool_shareable,
    public_tool_names,
)

ALL_TOOLS = [
    "query_flows", "describe_schema", "top_talkers", "run_sql", "get_entity",
    "locate", "neighbors", "find_path", "enforcement_points",
    "topology_snapshot", "explain_access",
]


def _classification(**overrides):
    """Build a Classification with the given class->label overrides (rest sovereign)."""
    import json, tempfile, os
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as handle:
        json.dump(overrides, handle)
    try:
        return load_classification(path)
    finally:
        os.unlink(path)


def test_run_sql_is_excluded_from_public():
    assert "run_sql" in PUBLIC_EXCLUDED_TOOLS


def test_no_shareable_classes_yields_empty_public_set():
    classification = _classification()  # all sovereign
    assert public_tool_names(classification, ALL_TOOLS) == []


def test_topology_flip_exposes_four_topology_tools():
    classification = _classification(topology="shareable")
    assert public_tool_names(classification, ALL_TOOLS) == [
        "locate", "neighbors", "find_path", "topology_snapshot",
    ]


def test_identity_flip_exposes_get_entity_only():
    classification = _classification(identity="shareable")
    assert public_tool_names(classification, ALL_TOOLS) == ["get_entity"]


def test_both_flips_expose_five_tools_and_not_run_sql():
    classification = _classification(topology="shareable", identity="shareable")
    selected = public_tool_names(classification, ALL_TOOLS)
    assert selected == [
        "get_entity", "locate", "neighbors", "find_path", "topology_snapshot",
    ]
    assert "run_sql" not in selected
    # enforcement_points + explain_access carry locked classes -> never public
    assert "enforcement_points" not in selected
    assert "explain_access" not in selected


def test_is_tool_shareable_false_for_unknown_tool():
    classification = _classification(topology="shareable", identity="shareable")
    assert is_tool_shareable(classification, "made_up_tool") is False
