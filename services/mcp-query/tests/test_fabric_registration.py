from ssdf_mcp_query.classification import TOOL_DATA_CLASSES, Classification, public_tool_names


def test_fabric_status_is_classed_security_log():
    assert TOOL_DATA_CLASSES["fabric_status"] == frozenset({"security_log"})


def test_fabric_status_can_never_be_public():
    """security_log is not a configurable class, so no config can flip it. The
    response carries device names, provider inventory and infrastructure shape."""
    # Even with every configurable class flipped shareable, fabric_status must
    # not be selected for a public build.
    classification = Classification(
        {
            "security_log": "sovereign",
            "firewall_config": "sovereign",
            "topology": "shareable",
            "identity": "shareable",
            "metrics": "shareable",
        }
    )
    selected = public_tool_names(classification, ["fabric_status", "locate"])
    assert "fabric_status" not in selected
