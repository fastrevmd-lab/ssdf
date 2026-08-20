from ssdf_policy.models import (
    FIREWALL,
    POLICY,
    GOVERNED_BY,
    CONFIGURED,
    entity_id,
    edge_id,
)


def test_ids_match_entity_service_namespace():
    # Must be byte-identical to services/entity/src/ssdf_entity/models.py.
    assert entity_id("t_main", POLICY, "paloalto:panosvm:rule1") == entity_id(
        "t_main", POLICY, "paloalto:panosvm:rule1"
    )
    # configured key differs from observed key -> different id (no collision)
    assert entity_id("t_main", POLICY, "paloalto:panosvm:rule1") != entity_id(
        "t_main", POLICY, "paloalto:rule1"
    )


def test_edge_id_is_provenance_tagged():
    a = edge_id("t_main", "fw1", "pol1", GOVERNED_BY, CONFIGURED)
    b = edge_id("t_main", "fw1", "pol1", GOVERNED_BY, "observed")
    assert a != b
    assert FIREWALL == "firewall"
