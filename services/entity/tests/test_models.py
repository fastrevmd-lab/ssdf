from ssdf_entity.models import (
    ASSET,
    POLICY,
    IDENTITY,
    COMMUNICATED_WITH,
    GOVERNED_BY,
    OBSERVED,
    CONFIGURED,
    entity_id,
    edge_id,
)


def test_entity_id_is_stable_and_namespaced():
    a = entity_id("t_main", ASSET, "mac:aa:bb")
    b = entity_id("t_main", ASSET, "mac:aa:bb")
    c = entity_id("t_main", ASSET, "ip:10.64.0.5")
    assert a == b and a != c
    assert len(a) == 16


def test_edge_id_distinguishes_source_and_type():
    base = ("t_main", "s", "d")
    assert edge_id(*base, COMMUNICATED_WITH, OBSERVED) != edge_id(*base, GOVERNED_BY, OBSERVED)
    assert edge_id(*base, COMMUNICATED_WITH, OBSERVED) != edge_id(
        *base, COMMUNICATED_WITH, CONFIGURED
    )


def test_constants_exist():
    assert {ASSET, POLICY, IDENTITY} == {"asset", "policy", "identity"}
    assert OBSERVED == "observed" and CONFIGURED == "configured"
