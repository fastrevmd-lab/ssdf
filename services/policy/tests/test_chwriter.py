from ssdf_policy.chwriter import entity_rows, edge_rows, ENTITY_COLUMNS, ENTITY_EDGE_COLUMNS


def test_entity_rows_match_m6a_column_order():
    # Must equal services/entity ENTITY_COLUMNS so inserts target the shared table layout.
    assert ENTITY_COLUMNS == [
        "entity_id", "tenant_id", "kind", "name", "identifiers", "source",
        "identity_basis", "confidence", "attrs", "first_seen", "last_seen",
    ]
    assert ENTITY_EDGE_COLUMNS == [
        "edge_id", "tenant_id", "src_id", "dst_id", "edge_type", "source",
        "confidence", "attrs", "first_seen", "last_seen",
    ]
    ent = {c: c for c in ENTITY_COLUMNS}
    assert entity_rows([ent]) == [[c for c in ENTITY_COLUMNS]]
    edge = {c: c for c in ENTITY_EDGE_COLUMNS}
    assert edge_rows([edge]) == [[c for c in ENTITY_EDGE_COLUMNS]]
