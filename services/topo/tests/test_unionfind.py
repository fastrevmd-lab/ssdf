from ssdf_topo.resolver.unionfind import UnionFind

def test_union_groups_connected_identifiers():
    uf = UnionFind()
    uf.union("chassis:abc", "sysname:sw1")
    uf.union("sysname:sw1", "mgmt:10.64.0.1")
    uf.add("mac:aa")
    groups = uf.groups()
    members = next(g for g in groups.values() if "chassis:abc" in g)
    assert set(members) == {"chassis:abc", "sysname:sw1", "mgmt:10.64.0.1"}
    assert any(g == ["mac:aa"] for g in groups.values())

def test_find_is_stable():
    uf = UnionFind()
    uf.union("a", "b")
    assert uf.find("a") == uf.find("b")
