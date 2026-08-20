def test_registry_has_both_vendors():
    from ssdf_policy import collectors  # noqa: F401  (triggers registration)
    from ssdf_policy.collectors.base import REGISTRY

    assert set(REGISTRY) == {"panos", "junos"}
