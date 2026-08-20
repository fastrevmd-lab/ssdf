from ssdf_pubmetrics.pseudonym import surrogate, mint_surrogate, PREFIXES

KEY = bytes.fromhex("00112233445566778899aabbccddeeff")


def test_surrogate_is_deterministic():
    assert surrogate(KEY, "host", "10.74.11.20") == surrogate(KEY, "host", "10.74.11.20")


def test_surrogate_has_kind_prefix():
    assert surrogate(KEY, "host", "10.74.11.20").startswith("h_")
    assert surrogate(KEY, "firewall", "panosvm").startswith("fw_")


def test_surrogate_changes_with_key():
    other = bytes.fromhex("ffeeddccbbaa99887766554433221100")
    assert surrogate(KEY, "host", "10.74.11.20") != surrogate(other, "host", "10.74.11.20")


def test_surrogate_unknown_kind_raises():
    import pytest

    with pytest.raises(ValueError):
        surrogate(KEY, "bogus", "x")


def test_mint_reuses_existing_map_entry():
    existing = {("host", "10.74.11.20"): "h_deadbeef00"}
    assert mint_surrogate(existing, KEY, "host", "10.74.11.20") == "h_deadbeef00"


def test_mint_lengthens_on_collision_with_different_value():
    # Force a collision: a DIFFERENT real_value already holds the base-length surrogate.
    base = surrogate(KEY, "host", "10.74.11.20")
    existing = {("host", "1.2.3.4"): base}
    minted = mint_surrogate(existing, KEY, "host", "10.74.11.20", base_length=len(base) - 2)
    assert minted != base
    assert minted.startswith("h_")
