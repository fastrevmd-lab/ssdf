"""MEC-992: Junos address-book + application object-book collection."""

from ssdf_policy.collectors.junos import (
    parse_address_book,
    parse_applications,
    parse_predefined_applications,
)

ADDRESS_BOOK_TEXT = """
set security address-book global address ADDR1 10.1.1.0/24
set security address-book global address ADDR2 dns-name example.com
set security address-book global address ADDR3 range-address 10.3.0.1 to 10.3.0.10
set security address-book global address ADDR4 wildcard-address 10.4.0.0/255.0.255.0
set security address-book global address-set SET1 address ADDR1
set security address-book global address-set SET1 address ADDR3
set security address-book global address-set NESTED address-set SET1
""".strip()

ZONE_ADDRESS_BOOK_TEXT = """
set security zones security-zone trust address-book address ZADDR1 10.2.0.0/16
set security zones security-zone trust address-book address-set ZSET1 address ZADDR1
""".strip()

APPLICATIONS_TEXT = """
set applications application CUSTOM-APP protocol tcp
set applications application CUSTOM-APP destination-port 8443
set applications application-set CUSTOM-SET application CUSTOM-APP
""".strip()

PREDEFINED_TEXT = """
set groups junos-defaults applications application junos-http protocol tcp
set groups junos-defaults applications application junos-http destination-port 80
set groups junos-defaults applications application junos-http inactivity-timeout 300
""".strip()


def test_plain_address_resolves_to_value():
    books = parse_address_book(ADDRESS_BOOK_TEXT)
    assert books["global"]["addresses"]["ADDR1"] == {"kind": "address", "value": "10.1.1.0/24"}


def test_dns_name_address_resolves_to_unknown():
    books = parse_address_book(ADDRESS_BOOK_TEXT)
    assert books["global"]["addresses"]["ADDR2"] == {"kind": "unknown", "reason": "dns-name"}


def test_range_address_resolves_to_low_high():
    books = parse_address_book(ADDRESS_BOOK_TEXT)
    assert books["global"]["addresses"]["ADDR3"] == {
        "kind": "range",
        "low": "10.3.0.1",
        "high": "10.3.0.10",
    }


def test_wildcard_address_resolves_to_value():
    books = parse_address_book(ADDRESS_BOOK_TEXT)
    assert books["global"]["addresses"]["ADDR4"] == {
        "kind": "wildcard",
        "value": "10.4.0.0/255.0.255.0",
    }


def test_address_set_collects_members_including_nested_sets():
    books = parse_address_book(ADDRESS_BOOK_TEXT)
    assert set(books["global"]["address_sets"]["SET1"]["members"]) == {"ADDR1", "ADDR3"}
    assert books["global"]["address_sets"]["NESTED"]["members"] == ["SET1"]


def test_zone_address_book_is_keyed_separately_from_global():
    books = parse_address_book(ZONE_ADDRESS_BOOK_TEXT)
    assert books["zone:trust"]["addresses"]["ZADDR1"] == {"kind": "address", "value": "10.2.0.0/16"}
    assert books["zone:trust"]["address_sets"]["ZSET1"]["members"] == ["ZADDR1"]


def test_custom_application_fields_are_parsed():
    result = parse_applications(APPLICATIONS_TEXT)
    assert result["applications"]["CUSTOM-APP"]["protocol"] == "tcp"
    assert result["applications"]["CUSTOM-APP"]["destination_port"] == "8443"
    assert result["application_sets"]["CUSTOM-SET"]["members"] == ["CUSTOM-APP"]


def test_predefined_applications_parsed_from_junos_defaults_group():
    # Confirmed read-only-readable on vsrx-ci, 2026-09-30 (task MEC-992 item 5):
    # `show configuration groups junos-defaults applications | display set`.
    predefined = parse_predefined_applications(PREDEFINED_TEXT)
    assert predefined["junos-http"]["protocol"] == "tcp"
    assert predefined["junos-http"]["destination_port"] == "80"
    assert predefined["junos-http"]["inactivity_timeout"] == "300"


def test_empty_input_yields_empty_book():
    assert parse_address_book("") == {}
    result = parse_applications("")
    assert result == {"applications": {}, "application_sets": {}}


def test_collect_objects_builds_per_device_object_book():
    from ssdf_policy.collectors.junos import JunosPolicyCollector

    class _FakeClient:
        def call_tool(self, name, args=None):
            command = (args or {}).get("command", "")
            if "address-book" in command:
                return ADDRESS_BOOK_TEXT
            if "security zones" in command:
                return ZONE_ADDRESS_BOOK_TEXT
            if "groups junos-defaults" in command:
                return PREDEFINED_TEXT
            if "applications" in command:
                return APPLICATIONS_TEXT
            return ""

    books = JunosPolicyCollector(["vSRX-test10"]).collect_objects(
        _FakeClient(), "2026-09-30T00:00:00Z"
    )
    assert len(books) == 1
    book = books[0]
    assert book["provider"] == "juniper"
    assert book["device_name"] == "vSRX-test10"
    assert book["object_book"]["address_books"]["global"]["addresses"]["ADDR1"]["kind"] == "address"
    assert book["object_book"]["applications"]["CUSTOM-APP"]["protocol"] == "tcp"
    assert book["object_book"]["predefined_applications"]["junos-http"]["protocol"] == "tcp"


def test_collect_objects_skips_unreachable_device():
    from ssdf_policy.collectors.junos import JunosPolicyCollector

    class _BoomClient:
        def call_tool(self, name, args=None):
            raise RuntimeError("device unreachable")

    books = JunosPolicyCollector(["vSRX-test10"]).collect_objects(
        _BoomClient(), "2026-09-30T00:00:00Z"
    )
    assert books == []
