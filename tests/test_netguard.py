from backend.netguard import is_protected_address, parse_address


def test_loopback_and_unspecified_are_protected():
    for address in ("127.0.0.1", "::1", "0.0.0.0", "::"):
        assert is_protected_address(address) is True, address


def test_private_ranges_are_protected():
    for address in ("10.1.2.3", "172.19.0.1", "192.168.1.1", "169.254.10.5", "fd00::1"):
        assert is_protected_address(address) is True, address


def test_multicast_is_protected():
    assert is_protected_address("224.0.0.1") is True


def test_documentation_ranges_are_not_protected():
    # These are the synthetic attacker addresses the demo relies on.
    for address in ("203.0.113.66", "198.51.100.7", "192.0.2.5"):
        assert is_protected_address(address) is False, address


def test_public_addresses_are_not_protected():
    assert is_protected_address("8.8.8.8") is False
    assert is_protected_address("1.1.1.1") is False


def test_invalid_values_are_never_protected():
    for value in ("not-an-ip", "", None, "999.1.1.1"):
        assert is_protected_address(value) is False, value
        assert parse_address(value) is None
