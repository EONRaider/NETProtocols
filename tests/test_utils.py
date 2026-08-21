import pytest

from netprotocols import (
    InvalidIPv4AddressError,
    InvalidMACAddressError,
    InvalidManufacturerCodeError,
    random_mac,
    validate_ipv4_addr,
    validate_mac_addr,
)
from netprotocols.utils.mac import mac_regex


class TestValidateMACAddress:
    @pytest.mark.parametrize(
        "mac",
        ["00:c0:ca:a8:19:74", "00-C0-CA-A8-19-74", "FF:FF:FF:FF:FF:FF"],
    )
    def test_valid(self, mac):
        assert validate_mac_addr(mac) == mac

    @pytest.mark.parametrize(
        "mac",
        [
            "00:c0:ca:a8:19",
            "00:c0:ca:a8:19:74:ff",
            "gg:c0:ca:a8:19:74",
            "",
            None,
            42,
        ],
    )
    def test_invalid(self, mac):
        with pytest.raises(InvalidMACAddressError):
            validate_mac_addr(mac)


class TestValidateIPv4Address:
    @pytest.mark.parametrize(
        "addr", ["0.0.0.0", "192.168.1.96", "255.255.255.255"]
    )
    def test_valid(self, addr):
        assert validate_ipv4_addr(addr) == addr

    @pytest.mark.parametrize(
        "addr",
        ["256.1.1.1", "192.168.1", "192.168.1.1.1", "fe80::1", "", None, 42],
    )
    def test_invalid(self, addr):
        with pytest.raises(InvalidIPv4AddressError):
            validate_ipv4_addr(addr)


class TestRandomMAC:
    def test_generates_valid_addresses(self):
        for _ in range(50):
            assert mac_regex.match(random_mac())

    def test_fixed_manufacturer_prefix(self):
        mac = random_mac("AA:BB:CC")
        assert mac.startswith("AA:BB:CC:")
        assert mac_regex.match(mac)

    def test_invalid_manufacturer_rejected(self):
        with pytest.raises(InvalidManufacturerCodeError):
            random_mac("not-an-oui")
