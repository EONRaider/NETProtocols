import pytest

from netprotocols import ARP, Ethernet, EtherType, InvalidMACAddressError


class TestEthernet:
    def test_decode(self, raw_eth_header):
        eth = Ethernet.decode(raw_eth_header)
        assert eth.dst == "ff:ff:ff:ff:ff:ff"
        assert eth.src == "00:07:0d:af:f4:54"
        assert eth.ethertype == 0x0806
        assert eth.ethertype_name == "ARP"
        assert eth.ethertype_enum == EtherType.ARP
        assert eth.header_len == 14

    def test_round_trip(self, raw_eth_header):
        eth = Ethernet.decode(raw_eth_header)
        assert bytes(eth) == raw_eth_header
        assert Ethernet.decode(bytes(eth)) == eth

    def test_build(self):
        eth = Ethernet(
            dst="ff:ff:ff:ff:ff:ff", src="00:07:0d:af:f4:54", ethertype=0x0806
        )
        assert bytes(eth) == (
            b"\xff\xff\xff\xff\xff\xff\x00\x07\x0d\xaf\xf4\x54\x08\x06"
        )

    def test_next_protocol(self, raw_eth_header):
        assert Ethernet.decode(raw_eth_header).next_protocol() is ARP

    def test_unknown_ethertype_ends_chain(self):
        eth = Ethernet(
            dst="ff:ff:ff:ff:ff:ff", src="00:07:0d:af:f4:54", ethertype=0x88CC
        )
        assert eth.next_protocol() is None
        assert eth.ethertype_name == "0x88cc"
        assert eth.ethertype_enum is None

    def test_invalid_mac_rejected(self):
        with pytest.raises(InvalidMACAddressError):
            Ethernet(dst="not-a-mac", src="00:07:0d:af:f4:54", ethertype=0x0800)
