import pytest

from netprotocols import ARP, InvalidIPv4AddressError


@pytest.fixture
def arp_reply() -> ARP:
    return ARP(
        htype=1,
        ptype=0x0800,
        hlen=6,
        plen=4,
        oper=2,
        sha="00:07:0d:af:f4:54",
        spa="24.166.172.1",
        tha="00:00:00:00:00:00",
        tpa="24.166.173.159",
    )


class TestARP:
    def test_decode(self, raw_arp_header):
        arp = ARP.decode(raw_arp_header)
        assert arp.htype == 1
        assert arp.ptype == 0x0800
        assert arp.hlen == 6
        assert arp.plen == 4
        assert arp.oper == 1
        assert arp.sha == "00:07:0d:af:f4:54"
        assert arp.spa == "24.166.172.1"
        assert arp.tha == "00:00:00:00:00:00"
        assert arp.tpa == "24.166.173.159"
        assert arp.oper_name == "request"
        assert arp.ptype_name == "IPv4"
        assert arp.ptype_hex_str == "0x0800"
        assert arp.header_len == 28

    def test_round_trip(self, raw_arp_header):
        arp = ARP.decode(raw_arp_header)
        assert bytes(arp) == raw_arp_header
        assert ARP.decode(bytes(arp)) == arp

    def test_build(self, arp_reply):
        assert arp_reply.oper_name == "reply"
        assert bytes(arp_reply) == (
            b"\x00\x01\x08\x00\x06\x04\x00\x02\x00\x07\x0d\xaf\xf4\x54"
            b"\x18\xa6\xac\x01\x00\x00\x00\x00\x00\x00\x18\xa6\xad\x9f"
        )

    def test_chain_ends_here(self, arp_reply):
        assert arp_reply.next_protocol() is None

    def test_invalid_protocol_address_rejected(self):
        with pytest.raises(InvalidIPv4AddressError):
            ARP(
                htype=1,
                ptype=0x0800,
                hlen=6,
                plen=4,
                oper=1,
                sha="00:07:0d:af:f4:54",
                spa="999.1.1.1",
                tha="00:00:00:00:00:00",
                tpa="24.166.173.159",
            )
