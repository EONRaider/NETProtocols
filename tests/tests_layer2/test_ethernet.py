from protocols.layer2.ethernet import Ethernet


dst_mac = "11:22:33:aa:bb:cc"
src_mac = "ab:bc:cd:11:22:33"
ethertype = 0x86dd
raw_header = b"\xdc\xd9\xae\x71\xc2\xa3\x00\xc0\xca\xa8\x20\x21\x08\x00"


class TestEthernet:
    def test_build_ethernet_header(self):
        """
        GIVEN a set of MAC addresses and Ethertype
        WHEN those values are valid and correctly formatted
        THEN an instance of Ethernet must be initialized without errors
        """
        eth_header = Ethernet(dst=dst_mac,
                              src=src_mac,
                              eth=ethertype)

        assert bytes(eth_header.dst) == b'\x11"3\xaa\xbb\xcc'
        assert bytes(eth_header.src) == b'\xab\xbc\xcd\x11"3'
        assert eth_header.eth == ethertype

    def test_decode_ethernet_header(self):
        """
        GIVEN a byte-string representation of an Ethernet header
        WHEN this header is successfully decoded
        THEN an instance of Ethernet must initialize each of its
            attributes in alignment with the byte fields
        """
        eth_header = Ethernet.decode(raw_header)

        assert eth_header.src == '00:c0:ca:a8:20:21'
        assert eth_header.dst == 'dc:d9:ae:71:c2:a3'
        assert eth_header.eth == 0x0800
        assert eth_header.encapsulated_proto == "IPv4"
