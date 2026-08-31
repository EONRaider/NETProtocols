"""DHCP decoding, driven by crafted messages for the decode contract,
option parsing, and UDP port dispatch."""

import struct

import pytest

from conftest import FIXTURES, read_pcap
from netprotocols import (
    DHCP,
    UDP,
    Ethernet,
    InvalidFieldError,
    IPv4,
    TruncatedHeaderError,
)
from test_corpus import walk

MAGIC = b"\x63\x82\x53\x63"


def ipv4_bytes(addr: str) -> bytes:
    return bytes(int(octet) for octet in addr.split("."))


def mac_bytes(mac: str) -> bytes:
    return bytes.fromhex(mac.replace(":", ""))


def build_options(
    entries: list[tuple[int, bytes]], *, cookie: bytes = MAGIC
) -> bytes:
    body = cookie
    for code, value in entries:
        body += bytes([code, len(value)]) + value
    return body + bytes([255])  # END


def build_dhcp(
    *,
    op: int = 2,
    flags: int = 0,
    xid: int = 0x3903F326,
    ciaddr: str = "0.0.0.0",
    yiaddr: str = "0.0.0.0",
    siaddr: str = "0.0.0.0",
    giaddr: str = "0.0.0.0",
    chaddr_mac: str = "00:0c:29:ab:cd:ef",
    sname: bytes = b"",
    file: bytes = b"",
    options: bytes = MAGIC + bytes([255]),
) -> bytes:
    fixed = struct.pack("!4BIHH", op, 1, 6, 0, xid, 0, flags)
    fixed += ipv4_bytes(ciaddr) + ipv4_bytes(yiaddr)
    fixed += ipv4_bytes(siaddr) + ipv4_bytes(giaddr)
    fixed += mac_bytes(chaddr_mac).ljust(16, b"\x00")
    fixed += sname.ljust(64, b"\x00")
    fixed += file.ljust(128, b"\x00")
    return fixed + options


class TestDHCPFields:
    def test_offer_fixed_header(self):
        raw = build_dhcp(
            op=2,
            flags=0x8000,
            yiaddr="192.168.1.100",
            siaddr="192.168.1.1",
            chaddr_mac="00:0c:29:ab:cd:ef",
        )
        dhcp = DHCP.decode(raw)
        assert dhcp.op == 2
        assert dhcp.op_name == "BOOTREPLY"
        assert dhcp.htype == 1
        assert dhcp.hlen == 6
        assert dhcp.xid == 0x3903F326
        assert dhcp.yiaddr == "192.168.1.100"
        assert dhcp.siaddr == "192.168.1.1"
        assert dhcp.ciaddr == "0.0.0.0"
        assert dhcp.is_broadcast is True
        assert dhcp.client_mac == "00:0c:29:ab:cd:ef"

    def test_request_op_name(self):
        dhcp = DHCP.decode(build_dhcp(op=1))
        assert dhcp.op_name == "BOOTREQUEST"
        assert dhcp.is_broadcast is False

    def test_unknown_op_degrades(self):
        dhcp = DHCP.decode(build_dhcp(op=7))
        assert dhcp.op_name == "unknown (0x07)"

    def test_client_mac_none_for_non_ethernet(self):
        raw = bytearray(build_dhcp())
        raw[1] = 0  # htype = 0 (not Ethernet)
        assert DHCP.decode(bytes(raw)).client_mac is None

    def test_server_name_and_boot_file(self):
        dhcp = DHCP.decode(build_dhcp(sname=b"dhcp-server", file=b"pxelinux.0"))
        assert dhcp.server_name == "dhcp-server"
        assert dhcp.boot_file == "pxelinux.0"

    def test_header_len_consumes_whole_message(self):
        raw = build_dhcp(options=build_options([(53, b"\x05")]))
        dhcp = DHCP.decode(raw)
        assert dhcp.header_len == len(raw)
        assert bytes(dhcp) == raw


class TestDHCPOptions:
    def test_message_type_and_name(self):
        raw = build_dhcp(options=build_options([(53, b"\x01")]))  # DISCOVER
        dhcp = DHCP.decode(raw)
        assert dhcp.has_magic_cookie is True
        assert dhcp.message_type == 1
        assert dhcp.message_type_name == "DISCOVER"

    def test_option_map_parses_tlvs(self):
        raw = build_dhcp(
            options=build_options(
                [
                    (53, b"\x02"),  # OFFER
                    (1, ipv4_bytes("255.255.255.0")),  # subnet mask
                    (54, ipv4_bytes("192.168.1.1")),  # server identifier
                ]
            )
        )
        options = DHCP.decode(raw).option_map
        assert options[53] == b"\x02"
        assert options[1] == ipv4_bytes("255.255.255.0")
        assert options[54] == ipv4_bytes("192.168.1.1")

    def test_pad_options_are_skipped(self):
        # Two PAD bytes (0x00) between the cookie and the message type.
        raw = build_dhcp(options=MAGIC + b"\x00\x00" + bytes([53, 1, 3, 255]))
        dhcp = DHCP.decode(raw)
        assert dhcp.message_type == 3  # REQUEST
        assert dhcp.message_type_name == "REQUEST"

    def test_split_option_is_concatenated(self):
        # RFC 3396: option 43 appearing twice concatenates in order.
        raw = build_dhcp(
            options=build_options([(43, b"\xaa\xbb"), (43, b"\xcc\xdd")])
        )
        assert DHCP.decode(raw).option_map[43] == b"\xaa\xbb\xcc\xdd"

    def test_unknown_message_type_degrades(self):
        raw = build_dhcp(options=build_options([(53, b"\x63")]))  # 99
        assert DHCP.decode(raw).message_type_name == "unknown (0x63)"

    def test_plain_bootp_without_options(self):
        # A BOOTP message whose options field is empty: no cookie, no
        # message type, but still a valid, round-tripping frame.
        raw = build_dhcp(options=b"")
        dhcp = DHCP.decode(raw)
        assert dhcp.has_magic_cookie is False
        assert dhcp.option_map == {}
        assert dhcp.message_type is None
        assert dhcp.message_type_name is None
        assert bytes(dhcp) == raw

    def test_message_type_wrong_length_is_none(self):
        raw = build_dhcp(options=build_options([(53, b"\x05\x05")]))
        assert DHCP.decode(raw).message_type is None


class TestDHCPContract:
    def test_truncated_fixed_header_raises(self):
        with pytest.raises(TruncatedHeaderError):
            DHCP.decode(build_dhcp()[:235])

    def test_missing_magic_cookie_raises(self):
        raw = build_dhcp(options=b"\x00\x00\x00\x00" + bytes([53, 1, 1, 255]))
        with pytest.raises(InvalidFieldError):
            _ = DHCP.decode(raw).option_map

    def test_option_running_past_buffer_raises(self):
        # Option 53 declares length 4 but only one value byte follows.
        raw = build_dhcp(options=MAGIC + bytes([53, 4, 1]))
        with pytest.raises(InvalidFieldError):
            _ = DHCP.decode(raw).option_map

    def test_option_missing_length_byte_raises(self):
        raw = build_dhcp(options=MAGIC + bytes([53]))  # code, no length
        with pytest.raises(InvalidFieldError):
            _ = DHCP.decode(raw).option_map

    def test_round_trip_is_byte_exact(self):
        raw = build_dhcp(
            op=2,
            flags=0x8000,
            yiaddr="10.0.0.55",
            sname=b"srv",
            file=b"boot.img",
            options=build_options([(53, b"\x05"), (51, b"\x00\x00\x0e\x10")]),
        )
        assert bytes(DHCP.decode(raw)) == raw

    def test_dhcp_ends_the_chain(self):
        assert DHCP.decode(build_dhcp()).next_protocol() is None


class TestCorpusDHCP:
    def test_dora_exchange_decodes(self):
        frames = read_pcap(FIXTURES / "dhcp.pcap")
        assert frames
        for frame in frames:
            layers = walk(frame)[0]
            assert [type(layer) for layer in layers] == [
                Ethernet,
                IPv4,
                UDP,
                DHCP,
            ]
        # The four DORA message types are present (option 53):
        # DISCOVER 1, OFFER 2, REQUEST 3, ACK 5.
        types = {walk(frame)[0][-1].message_type for frame in frames}
        assert {1, 2, 3, 5} <= types

    def test_offer_assigns_an_address(self):
        offer = next(
            dhcp
            for dhcp in (
                walk(f)[0][-1] for f in read_pcap(FIXTURES / "dhcp.pcap")
            )
            if dhcp.message_type == 2
        )
        assert offer.op_name == "BOOTREPLY"
        assert offer.yiaddr != "0.0.0.0"
        assert offer.client_mac is not None


class TestDHCPDispatch:
    def test_udp_dst_67_dispatches(self):
        udp = UDP(src_port=68, dst_port=67, length=8, checksum=0)
        assert udp.next_protocol() is DHCP

    def test_udp_dst_68_dispatches(self):
        udp = UDP(src_port=67, dst_port=68, length=8, checksum=0)
        assert udp.next_protocol() is DHCP

    def test_non_dhcp_ports_do_not_dispatch(self):
        udp = UDP(src_port=12345, dst_port=80, length=8, checksum=0)
        assert udp.next_protocol() is None
