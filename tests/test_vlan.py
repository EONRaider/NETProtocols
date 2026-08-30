"""VLAN tag decoding: fields, single tag, QinQ stacking, round-trip,
and the decode contract (short buffers raise, never escape)."""

import struct

import pytest

from netprotocols import (
    VLAN,
    Ethernet,
    IPv4,
    Protocol,
    TruncatedHeaderError,
)

ETH = struct.Struct("!6s6sH")
TAG = struct.Struct("!HH")

DST = b"\xaa" * 6
SRC = b"\xbb" * 6


def tagged(inner_ethertype: int, payload: bytes, tci: int = 0x002A) -> bytes:
    return ETH.pack(DST, SRC, 0x8100) + TAG.pack(tci, inner_ethertype) + payload


class TestVLANFields:
    def test_decode_and_fields(self) -> None:
        tag = VLAN.decode(TAG.pack(0xE02A, 0x0800))
        assert tag.tci == 0xE02A
        assert tag.pcp == 7
        assert tag.dei == 0
        assert tag.vid == 42
        assert tag.ethertype == 0x0800
        assert tag.ethertype_name == "IPv4"
        assert tag.header_len == 4

    def test_roundtrip(self) -> None:
        tag = VLAN(tci=0x0123, ethertype=0x86DD)
        assert VLAN.decode(bytes(tag)) == tag

    def test_unknown_ethertype_name_falls_back(self) -> None:
        assert VLAN(tci=0, ethertype=0xCAFE).ethertype_name == "0xcafe"


class TestVLANChain:
    def test_single_tag_dispatch(self) -> None:
        ipv4_bytes = b"\x45" + b"\x00" * 19
        eth_header = Ethernet.decode(tagged(0x0800, ipv4_bytes))
        assert eth_header.ethertype_name == "802.1Q VLAN tag"
        tag_cls: type[Protocol] | None = eth_header.next_protocol()
        assert tag_cls is VLAN
        assert tag_cls is not None
        tag = tag_cls.decode(TAG.pack(0x002A, 0x0800) + ipv4_bytes)
        assert tag.next_protocol() is IPv4

    def test_qinq_stacks_one_layer_per_tag(self) -> None:
        ipv4_bytes = b"\x45" + b"\x00" * 19
        frame = (
            ETH.pack(DST, SRC, 0x88A8)
            + TAG.pack(0, 0x8100)
            + TAG.pack(0x002A, 0x0800)
            + ipv4_bytes
        )
        eth_header = Ethernet.decode(frame)
        first = eth_header.next_protocol()
        assert first is VLAN
        assert first is not None
        tag1 = first.decode(frame[ETH.size :])
        assert tag1.next_protocol() is VLAN
        tag2_cls = tag1.next_protocol()
        assert tag2_cls is not None
        tag2 = tag2_cls.decode(frame[ETH.size + VLAN._struct.size :])
        assert tag2.next_protocol() is IPv4


class TestVLANContract:
    def test_short_buffers_raise_truncated(self) -> None:
        with pytest.raises(TruncatedHeaderError):
            VLAN.decode(b"")
        with pytest.raises(TruncatedHeaderError):
            VLAN.decode(b"\x00")
        with pytest.raises(TruncatedHeaderError):
            VLAN.decode(b"\x00\x00\x00")

    def test_unknown_inner_ethertype_ends_chain(self) -> None:
        tag = VLAN(tci=0, ethertype=0xCAFE)
        assert tag.next_protocol() is None
