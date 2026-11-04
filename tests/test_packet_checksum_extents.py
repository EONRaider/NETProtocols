"""Packet checksums cover their enclosing IP datagram's bytes."""

import binascii
import struct
from dataclasses import replace

import pytest

from netprotocols import GRE, IGMP, IPv4, IPv6, Packet, compute, decode_frame
from test_vrrp import ones_complement


def ipv4(
    payload,
    protocol,
    options=b"",
    *,
    destination=b"\xc0\x00\x02\x02",
    ttl=64,
):
    header = (
        struct.pack(
            "!BBHHHBBH4s4s",
            0x45 + len(options) // 4,
            0,
            20 + len(options) + len(payload),
            1,
            0,
            ttl,
            protocol,
            0,
            bytes.fromhex("c0000201"),
            destination,
        )
        + options
    )
    checksum = ones_complement(header).to_bytes(2, "big")
    return header[:10] + checksum + header[12:] + payload


def ipv6(payload, next_header):
    return (
        struct.pack(
            "!IHBB16s16s",
            0x60000000,
            len(payload),
            next_header,
            64,
            bytes.fromhex("20010db8000000000000000000000001"),
            bytes.fromhex("20010db8000000000000000000000002"),
        )
        + payload
    )


def ethernet(
    payload,
    ethertype=0x0800,
    *,
    fcs=False,
    destination=b"\x00\x00\x5e\x00\x53\x02",
):
    frame = destination + bytes.fromhex("00005e005301")
    frame += ethertype.to_bytes(2, "big") + payload
    frame += bytes(range(1, max(0, 60 - len(frame)) + 1))
    if fcs:
        frame += binascii.crc32(frame).to_bytes(4, "little")
    return frame


def igmp(kind):
    message = struct.pack(
        "!BBH4s", kind, 10 if kind == 0x11 else 0, 0, bytes.fromhex("e0010203")
    )
    return (
        message[:2] + ones_complement(message).to_bytes(2, "big") + message[4:]
    )


def gre(payload, flags=0x8000, protocol=0x88B5):
    header = struct.pack("!HHHH", flags, protocol, 0, 0)
    if flags & 0x2000:
        header += bytes.fromhex("cafebabe")
    if flags & 0x1000:
        header += bytes.fromhex("00010203")
    checksum = ones_complement(header + payload).to_bytes(2, "big")
    return header[:4] + checksum + header[6:] + payload


def refill(frame):
    packet = decode_frame(frame)
    stale = []
    for layer in packet.layers:
        if isinstance(layer, IGMP):
            layer = replace(layer, checksum=layer.checksum ^ 1)
        elif isinstance(layer, GRE):
            layer = replace(
                layer,
                fields=(layer.checksum ^ 1).to_bytes(2, "big")
                + layer.fields[2:],
            )
        stale.append(layer)
    payload = frame[packet.consumed :]
    filled = Packet(*stale).with_checksums(payload)
    return bytes(filled) + payload, filled, packet


@pytest.mark.parametrize("kind", [0x11, 0x12, 0x16, 0x17])
@pytest.mark.parametrize("nops", [False, True])
def test_igmp_excludes_nonzero_ethernet_padding(kind, nops):
    message = igmp(kind)
    options = b"" if kind == 0x12 else bytes.fromhex("94040000")
    options += bytes.fromhex("01010101") if nops else b""
    destination = bytes.fromhex("e0000002" if kind == 0x17 else "e0010203")
    mac = bytes([1, 0, 0x5E, destination[1] & 0x7F, *destination[2:]])
    frame = ethernet(
        ipv4(message, 2, options, destination=destination, ttl=1),
        destination=mac,
    )
    start = 14 + 20 + len(options)
    end = start + len(message)
    assert frame[end:]
    assert ones_complement(frame[start:end]) == 0
    wire, filled, packet = refill(frame)
    assert ones_complement(wire[start:end]) == 0
    assert filled[IGMP].body == packet[IGMP].body
    assert wire == frame


@pytest.mark.parametrize("flags", [0x8000, 0xA000, 0x9000, 0xB000])
@pytest.mark.parametrize("options", [b"", bytes.fromhex("01010100")])
@pytest.mark.parametrize("payload", [b"", b"odd"])
def test_gre_excludes_nonzero_ethernet_padding(flags, options, payload):
    message = gre(payload, flags)
    frame = ethernet(ipv4(message, 47, options))
    start = 14 + 20 + len(options)
    end = start + len(message)
    assert frame[end:]
    assert ones_complement(frame[start:end]) == 0
    wire, filled, packet = refill(frame)
    assert ones_complement(wire[start:end]) == 0
    assert filled[GRE].fields[2:] == packet[GRE].fields[2:]
    assert wire == frame


@pytest.mark.parametrize("extension", [b"", bytes.fromhex("2f00000000000000")])
@pytest.mark.parametrize("flags", [0x8000, 0xA000, 0x9000, 0xB000])
def test_gre_over_ipv6_excludes_captured_ethernet_fcs(extension, flags):
    message = gre(b"odd", flags)
    datagram = ipv6(extension + message, 0 if extension else 47)
    frame = ethernet(datagram, 0x86DD, fcs=True)
    start = 14 + 40 + len(extension)
    end = start + len(message)
    assert ones_complement(frame[start:end]) == 0
    wire, filled, packet = refill(frame)
    assert ones_complement(wire[start:end]) == 0
    assert filled[GRE].fields[2:] == packet[GRE].fields[2:]
    assert wire == frame


def test_gre_extent_accounts_for_an_intervening_ipv4_ah_header():
    message = gre(b"odd")
    authentication = struct.pack("!BBHII", 47, 5, 0, 1, 1) + bytes(16)
    frame = ethernet(ipv4(authentication + message, 51), fcs=True)
    start = 14 + 20 + len(authentication)
    wire, _, _ = refill(frame)
    assert ones_complement(wire[start : start + len(message)]) == 0
    assert wire == frame


@pytest.mark.parametrize("inner_family", [4, 6])
def test_nested_gre_uses_each_ip_extent_and_keeps_outer_payload(inner_family):
    inner_message = gre(b"odd")
    inner_ip = (
        ipv4(inner_message, 47)
        if inner_family == 4
        else ipv6(inner_message, 47)
    )
    trailer = bytes.fromhex("12345678")
    outer_message = gre(
        inner_ip + trailer, protocol=0x0800 if inner_family == 4 else 0x86DD
    )
    frame = ethernet(ipv4(outer_message, 47))
    inner_start = 14 + 20 + 8 + (20 if inner_family == 4 else 40)
    inner_end = inner_start + len(inner_message)
    wire, _, _ = refill(frame)
    assert ones_complement(wire[14 + 20 :]) == 0
    assert ones_complement(wire[inner_start:inner_end]) == 0
    assert wire == frame


def test_gre_keeps_padding_stored_in_an_inner_igmp_body():
    message = igmp(0x12)
    inner_ip = ipv4(message, 2, destination=bytes.fromhex("e0010203"), ttl=1)
    padding = bytes(range(1, 11))
    outer_message = gre(inner_ip + padding, protocol=0x0800)
    frame = ethernet(ipv4(outer_message, 47))
    start = 14 + 20 + 8 + 20
    wire, filled, packet = refill(frame)
    assert ones_complement(wire[start : start + len(message)]) == 0
    assert ones_complement(wire[14 + 20 :]) == 0
    assert filled[IGMP].body == packet[IGMP].body
    assert wire == frame


@pytest.mark.parametrize("protocol", [IGMP, GRE])
@pytest.mark.parametrize(
    "family,short",
    [(None, False), (4, False), (4, True), (6, False), (6, True)],
)
def test_missing_or_impossible_extents_keep_unbounded_checksums(
    protocol, family, short
):
    layer = (
        IGMP(type=0x16, max_resp_code=0, checksum=0, body=b"message-body")
        if protocol is IGMP
        else GRE(flags=0x8000, protocol_type=0x88B5, fields=bytes(4))
    )
    payload = b"trailing"
    minimum = 4 if protocol is IGMP else layer.header_len
    layers = []
    if family == 4:
        ip = IPv4.decode(ipv4(b"", 2 if protocol is IGMP else 47))
        layers.append(
            replace(ip, total_length=20 + minimum - 1 if short else 0)
        )
    elif family == 6:
        ip = IPv6.decode(ipv6(b"", 2 if protocol is IGMP else 47))
        layers.append(replace(ip, payload_length=minimum - 1 if short else 0))
    packet = Packet(*layers, layer)
    expected = compute(layer, payload=payload)
    filled = packet.with_checksums(payload)[protocol]
    assert filled.checksum == expected
    if protocol is IGMP:
        assert filled.body == layer.body
    else:
        assert filled.fields[2:] == layer.fields[2:]


def test_zero_length_ipv6_does_not_use_an_outer_ipv4_extent():
    layer = GRE(flags=0x8000, protocol_type=0x88B5, fields=bytes(4))
    payload = b"trailing"
    outer = IPv4.decode(ipv4(bytes(40 + layer.header_len), 41))
    inner = IPv6.decode(ipv6(b"", 47))
    filled = Packet(outer, inner, layer).with_checksums(payload)[GRE]
    assert filled.checksum == compute(layer, payload=payload)
