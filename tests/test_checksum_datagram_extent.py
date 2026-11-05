"""Given ``ip``, IGMP, ICMPv4 and GRE checksums end at the datagram's end."""

import binascii
import struct
from dataclasses import replace

import pytest

from netprotocols import (
    AH,
    GRE,
    IGMP,
    ICMPv4,
    IPv4,
    IPv6,
    IPv6Routing,
    Packet,
    compute,
    verify,
)
from netprotocols.utils.exceptions import InvalidFieldError
from test_packet_checksum_extents import gre, ipv4, ipv6
from test_vrrp import ones_complement

PADDING = bytes(range(1, 19))
ROUTER_ALERT = bytes.fromhex("94040000")
GROUP = bytes.fromhex("e0010203")


def checksummed(message, offset=2):
    """Fill the 16-bit field at ``offset`` with ``message``'s sum."""
    zeroed = message[:offset] + b"\x00\x00" + message[offset + 2 :]
    field = ones_complement(zeroed).to_bytes(2, "big")
    return zeroed[:offset] + field + zeroed[offset + 2 :]


def zeroed_sum(data, offset=2):
    """Return the RFC 1071 sum of ``data`` with its field zeroed."""
    return ones_complement(data[:offset] + b"\x00\x00" + data[offset + 2 :])


IGMP_MESSAGES = {
    "v1-report": struct.pack("!BBH4s", 0x12, 0, 0, GROUP),
    "v2-query": struct.pack("!BBH4s", 0x11, 100, 0, GROUP),
    "v2-report": struct.pack("!BBH4s", 0x16, 0, 0, GROUP),
    "v2-leave": struct.pack(
        "!BBH4s", 0x17, 0, 0, bytes.fromhex("e0000002")
    ),
    "v3-query": struct.pack(
        "!BBH4sBBH4s", 0x11, 100, 0, GROUP, 0x02, 125, 1,
        bytes.fromhex("c0000209"),
    ),
    "v3-report": struct.pack(
        "!BBHHHBBH4s4s", 0x22, 0, 0, 0, 1, 1, 0, 1, GROUP,
        bytes.fromhex("c0000209"),
    ),
}  # fmt: skip

ICMP_MESSAGES = {
    "echo-request": struct.pack("!BBHHH", 8, 0, 0, 0x1234, 1) + b"abcd",
    "echo-reply-odd": struct.pack("!BBHHH", 0, 0, 0, 0x1234, 2) + b"odd",
    "unreachable": struct.pack("!BBHI", 3, 3, 0, 0)
    + ipv4(b"\x00\x35\x00\x35\x00\x08\x00\x00", 17)[:28],
}


def message_cases():
    for name, message in IGMP_MESSAGES.items():
        yield pytest.param(IGMP, 2, checksummed(message), id=f"igmp-{name}")
    for name, message in ICMP_MESSAGES.items():
        yield pytest.param(ICMPv4, 1, checksummed(message), id=f"icmp-{name}")


def trailer(kind, datagram):
    fcs = binascii.crc32(datagram).to_bytes(4, "little")
    return {"padding": PADDING, "fcs": fcs, "both": PADDING + fcs}[kind]


@pytest.mark.parametrize("cls,protocol,message", list(message_cases()))
@pytest.mark.parametrize("kind", ["padding", "fcs", "both"])
@pytest.mark.parametrize("options", [b"", ROUTER_ALERT])
def test_a_standalone_message_verifies_with_its_trailer_in_the_body(
    cls, protocol, message, kind, options
):
    datagram = ipv4(message, protocol, options)
    ip = IPv4.decode(datagram)
    extra = trailer(kind, datagram)
    layer = cls.decode(message + extra)
    wire = int.from_bytes(message[2:4], "big")
    assert layer.body.endswith(extra)
    assert zeroed_sum(message + extra) != wire
    assert verify(layer, ip=ip)
    assert compute(layer, ip=ip) == wire
    assert not verify(layer)
    assert compute(layer) == zeroed_sum(message + extra)


@pytest.mark.parametrize("cls,protocol,message", list(message_cases()))
def test_icmpv4_and_igmp_ignore_a_payload_past_the_datagram(
    cls, protocol, message
):
    ip = IPv4.decode(ipv4(message, protocol))
    layer = cls.decode(message)
    wire = int.from_bytes(message[2:4], "big")
    assert compute(layer, ip=ip, payload=PADDING) == wire
    assert verify(layer, ip=ip, payload=PADDING)
    expected = zeroed_sum(message + PADDING) if cls is ICMPv4 else wire
    assert compute(layer, payload=PADDING) == expected


def test_an_icmpv4_payload_inside_the_datagram_is_summed_up_to_its_end():
    message = checksummed(ICMP_MESSAGES["echo-request"])
    ip = IPv4.decode(ipv4(message, 1))
    layer = ICMPv4.decode(message[:8])
    payload = message[8:] + PADDING
    wire = int.from_bytes(message[2:4], "big")
    assert compute(layer, ip=ip, payload=payload) == wire
    assert verify(layer, ip=ip, payload=payload)


def test_an_ipv6_payload_length_bounds_the_sum_too():
    message = checksummed(ICMP_MESSAGES["echo-request"])
    ip = IPv6.decode(ipv6(message, 1))
    layer = ICMPv4.decode(message + PADDING)
    assert compute(layer, ip=ip) == int.from_bytes(message[2:4], "big")
    assert verify(layer, ip=ip)


def igmp_case():
    """Return a padded IGMPv2 report, its message and IP protocol."""
    message = checksummed(IGMP_MESSAGES["v2-report"])
    return IGMP.decode(message + PADDING), message, 2


def icmp_case():
    """Return a padded ICMPv4 echo reply, its message and IP protocol."""
    message = checksummed(ICMP_MESSAGES["echo-reply-odd"])
    return ICMPv4.decode(message + PADDING), message, 1


@pytest.mark.parametrize("case", [igmp_case, icmp_case], ids=["igmp", "icmp"])
@pytest.mark.parametrize(
    "variant",
    ["exact", "options", "zero", "lying", "lying-options", "short", "minimum"],
)
def test_compute_and_with_checksums_agree_on_igmp_and_icmpv4(case, variant):
    """Each ``ip`` gives one checksum to :func:`compute` and to
    :meth:`Packet.with_checksums`, and that checksum is the RFC 1071
    sum of the bytes up to the declared end, or of every byte when
    nothing bounds them."""
    layer, message, protocol = case()
    minimum = 4 if isinstance(layer, IGMP) else 8
    options = ROUTER_ALERT if "options" in variant else b""
    ip = IPv4.decode(ipv4(message, protocol, options))
    header = 20 + len(options)
    total_length = {
        "exact": ip.total_length,
        "options": ip.total_length,
        "zero": 0,
        "lying": 10,
        "lying-options": header - 1,
        "short": header + minimum - 1,
        "minimum": header + minimum,
    }[variant]
    ip = replace(ip, total_length=total_length)
    whole = bytes(layer)
    bound = {
        "exact": len(message),
        "options": len(message),
        "minimum": minimum,
    }.get(variant)
    expected = zeroed_sum(whole if bound is None else whole[:bound])
    stale = replace(layer, checksum=layer.checksum ^ 1)
    filled = Packet(ip, stale).with_checksums()[type(layer)]
    assert compute(stale, ip=ip) == expected
    assert filled.checksum == expected
    assert filled.body == layer.body
    assert verify(filled, ip=ip)


def test_with_checksums_counts_an_ipv4_ah_header_before_icmpv4():
    message = checksummed(ICMP_MESSAGES["echo-request"])
    authentication = struct.pack("!BBHII", 1, 4, 0, 1, 1) + bytes(12)
    datagram = ipv4(authentication + message, 51)
    ip = IPv4.decode(datagram)
    ah = AH.decode(datagram[20:])
    stale = ICMPv4.decode(message + PADDING)
    stale = replace(stale, checksum=stale.checksum ^ 1)
    filled = Packet(ip, ah, stale).with_checksums()[ICMPv4]
    assert filled.checksum == int.from_bytes(message[2:4], "big")
    assert compute(stale, ip=ip) != filled.checksum


def test_with_checksums_leaves_icmpv4_unbounded_below_its_header_after_ah():
    """The datagram ends 7 bytes after AH, short of ICMPv4's 8-byte
    header, so the sum covers the message and the padding after it."""
    message = checksummed(ICMP_MESSAGES["echo-request"])
    authentication = struct.pack("!BBHII", 1, 4, 0, 1, 1) + bytes(12)
    datagram = ipv4(authentication + message, 51)
    ip = replace(IPv4.decode(datagram), total_length=20 + 24 + 7)
    ah = AH.decode(datagram[20:])
    stale = ICMPv4.decode(message + PADDING)
    stale = replace(stale, checksum=stale.checksum ^ 1)
    filled = Packet(ip, ah, stale).with_checksums()[ICMPv4]
    assert filled.checksum == zeroed_sum(message + PADDING)
    assert filled.checksum != zeroed_sum((message + PADDING)[:7])


#: A 2056-byte ICMPv4 echo request, 8 header bytes and 2048 of data;
#: its sum is ``0800 + 1234 + 0001 + 8 * 3fc000`` folded to ``1c33``,
#: whose complement is ``e3cc``.
REASSEMBLED_ECHO = checksummed(
    struct.pack("!BBHHH", 8, 0, 0, 0x1234, 1) + bytes(range(256)) * 8
)


def fragment_header(total_length, flags, fragment_offset):
    """Return the IPv4 header of one fragment of an ICMPv4 datagram."""
    ip = IPv4.decode(ipv4(REASSEMBLED_ECHO, 1))
    return replace(
        ip,
        total_length=total_length,
        flags=flags,
        fragment_offset=fragment_offset,
    )


FRAGMENT_HEADERS = {
    "first": (1500, 0b001, 0),
    "last": (20 + 2056 - 1480, 0b000, 1480 // 8),
}


@pytest.mark.parametrize("fragment", FRAGMENT_HEADERS)
def test_a_fragment_header_leaves_a_reassembled_icmpv4_unbounded(fragment):
    """A fragment's Total Length covers that fragment alone, so the
    reassembled message is summed whole."""
    ip = fragment_header(*FRAGMENT_HEADERS[fragment])
    assert int.from_bytes(REASSEMBLED_ECHO[2:4], "big") == 0xE3CC
    layer = ICMPv4.decode(REASSEMBLED_ECHO)
    bound = ip.total_length - 20
    assert zeroed_sum(REASSEMBLED_ECHO[:bound]) != 0xE3CC
    assert compute(layer, ip=ip) == 0xE3CC
    assert verify(layer, ip=ip)
    header = ICMPv4.decode(REASSEMBLED_ECHO[:8])
    assert compute(header, ip=ip, payload=REASSEMBLED_ECHO[8:]) == 0xE3CC
    stale = replace(layer, checksum=0xE3CC ^ 1)
    filled = Packet(ip, stale).with_checksums()[ICMPv4]
    assert filled.checksum == 0xE3CC == compute(stale, ip=ip)


def test_a_routing_header_loosens_gre_bound_by_its_length():
    """``ip``'s Payload Length counts the 24-byte Segment Routing header
    before GRE, so :func:`compute` ends its input 24 bytes past the
    datagram, where :meth:`Packet.with_checksums` counts the header."""
    layer, payload, message = gre_layer(0x8000, b"inner datagram")
    segment = bytes.fromhex("20010db8000000000000000000000002")
    srh = bytes([47, 2, 4, 1, 0, 0, 0, 0]) + segment
    routing = IPv6Routing.decode(srh)
    ip = IPv6.decode(ipv6(srh + message, 43))
    after = payload + PADDING * 2
    expected = zeroed_sum((message + PADDING * 2)[: 24 + len(message)], 4)
    assert expected not in (
        layer.checksum,
        zeroed_sum(message + PADDING * 2, 4),
    )
    assert compute(layer, ip=ip, routing=routing, payload=after) == expected
    filled = Packet(ip, routing, layer).with_checksums(after)[GRE]
    assert filled.checksum == layer.checksum


def gre_layer(flags, payload):
    message = gre(payload, flags)
    layer = GRE.decode(message)
    return layer, message[layer.header_len :], message


@pytest.mark.parametrize("flags", [0x8000, 0xB000])
@pytest.mark.parametrize("family", [4, 6])
@pytest.mark.parametrize("split", ["payload", "trailer", "zero"])
def test_compute_and_with_checksums_agree_on_gre(flags, family, split):
    """``with_checksums()`` hands GRE the trailer only when the datagram
    ends inside it, so ``compute`` given the same ``ip`` and the bytes
    after GRE on the wire up to the trailer, or the trailer too when
    the datagram runs into it, returns what it writes."""
    layer, payload, message = gre_layer(flags, b"inner datagram")
    if family == 4:
        ip = IPv4.decode(ipv4(message, 47, ROUTER_ALERT))
    else:
        ip = IPv6.decode(ipv6(message, 47))
    fcs = binascii.crc32(message).to_bytes(4, "little")
    stale = replace(
        layer,
        fields=(layer.checksum ^ 1).to_bytes(2, "big") + layer.fields[2:],
    )
    if split == "zero":
        ip = (
            replace(ip, total_length=0)
            if family == 4
            else replace(ip, payload_length=0)
        )
        wire_after, packet_trailer = payload, PADDING + fcs
        compute_payload = wire_after
        expected = zeroed_sum(message, 4)
    elif split == "payload":
        wire_after, packet_trailer = payload + PADDING, fcs
        compute_payload = wire_after + packet_trailer
        expected = layer.checksum
    else:
        wire_after, packet_trailer = b"", payload + PADDING + fcs
        compute_payload = packet_trailer
        expected = layer.checksum
    packet = Packet(ip, stale, trailer=packet_trailer)
    filled = packet.with_checksums(wire_after)[GRE]
    assert filled.checksum == expected
    assert compute(stale, ip=ip, payload=compute_payload) == expected
    assert verify(filled, ip=ip, payload=compute_payload)


@pytest.mark.parametrize("total_length", [1, 10, 19])
def test_a_lying_total_length_leaves_compute_unbounded(total_length):
    """``8000 + 88b5 + 8 * 0102`` folds to ``10c6``, whose complement
    is ``ef39``: the GRE header and all 16 payload bytes."""
    layer = GRE(flags=0x8000, protocol_type=0x88B5, fields=bytes(4))
    ip = replace(IPv4.decode(ipv4(b"", 47)), total_length=total_length)
    payload = b"\x01\x02" * 8
    assert compute(layer, ip=ip, payload=payload) == 0xEF39
    assert not verify(layer, ip=ip, payload=payload)


def test_a_bound_inside_gre_header_leaves_compute_unbounded():
    layer, payload, message = gre_layer(0xB000, b"odd")
    ip = replace(
        IPv4.decode(ipv4(message, 47)), total_length=20 + layer.header_len - 1
    )
    assert compute(layer, ip=ip, payload=payload + PADDING) == zeroed_sum(
        message + PADDING, 4
    )


def test_a_bound_at_gre_header_end_covers_the_header_alone():
    layer, payload, message = gre_layer(0xB000, b"odd")
    ip = replace(
        IPv4.decode(ipv4(message, 47)), total_length=20 + layer.header_len
    )
    expected = zeroed_sum(message[: layer.header_len], 4)
    assert compute(layer, ip=ip, payload=payload) == expected
    filled = Packet(ip, layer).with_checksums(payload)[GRE]
    assert filled.checksum == expected


def test_gre_without_its_checksum_field_still_raises_given_ip():
    layer = GRE(flags=0x0000, protocol_type=0x88B5, fields=b"")
    ip = IPv4.decode(ipv4(bytes(layer), 47))
    with pytest.raises(InvalidFieldError, match="Checksum-Present"):
        compute(layer, ip=ip)
    assert verify(layer, ip=ip)
