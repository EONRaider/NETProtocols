"""Checksum computation and verification: the internet checksum (RFC
1071), SCTP's CRC32c (RFC 9260 Appendix A), and the Fletcher checksum
OSPF's LSAs carry (RFC 2328 §12.1.7).

The primitive, :func:`internet_checksum`, returns the raw ones'-
complement result — ``0x0000`` is a legal return value, and TCP, ICMP,
and the IPv4 header checksum legitimately transmit it. The famous
``0x0000 → 0xFFFF`` substitution is a **UDP-only transmit rule**
(RFC 768; RFC 8200 §8.1) and lives solely in the UDP arm of
:func:`compute`.

SCTP alone does not use the internet checksum: its packets carry a
CRC32c (the Castagnoli CRC, also iSCSI's), computed by :func:`crc32c`
over the whole packet with no pseudo-header.

OSPF carries two kinds. The packet checksum is the internet checksum
of the whole packet but its 64-bit Authentication field (RFC 2328
§D.4.1), through :func:`compute`/:func:`verify` like the others. Each
LSA inside also carries an LS Checksum, the ISO 8473 Fletcher checksum
of the LSA but its LS Age (RFC 2328 §12.1.7, RFC 905 Annex B). An LSA
is not a layer, so that one has functions of its own:
:func:`lsa_checksum` and :func:`verify_lsa`.

VRRP's internet checksum depends on its version: VRRPv2's covers the
message alone (RFC 3768 §5.3.8), VRRPv3's adds an IP pseudo-header.
Over IPv6 that is RFC 5798 §5.2.8's rule. Over IPv4 it is a reading,
not the text: §5.2.8 cites only the pseudo-header of RFC 2460 §8.1,
which is IPv6's, and RFC 9568 §5.2.8, which obsoletes RFC 5798 without
otherwise changing the wire format, has the IPv4 sum cover the message
alone (its §1.1 calls that a clarification). :func:`compute` adds the
IPv4 pseudo-header too, as keepalived does by default: keepalived
2.2.8 sends it, multicast and unicast alike
(``tests/fixtures/vrrp.pcap``). keepalived 2.2.8's keepalived.conf(5)
says some manufacturers (e.g. Cisco) read §5.2.8 as IPv6-only, and
its ``v3_checksum_as_v2`` option leaves the IPv4 pseudo-header out;
keepalived 2.3.0's adds Juniper, and says most open-source
implementations, tcpdump and Wireshark among them, include it.
:func:`verify` returns ``False`` for an advert checksummed without it.

CDP's checksum is the internet checksum but for an odd final byte,
which it does not pad into the high byte of a last word as RFC 1071
does: see :func:`compute`. :meth:`~netprotocols.Packet.with_checksums`
fills it like IPv4's, from the layer alone.

Length fields are trusted, not reconciled: UDP uses ``layer.length``
for the pseudo-header, TCP uses ``layer.header_len + len(payload)``,
and nothing checks ``IPv4.total_length`` against the payload you pass.
Feed these helpers the payload exactly as it appears on the wire.
"""

from __future__ import annotations

import struct
from dataclasses import replace
from functools import reduce

from netprotocols._base import (
    Protocol,
    ipv4_to_bytes,
    ipv6_to_bytes,
)
from netprotocols._enums import IPProtocol
from netprotocols.layer2.cdp import CDP
from netprotocols.layer3.gre import GRE
from netprotocols.layer3.icmp import ICMPv4, ICMPv6
from netprotocols.layer3.igmp import IGMP
from netprotocols.layer3.ip import IPv4, IPv6
from netprotocols.layer3.ipv6_ext import IPv6Routing, effective_destination
from netprotocols.layer3.ospf import OSPF, OSPFLSA
from netprotocols.layer3.pim import PIM
from netprotocols.layer3.vrrp import VRRP
from netprotocols.layer4.sctp import SCTP
from netprotocols.layer4.tcp import TCP
from netprotocols.layer4.udp import UDP
from netprotocols.utils.exceptions import InvalidFieldError

__all__ = [
    "compute",
    "crc32c",
    "fletcher_checksum",
    "internet_checksum",
    "lsa_checksum",
    "verify",
    "verify_lsa",
]


def internet_checksum(data: bytes | memoryview) -> int:
    """The RFC 1071 checksum of ``data``: the ones' complement of the
    ones'-complement sum of its 16-bit words (odd lengths are padded
    with a zero byte).

    Returns the raw result: ``0x0000`` is a legal value here. Protocol
    rules such as UDP's zero substitution belong to :func:`compute`.
    """
    if len(data) % 2:
        data = bytes(data) + b"\x00"
    words: tuple[int, ...] = struct.unpack(f"!{len(data) // 2}H", data)
    total = sum(words)
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


#: The Castagnoli polynomial 0x1EDC6F41, bit-reflected (RFC 3720 §12.1,
#: RFC 9260 Appendix A).
_CRC32C_POLY = 0x82F63B78

#: The CRC of each byte value, for the byte-at-a-time loop in
#: :func:`crc32c`: eight shift-and-conditionally-xor steps, one per bit.
#: Built by a module-level expression rather than a helper function so
#: the mutation audit (see pyproject.toml's [tool.mutmut]) never sees an
#: import-time call it cannot attribute to a test; the table is pinned
#: through :func:`crc32c`'s test vectors instead.
_CRC32C_TABLE: tuple[int, ...] = tuple(
    reduce(
        lambda crc, _: (crc >> 1) ^ (_CRC32C_POLY if crc & 1 else 0),
        range(8),
        byte,
    )
    for byte in range(256)
)


def crc32c(data: bytes | memoryview) -> int:
    """The CRC32c (Castagnoli) of ``data``: reflected, initial value and
    final xor ``0xFFFFFFFF`` (RFC 3720 §12.1, RFC 9260 Appendix A), e.g.
    ``crc32c(b"123456789") == 0xE3069283``.

    Not :func:`zlib.crc32`, which is the IEEE 802.3 CRC-32 — a
    different polynomial — and the standard library has no CRC32c.

    This is the CRC as a number. SCTP transmits it least significant
    byte first, so the packet's checksum field, read big-endian, is
    this value byte-swapped; :func:`compute` applies that for an
    :class:`~netprotocols.SCTP` layer.
    """
    crc = 0xFFFFFFFF
    for byte in data:
        crc = _CRC32C_TABLE[(crc ^ byte) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


def _fletcher_sums(data: bytes) -> tuple[int, int]:
    """Return the ISO 8473 running sums ``C0`` and ``C1`` of ``data``.

    Each octet is added to ``C0``, then ``C0`` to ``C1`` (RFC 905
    B.3.3, B.4.2), both modulo 255, the arithmetic RFC 905 B.2(a)
    defines.
    """
    c0 = c1 = 0
    for byte in data:
        c0 = (c0 + byte) % 255
        c1 = (c1 + c0) % 255
    return c0, c1


def fletcher_checksum(data: bytes | memoryview, offset: int) -> int:
    """Compute the ISO 8473 Fletcher checksum field for ``data``.

    The field's two bytes sit at ``offset`` and are read as zero (RFC
    905 B.3.1; RFC 1008 §7.2.1). The result is the 16-bit value
    ``X << 8 | Y`` that makes both running sums of ``data``, with it in
    place, ``0`` modulo 255.

    Each of ``X`` and ``Y`` is reported in ``1``-``255``, ``255``
    standing for zero, so the result never has a zero byte: RFC 905
    B.2(b) regards ``255`` as zero, and RFC 1008 §7.2.1's reference
    code writes ``255``. OSPF's LS Checksum is this over an LSA from
    byte 2, its LS Age excluded (see :func:`lsa_checksum`).

    :raises ValueError: if the two-byte field at ``offset`` does not
        lie inside ``data``: ``offset`` must be ``0`` to
        ``len(data) - 2``.
    """
    field = bytes(data)
    if not 0 <= offset <= len(field) - 2:
        raise ValueError(
            f"a 2-byte checksum field at offset {offset} does not fit in "
            f"{len(field)} bytes"
        )
    c0, c1 = _fletcher_sums(field[:offset] + b"\x00\x00" + field[offset + 2 :])
    x = ((len(field) - offset - 1) * c0 - c1) % 255 or 255
    y = (510 - c0 - x) % 255 or 255
    return x << 8 | y


#: Where an LSA's LS Checksum sits once its 2-byte LS Age is excluded:
#: header byte 16 (RFC 2328 §A.4.1), counted from byte 2.
_LSA_CHECKSUM_OFFSET = 14


def lsa_checksum(lsa: OSPFLSA) -> int:
    """Compute the correct LS Checksum for ``lsa``.

    That is :func:`fletcher_checksum` of the whole LSA but its LS Age
    (RFC 2328 §12.1.7), the checksum field read as zero.
    """
    return fletcher_checksum(bytes(lsa)[2:], _LSA_CHECKSUM_OFFSET)


def verify_lsa(lsa: OSPFLSA) -> bool:
    """Return whether ``lsa``'s LS Checksum checks.

    That is RFC 905 B.4's check over the LSA but its LS Age, the
    checksum in place: both running sums must be ``0`` modulo 255. It
    does not compare the field with :func:`lsa_checksum`, which reports
    a zero ``X`` or ``Y`` as ``255``: the check accepts either form of
    one byte, ``0x00`` and ``0xff`` being equal modulo 255.

    RFC 2328 §12.1.7 adds one rule: the LS Checksum cannot be zero, and
    a zero is a checksum failure. So a field of ``0x0000`` fails even
    where B.4's sums come out zero, as they do for an LSA whose
    generated checksum is ``0xffff``.
    """
    sums = _fletcher_sums(bytes(lsa)[2:])
    return lsa.header.ls_checksum != 0 and sums == (0, 0)


def _cdp_sum(data: bytes) -> int:
    """Return CDP's checksum of ``data``.

    It is :func:`internet_checksum` with one exception: an odd final
    byte ``v`` is not padded into the high byte of a last word. It is
    the word's low byte when below 0x80, and from 0x80 the word is
    ``0xFF00 + v - 1``: the byte sign-extended, less 1, which
    packet-cdp.c's comment explains as Cisco's code adding the last
    word as a signed number and compensating an off-by-one. That is
    lldpd 1.0.18's src/daemon/frame.c ``frame_checksum()`` ("sum +=
    0xff << 8; sum += v - 1;") and Wireshark's
    epan/dissectors/packet-cdp.c (commit 31bf0857, fetched 2026-10-25),
    which builds the same last word by decrementing both of its bytes.
    """
    if len(data) % 2:
        last = data[-1]
        word = 0xFF00 + last - 1 if last & 0x80 else last
        data = data[:-1] + word.to_bytes(2)
    return internet_checksum(data)


def _whole_message_checksum(layer: IGMP | CDP) -> int:
    """Checksum a message whose field is bytes 2-3 and covers it all.

    Those are IGMP's and CDP's: the whole message with the field
    zeroed, no pseudo-header, nothing after the message. IGMP's is the
    internet checksum, CDP's :func:`_cdp_sum`.
    """
    message = _zeroed(bytes(layer), 2)
    if isinstance(layer, CDP):
        return _cdp_sum(message)
    return internet_checksum(message)


def _pseudo_header(ip: IPv4 | IPv6, protocol: int, length: int) -> bytes:
    """The pseudo-header prepended to transport checksums.

    IPv4 (RFC 793/768): src, dst, zero byte, protocol, 16-bit length.
    IPv6 (RFC 8200 §8.1): src, dst, 32-bit length, three zero bytes,
    next-header.
    """
    if isinstance(ip, IPv4):
        return (
            ipv4_to_bytes(ip.src)
            + ipv4_to_bytes(ip.dst)
            + struct.pack("!BBH", 0, protocol, length)
        )
    return (
        ipv6_to_bytes(ip.src)
        + ipv6_to_bytes(ip.dst)
        + struct.pack("!IBBBB", length, 0, 0, 0, protocol)
    )


def _pseudo_ip(
    ip: IPv4 | IPv6 | None, routing: IPv6Routing | None
) -> IPv4 | IPv6 | None:
    """Return ``ip`` with ``dst`` set to the pseudo-header destination.

    That is the final destination when ``routing`` puts it elsewhere
    (RFC 8200 §8.1), so that every pseudo-header built from the result
    uses the right address; ``ip`` itself when nothing changes. The
    choice is
    :func:`~netprotocols.layer3.ipv6_ext.effective_destination`.
    """
    if routing is None or ip is None:
        return ip
    dst = effective_destination(ip, routing)
    return ip if dst == ip.dst else replace(ip, dst=dst)


def _require_ip(layer: Protocol, ip: IPv4 | IPv6 | None) -> IPv4 | IPv6:
    if ip is None:
        raise InvalidFieldError(
            f"Computing a {type(layer).__name__} checksum requires the "
            f"enclosing IPv4/IPv6 layer (its pseudo-header covers the "
            f"addresses)",
            protocol=type(layer),
            field="checksum",
        )
    return ip


def _zeroed(layer_bytes: bytes, checksum_offset: int) -> bytes:
    return (
        layer_bytes[:checksum_offset]
        + b"\x00\x00"
        + layer_bytes[checksum_offset + 2 :]
    )


def _gre_checksum(layer: GRE, payload: bytes) -> int:
    """GRE header plus payload, checksum field (bytes 4-5) zeroed, no
    pseudo-header (RFC 2784 §2.5). Only meaningful when the
    Checksum-Present bit announces the field."""
    if layer.checksum is None:
        raise InvalidFieldError(
            "Computing a GRE checksum requires the Checksum-Present "
            "bit and its field (RFC 2784 §2.5)",
            protocol=type(layer),
            field="checksum",
        )
    return internet_checksum(_zeroed(bytes(layer), 4) + payload)


def _sctp_checksum(layer: SCTP, payload: bytes) -> int:
    """The whole packet, checksum field (bytes 8-11) zeroed, no
    pseudo-header. The CRC goes on the wire least significant byte
    first, and the field reads its four bytes big-endian."""
    packet = bytes(layer)
    crc = crc32c(packet[:8] + b"\x00\x00\x00\x00" + packet[12:] + payload)
    field: int = struct.unpack("!I", crc.to_bytes(4, "little"))[0]
    return field


#: The PIM Register message type, whose checksum covers only the PIM
#: header and the 4-byte Register header after it (RFC 7761 §4.9.3).
_PIM_REGISTER = 1
_PIM_REGISTER_HEADER_LEN = 8


def _pim_covered(layer: PIM, ip: IPv4 | IPv6 | None) -> bytes:
    """The PIM message bytes the checksum covers, checksum field (bytes
    2-3) zeroed: the whole message, or a Register's first 8 bytes (RFC
    7761 §4.9.3). ``ip`` is required, since only the family says
    whether a pseudo-header goes in front."""
    if ip is None:
        raise InvalidFieldError(
            "Computing a PIM checksum requires the enclosing IPv4/IPv6 "
            "layer (over IPv6 its pseudo-header covers the addresses)",
            protocol=type(layer),
            field="checksum",
        )
    message = _zeroed(bytes(layer), 2)
    if layer.type == _PIM_REGISTER:
        return message[:_PIM_REGISTER_HEADER_LEN]
    return message


def _pim_sum(covered: bytes, ip: IPv4 | IPv6 | None) -> int:
    """The internet checksum over ``covered``, behind the IPv6
    pseudo-header (next header 103, the covered length) when ``ip`` is
    IPv6, alone over IPv4 (RFC 7761 §4.9)."""
    if isinstance(ip, IPv6):
        covered = _pseudo_header(ip, IPProtocol.PIM, len(covered)) + covered
    return internet_checksum(covered)


def _pim_checksum(layer: PIM, ip: IPv4 | IPv6 | None) -> int:
    """The PIM checksum: the internet checksum over the message, or over
    a Register's first 8 bytes, with the IPv6 pseudo-header in front
    over IPv6, whose length is then the covered length (RFC 7761
    §4.9)."""
    return _pim_sum(_pim_covered(layer, ip), ip)


def _verify_pim(layer: PIM, ip: IPv4 | IPv6 | None) -> bool:
    """Verify a PIM checksum. A Register's is also accepted computed
    over the whole message, encapsulated packet included, as RFC 7761
    §4.9.3 asks for interoperability with senders that sum it all."""
    if layer.checksum == _pim_checksum(layer, ip):
        return True
    if layer.type != _PIM_REGISTER:
        return False
    return layer.checksum == _pim_sum(_zeroed(bytes(layer), 2), ip)


def _ospf_checksum(layer: OSPF) -> int:
    """Checksum an OSPF packet but its Authentication field.

    The whole packet, checksum field (bytes 12-13) zeroed and the
    8-byte Authentication field (bytes 16-23) left out (RFC 2328
    §D.4.1); no pseudo-header. ``bytes(layer)`` is exactly Packet
    Length bytes here: only cryptographic authentication (AuType 2 or
    3) appends a trailer, and it computes no checksum (RFC 2328
    §D.4.3 step 2, which RFC 7474 §5, through RFC 5709 §3.1, leaves
    unchanged for AuType 3).
    """
    if layer.au_type in OSPF.CRYPTOGRAPHIC_AU_TYPES:
        raise InvalidFieldError(
            f"An OSPF packet under cryptographic authentication (AuType "
            f"{layer.au_type}) carries no checksum; its digest protects it "
            f"(RFC 2328 §D.4.3)",
            protocol=type(layer),
            field="checksum",
        )
    packet = bytes(layer)
    return internet_checksum(
        packet[:12] + b"\x00\x00" + packet[14:16] + packet[24:]
    )


def _udp_checksum(layer: UDP, ip: IPv4 | IPv6 | None, payload: bytes) -> int:
    """UDP header plus payload behind the pseudo-header, whose length is
    ``layer.length`` (RFC 768)."""
    enclosing = _require_ip(layer, ip)
    datagram = _zeroed(bytes(layer), 6) + payload
    raw = internet_checksum(
        _pseudo_header(enclosing, IPProtocol.UDP, layer.length) + datagram
    )
    # UDP-only transmit rule: 0 means "no checksum", so a computed
    # 0x0000 is sent as 0xFFFF (RFC 768; mandatory path RFC 8200).
    return raw or 0xFFFF


def _vrrp_checksum(layer: VRRP, ip: IPv4 | IPv6 | None) -> int:
    """Return VRRP's checksum, over the message with bytes 6-7 zeroed.

    VRRPv2 sums the message alone (RFC 3768 §5.3.8). VRRPv3 puts the
    pseudo-header of ``ip``, with protocol 112 and the message's
    length, in front of it, over IPv4 as over IPv6: RFC 5798 §5.2.8
    gives the IPv6 one, the IPv4 one is keepalived's default, and RFC
    9568 §5.2.8 leaves it out (see the module docstring). The message
    is ``bytes(layer)``, never what follows it, so Ethernet padding
    cannot reach the sum.
    """
    message = _zeroed(bytes(layer), 6)
    if layer.version == 2:
        return internet_checksum(message)
    enclosing = _require_ip(layer, ip)
    return internet_checksum(
        _pseudo_header(enclosing, IPProtocol.VRRP, len(message)) + message
    )


def _pseudo_header_checksum(
    layer: Protocol, ip: IPv4 | IPv6 | None, payload: bytes
) -> int | None:
    """Checksum a transport whose checksum covers a pseudo-header.

    Those are ICMPv6, TCP and UDP, over the enclosing IP header's
    pseudo-header; ``None`` for any other layer.
    """
    if isinstance(layer, ICMPv6):
        enclosing = _require_ip(layer, ip)
        segment = _zeroed(bytes(layer), 2) + payload
        return internet_checksum(
            _pseudo_header(enclosing, IPProtocol.IPV6_ICMP, len(segment))
            + segment
        )
    if isinstance(layer, TCP):
        enclosing = _require_ip(layer, ip)
        segment = _zeroed(bytes(layer), 16) + payload
        return internet_checksum(
            _pseudo_header(enclosing, IPProtocol.TCP, len(segment)) + segment
        )
    if isinstance(layer, UDP):
        return _udp_checksum(layer, ip, payload)
    return None


def compute(
    layer: Protocol,
    *,
    ip: IPv4 | IPv6 | None = None,
    routing: IPv6Routing | None = None,
    payload: bytes = b"",
) -> int:
    """The correct checksum field value for ``layer``.

    :param layer: The header to checksum. ``IPv4`` covers its own
        header only (options included; ``ip``/``payload`` ignored);
        ``ICMPv4`` covers header plus ``payload`` (no pseudo-header);
        ``GRE`` covers header plus ``payload`` with no pseudo-header
        (RFC 2784 §2.5) and requires the Checksum-Present bit;
        ``TCP``, ``UDP``, and ``ICMPv6`` prepend the pseudo-header
        built from ``ip``; ``SCTP`` is a CRC32c over the whole packet,
        its chunks included, with no pseudo-header (``ip`` ignored),
        returned as the field's big-endian reading of the CRC's
        little-endian wire bytes (RFC 9260 Appendix A); ``VRRP`` covers
        the message alone in VRRPv2 and prepends the pseudo-header in
        VRRPv3, over IPv4 too as keepalived does by default, though RFC
        9568 §5.2.8 leaves it out there (see the module docstring),
        with ``payload`` ignored either way; ``OSPF`` covers its own
        Packet Length bytes but the Authentication field, with no
        pseudo-header (``ip`` and ``payload`` ignored, so an LLS block
        after the packet never enters it), and raises under
        cryptographic authentication, which computes none; ``PIM`` covers
        the whole message, or only the first 8 bytes of a Register
        (RFC 7761 §4.9.3), behind the IPv6 pseudo-header over IPv6 and
        alone over IPv4 (``payload`` ignored); ``CDP`` covers the
        whole PDU, its TLVs included, with no pseudo-header (``ip``
        and ``payload`` ignored), summed as the internet checksum but
        for an odd final byte ``v``, added as the low byte of a last
        word below 0x80 and as ``0xFF00 + v - 1`` from 0x80, as lldpd
        and Wireshark sum it (see :func:`_cdp_sum`).
    :param ip: The enclosing IP layer, required for TCP/UDP/ICMPv6,
        VRRPv3, and PIM, whose coverage depends on the family.
    :param routing: The :class:`~netprotocols.IPv6Routing` header
        between ``ip`` and ``layer``, if there is one. RFC 8200 §8.1
        puts the *final* destination in the pseudo-header behind a
        Routing header, but ``ip.dst`` of a packet in flight is the
        next hop while ``routing.segments_left`` is above 0. With
        ``routing`` given, ``ip`` IPv6 and segments left, the
        pseudo-header uses
        :meth:`~netprotocols.IPv6Routing.final_destination`; otherwise
        (no segments left, IPv4, a routing type or data that method
        cannot resolve) it uses ``ip.dst`` as before. Used only by the
        layers whose checksum has a pseudo-header
        (see ``ip``). If several Routing headers precede the layer,
        pass the first, as :meth:`Packet.with_checksums
        <netprotocols.packet.Packet.with_checksums>` does.
    :param payload: The bytes following ``layer`` on the wire. A decoded
        ``ICMPv4``/``ICMPv6``/``IGMP``/``PIM`` message, and a decoded
        ``SCTP`` packet, already carries its whole body in
        ``bytes(layer)``, so pass a ``payload`` only for bytes the layer
        object does not itself hold. ``IGMP``, ``VRRP``, ``PIM`` and
        ``CDP`` ignore it: nothing after the message is part of it.
    :raises InvalidFieldError: For layers without a checksum field, or
        a missing ``ip`` where the pseudo-header needs one.
    """
    ip = _pseudo_ip(ip, routing)
    if isinstance(layer, IPv4):
        return internet_checksum(_zeroed(bytes(layer), 10))
    if isinstance(layer, ICMPv4):
        return internet_checksum(_zeroed(bytes(layer), 2) + payload)
    if isinstance(layer, (IGMP, CDP)):
        # Whole message, checksum field (bytes 2-3) zeroed, no
        # pseudo-header; the body is already part of bytes(layer).
        return _whole_message_checksum(layer)
    if isinstance(layer, GRE):
        return _gre_checksum(layer, payload)
    if isinstance(layer, SCTP):
        return _sctp_checksum(layer, payload)
    if isinstance(layer, OSPF):
        return _ospf_checksum(layer)
    if isinstance(layer, VRRP):
        return _vrrp_checksum(layer, ip)
    if isinstance(layer, PIM):
        return _pim_checksum(layer, ip)
    transport = _pseudo_header_checksum(layer, ip, payload)
    if transport is not None:
        return transport
    raise InvalidFieldError(
        f"{type(layer).__name__} has no checksum field to compute",
        protocol=type(layer),
        field="checksum",
    )


def verify(
    layer: Protocol,
    *,
    ip: IPv4 | IPv6 | None = None,
    routing: IPv6Routing | None = None,
    payload: bytes = b"",
) -> bool:
    """Whether ``layer``'s checksum field matches a recomputation.

    It accepts what the governing RFC tells a receiver to accept, which
    can be more than :func:`compute` produces: a UDP-over-IPv4 checksum
    of ``0``, a GRE header without the C bit, and a PIM Register summed
    over the whole message, each described below.

    A UDP-over-IPv4 checksum of ``0`` means "no checksum in use" and
    verifies as True (over IPv6 the checksum is mandatory and ``0`` is
    invalid). A GRE header whose Checksum-Present bit is clear carries
    no checksum at all (RFC 2784 §2.5) and likewise verifies as True —
    a frame cannot fail a checksum it does not have — as does an OSPF
    packet under cryptographic authentication (AuType 2 or 3, RFC 2328
    §D.4.3, RFC 7474 §5), whose digest this library cannot check
    without the key. A PIM Register verifies with its checksum over its
    first 8 bytes, as RFC 7761 §4.9.3 computes it, or over the whole
    message, as it asks a receiver to accept too ("for interoperability
    reasons"). So a whole-message Register verifies, but
    :meth:`~netprotocols.Packet.with_checksums` rewrites its checksum to
    the 8-byte form :func:`compute` returns.

    ``routing`` is :func:`compute`'s: behind a Routing header with
    segments left, the pseudo-header uses the route's final destination
    (RFC 8200 §8.1).
    """
    ip = _pseudo_ip(ip, routing)
    if (
        isinstance(layer, UDP)
        and layer.checksum == 0
        and not isinstance(ip, IPv6)
    ):
        return True
    if isinstance(layer, GRE) and not layer.checksum_present:
        return True
    if isinstance(layer, OSPF) and layer.au_type in OSPF.CRYPTOGRAPHIC_AU_TYPES:
        return True
    if isinstance(layer, PIM):
        return _verify_pim(layer, ip)
    wire: int = layer.checksum  # type: ignore[attr-defined]
    return compute(layer, ip=ip, payload=payload) == wire
