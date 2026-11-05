"""Checksum computation and verification.

The checksums are the internet checksum (RFC 1071), SCTP's CRC32c
(RFC 9260 §A), and the Fletcher checksum OSPF's LSAs carry
(RFC 2328 §12.1.7).

The primitive, :func:`internet_checksum`, returns the raw ones'-
complement result — ``0x0000`` is a legal return value, and TCP, ICMP,
and the IPv4 header checksum legitimately transmit it. The famous
``0x0000 → 0xFFFF`` substitution is a **UDP-only transmit rule**
(RFC 768, RFC 8200 §8.1) and lives solely in the UDP arm of
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
message alone (RFC 3768 §5.3.8), VRRPv3's over IPv6 adds the IPv6
pseudo-header (RFC 9568 §5.2.8, RFC 5798 §5.2.8). VRRPv3 over IPv4 has
two forms. :func:`compute` returns the one with the IPv4 pseudo-header
(protocol 112, the message's length) in front, keepalived's default;
RFC 9568 §5.2.8 covers the message alone, which keepalived's
``v3_checksum_as_v2`` option sends. :func:`verify` accepts either, so
:meth:`~netprotocols.Packet.with_checksums` rewrites an advert of the
RFC 9568 form into the pseudo-header form.

CDP's checksum is the internet checksum but for an odd final byte,
which it does not pad into the high byte of a last word as RFC 1071
does: see :func:`compute`. :meth:`~netprotocols.Packet.with_checksums`
fills it like IPv4's, from the layer alone.

STUN's FINGERPRINT attribute is a checksum too, though not in a header
field: the IEEE CRC-32 (the standard library's, the one Ethernet's FCS
uses) of the message up to the attribute, XORed with ``0x5354554E``
(RFC 8489 §14.7, RFC 5389 §15.5). :func:`compute` returns it for a
message that ends in one, and :func:`verify` accepts a message without
one, as it does a GRE header without the C bit. No one field says
whether a message has one, so a message has none only when its
attributes walk whole, none of them a FINGERPRINT, and its last 8 bytes
do not begin like one: a corrupted Length earlier in the list, which
would end the walk short of the FINGERPRINT or fold it into a longer
value, fails rather than reading as a message without one.
MESSAGE-INTEGRITY, the keyed HMAC beside it, is not a checksum this
module can compute: it needs the credential's key.

IGMP, ICMPv4 and GRE have no length field of their own: each message
runs to the end of its IP datagram. Given ``ip``, :func:`compute` and
:func:`verify` end their input at that datagram's declared end, so
Ethernet padding or a captured FCS that a layer decoded on its own
holds in its ``body``, or that ``payload`` carries, stays out of the
sum. ``ip`` is then the IP header directly before the layer, and the
end is ``ip._payload_extent()`` bytes after the layer's start, the
arithmetic :func:`~netprotocols.decode_frame` bounds its walk with: an
IPv4 ``total_length - ihl * 4`` or an IPv6 ``payload_length``. An
IPv4 Total Length or IPv6 Payload Length of 0, an IPv4 Total Length
shorter than its header, or an end before the layer's required bytes
(IGMP's 4-byte header, ICMPv4's 8-byte header, GRE's whole header)
leaves the input unbounded, as it is without ``ip``.
:meth:`~netprotocols.Packet.with_checksums` applies the same bound
with the same helper, from the nearest IP header before the layer and
counting the headers between.

Other length fields are trusted, not reconciled: UDP uses
``layer.length`` for the pseudo-header, TCP and ICMPv6 use the
segment's length, ``layer.header_len + len(payload)``, and nothing
checks ``IPv4.total_length`` against a TCP or UDP payload you pass.
Feed these helpers the payload exactly as it appears on the wire.
"""

from __future__ import annotations

import binascii
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
from netprotocols.layer3.ipv6_ext import IPv6Routing, _effective_destination
from netprotocols.layer3.ospf import OSPF, OSPFLSA
from netprotocols.layer3.pim import PIM
from netprotocols.layer3.vrrp import VRRP
from netprotocols.layer4.sctp import SCTP
from netprotocols.layer4.tcp import TCP
from netprotocols.layer4.udp import UDP
from netprotocols.layer7.stun import STUN
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
    """Return the RFC 1071 checksum of ``data``.

    That is the ones' complement of the ones'-complement sum of its
    16-bit words (odd lengths are padded with a zero byte).

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
#: RFC 9260 §A).
_CRC32C_POLY = 0x82F63B78

#: The CRC of each byte value, for the byte-at-a-time loop in
#: :func:`crc32c`: eight shift-and-conditionally-xor steps, one per bit.
#: A module-level expression with no helper function, so the mutation
#: audit (see pyproject.toml's [tool.mutmut]) sees no import-time call it
#: cannot attribute to a test; :func:`crc32c`'s test vectors pin the
#: table.
_CRC32C_TABLE: tuple[int, ...] = tuple(
    reduce(
        lambda crc, _: (crc >> 1) ^ (_CRC32C_POLY if crc & 1 else 0),
        range(8),
        byte,
    )
    for byte in range(256)
)


def crc32c(data: bytes | memoryview) -> int:
    """Return the CRC32c (Castagnoli) of ``data``.

    The CRC is reflected, with initial value and final xor
    ``0xFFFFFFFF`` (RFC 3720 §12.1, RFC 9260 §A), e.g.
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
    §B.3.3, §B.4.2), both modulo 255, the arithmetic RFC 905 §B.2(a)
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
    905 §B.3.1, RFC 1008 §7.2.1). The result is the 16-bit value
    ``X << 8 | Y`` that makes both running sums of ``data``, with it in
    place, ``0`` modulo 255.

    Each of ``X`` and ``Y`` is reported in ``1``-``255``, ``255``
    standing for zero, so the result never has a zero byte: RFC 905
    §B.2(b) regards ``255`` as zero, and RFC 1008 §7.2.1's reference
    code writes ``255``. OSPF's LS Checksum is this over an LSA from
    byte 2, its LS Age excluded (see :func:`lsa_checksum`).

    :param data: The bytes the checksum covers, the field included.
    :param offset: Where the checksum field's two bytes start in
        ``data``.
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

    That is RFC 905 §B.4's check over the LSA but its LS Age, the
    checksum in place: both running sums must be ``0`` modulo 255. It
    does not compare the field with :func:`lsa_checksum`, which reports
    a zero ``X`` or ``Y`` as ``255``: the check accepts either form of
    one byte, ``0x00`` and ``0xff`` being equal modulo 255.

    RFC 2328 §12.1.7 adds one rule: the LS Checksum cannot be zero, and
    a zero is a checksum failure. So a field of ``0x0000`` fails even
    where §B.4's sums come out zero, as they do for an LSA whose
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


def _cdp_checksum(layer: CDP) -> int:
    """Checksum a CDP PDU: the whole PDU with bytes 2-3 zeroed.

    There is no pseudo-header and nothing after the PDU; the sum is
    :func:`_cdp_sum`.
    """
    return _cdp_sum(_zeroed(bytes(layer), 2))


def _pseudo_header(ip: IPv4 | IPv6, protocol: int, length: int) -> bytes:
    """Build the pseudo-header prepended to transport checksums.

    IPv4 (RFC 793, RFC 768): src, dst, zero byte, protocol, 16-bit length.
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
    choice is made by
    :func:`~netprotocols.layer3.ipv6_ext._effective_destination`.
    """
    if routing is None or ip is None:
        return ip
    dst = _effective_destination(ip, routing)
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


def _datagram_extent(ip: IPv4 | IPv6, offset: int, minimum: int) -> int | None:
    """Return the declared bytes from ``offset`` into ``ip``'s payload on.

    The payload ends where ``ip._payload_extent()`` says, the
    arithmetic :func:`~netprotocols.decode_frame` bounds its walk with.
    ``None`` when that length is zero, an IPv4 Total Length is shorter
    than its header, or the bytes left fall short of ``minimum``.

    :param ip: The IPv4 or IPv6 header whose datagram bounds the input.
    :param offset: The bytes between the end of ``ip`` and the layer's
        start.
    :param minimum: The bytes the layer requires at its start.
    """
    try:
        payload = ip._payload_extent()
    except InvalidFieldError:
        return None
    if payload is None:
        return None
    extent = payload - offset
    return extent if extent >= minimum else None


def _required_bytes(layer: IGMP | ICMPv4 | GRE) -> int:
    """Return the bytes a datagram-bounded layer requires at its start.

    That is IGMP's 4-byte and ICMPv4's 8-byte header, and GRE's whole
    header with its optional fields.
    """
    if isinstance(layer, GRE):
        return layer.header_len
    return layer._struct.size


def _bounded_checksum(
    layer: IGMP | ICMPv4 | GRE, extent: int | None, payload: bytes
) -> int:
    """Return the internet checksum of ``layer`` cut at ``extent``.

    The input is the layer with its checksum field zeroed, followed by
    ``payload`` for ICMPv4 and GRE (IGMP covers its message alone), and
    ends ``extent`` bytes after the layer's start, or runs to its end
    when ``extent`` is ``None``. GRE's field is bytes 4-5 and exists
    only when the Checksum-Present bit announces it (RFC 2784 §2.5);
    IGMP's and ICMPv4's is bytes 2-3, with no pseudo-header.

    :param layer: The IGMP, ICMPv4 or GRE header.
    :param extent: The bytes from the layer's start to its datagram's
        declared end, or ``None`` for no bound.
    :param payload: The bytes following the layer on the wire.
    :raises InvalidFieldError: if ``layer`` is GRE and
        :attr:`GRE.checksum` is ``None``.
    """
    if isinstance(layer, GRE):
        if layer.checksum is None:
            raise InvalidFieldError(
                "Computing a GRE checksum requires the Checksum-Present "
                "bit and its field (RFC 2784 §2.5)",
                protocol=type(layer),
                field="checksum",
            )
        covered = _zeroed(bytes(layer), 4) + payload
    elif isinstance(layer, ICMPv4):
        covered = _zeroed(bytes(layer), 2) + payload
    else:
        covered = _zeroed(bytes(layer), 2)
    return internet_checksum(covered if extent is None else covered[:extent])


def _sctp_checksum(layer: SCTP, payload: bytes) -> int:
    """Return SCTP's CRC32c over the whole packet, as the field reads it.

    The checksum field (bytes 8-11) is zeroed, and there is no
    pseudo-header. The CRC goes on the wire least significant byte
    first, and the field reads its four bytes big-endian.
    """
    packet = bytes(layer)
    crc = crc32c(packet[:8] + b"\x00\x00\x00\x00" + packet[12:] + payload)
    field: int = struct.unpack("!I", crc.to_bytes(4, "little"))[0]
    return field


#: The PIM Register message type, whose checksum covers only the PIM
#: header and the 4-byte Register header after it (RFC 7761 §4.9.3).
_PIM_REGISTER = 1
_PIM_REGISTER_HEADER_LEN = 8


def _pim_covered(layer: PIM, ip: IPv4 | IPv6 | None) -> bytes:
    """Return the PIM message bytes the checksum covers.

    The checksum field (bytes 2-3) is zeroed. The bytes are the whole
    message, or a Register's first 8 bytes (RFC 7761 §4.9.3). ``ip`` is
    required, since only the family says whether a pseudo-header goes
    in front.

    :param layer: The PIM message.
    :param ip: The enclosing IP header.
    :raises InvalidFieldError: if ``ip`` is ``None``.
    """
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
    """Return the internet checksum over ``covered`` for PIM.

    The IPv6 pseudo-header (next header 103, the covered length) goes
    in front when ``ip`` is IPv6; over IPv4 ``covered`` is summed alone
    (RFC 7761 §4.9).
    """
    if isinstance(ip, IPv6):
        covered = _pseudo_header(ip, IPProtocol.PIM, len(covered)) + covered
    return internet_checksum(covered)


def _pim_checksum(layer: PIM, ip: IPv4 | IPv6 | None) -> int:
    """Return the PIM checksum.

    That is the internet checksum over the message, or over a
    Register's first 8 bytes, with the IPv6 pseudo-header in front over
    IPv6, whose length is then the covered length (RFC 7761 §4.9).
    """
    return _pim_sum(_pim_covered(layer, ip), ip)


def _verify_pim(layer: PIM, ip: IPv4 | IPv6 | None) -> bool:
    """Verify a PIM checksum.

    A Register's is also accepted computed over the whole message,
    encapsulated packet included, as RFC 7761 §4.9.3 asks for
    interoperability with senders that sum it all.
    """
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
    """Return UDP's checksum over its header and ``payload``.

    The pseudo-header goes in front, with ``layer.length`` as its
    length (RFC 768).
    """
    enclosing = _require_ip(layer, ip)
    datagram = _zeroed(bytes(layer), 6) + payload
    raw = internet_checksum(
        _pseudo_header(enclosing, IPProtocol.UDP, layer.length) + datagram
    )
    # UDP-only transmit rule: 0 means "no checksum", so a computed
    # 0x0000 is sent as 0xFFFF (RFC 768, RFC 8200 §8.1).
    return raw or 0xFFFF


def _vrrp_checksum(layer: VRRP, ip: IPv4 | IPv6 | None) -> int:
    """Return VRRP's checksum, over the message with bytes 6-7 zeroed.

    VRRPv2 sums the message alone (RFC 3768 §5.3.8). VRRPv3 puts the
    pseudo-header of ``ip``, with protocol 112 and the message's
    length, in front of it, over IPv4 as over IPv6 (see the module
    docstring for the IPv4 form RFC 9568 §5.2.8 gives). The message is
    ``bytes(layer)``, never what follows it, so Ethernet padding
    cannot reach the sum.
    """
    message = _zeroed(bytes(layer), 6)
    if layer.version == 2:
        return internet_checksum(message)
    enclosing = _require_ip(layer, ip)
    return internet_checksum(
        _pseudo_header(enclosing, IPProtocol.VRRP, len(message)) + message
    )


def _verify_vrrp(layer: VRRP, ip: IPv4 | IPv6 | None) -> bool:
    """Verify a VRRP checksum.

    A VRRPv3 advert over IPv4 is also accepted summed over the message
    alone, without the IPv4 pseudo-header, as RFC 9568 §5.2.8 computes
    it.
    """
    if layer.checksum == _vrrp_checksum(layer, ip):
        return True
    if layer.version != 3 or not isinstance(ip, IPv4):
        return False
    return layer.checksum == internet_checksum(_zeroed(bytes(layer), 6))


def _stun_fingerprint(layer: STUN) -> int:
    """Return STUN's FINGERPRINT value for ``layer``.

    That is the CRC-32 of the message up to the attribute, its header's
    Length already counting it, XORed with ``0x5354554E`` (RFC 8489
    §14.7). The attribute must be the last, with a 4-byte value, so the
    message up to it is all but its last 8 bytes.

    :param layer: The STUN message.
    :raises InvalidFieldError: if :attr:`STUN.fingerprint` is ``None``:
        no 4-byte FINGERPRINT is the last attribute of a list that walks
        to its end.
    """
    if layer.fingerprint is None:
        raise InvalidFieldError(
            "Computing a STUN fingerprint requires a FINGERPRINT "
            "attribute, last in the message (RFC 8489 §14.7)",
            protocol=type(layer),
            field="attributes",
        )
    return binascii.crc32(bytes(layer)[:-8]) ^ STUN.FINGERPRINT_XOR


#: A FINGERPRINT attribute's header: its type and a Length of 4.
_STUN_FINGERPRINT_HEADER = STUN.FINGERPRINT.to_bytes(2, "big") + b"\x00\x04"


def _stun_carries_no_fingerprint(layer: STUN) -> bool:
    """Return whether a STUN message carries no FINGERPRINT to verify.

    Only a message whose attributes walk whole with no attribute of
    type ``0x8028`` among them, and whose last 8 bytes do not begin
    like one, carries none. Presence is not read from the walk alone:
    a corrupted Length earlier in the list could end the walk before
    the FINGERPRINT, or swallow it into a longer value, and a message
    that does carry one would read as one without. A FINGERPRINT must
    be last (RFC 8489 §14.7), so its header in the last 8 bytes is
    enough to claim one; the walk not reaching the end, or finding one
    anywhere, is too.
    """
    if layer.attributes[-8:-4] == _STUN_FINGERPRINT_HEADER:
        return False
    try:
        attributes = layer.parsed_attributes
    except InvalidFieldError:
        return False
    return all(attribute.type != STUN.FINGERPRINT for attribute in attributes)


def _standalone_checksum(layer: Protocol) -> int | None:
    """Checksum a layer whose checksum covers its own bytes alone.

    Those are IPv4's header, CDP's whole PDU, OSPF's packet and STUN's
    FINGERPRINT, none of which takes an IP header or a payload;
    ``None`` for any other layer.
    """
    if isinstance(layer, IPv4):
        return internet_checksum(_zeroed(bytes(layer), 10))
    if isinstance(layer, CDP):
        return _cdp_checksum(layer)
    if isinstance(layer, OSPF):
        return _ospf_checksum(layer)
    if isinstance(layer, STUN):
        return _stun_fingerprint(layer)
    return None


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
    """Return the correct checksum field value for ``layer``.

    :param layer: The header to checksum. ``IPv4`` covers its own
        header only (options included; ``ip``/``payload`` ignored);
        ``ICMPv4`` covers header plus ``payload`` (no pseudo-header);
        ``GRE`` covers header plus ``payload`` with no pseudo-header
        (RFC 2784 §2.5) and requires the Checksum-Present bit;
        ``IGMP`` covers its whole message, body included, with no
        pseudo-header (``payload`` ignored); given ``ip``, the input of
        all three ends at its datagram's declared end (see ``ip``);
        ``TCP``, ``UDP``, and ``ICMPv6`` prepend the pseudo-header
        built from ``ip``; ``SCTP`` is a CRC32c over the whole packet,
        its chunks included, with no pseudo-header (``ip`` ignored),
        returned as the field's big-endian reading of the CRC's
        little-endian wire bytes (RFC 9260 §A); ``VRRP`` covers
        the message alone in VRRPv2 and prepends the pseudo-header in
        VRRPv3, over IPv4 too, keepalived's default form rather than RFC
        9568 §5.2.8's (see the module docstring), with ``payload``
        ignored either way; ``OSPF`` covers its own
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
        and Wireshark sum it (see :func:`_cdp_sum`); ``STUN`` is its
        FINGERPRINT attribute's value, the CRC-32 of the message up to
        it XORed with ``0x5354554E`` (RFC 8489 §14.7; ``ip`` and
        ``payload`` ignored), and raises for a message whose last
        attribute is not a FINGERPRINT.
    :param ip: The enclosing IP layer, required for TCP/UDP/ICMPv6,
        VRRPv3, and PIM, whose coverage depends on the family. For
        ``IGMP``, ``ICMPv4`` and ``GRE`` it is optional and is the IP
        header directly before the layer: the input then ends
        ``ip._payload_extent()`` bytes after the layer's start, unless
        that length is 0, an IPv4 Total Length is shorter than its
        header, or the end falls before the layer's required bytes
        (see the module docstring), and without it the input runs to
        the end of ``bytes(layer)`` and ``payload``.
    :param routing: The :class:`~netprotocols.IPv6Routing` header
        between ``ip`` and ``layer``, if there is one. RFC 8200 §8.1
        puts the *final* destination in the pseudo-header behind a
        Routing header, but ``ip.dst`` of a packet in flight is the
        next hop while ``routing.segments_left`` is above 0. With
        ``routing`` given, ``ip`` IPv6 and segments left, the
        pseudo-header uses
        :meth:`~netprotocols.IPv6Routing.final_destination`; otherwise
        (no segments left, IPv4, a routing type or data that method
        cannot resolve) it uses ``ip.dst``. Used only by the
        layers whose checksum has a pseudo-header
        (see ``ip``). If several Routing headers precede the layer,
        pass the last one with segments left, as
        :meth:`Packet.with_checksums
        <netprotocols.packet.Packet.with_checksums>` does: a receiver
        skips a Routing header with none left (RFC 8200 §4.4 for
        unrecognized types, and each type's own processing rules: RFC
        2460 §4.4, RFC 6554 §4.2, RFC 8754 §4.3), so the route ends at
        the last that has some.
    :param payload: The bytes following ``layer`` on the wire. A decoded
        ``ICMPv4``/``ICMPv6``/``IGMP``/``PIM`` message, and a decoded
        ``SCTP`` packet, already carries its whole body in
        ``bytes(layer)``, so pass a ``payload`` only for bytes the layer
        object does not itself hold. ``IGMP``, ``VRRP``, ``PIM``,
        ``CDP`` and ``STUN`` ignore it: nothing after the message is
        part of it.
    :raises InvalidFieldError: if ``layer`` has no checksum field to
        compute, or ``ip`` is missing where the checksum needs it.
    """
    ip = _pseudo_ip(ip, routing)
    if isinstance(layer, (IGMP, ICMPv4, GRE)):
        extent = (
            None
            if ip is None
            else _datagram_extent(ip, 0, _required_bytes(layer))
        )
        return _bounded_checksum(layer, extent, payload)
    standalone = _standalone_checksum(layer)
    if standalone is not None:
        return standalone
    if isinstance(layer, SCTP):
        return _sctp_checksum(layer, payload)
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


def _carries_no_checksum(layer: Protocol, ip: IPv4 | IPv6 | None) -> bool:
    """Return whether ``layer`` carries no checksum to verify.

    That is a UDP-over-IPv4 checksum of ``0`` (RFC 768), a GRE header
    without the C bit (RFC 2784 §2.5), an OSPF packet under
    cryptographic authentication (RFC 2328 §D.4.3, RFC 7474 §5), and a
    STUN message whose attributes walk whole with no FINGERPRINT
    attribute among them or begun in their last 8 bytes (RFC 8489
    §14.7; see :func:`_stun_carries_no_fingerprint`).
    """
    if isinstance(layer, UDP):
        return layer.checksum == 0 and not isinstance(ip, IPv6)
    if isinstance(layer, GRE):
        return not layer.checksum_present
    if isinstance(layer, OSPF):
        return layer.au_type in OSPF.CRYPTOGRAPHIC_AU_TYPES
    if isinstance(layer, STUN):
        return _stun_carries_no_fingerprint(layer)
    return False


def verify(
    layer: Protocol,
    *,
    ip: IPv4 | IPv6 | None = None,
    routing: IPv6Routing | None = None,
    payload: bytes = b"",
) -> bool:
    """Return whether ``layer``'s checksum field matches a recomputation.

    It accepts what the governing RFC tells a receiver to accept, which
    can be more than :func:`compute` produces: a UDP-over-IPv4 checksum
    of ``0``, a GRE header without the C bit, a PIM Register summed
    over the whole message, and a VRRPv3-over-IPv4 advert summed
    without the IPv4 pseudo-header, each described below.

    A UDP-over-IPv4 checksum of ``0`` means "no checksum in use" and
    verifies as True (over IPv6 the checksum is mandatory and ``0`` is
    invalid). A GRE header whose Checksum-Present bit is clear carries
    no checksum at all (RFC 2784 §2.5) and likewise verifies as True —
    a frame cannot fail a checksum it does not have — as does an OSPF
    packet under cryptographic authentication (AuType 2 or 3, RFC 2328
    §D.4.3, RFC 7474 §5), whose digest this library cannot check
    without the key, and a STUN message with no FINGERPRINT attribute
    (RFC 8489 §14.7). A STUN message with one anywhere but last, where
    RFC 8489 §14.7 requires it, fails, and so does one whose attributes
    do not walk to their end, or whose last 8 bytes begin like a
    FINGERPRINT the walk does not reach: either may be a FINGERPRINTed
    message with an earlier Length corrupted.

    A PIM Register verifies with its checksum over its first 8 bytes,
    as RFC 7761 §4.9.3 computes it, or over the whole message, as it
    asks a receiver to accept too ("for interoperability reasons"). So
    a whole-message Register verifies, but
    :meth:`~netprotocols.Packet.with_checksums` rewrites its checksum to
    the 8-byte form :func:`compute` returns.

    A VRRPv3 advert over IPv4 verifies with its checksum behind the
    IPv4 pseudo-header, as :func:`compute` returns it, or over the
    message alone, as RFC 9568 §5.2.8 computes it.
    :meth:`~netprotocols.Packet.with_checksums` rewrites the second to
    the first. A VRRPv2 advert, whose sum never has a pseudo-header,
    and a VRRPv3 advert over IPv6, whose sum always has one, verify
    only in :func:`compute`'s form.

    ``routing`` is :func:`compute`'s: behind a Routing header with
    segments left, the pseudo-header uses the route's final destination
    (RFC 8200 §8.1).

    ``ip`` and ``payload`` are :func:`compute`'s too. Given ``ip``, an
    IGMP, ICMPv4 or GRE checksum is recomputed over the bytes up to the
    IP datagram's declared end, so an IGMP or ICMPv4 message decoded on
    its own with Ethernet padding or an FCS in its ``body`` verifies.
    """
    ip = _pseudo_ip(ip, routing)
    if _carries_no_checksum(layer, ip):
        return True
    if isinstance(layer, PIM):
        return _verify_pim(layer, ip)
    if isinstance(layer, VRRP):
        return _verify_vrrp(layer, ip)
    if isinstance(layer, STUN):
        return layer.fingerprint is not None and (
            _stun_fingerprint(layer) == layer.fingerprint
        )
    wire: int = layer.checksum  # type: ignore[attr-defined]
    return compute(layer, ip=ip, payload=payload) == wire
