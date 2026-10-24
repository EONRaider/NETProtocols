#!/usr/bin/env python3
"""Build, send, and cross-check the IPsec fixture packets.

Run by ``scripts/capture_fixtures_ipsec.sh`` inside the sending netns;
stdlib only, and never imports netprotocols, for the same reason
``check_fixtures.py`` does not: a fixture must be able to disqualify
the library, not be shaped by it.

The packets are genuine IPsec, not random bytes: ESP with NULL
encryption (RFC 2410) and AH, both with HMAC-SHA-256-128 integrity (RFC
4868), so every payload stays readable and every ICV verifies with the
published test keys (``tests/fixtures/MANIFEST.md``).

Usage::

    python3 scripts/ipsec_fixture_packets.py send esp|ah SENT_LOG
    python3 scripts/ipsec_fixture_packets.py compare esp|ah PCAP SENT_LOG

``send`` transmits the packets to 10.9.11.2 and records what it built
in ``SENT_LOG``; ``compare`` reads the capture back and reports, frame
by frame, which bytes the kernel built and confirms the rest are the
script's own, byte for byte.
"""

from __future__ import annotations

import hashlib
import hmac
import socket
import struct
import sys
from dataclasses import dataclass
from pathlib import Path

SRC = "10.9.11.1"
DST = "10.9.11.2"

#: Tunnel-mode inner endpoints (RFC 5737 TEST-NET-1): the hosts behind
#: the two security gateways at SRC and DST.
INNER_SRC = "192.0.2.1"
INNER_DST = "192.0.2.2"

PROTO_IPIP = 4
PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17
PROTO_ESP = 50
PROTO_AH = 51

#: HMAC-SHA-256-128 (RFC 4868 §2.3): the HMAC truncated to 128 bits.
ICV_LEN = 16

ESP_PAYLOAD = b"NETProtocols ESP fixture"
AH_PAYLOAD = b"NETProtocols AH fixture"

#: DSCP AF11 on every AH packet's outer header. TOS is one of the
#: fields AH's ICV treats as mutable (RFC 4302 §3.3.3.1.1.1), so a
#: non-zero value shows the verifier zeroing it.
AH_TOS = 0x28


@dataclass(frozen=True)
class SA:
    """A Security Association's on-the-wire identity and its integrity
    key. The keys are published test keys, not secrets."""

    spi: int
    key: bytes


ESP_TRANSPORT = SA(
    0x10000001,
    bytes.fromhex(
        "e41126360fbc54a0e11a8747218b24d0cc4638f579c3985017b4d0ab1a30398b"
    ),
)
ESP_TUNNEL = SA(
    0x10000002,
    bytes.fromhex(
        "4bc3ce948208049b2f5016e06616867773924d2ccb4dab8b3aff93e6d26f3834"
    ),
)
ESP_BUNDLE = SA(
    0x10000003,
    bytes.fromhex(
        "107c873bdbb0c7a11be8aa1d9064e51f63b26098412295c3bd6785958abd44d4"
    ),
)
AH_TRANSPORT = SA(
    0x20000001,
    bytes.fromhex(
        "8eaa03a41a3b08f31a67f3a4b7fd78a2bf3d963a97b0af5a104301ef8fbff685"
    ),
)
AH_TUNNEL = SA(
    0x20000002,
    bytes.fromhex(
        "d2142153fb758a3f698e45720e2af765b2ada021d70ac1bcbde1f5bc38514fd1"
    ),
)
AH_BUNDLE = SA(
    0x20000003,
    bytes.fromhex(
        "008a9a220d8c1bf5edec1838a724b588364c08314bf93206985e776c385e1c7a"
    ),
)


def internet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def addr(text: str) -> bytes:
    return socket.inet_aton(text)


def icv(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()[:ICV_LEN]


def icmp_echo(seq: int, payload: bytes) -> bytes:
    message = struct.pack("!BBHHH", 8, 0, 0, 0x4E50, seq) + payload
    checksum = internet_checksum(message)
    return message[:2] + struct.pack("!H", checksum) + message[4:]


def udp(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    pseudo = addr(src) + addr(dst) + struct.pack("!BBH", 0, PROTO_UDP, length)
    datagram = struct.pack("!HHHH", sport, dport, length, 0) + payload
    checksum = internet_checksum(pseudo + datagram) or 0xFFFF
    return datagram[:6] + struct.pack("!H", checksum) + datagram[8:]


def tcp_syn(src: str, dst: str, sport: int, dport: int, seq: int) -> bytes:
    """A SYN carrying an MSS option (RFC 9293 §3.7.1), no payload."""
    options = struct.pack("!BBH", 2, 4, 1460)
    segment = (
        struct.pack(
            "!HHIIBBHHH", sport, dport, seq, 0, 6 << 4, 0x02, 64240, 0, 0
        )
        + options
    )
    pseudo = (
        addr(src) + addr(dst) + struct.pack("!BBH", 0, PROTO_TCP, len(segment))
    )
    checksum = internet_checksum(pseudo + segment)
    return segment[:16] + struct.pack("!H", checksum) + segment[18:]


def ipv4(
    src: str,
    dst: str,
    protocol: int,
    payload: bytes,
    *,
    identification: int,
    tos: int = 0,
    flags_frag: int = 0x4000,
    ttl: int = 64,
) -> bytes:
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        tos,
        20 + len(payload),
        identification,
        flags_frag,
        ttl,
        protocol,
        0,
        addr(src),
        addr(dst),
    )
    checksum = internet_checksum(header)
    return header[:10] + struct.pack("!H", checksum) + header[12:] + payload


def esp(sa: SA, seq: int, next_header: int, payload: bytes) -> bytes:
    """An ESP packet under NULL encryption and HMAC-SHA-256-128.

    The trailer pads the payload so that payload + padding + the two
    trailer bytes end on a 4-byte boundary (RFC 4303 §2.4; NULL's block
    size is 1), with the RFC's default pad bytes 1, 2, 3, ... The ICV
    covers SPI through Next Header (RFC 4303 §2.8, §3.3.2.1).
    """
    pad_len = -(len(payload) + 2) % 4
    padding = bytes(range(1, pad_len + 1))
    protected = (
        struct.pack("!II", sa.spi, seq)
        + payload
        + padding
        + bytes([pad_len, next_header])
    )
    return protected + icv(sa.key, protected)


def ah_datagram(
    sa: SA, seq: int, next_header: int, payload: bytes, *, identification: int
) -> bytes:
    """A whole IPv4 datagram protected by AH with HMAC-SHA-256-128.

    The ICV covers the IPv4 header with its mutable fields — TOS,
    flags and fragment offset, TTL, header checksum — zeroed, then the
    AH header with its ICV zeroed, then the payload (RFC 4302 §3.3.3).
    That is why the script builds the IPv4 header itself and sends it
    with IP_HDRINCL: the identification and every other immutable field
    on the wire must be the ones that were authenticated.
    """
    payload_len = (12 + ICV_LEN) // 4 - 2  # 28 bytes, IPv4-aligned
    ah = struct.pack("!BBHII", next_header, payload_len, 0, sa.spi, seq)
    blank = ah + bytes(ICV_LEN) + payload
    header = ipv4(
        SRC,
        DST,
        PROTO_AH,
        blank,
        identification=identification,
        tos=AH_TOS,
    )[:20]
    # The same header as the ICV sees it: TOS (byte 1), flags and
    # fragment offset (bytes 6-7), TTL (byte 8) and the checksum (bytes
    # 10-11) zeroed; version/IHL, total length, identification,
    # protocol and the addresses kept.
    immutable = (
        header[:1]
        + bytes(1)
        + header[2:6]
        + bytes(3)
        + header[9:10]
        + bytes(2)
        + header[12:]
    )
    return header + ah + icv(sa.key, immutable + blank) + payload


def inner_ipv4(identification: int, protocol: int, payload: bytes) -> bytes:
    return ipv4(
        INNER_SRC,
        INNER_DST,
        protocol,
        payload,
        identification=identification,
    )


def esp_packets() -> list[bytes]:
    """The ESP payloads, in send order; the kernel adds the outer IPv4
    header to each."""
    tunnel_udp = udp(INNER_SRC, INNER_DST, 40000, 9, ESP_PAYLOAD)
    return [
        # Transport mode: the upper-layer protocol rides ESP directly,
        # its pseudo-header taken from the outer (only) IP header.
        esp(ESP_TRANSPORT, 1, PROTO_ICMP, icmp_echo(1, ESP_PAYLOAD)),
        esp(ESP_TRANSPORT, 2, PROTO_ICMP, icmp_echo(2, ESP_PAYLOAD)),
        esp(ESP_TRANSPORT, 3, PROTO_UDP, udp(SRC, DST, 40000, 9, ESP_PAYLOAD)),
        # Tunnel mode: a whole inner IPv4 packet between the hosts the
        # two gateways front (RFC 4303 §3.1.2).
        esp(
            ESP_TUNNEL,
            1,
            PROTO_IPIP,
            inner_ipv4(0x0101, PROTO_ICMP, icmp_echo(1, ESP_PAYLOAD)),
        ),
        esp(
            ESP_TUNNEL,
            2,
            PROTO_IPIP,
            inner_ipv4(0x0102, PROTO_ICMP, icmp_echo(2, ESP_PAYLOAD)),
        ),
        esp(
            ESP_TUNNEL, 3, PROTO_IPIP, inner_ipv4(0x0103, PROTO_UDP, tunnel_udp)
        ),
    ]


def ah_datagrams() -> list[bytes]:
    """The AH datagrams, in send order, outer IPv4 header included."""
    return [
        # Transport mode: AH between the IPv4 header and the transport,
        # whose pseudo-header is still the IPv4 header's.
        ah_datagram(
            AH_TRANSPORT,
            1,
            PROTO_TCP,
            tcp_syn(SRC, DST, 40001, 80, 0x4E500001),
            identification=0xA101,
        ),
        ah_datagram(
            AH_TRANSPORT,
            2,
            PROTO_ICMP,
            icmp_echo(1, AH_PAYLOAD),
            identification=0xA102,
        ),
        ah_datagram(
            AH_TRANSPORT,
            3,
            PROTO_UDP,
            udp(SRC, DST, 40002, 9, AH_PAYLOAD),
            identification=0xA103,
        ),
        # Tunnel mode: a whole inner IPv4 packet, which the ICV covers
        # entirely, mutable fields and all (RFC 4302 §3.1.2).
        ah_datagram(
            AH_TUNNEL,
            1,
            PROTO_IPIP,
            inner_ipv4(0x0201, PROTO_ICMP, icmp_echo(1, AH_PAYLOAD)),
            identification=0xA104,
        ),
        ah_datagram(
            AH_TUNNEL,
            2,
            PROTO_IPIP,
            inner_ipv4(
                0x0202,
                PROTO_TCP,
                tcp_syn(INNER_SRC, INNER_DST, 40003, 80, 0x4E500002),
            ),
            identification=0xA105,
        ),
        # A transport-adjacency bundle (RFC 4301 §4.5): AH over ESP, the
        # ESP packet protecting an ICMP echo and AH protecting both.
        ah_datagram(
            AH_BUNDLE,
            1,
            PROTO_ESP,
            esp(ESP_BUNDLE, 1, PROTO_ICMP, icmp_echo(1, AH_PAYLOAD)),
            identification=0xA106,
        ),
    ]


def send(kind: str, log: Path) -> None:
    sent: list[str] = []
    if kind == "esp":
        # A raw socket for protocol 50: the kernel builds and checksums
        # the outer IPv4 header, as an IPsec endpoint's stack would.
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, PROTO_ESP) as s:
            for packet in esp_packets():
                s.sendto(packet, (DST, 0))
                sent.append(packet.hex())
    elif kind == "ah":
        # IPPROTO_RAW implies IP_HDRINCL: the script's IPv4 header goes
        # out as built, because AH's ICV covers it.
        with socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW
        ) as s:
            for datagram in ah_datagrams():
                s.sendto(datagram, (DST, 0))
                sent.append(datagram.hex())
    else:
        raise SystemExit(f"unknown packet kind {kind!r}")
    log.write_text("\n".join(sent) + "\n")


def pcap_datagrams(path: Path) -> list[bytes]:
    """The IPv4 datagrams of an Ethernet pcap (little-endian classic
    pcap, as tcpdump writes it), trimmed to their total length."""
    data = path.read_bytes()
    datagrams, cursor = [], 24
    while cursor + 16 <= len(data):
        incl_len = struct.unpack_from("<I", data, cursor + 8)[0]
        frame = data[cursor + 16 : cursor + 16 + incl_len]
        cursor += 16 + incl_len
        total_length = struct.unpack_from("!H", frame, 16)[0]
        datagrams.append(frame[14 : 14 + total_length])
    return datagrams


def compare(kind: str, pcap: Path, log: Path) -> int:
    sent = [bytes.fromhex(line) for line in log.read_text().split()]
    captured = pcap_datagrams(pcap)
    if len(sent) != len(captured):
        print(f"[!] sent {len(sent)} packets, captured {len(captured)}")
        return 1
    failures = 0
    for index, (built, wire) in enumerate(zip(sent, captured, strict=True)):
        ihl = (wire[0] & 0x0F) * 4
        if kind == "esp":
            # The script built only the ESP packet; the header is the
            # kernel's.
            identical = wire[ihl:] == built
            ident, ttl = struct.unpack_from("!H", wire, 4)[0], wire[8]
            note = f"kernel-built IPv4 header (id {ident:#06x}, ttl {ttl})"
        elif kind == "ah":
            # The script built the whole datagram. Under IP_HDRINCL the
            # kernel still rewrites the total length and the header
            # checksum; identical bytes mean it rewrote them to the
            # script's own values.
            identical = wire == built
            note = "whole datagram script-built (IP_HDRINCL)"
        else:
            raise SystemExit(f"unknown packet kind {kind!r}")
        verdict = "identical" if identical else "DIFFERS"
        print(f"    frame {index}: script bytes {verdict}; {note}")
        failures += not identical
    return 1 if failures else 0


def main(argv: list[str]) -> int:
    if len(argv) == 3 and argv[0] == "send":
        send(argv[1], Path(argv[2]))
        return 0
    if len(argv) == 4 and argv[0] == "compare":
        return compare(argv[1], Path(argv[2]), Path(argv[3]))
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
