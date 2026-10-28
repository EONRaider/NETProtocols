#!/usr/bin/env python3
"""Build, send, and cross-check the MPLS fixture frames.

Run by ``scripts/capture_fixtures_mpls.sh``; stdlib only, and never
imports netprotocols, for the same reason ``check_fixtures.py`` does
not: a fixture must be able to disqualify the library, not be shaped
by it.

The kernel cannot build MPLS (CONFIG_MPLS_ROUTING is off on the capture
host, and on many others), so this script builds the Ethernet header
and the label stack of every frame itself and sends the frames whole
through an ``AF_PACKET`` socket. The labelled packets are the kernel's:
IPv4 datagrams (two ICMP echo requests and two UDP datagrams) the
capture script has the kernel send over the same veth pair first,
captured inbound with offload off, so their headers and checksums are
the kernel's own. Two payloads are not: the IPv6 packet under IPv6
Explicit NULL, which this script builds and checksums (the capture
host runs with IPv6 disabled), and the pseudowire control word, which
precedes a whole kernel-built Ethernet frame.

Usage::

    python3 scripts/mpls_fixture_packets.py send INNER_PCAP IFACE SENT_LOG
    python3 scripts/mpls_fixture_packets.py compare PCAP SENT_LOG

``send`` reads the kernel's frames from ``INNER_PCAP``, wraps them as
:data:`PLAN` says, transmits the frames on ``IFACE`` and records them in
``SENT_LOG``; ``compare`` reads the capture back and confirms, frame by
frame, that every byte arrived as sent.
"""

from __future__ import annotations

import socket
import struct
import sys
from dataclasses import dataclass
from pathlib import Path

#: The veth pair's addresses (set by the capture script).
MAC_A = bytes.fromhex("02000a093c01")
MAC_B = bytes.fromhex("02000a093c02")
#: An IPv4 multicast MAC (RFC 1112 §6.4) for the upstream-assigned
#: frame: RFC 5332 §4 keeps EtherType 0x8848 for a multicast frame.
MAC_MULTICAST = bytes.fromhex("01005e000001")

ETHERTYPE_MPLS = 0x8847
ETHERTYPE_MPLS_UPSTREAM = 0x8848

#: The IPv6 packet's endpoints (RFC 3849 documentation prefix).
V6_SRC = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
V6_DST = socket.inet_pton(socket.AF_INET6, "2001:db8::2")
V6_PAYLOAD = b"NETProtocols MPLS IPv6 fixture"

#: An Ethernet sender pads a frame to 60 bytes before the FCS.
MIN_FRAME = 60


@dataclass(frozen=True)
class Entry:
    """One label stack entry; ``bottom`` is set on the last only."""

    label: int
    tc: int = 0
    ttl: int = 64

    def pack(self, bottom: bool) -> bytes:
        """Pack the entry, its S bit set if ``bottom``."""
        word = (self.label << 12) | (self.tc << 9) | (bottom << 8) | self.ttl
        return struct.pack("!I", word)


@dataclass(frozen=True)
class Frame:
    """One fixture frame: its label stack and what follows it.

    ``inner`` names the payload: an index into the kernel's captured
    IPv4 datagrams, ``"ipv6"`` for the script-built IPv6 packet, or
    ``"pw"`` for a control word and the kernel's first whole frame.
    """

    note: str
    stack: tuple[Entry, ...]
    inner: int | str
    ethertype: int = ETHERTYPE_MPLS
    dst: bytes = MAC_B
    pad: bool = False


#: The frames, in send order. The kernel's datagrams are, in capture
#: order: 0 and 1 the two ICMP echo requests, 2 the short UDP datagram,
#: 3 the long one.
PLAN = (
    Frame("one label carrying IPv4 (ICMP echo)", (Entry(0x12345),), 0),
    Frame(
        "two labels carrying IPv4 (UDP)",
        (Entry(16001), Entry(16002)),
        3,
    ),
    Frame(
        "three labels carrying IPv4 (ICMP echo), traffic classes 5/3/0",
        (Entry(16001, tc=5), Entry(16002, tc=3, ttl=63), Entry(16003)),
        1,
    ),
    Frame(
        "Entropy Label Indicator then an entropy label (RFC 6790), IPv4",
        (Entry(16001), Entry(7), Entry(0xABCDE, ttl=0)),
        0,
    ),
    Frame(
        "IPv4 Explicit NULL bottom, a short UDP datagram, zero padded",
        (Entry(16001), Entry(0)),
        2,
        pad=True,
    ),
    Frame(
        "IPv6 Explicit NULL bottom, a script-built IPv6 UDP datagram",
        (Entry(16001), Entry(2)),
        "ipv6",
    ),
    Frame(
        "EtherType 0x8848 to a multicast MAC, IPv4 (ICMP echo)",
        (Entry(0x54321),),
        1,
        ethertype=ETHERTYPE_MPLS_UPSTREAM,
        dst=MAC_MULTICAST,
    ),
    Frame(
        "Ethernet pseudowire: control word, then a whole Ethernet frame",
        (Entry(16001), Entry(0x23456)),
        "pw",
    ),
)


def internet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def ipv6_udp() -> bytes:
    """Build an IPv6 UDP datagram, its checksum computed (RFC 8200 §8.1)."""
    length = 8 + len(V6_PAYLOAD)
    datagram = struct.pack("!HHHH", 40000, 9, length, 0) + V6_PAYLOAD
    pseudo = V6_SRC + V6_DST + struct.pack("!I3xB", length, 17)
    checksum = internet_checksum(pseudo + datagram) or 0xFFFF
    datagram = datagram[:6] + struct.pack("!H", checksum) + datagram[8:]
    header = struct.pack("!IHBB", 6 << 28, length, 17, 64)
    return header + V6_SRC + V6_DST + datagram


def control_word(sequence: int) -> bytes:
    """Build an RFC 4448 §4.6 control word.

    First nibble 0, then reserved bits and a 16-bit sequence number.
    """
    return struct.pack("!HH", 0, sequence)


def pcap_frames(path: Path) -> list[bytes]:
    """Read the frames of a little-endian classic pcap, as tcpdump writes."""
    data = path.read_bytes()
    if data[:4] != b"\xd4\xc3\xb2\xa1":
        raise SystemExit(f"{path}: not a little-endian microsecond pcap")
    frames, cursor = [], 24
    while cursor + 16 <= len(data):
        incl_len = struct.unpack_from("<I", data, cursor + 8)[0]
        frames.append(data[cursor + 16 : cursor + 16 + incl_len])
        cursor += 16 + incl_len
    return frames


def kernel_datagrams(frames: list[bytes]) -> list[bytes]:
    """Extract the IPv4 datagrams of the kernel's frames.

    Each is trimmed to its total length, and checked to be the kind the
    plan expects.
    """
    datagrams = []
    for frame in frames:
        if struct.unpack_from("!H", frame, 12)[0] != 0x0800:
            raise SystemExit("the kernel's capture holds a non-IPv4 frame")
        total_length = struct.unpack_from("!H", frame, 16)[0]
        datagrams.append(frame[14 : 14 + total_length])
    kinds = [datagram[9] for datagram in datagrams]
    if kinds != [1, 1, 17, 17]:
        raise SystemExit(f"expected 2 ICMP then 2 UDP datagrams, got {kinds}")
    return datagrams


def build(plan: Frame, frames: list[bytes], datagrams: list[bytes]) -> bytes:
    """One fixture frame, Ethernet header to the end of its payload."""
    last = len(plan.stack) - 1
    labels = b"".join(
        entry.pack(index == last) for index, entry in enumerate(plan.stack)
    )
    if plan.inner == "ipv6":
        payload = ipv6_udp()
    elif plan.inner == "pw":
        payload = control_word(1) + frames[0]
    else:
        assert isinstance(plan.inner, int)
        payload = datagrams[plan.inner]
    frame = plan.dst + MAC_A + struct.pack("!H", plan.ethertype)
    frame += labels + payload
    if plan.pad:
        frame += bytes(max(0, MIN_FRAME - len(frame)))
    return frame


def send(inner: Path, iface: str, log: Path) -> None:
    frames = pcap_frames(inner)
    datagrams = kernel_datagrams(frames)
    built = [build(plan, frames, datagrams) for plan in PLAN]
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as s:
        s.bind((iface, 0))
        for frame in built:
            s.send(frame)
    log.write_text("\n".join(frame.hex() for frame in built) + "\n")


def compare(pcap: Path, log: Path) -> int:
    sent = [bytes.fromhex(line) for line in log.read_text().split()]
    captured = pcap_frames(pcap)
    if len(sent) != len(captured):
        print(f"[!] sent {len(sent)} frames, captured {len(captured)}")
        return 1
    failures = 0
    for index, (plan, built, wire) in enumerate(
        zip(PLAN, sent, captured, strict=True)
    ):
        verdict = "identical" if wire == built else "DIFFERS"
        print(f"    frame {index}: {verdict}; {plan.note}")
        failures += wire != built
    return 1 if failures else 0


def main(argv: list[str]) -> int:
    if len(argv) == 4 and argv[0] == "send":
        send(Path(argv[1]), argv[2], Path(argv[3]))
        return 0
    if len(argv) == 3 and argv[0] == "compare":
        return compare(Path(argv[1]), Path(argv[2]))
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
