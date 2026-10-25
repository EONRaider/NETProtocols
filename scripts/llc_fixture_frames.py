#!/usr/bin/env python3
"""Build and send the script-built frames of the LLC fixture.

Run by ``scripts/capture_fixtures_llc.sh`` inside the sending netns;
stdlib only, and never imports netprotocols, for the same reason
``check_fixtures.py`` does not: a fixture must be able to disqualify
the library, not be shaped by it.

The kernel's bridge and lldpd produce the fixture's 802.1D BPDUs and
CDP frames. What neither produces on this host is built here, every
byte of it, and sent through an ``AF_PACKET`` socket, which hands the
frame to the veth as it stands (no padding, no FCS):

1. RFC 1042: an ARP request in LLC/SNAP with OUI 00-00-00 and PID
   0x0806, zero-padded to Ethernet's minimum frame size (64 bytes with
   the FCS, so 60 here) as a NIC pads a short frame, so the 802.3
   Length (36) stops 10 bytes short of the frame.
2. RFC 1042: an ICMP echo request in IPv4 in LLC/SNAP, with correct
   IPv4 header and ICMP checksums; long enough to need no padding.
3. IEEE 802.1H bridge-tunnel: the same ARP request under OUI 00-00-F8,
   also padded to 60 bytes.
4. The ARP request of 1, in RFC 1042 framing behind an 802.1Q tag
   (VID 30): the type/length field after the tag holds the Length.
5. Novell "raw 802.3": an IPX header (checksum 0xFFFF, no LLC header)
   after the 802.3 Length, padded to 60 bytes.
6. A type/length value of 0x05DD (1501), in the range IEEE 802.3
   leaves undefined, followed by 46 bytes of a counting pattern.

Usage::

    python3 scripts/llc_fixture_frames.py send IFACE
"""

from __future__ import annotations

import socket
import struct
import sys

#: The sending veth's own address and its peer's (the capture script
#: sets both), and the broadcast address an ARP request goes to.
SRC_MAC = bytes.fromhex("02000000a001")
PEER_MAC = bytes.fromhex("02000000b001")
BROADCAST = b"\xff" * 6

SRC_IP = bytes((10, 9, 30, 1))
DST_IP = bytes((10, 9, 30, 2))

#: LLC header for SNAP (DSAP 0xAA, SSAP 0xAA, UI) and the two OUIs under
#: which the SNAP PID is an EtherType.
LLC_SNAP = b"\xaa\xaa\x03"
OUI_RFC1042 = b"\x00\x00\x00"
OUI_8021H = b"\x00\x00\xf8"

ETH_P_ARP = 0x0806
ETH_P_IP = 0x0800
ETH_P_8021Q = 0x8100

#: Ethernet's minimum frame size, 64 bytes, less the 4-byte FCS.
MIN_FRAME = 60


def internet_checksum(data: bytes) -> int:
    """Return the RFC 1071 checksum of ``data``."""
    if len(data) % 2:
        data += b"\x00"
    total = sum(word for (word,) in struct.iter_unpack("!H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def pad(frame: bytes) -> bytes:
    """Zero-pad ``frame`` to the 60-byte minimum, as a NIC would."""
    return frame + bytes(max(0, MIN_FRAME - len(frame)))


def ethernet_8023(dst: bytes, pdu: bytes) -> bytes:
    """An 802.3 header whose Length is ``len(pdu)``, then the PDU."""
    return dst + SRC_MAC + struct.pack("!H", len(pdu)) + pdu


def arp_request() -> bytes:
    """ARP: who has 10.9.30.2? Tell 10.9.30.1 (RFC 826)."""
    return struct.pack(
        "!HHBBH6s4s6s4s",
        1,
        ETH_P_IP,
        6,
        4,
        1,
        SRC_MAC,
        SRC_IP,
        bytes(6),
        DST_IP,
    )


def icmp_echo_in_ipv4() -> bytes:
    """An IPv4 packet carrying an ICMP echo request, checksums filled."""
    payload = b"NETProtocols LLC/SNAP fixture"
    icmp = struct.pack("!BBHHH", 8, 0, 0, 0x4C4C, 1) + payload
    icmp = icmp[:2] + struct.pack("!H", internet_checksum(icmp)) + icmp[4:]
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(icmp),
        0x1042,
        0x4000,
        64,
        1,
        0,
        SRC_IP,
        DST_IP,
    )
    header = (
        header[:10] + struct.pack("!H", internet_checksum(header)) + header[12:]
    )
    return header + icmp


def snap(oui: bytes, pid: int, payload: bytes) -> bytes:
    """An LLC/SNAP PDU: the SNAP LLC header, OUI, PID, then payload."""
    return LLC_SNAP + oui + struct.pack("!H", pid) + payload


def raw_ipx() -> bytes:
    """A Novell raw 802.3 PDU: a 30-byte IPX header, no LLC, no data.

    Checksum 0xFFFF, length 30, transport control 0, packet type 4
    (PEP), destination network 0 node broadcast socket 0x0452 (SAP),
    source network 0 node SRC_MAC socket 0x4000.
    """
    return struct.pack(
        "!HHBB4s6sH4s6sH",
        0xFFFF,
        30,
        0,
        4,
        bytes(4),
        BROADCAST,
        0x0452,
        bytes(4),
        SRC_MAC,
        0x4000,
    )


def frames() -> list[bytes]:
    """The six frames, in the order they are sent."""
    arp = arp_request()
    tagged_pdu = snap(OUI_RFC1042, ETH_P_ARP, arp)
    tagged = (
        BROADCAST
        + SRC_MAC
        + struct.pack("!HHH", ETH_P_8021Q, 30, len(tagged_pdu))
        + tagged_pdu
    )
    gap = BROADCAST + SRC_MAC + struct.pack("!H", 1501) + bytes(range(46))
    icmp = icmp_echo_in_ipv4()
    return [
        pad(ethernet_8023(BROADCAST, snap(OUI_RFC1042, ETH_P_ARP, arp))),
        ethernet_8023(PEER_MAC, snap(OUI_RFC1042, ETH_P_IP, icmp)),
        pad(ethernet_8023(BROADCAST, snap(OUI_8021H, ETH_P_ARP, arp))),
        pad(tagged),
        pad(ethernet_8023(BROADCAST, raw_ipx())),
        gap,
    ]


def send(iface: str) -> None:
    """Send every frame out ``iface`` through one AF_PACKET socket."""
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as sock:
        sock.bind((iface, 0))
        for frame in frames():
            sock.send(frame)


def main(argv: list[str]) -> int:
    if len(argv) != 3 or argv[1] != "send":
        print(__doc__, file=sys.stderr)
        return 2
    send(argv[2])
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
