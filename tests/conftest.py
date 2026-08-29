"""Shared fixtures: real header bytes from captured traffic.

Sources include the Wireshark sample captures at
https://wiki.wireshark.org/SampleCaptures (arp-storm.pcap, among
others), locally captured frames, and the real-capture corpus under
``tests/fixtures/`` (see its MANIFEST.md).
"""

import struct
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


def read_pcap(path: Path) -> list[bytes]:
    """Minimal classic-pcap reader for the fixture corpus (test-only;
    independent of any library or application pcap code)."""
    data = path.read_bytes()
    magic = data[:4]
    if magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    elif magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    else:
        raise ValueError(f"{path.name}: not a pcap")
    frames = []
    cursor = 24
    while cursor + 16 <= len(data):
        (incl_len,) = struct.unpack_from(f"{endian}I", data, cursor + 8)
        cursor += 16
        frames.append(data[cursor : cursor + incl_len])
        cursor += incl_len
    return frames


def corpus_frames() -> list[tuple[str, int, bytes]]:
    """Every corpus frame as ``(pcap_name, index, frame_bytes)``."""
    return [
        (pcap.name, index, frame)
        for pcap in sorted(FIXTURES.glob("*.pcap"))
        for index, frame in enumerate(read_pcap(pcap))
    ]


@pytest.fixture
def raw_eth_header() -> bytes:
    """Ethernet II header of a broadcast ARP frame."""
    return b"\xff\xff\xff\xff\xff\xff\x00\x07\x0d\xaf\xf4\x54\x08\x06"


@pytest.fixture
def raw_arp_header() -> bytes:
    """ARP request: who has 24.166.173.159? Tell 24.166.172.1."""
    return (
        b"\x00\x01\x08\x00\x06\x04\x00\x01\x00\x07\x0d\xaf\xf4\x54"
        b"\x18\xa6\xac\x01\x00\x00\x00\x00\x00\x00\x18\xa6\xad\x9f"
    )


@pytest.fixture
def raw_ipv4_header() -> bytes:
    """IPv4 header, IHL 5, encapsulating TCP."""
    return (
        b"\x45\x00\x00\x28\xec\x6c\x40\x00\x40\x06\x2b\x51\xc0\xa8\x01\x60"
        b"\xc0\xa8\x01\xfe"
    )


@pytest.fixture
def raw_ipv6_header() -> bytes:
    """IPv6 header, fe80::1 -> ff02::1, encapsulating TCP."""
    return (
        b"\x60\x00\x00\x00\x00\x78\x06\xff\xfe\x80\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x01\xff\x02\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x01"
    )


@pytest.fixture
def raw_icmpv4_echo_request() -> bytes:
    """ICMPv4 echo request: 8-byte header followed by ping payload."""
    return (
        b"\x08\x00\x83\xf7\x00\x01\x00\x01\xbf\xc8\xea\x61\x00\x00\x00\x00"
        b"\x08\x09\x03\x00\x00\x00\x00\x00\x10\x11\x12\x13\x14\x15\x16\x17"
        b"\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27"
        b"\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37"
    )


@pytest.fixture
def raw_icmpv6_echo_request() -> bytes:
    """ICMPv6 echo request: 8-byte header followed by payload."""
    return b"\x80\x00\x3f\x69\x76\x20\x01\x00\x02\xc9\xe7\x36\x37\x43\x06\x00"


@pytest.fixture
def raw_tcp_header_with_options() -> bytes:
    """TCP header with data offset 8: 20 fixed bytes + 12 bytes of
    options (NOP, NOP, timestamp)."""
    return (
        b"\x03\xfe\x00\x16\xd6\x76\xf6\x71\x0c\x7a\x14\x57\x80\x18\x21\x5c"
        b"\x20\x08\x00\x00\x01\x01\x08\x0a\x00\x08\xca\x61\x00\x01\x69\x2e"
    )


@pytest.fixture
def raw_udp_header() -> bytes:
    """UDP header of a DNS query (destination port 53)."""
    return b"\x09\x5e\x00\x35\x00\x29\x36\x49"
