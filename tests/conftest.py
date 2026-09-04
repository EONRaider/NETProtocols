"""Shared fixtures: real header bytes from captured traffic.

Sources include the Wireshark sample captures at
https://wiki.wireshark.org/SampleCaptures (arp-storm.pcap, among
others), locally captured frames, and the real-capture corpus under
``tests/fixtures/`` (see its MANIFEST.md).
"""

from pathlib import Path

import pytest

from netprotocols.pcap import read_pcap

FIXTURES = Path(__file__).parent / "fixtures"


def pcap_frames(path: Path) -> list[bytes]:
    """Every frame's raw bytes from one pcap file, in order.

    A thin adapter over :func:`netprotocols.pcap.read_pcap` for call
    sites that only want frame bytes, not timestamps (see
    :func:`corpus_frames` for both) — this suite no longer carries its
    own pcap-parsing implementation (#100); it exercises the shipped
    one, the same as any other caller would.
    """
    return [frame.data for frame in read_pcap(path.read_bytes())]


def corpus_frames() -> list[tuple[str, int, bytes]]:
    """Every corpus frame as ``(pcap_name, index, frame_bytes)``."""
    return [
        (pcap.name, index, frame)
        for pcap in sorted(FIXTURES.glob("*.pcap"))
        for index, frame in enumerate(pcap_frames(pcap))
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
