"""Shared fixtures: real header bytes from captured traffic.

Sources include the Wireshark sample captures at
https://wiki.wireshark.org/SampleCaptures (arp-storm.pcap, among
others), locally captured frames, and the real-capture corpus under
``tests/fixtures/`` (see its MANIFEST.md).

Two pieces of suite-wide setup also live here, because conftest.py is
the one module pytest loads for *every* selection of test files —
including the narrow selection mutmut runs (pyproject.toml's
``pytest_add_cli_args_test_selection``), which never imports
test_fuzz.py:

- The Hypothesis profiles (see test_fuzz.py's module docstring), so a
  property test anywhere runs under the same derandomized, deadline-free
  settings whether or not test_fuzz.py was collected.
- Clearing every module-level ``functools`` cache in the package before
  each test. mutmut 3 runs the clean suite in-process and then forks
  once per mutant, so without this a cache warmed by the original code
  answers in the child and hides the mutant (a false survivor), and a
  test whose input was already cached is never associated with the
  cached function at all.
"""

import importlib
import os
import pkgutil
import struct
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from hypothesis import settings

import netprotocols
from netprotocols.pcap import read_pcap

FIXTURES = Path(__file__).parent / "fixtures"

settings.register_profile(
    "netprotocols", max_examples=200, deadline=None, derandomize=True
)
settings.register_profile(
    "nightly", max_examples=10_000, deadline=None, derandomize=False
)
settings.load_profile(os.getenv("HYPOTHESIS_PROFILE", "netprotocols"))


def _package_caches() -> tuple[Callable[[], None], ...]:
    """The ``cache_clear`` of every ``functools`` cache defined at module
    level anywhere in the package.

    Discovered rather than listed, so a cache added to any module later
    is cleared without anyone remembering to register it here. The
    ``__module__`` check skips a cached function re-exported from some
    other module, so each cache is collected once.
    """
    clears: list[Callable[[], None]] = []
    for info in pkgutil.walk_packages(
        netprotocols.__path__, f"{netprotocols.__name__}."
    ):
        module = importlib.import_module(info.name)
        for value in vars(module).values():
            clear = getattr(value, "cache_clear", None)
            owner = getattr(value, "__module__", None)
            if callable(clear) and owner == module.__name__:
                clears.append(clear)
    return tuple(clears)


PACKAGE_CACHES = _package_caches()


@pytest.fixture(autouse=True)
def _clear_package_caches() -> Iterator[None]:
    """Start every test with every package-level cache empty."""
    for clear in PACKAGE_CACHES:
        clear()
    yield


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


@pytest.fixture
def raw_sctp_packet() -> bytes:
    """SCTP COOKIE ACK, from tests/fixtures/sctp.pcap: the common header
    and one 4-byte chunk."""
    return b"\x00\x07\xd5\xf2\xff\x09\xba\x55\xb2\x83\xdb\xc1\x0b\x00\x00\x04"


@pytest.fixture
def raw_ospf_hello() -> bytes:
    """OSPFv2 Hello from tests/fixtures/ospf.pcap (AuType 0): router
    10.0.0.1, area 0, DR 10.9.83.1, one neighbor (10.0.0.2)."""
    return bytes.fromhex(
        "020100300a000001000000008bac00000000000000000000"
        "ffffff000002020a000000080a095301000000000a000002"
    )


@pytest.fixture
def raw_pim_join_prune() -> bytes:
    """PIM Join/Prune from tests/fixtures/pim.pcap: R2's (*,G) Join for
    239.184.0.2 towards R1, the RP (one group set, one joined source
    with the S, W and R bits)."""
    return bytes.fromhex(
        "2300b4be01000ab80c01000100d201000020efb8000200010000010007200ab80c01"
    )


@pytest.fixture
def raw_esp_packet() -> bytes:
    """ESP packet (SPI 0x10000001, sequence 1) from ``esp.pcap``:
    NULL encryption, HMAC-SHA-256-128, carrying an ICMPv4 echo request
    in transport mode — 8 cleartext bytes, then the 52-byte protected
    remainder (payload, padding, Pad Length, Next Header, ICV)."""
    return bytes.fromhex(
        "10000001000000010800"
        "6c084e5000014e455450726f746f636f6c7320455350206669787475726501"
        "020201ae4c50f31eb8912ffc460ec5e194475e"
    )


@pytest.fixture
def raw_ah_header() -> bytes:
    """AH header (SPI 0x20000001, sequence 1) from ``ah.pcap``:
    Payload Len 5 (28 bytes), Next Header 6, then the 16-byte
    HMAC-SHA-256-128 ICV, followed by the TCP SYN it protects."""
    return bytes.fromhex(
        "060500002000000100000001e91ff0893d37de87e576dc91a70ddbe2"
        "9c4100504e500001000000006002faf0883e0000020405b4"
    )


@pytest.fixture
def raw_bgp_keepalive() -> bytes:
    """BGP KEEPALIVE from tests/fixtures/bgp.pcap: the all-ones Marker,
    Length 19, Type 4, and no body."""
    return b"\xff" * 16 + b"\x00\x13\x04"


@pytest.fixture
def raw_vxlan_header() -> bytes:
    """VXLAN header from tests/fixtures/vxlan.pcap: I flag set, VNI
    1193046 (0x123456), reserved bits zero."""
    return b"\x08\x00\x00\x00\x12\x34\x56\x00"


@pytest.fixture
def raw_llc_header() -> bytes:
    """LLC header of an 802.1D BPDU from tests/fixtures/llc.pcap: DSAP
    and SSAP 0x42 (Bridge Spanning Tree), Control 0x03 (UI)."""
    return b"\x42\x42\x03"


@pytest.fixture
def raw_stp_config_bpdu() -> bytes:
    """The root's Configuration BPDU with Topology Change from
    tests/fixtures/llc.pcap: Root and Bridge Identifier 0x1000 /
    02:00:00:00:a0:00, Port Identifier 0x8001, Max Age 20 s, Hello Time
    1 s, Forward Delay 2 s."""
    return bytes.fromhex(
        "0000000001100002000000a00000000000100002000000a00080010000140001000200"
    )


@pytest.fixture
def raw_stp_tcn() -> bytes:
    """The Topology Change Notification BPDU from
    tests/fixtures/llc.pcap."""
    return b"\x00\x00\x00\x80"


@pytest.fixture
def raw_snap_header() -> bytes:
    """SNAP header of a CDP frame from tests/fixtures/llc.pcap: OUI
    00-00-0C (Cisco), PID 0x2000 (CDP)."""
    return b"\x00\x00\x0c\x20\x00"


@pytest.fixture
def raw_cdp_header() -> bytes:
    """CDP header of the CDPv2 frame in tests/fixtures/llc.pcap: Version
    2, TTL 4, Checksum 0xFCF3."""
    return b"\x02\x04\xfc\xf3"


@pytest.fixture
def raw_mpls_stack() -> bytes:
    """A two-entry MPLS label stack in the shape of
    tests/fixtures/mpls.pcap's: label 16001, then label 16002 with the
    bottom of stack bit set, TTL 64 each."""
    return bytes.fromhex("03e8104003e82140")


@pytest.fixture
def raw_hsrp_hello() -> bytes:
    """A constructed HSRPv1 Hello (RFC 2281 §5.1's layout): Speak state
    for group 1 (Hellotime 3, Holdtime 10, priority 100), the default
    Authentication Data ``cisco`` and virtual IP 192.0.2.1. Built by
    hand rather than cut from tests/fixtures/hsrp.pcap, so the tests
    that use it do not depend on the capture."""
    return bytes.fromhex("000004030a640100636973636f000000c0000201")


@pytest.fixture
def raw_tls_client_hello() -> bytes:
    """A constructed TLS record holding a ClientHello (RFC 8446 §4.1.2):
    record version 0x0301, ClientHello version 0x0303, a Random of
    bytes 0-31, no session ID, one cipher suite (TLS_AES_128_GCM_SHA256),
    the null compression method and one extension, server_name for
    ``example.com``. Built by hand rather than cut from
    tests/fixtures/tls.pcap, so the tests that use it do not depend on
    the capture."""
    sni = b"\x00\x00\x0b" + b"example.com"
    sni = struct.pack("!H", len(sni)) + sni
    extensions = struct.pack("!HH", 0, len(sni)) + sni
    body = (
        b"\x03\x03"
        + bytes(range(32))
        + b"\x00"
        + b"\x00\x02\x13\x01"
        + b"\x01\x00"
        + struct.pack("!H", len(extensions))
        + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


@pytest.fixture
def raw_ntp_message() -> bytes:
    """NTPv4 server answer from tests/fixtures/ntp.pcap: chronyd at
    stratum 8 on its local reference (Reference ID 127.127.1.1), the
    48-byte header alone, no extension field or MAC."""
    return bytes.fromhex(
        "240800e700000000000000007f7f0101"
        "ee903023f016af37ee90302594864000"
        "ee90302594d55999ee90302594f33bb4"
    )


@pytest.fixture
def raw_rip_message() -> bytes:
    """RIPv2 Response from tests/fixtures/rip.pcap: the header and four
    route entries (10.20.2.0/24, 10.20.1.0/24, 10.20.3.128/25 and
    10.9.52.0/24, metric 1), no authentication."""
    return bytes.fromhex(
        "02020000"
        "000200000a140200ffffff000000000000000001"
        "000200000a140100ffffff000000000000000001"
        "000200000a140380ffffff800000000000000001"
        "000200000a093400ffffff000000000000000001"
    )


@pytest.fixture
def raw_radius_status_server() -> bytes:
    """Status-Server from tests/fixtures/radius.pcap: the 20-byte header
    (Code 12, Identifier 228, Length 38, the random Request
    Authenticator) and its one attribute, a Message-Authenticator."""
    return bytes.fromhex(
        "0ce40026"
        "88699679518971d08ca160f10302d1c5"
        "5012"
        "85541b6f94ed552994cbc2c449000a22"
    )


@pytest.fixture
def raw_vrrpv2_advert() -> bytes:
    """VRRPv2 advert from ``vrrp.pcap``: VRID 51, priority 200, Auth
    Type 1 (PASS), Adver Int 1 s, two addresses, then the null-padded
    password ``np-vrrp``."""
    return bytes.fromhex("2133c80201015af60a0914330a0914346e702d7672727000")


@pytest.fixture
def raw_vrrpv3_advert() -> bytes:
    """VRRPv3 advert from ``vrrp.pcap``: VRID 53, priority 200, Max
    Adver Int 100 cs, one address — the minimal 12-byte message."""
    return bytes.fromhex("3135c8010064e97c0a091446")


@pytest.fixture
def raw_lldp_shutdown() -> bytes:
    """Shutdown LLDPDU from ``lldp.pcap``: agent A's Chassis ID (MAC
    address ``02:4e:50:86:00:0a``), Port ID (interface name
    ``nplldp-va``), a Time To Live of 0, and End of LLDPDU."""
    return bytes.fromhex(
        "020704024e5086000a040a056e706c6c64702d7661060200000000"
    )


@pytest.fixture
def raw_tftp_rrq() -> bytes:
    """RRQ from ``tftp.pcap``: curl asking for ``boot.bin`` in octet
    mode with options tsize 0, blksize 1024 and timeout 6."""
    return (
        b"\x00\x01boot.bin\x00octet\x00"
        b"tsize\x000\x00blksize\x001024\x00timeout\x006\x00"
    )


@pytest.fixture
def raw_stun_message() -> bytes:
    """Binding Success Response from tests/fixtures/stun.pcap: coturn's
    XOR-MAPPED-ADDRESS and MAPPED-ADDRESS (10.9.194.1:36125),
    RESPONSE-ORIGIN, SOFTWARE and FINGERPRINT."""
    return bytes.fromhex(
        "010100442112a442d6f0c4b3d2008e560d5787f8"
        "002000080001ac0f2b1b6643"
        "0001000800018d1d0a09c201"
        "802b000800010d960a09c202"
        "80220014436f7475726e2d342e362e312027476f72737427"
        "80280004d28d393d"
    )
