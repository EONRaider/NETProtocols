"""VRRP, the Virtual Router Redundancy Protocol, IP protocol 112.

VRRPv2 is RFC 3768, VRRPv3 RFC 5798.

One class decodes both versions and branches on the version nibble;
the address width comes from the IP family, so the class comes as a
pair, ``VRRP`` in ``ip.proto`` and ``VRRPv6`` in ``ip.proto.v6``. The
capture host has no IPv6, so VRRPv3 over IPv6 is tested here with
constructed frames whose checksums this file computes itself, with its
own ones'-complement sum rather than :mod:`netprotocols.checksum`.
``scripts/check_fixtures.py``, which shares no code with the library,
is run over those frames and over tampered copies of the corpus.
"""

import importlib.util
import socket
import struct
from dataclasses import dataclass, replace
from pathlib import Path

import pytest

from conftest import FIXTURES, pcap_frames
from netprotocols import (
    VRRP,
    Ethernet,
    InvalidFieldError,
    IPProtocol,
    IPv4,
    IPv6,
    IPv6HopByHopOptions,
    Packet,
    Registry,
    TruncatedHeaderError,
    VRRPv6,
    decode_frame,
    verify,
)
from netprotocols.registry import DEFAULT, TABLE_IP_PROTO, TABLE_IP_PROTO_V6

CHECKER = Path(__file__).resolve().parent.parent / "scripts/check_fixtures.py"


@pytest.fixture(scope="module")
def check_fixtures():
    """Load scripts/check_fixtures.py on demand.

    test_checksum.py imports this module's helpers, and runs where
    scripts/ is absent (the mutation audit's mutants/ tree).
    """
    spec = importlib.util.spec_from_file_location("check_fixtures", CHECKER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def ones_complement(data: bytes) -> int:
    """Return the RFC 1071 checksum of ``data``.

    Written out here so the constructed frames' checksums do not come
    from the code under test.
    """
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for (word,) in struct.iter_unpack("!H", data):
        total += word
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def v3_checksum_v6(src: str, dst: str, message: bytes) -> int:
    """Return a VRRPv3 checksum over IPv6 (RFC 5798 §5.2.8).

    The 40-byte pseudo-header (RFC 8200 §8.1) with Next Header 112,
    then the message with its checksum field zeroed.
    """
    pseudo = (
        socket.inet_pton(socket.AF_INET6, src)
        + socket.inet_pton(socket.AF_INET6, dst)
        + struct.pack("!I3xB", len(message), 112)
    )
    return ones_complement(pseudo + message[:6] + b"\x00\x00" + message[8:])


def v3_checksum_v4(src: str, dst: str, message: bytes) -> int:
    """Return a VRRPv3 checksum over IPv4, as RFC 5798 §5.2.8 gives it.

    The pseudo-header with protocol 112, then the message, checksum
    field zeroed.
    """
    pseudo = (
        socket.inet_aton(src)
        + socket.inet_aton(dst)
        + struct.pack("!xBH", 112, len(message))
    )
    return ones_complement(pseudo + message[:6] + b"\x00\x00" + message[8:])


V6_SRC = "fe80::1"
V6_GROUP = "ff02::12"  # RFC 5798 §5.1.2.2
V6_ADDRESSES = ("fe80::1:1", "2001:db8::100")


def v6_message(addresses=V6_ADDRESSES, priority: int = 200) -> bytes:
    """Build a VRRPv3 advert's bytes for IPv6, checksum computed here."""
    message = struct.pack(
        "!BBBBHH", 0x31, 7, priority, len(addresses), 100, 0
    ) + b"".join(socket.inet_pton(socket.AF_INET6, a) for a in addresses)
    checksum = v3_checksum_v6(V6_SRC, V6_GROUP, message)
    return message[:6] + struct.pack("!H", checksum) + message[8:]


def v6_frame(message: bytes, *, hop_by_hop: bool = False) -> bytes:
    """Build ``Ethernet → IPv6 [→ Hop-by-Hop] → message`` by hand.

    Hop Limit 255; none of it comes from the library's encoders.
    """
    ext = b""
    next_header = 112
    if hop_by_hop:
        ext = bytes([112, 0]) + b"\x01\x04\x00\x00\x00\x00"  # PadN
        next_header = 0
    ipv6 = (
        struct.pack("!IHBB", 6 << 28, len(ext) + len(message), next_header, 255)
        + socket.inet_pton(socket.AF_INET6, V6_SRC)
        + socket.inet_pton(socket.AF_INET6, V6_GROUP)
    )
    eth = bytes.fromhex("333300000012005e0002010786dd")
    return eth + ipv6 + ext + message


def v4_frame(message: bytes, dst: str = "224.0.0.18") -> bytes:
    """Build ``Ethernet → IPv4 → message`` by hand.

    Protocol 112, TTL 255, the IPv4 header checksum computed here.
    """
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0xC0,
        20 + len(message),
        1,
        0,
        255,
        112,
        0,
        socket.inet_aton("10.9.20.1"),
        socket.inet_aton(dst),
    )
    header = (
        header[:10] + struct.pack("!H", ones_complement(header)) + header[12:]
    )
    eth = bytes.fromhex("01005e000012005e000101350800")
    return eth + header + message


class TestWiring:
    def test_protocol_number_and_display_name(self):
        assert IPProtocol.VRRP == 112
        assert IPProtocol.VRRP.display_name == "VRRP"

    def test_each_family_has_its_own_class(self):
        assert DEFAULT.get(TABLE_IP_PROTO, 112) is VRRP
        assert DEFAULT.get(TABLE_IP_PROTO_V6, 112) is VRRPv6

    def test_vrrpv6_is_a_vrrp(self):
        layer = decode_frame(v6_frame(v6_message()))[VRRP]
        assert type(layer) is VRRPv6
        assert isinstance(layer, VRRP)

    def test_ipv4_dispatches_to_vrrp(self, raw_vrrpv3_advert):
        layers = decode_frame(v4_frame(raw_vrrpv3_advert)).layers
        assert [type(layer) for layer in layers] == [Ethernet, IPv4, VRRP]

    def test_ipv6_dispatches_to_vrrpv6(self):
        layers = decode_frame(v6_frame(v6_message())).layers
        assert [type(layer) for layer in layers] == [Ethernet, IPv6, VRRPv6]

    def test_an_extension_header_dispatches_to_vrrpv6(self):
        layers = decode_frame(v6_frame(v6_message(), hop_by_hop=True)).layers
        assert [type(layer) for layer in layers] == [
            Ethernet,
            IPv6,
            IPv6HopByHopOptions,
            VRRPv6,
        ]

    def test_derived_registries_keep_the_split(self):
        registry = Registry.from_defaults()
        assert registry.get(TABLE_IP_PROTO, 112) is VRRP
        assert registry.get(TABLE_IP_PROTO_V6, 112) is VRRPv6

    def test_overriding_ip_proto_112_reaches_ipv4_only(self, raw_vrrpv3_advert):
        @dataclass(frozen=True, slots=True)
        class OtherVRRP(VRRP):
            pass

        registry = Registry.from_defaults()
        registry.register(TABLE_IP_PROTO, 112, OtherVRRP, override=True)
        v4 = decode_frame(v4_frame(raw_vrrpv3_advert), registry=registry)
        v6 = decode_frame(v6_frame(v6_message()), registry=registry)
        assert type(v4.layers[-1]) is OtherVRRP
        assert type(v6.layers[-1]) is VRRPv6

    def test_the_layer_is_terminal(self, raw_vrrpv2_advert):
        assert VRRP.decode(raw_vrrpv2_advert).next_protocol() is None


class TestDecodeV2:
    def test_fixed_fields(self, raw_vrrpv2_advert):
        vrrp = VRRP.decode(raw_vrrpv2_advert)
        assert (vrrp.version, vrrp.type, vrrp.vrid, vrrp.priority) == (
            2,
            1,
            51,
            200,
        )
        assert vrrp.count_ip_addrs == 2
        assert vrrp.adver_word == 0x0101
        assert vrrp.checksum == 0x5AF6
        assert vrrp.addresses == ("10.9.20.51", "10.9.20.52")
        assert vrrp.auth_data == b"np-vrrp\x00"

    def test_accessors(self, raw_vrrpv2_advert):
        vrrp = VRRP.decode(raw_vrrpv2_advert)
        assert vrrp.type_name == "Advertisement"
        assert vrrp.auth_type == 1
        assert vrrp.auth_type_name == "Simple Text Password"
        assert vrrp.adver_int == 1
        assert vrrp.advertisement_interval == 1.0
        assert vrrp.reserved is None
        assert vrrp.max_adver_int is None
        assert vrrp.checksum_hex_str == "0x5af6"

    def test_a_short_checksum_is_zero_padded(self, raw_vrrpv2_advert):
        vrrp = replace(VRRP.decode(raw_vrrpv2_advert), checksum=0x0ABC)
        assert vrrp.checksum_hex_str == "0x0abc"

    def test_the_header_is_the_whole_message(self, raw_vrrpv2_advert):
        # 8 fixed bytes, two 4-byte addresses, 8 bytes of auth data.
        assert VRRP.decode(raw_vrrpv2_advert).header_len == 24

    def test_wire_to_object_to_wire(self, raw_vrrpv2_advert):
        assert bytes(VRRP.decode(raw_vrrpv2_advert)) == raw_vrrpv2_advert

    def test_object_to_wire_to_object(self, raw_vrrpv2_advert):
        vrrp = VRRP.decode(raw_vrrpv2_advert)
        assert VRRP.decode(bytes(vrrp)) == vrrp

    def test_memoryview_is_materialized(self, raw_vrrpv2_advert):
        vrrp = VRRP.decode(memoryview(raw_vrrpv2_advert))
        assert type(vrrp.auth_data) is bytes
        assert vrrp == VRRP.decode(raw_vrrpv2_advert)

    @pytest.mark.parametrize(
        "trailer", [bytes(6), bytes(46), b"\xde\xad\xbe\xef"]
    )
    def test_trailing_bytes_are_not_vrrp(self, raw_vrrpv2_advert, trailer):
        """Ethernet padding or an FCS after the message is left alone."""
        vrrp = VRRP.decode(raw_vrrpv2_advert + trailer)
        assert vrrp == VRRP.decode(raw_vrrpv2_advert)
        assert vrrp.header_len == len(raw_vrrpv2_advert)

    def test_no_authentication(self):
        raw = bytes.fromhex("2134c8010001f8830a09143c0000000000000000")
        vrrp = VRRP.decode(raw)
        assert vrrp.auth_type == 0
        assert vrrp.auth_type_name == "No Authentication"
        assert vrrp.auth_data == bytes(8)
        assert vrrp.header_len == 20
        # Auth Type 0 and Adver Int 1: the interval is the low byte.
        assert vrrp.adver_int == 1
        assert vrrp.advertisement_interval == 1.0

    @pytest.mark.parametrize(
        "auth_type,name",
        [(2, "IP Authentication Header"), (7, "unknown (7)")],
    )
    def test_other_auth_types_are_named(
        self, raw_vrrpv2_advert, auth_type, name
    ):
        raw = raw_vrrpv2_advert[:4] + bytes([auth_type]) + raw_vrrpv2_advert[5:]
        vrrp = VRRP.decode(raw)
        assert vrrp.auth_type == auth_type
        assert vrrp.auth_type_name == name
        assert vrrp.adver_int == 1
        assert vrrp.advertisement_interval == 1.0


class TestDecodeV3:
    def test_fixed_fields(self, raw_vrrpv3_advert):
        vrrp = VRRP.decode(raw_vrrpv3_advert)
        assert (vrrp.version, vrrp.type, vrrp.vrid, vrrp.priority) == (
            3,
            1,
            53,
            200,
        )
        assert vrrp.count_ip_addrs == 1
        assert vrrp.addresses == ("10.9.20.70",)
        assert vrrp.auth_data == b""
        assert vrrp.checksum == 0xE97C

    def test_accessors(self, raw_vrrpv3_advert):
        vrrp = VRRP.decode(raw_vrrpv3_advert)
        assert vrrp.max_adver_int == 100
        assert vrrp.reserved == 0
        assert vrrp.advertisement_interval == 1.0
        assert vrrp.auth_type is None
        assert vrrp.auth_type_name is None
        assert vrrp.adver_int is None

    def test_the_minimal_advert_is_twelve_bytes(self, raw_vrrpv3_advert):
        assert VRRP.decode(raw_vrrpv3_advert).header_len == 12

    def test_round_trips(self, raw_vrrpv3_advert):
        vrrp = VRRP.decode(raw_vrrpv3_advert)
        assert bytes(vrrp) == raw_vrrpv3_advert
        assert VRRP.decode(bytes(vrrp)) == vrrp

    @pytest.mark.parametrize(
        "trailer", [bytes(14), bytes(46), b"\xde\xad\xbe\xef"]
    )
    def test_trailing_bytes_are_not_vrrp(self, raw_vrrpv3_advert, trailer):
        vrrp = VRRP.decode(raw_vrrpv3_advert + trailer)
        assert vrrp.header_len == 12
        assert bytes(vrrp) == raw_vrrpv3_advert

    def test_the_reserved_nibble_and_a_wide_interval_are_carried(
        self, raw_vrrpv3_advert
    ):
        raw = raw_vrrpv3_advert[:4] + b"\xaf\xff" + raw_vrrpv3_advert[6:]
        vrrp = VRRP.decode(raw)
        assert vrrp.reserved == 0xA
        assert vrrp.max_adver_int == 0xFFF
        assert vrrp.advertisement_interval == 40.95
        assert bytes(vrrp) == raw

    def test_an_unknown_type_is_carried(self, raw_vrrpv3_advert):
        raw = b"\x32" + raw_vrrpv3_advert[1:]
        vrrp = VRRP.decode(raw)
        assert vrrp.type == 2
        assert vrrp.type_name == "unknown (2)"
        assert bytes(vrrp) == raw

    def test_a_zero_count_is_carried(self):
        """Carry a count below RFC 5798 §5.2.5's minimum of 1.

        Enforcing it is the receiver's job; the layout is still clear.
        """
        vrrp = VRRP.decode(bytes.fromhex("3135000000640000"))
        assert vrrp.addresses == ()
        assert vrrp.header_len == 8


class TestVRRPv6:
    def test_decodes_sixteen_byte_addresses(self):
        message = v6_message()
        vrrp = VRRPv6.decode(message)
        assert vrrp.version == 3
        assert vrrp.vrid == 7
        assert vrrp.addresses == V6_ADDRESSES
        assert vrrp.header_len == 8 + 2 * 16
        assert bytes(vrrp) == message

    def test_the_constructed_checksum_verifies(self):
        packet = decode_frame(v6_frame(v6_message()))
        assert verify(packet[VRRP], ip=packet[IPv6])

    def test_padding_after_it_is_left_alone(self):
        message = v6_message(addresses=("fe80::1",))
        vrrp = VRRPv6.decode(message + b"\xde\xad\xbe\xef")
        assert vrrp.header_len == 24
        assert bytes(vrrp) == message

    def test_the_two_classes_read_the_same_bytes_by_their_own_width(self):
        """Nothing in the header says how wide an address is."""
        message = v6_message(addresses=("fe80::1",))
        v4 = VRRP.decode(message)
        v6 = VRRPv6.decode(message)
        assert v4.addresses == ("254.128.0.0",)
        assert v6.addresses == ("fe80::1",)
        assert (v4.header_len, v6.header_len) == (12, 24)

    def test_vrrpv2_is_ipv4_only(self, raw_vrrpv2_advert):
        with pytest.raises(InvalidFieldError) as excinfo:
            VRRPv6.decode(raw_vrrpv2_advert)
        assert excinfo.value.field == "version"
        assert excinfo.value.expected == "3"

    def test_the_checker_verifies_the_constructed_frames(self, check_fixtures):
        """Agree with check_fixtures.py, which shares no library code."""
        for frame in (
            v6_frame(v6_message()),
            v6_frame(v6_message(addresses=("fe80::1",), priority=0)),
            v6_frame(v6_message(), hop_by_hop=True),
        ):
            stats = check_fixtures.Counter()
            assert check_fixtures.check_frame(frame, stats) == []
            assert stats["vrrpv3"] == 1


class TestRejected:
    @pytest.mark.parametrize("version", [0, 1, 4, 15])
    def test_a_version_with_no_layout(self, raw_vrrpv3_advert, version):
        raw = bytes([version << 4 | 1]) + raw_vrrpv3_advert[1:]
        with pytest.raises(InvalidFieldError) as excinfo:
            VRRP.decode(raw)
        err = excinfo.value
        assert (err.protocol, err.field, err.offset) == (VRRP, "version", 0)
        assert (err.expected, err.actual) == ("2 or 3", version)

    def test_a_count_past_the_buffer(self, raw_vrrpv3_advert):
        lying = raw_vrrpv3_advert[:3] + b"\x02" + raw_vrrpv3_advert[4:]
        with pytest.raises(TruncatedHeaderError) as excinfo:
            VRRP.decode(lying)
        err = excinfo.value
        assert (err.field, err.offset) == ("count_ip_addrs", 0)
        assert (err.expected, err.actual) == (16, 12)

    def test_authentication_data_cut_short(self, raw_vrrpv2_advert):
        with pytest.raises(TruncatedHeaderError) as excinfo:
            VRRP.decode(raw_vrrpv2_advert[:-1])
        err = excinfo.value
        assert (err.field, err.expected, err.actual) == ("auth_data", 24, 23)

    def test_the_addresses_exactly_without_auth_data(self, raw_vrrpv2_advert):
        with pytest.raises(TruncatedHeaderError) as excinfo:
            VRRP.decode(raw_vrrpv2_advert[:16])
        assert excinfo.value.field == "auth_data"

    def test_an_ipv6_address_cut_short(self):
        with pytest.raises(TruncatedHeaderError) as excinfo:
            VRRPv6.decode(v6_message()[:-1])
        assert excinfo.value.field == "count_ip_addrs"
        assert excinfo.value.expected == 40

    @pytest.mark.parametrize("length", [0, 7])
    def test_truncated_fixed_header(self, raw_vrrpv3_advert, length):
        with pytest.raises(TruncatedHeaderError):
            VRRP.decode(raw_vrrpv3_advert[:length])

    def test_the_walk_reports_the_frame_offset(self, raw_vrrpv3_advert):
        frame = v4_frame(b"\x41" + raw_vrrpv3_advert[1:])
        with pytest.raises(InvalidFieldError) as excinfo:
            decode_frame(frame)
        assert excinfo.value.frame_offset == 34

    def test_lax_mode_keeps_the_ip_header(self, raw_vrrpv3_advert):
        frame = v4_frame(b"\x41" + raw_vrrpv3_advert[1:])
        packet = decode_frame(frame, lax=True)
        assert [type(layer) for layer in packet.layers] == [Ethernet, IPv4]
        assert isinstance(packet.stopped_by, InvalidFieldError)


class TestConstruction:
    def make(self, **fields) -> VRRP:
        values = {
            "version": 3,
            "type": 1,
            "vrid": 1,
            "priority": 100,
            "count_ip_addrs": 1,
            "adver_word": 100,
            "checksum": 0,
            "addresses": ("192.0.2.1",),
        }
        values.update(fields)
        return VRRP(**values)

    def test_a_valid_advert(self):
        assert self.make().header_len == 12

    def test_the_count_must_agree_with_the_addresses(self):
        with pytest.raises(InvalidFieldError) as excinfo:
            self.make(count_ip_addrs=2)
        err = excinfo.value
        assert (err.field, err.offset, err.expected, err.actual) == (
            "count_ip_addrs",
            None,
            1,
            2,
        )

    def test_vrrpv2_needs_eight_bytes_of_auth_data(self):
        with pytest.raises(InvalidFieldError) as excinfo:
            self.make(version=2)
        err = excinfo.value
        assert (err.field, err.expected, err.actual) == ("auth_data", 8, 0)
        assert self.make(version=2, auth_data=bytes(8)).header_len == 20

    def test_vrrpv3_carries_none(self):
        with pytest.raises(InvalidFieldError) as excinfo:
            self.make(auth_data=bytes(8))
        assert excinfo.value.expected == 0

    @pytest.mark.parametrize("version", [1, 4])
    def test_the_version_must_have_a_layout(self, version):
        with pytest.raises(InvalidFieldError) as excinfo:
            self.make(version=version)
        assert (excinfo.value.field, excinfo.value.offset) == ("version", None)

    @pytest.mark.parametrize("type_", [-1, 16])
    def test_the_type_must_fit_its_nibble(self, type_):
        with pytest.raises(InvalidFieldError) as excinfo:
            self.make(type=type_)
        assert excinfo.value.field == "type"
        assert self.make(type=15).type_name == "unknown (15)"

    def test_vrrpv6_rejects_vrrpv2(self):
        with pytest.raises(InvalidFieldError) as excinfo:
            VRRPv6(
                version=2,
                type=1,
                vrid=1,
                priority=100,
                count_ip_addrs=0,
                adver_word=0x0001,
                checksum=0,
                addresses=(),
                auth_data=bytes(8),
            )
        assert excinfo.value.protocol is VRRPv6

    def test_with_checksums_fills_a_built_packet(self):
        vrrp = self.make()
        ip = IPv4(
            version=4,
            ihl=5,
            dscp=48,
            ecn=0,
            total_length=20 + vrrp.header_len,
            identification=1,
            flags=0,
            fragment_offset=0,
            ttl=255,
            protocol=112,
            checksum=0,
            src="10.9.20.1",
            dst="224.0.0.18",
        )
        packet = Packet(ip, vrrp).with_checksums()
        built = packet[VRRP]
        assert built.checksum == v3_checksum_v4(
            "10.9.20.1", "224.0.0.18", bytes(vrrp)
        )
        assert verify(built, ip=packet[IPv4])


class TestCorpusVRRP:
    FRAMES = pcap_frames(FIXTURES / "vrrp.pcap")

    def test_composition(self):
        adverts = [decode_frame(frame)[VRRP] for frame in self.FRAMES]
        assert [(a.version, a.vrid) for a in adverts] == (
            [(2, 51)] * 6 + [(2, 52)] * 3 + [(3, 53)] * 6 + [(3, 54)] * 3
        )
        assert [a.priority for a in adverts] == [
            200, 200, 0, 100, 100, 0,
            200, 200, 0,
            200, 200, 0, 100, 100, 0,
            200, 200, 0,
        ]  # fmt: skip
        assert {a.count_ip_addrs for a in adverts if a.vrid == 54} == {3}
        assert {a.max_adver_int for a in adverts if a.vrid == 54} == {50}

    def test_vrrpv2_carries_its_auth_data(self):
        adverts = [decode_frame(frame)[VRRP] for frame in self.FRAMES[:9]]
        assert {a.auth_data for a in adverts[:6]} == {b"np-vrrp\x00"}
        assert {a.auth_data for a in adverts[6:]} == {bytes(8)}
        assert [a.auth_type for a in adverts] == [1] * 6 + [0] * 3

    def test_the_message_is_the_ip_payload(self):
        """Hold the VRRP message as the whole IP payload.

        veth does not pad a short frame, so every captured frame ends
        where the IPv4 datagram does.
        """
        for frame in self.FRAMES:
            packet = decode_frame(frame)
            ip = packet[IPv4]
            assert len(frame) == 14 + ip.total_length
            assert packet[VRRP].header_len == ip.total_length - ip.header_len
            assert packet.consumed == len(frame)

    def test_padded_to_ethernet_minimum(self):
        """Leave a NIC's padding to 60 bytes, and an FCS, undecoded.

        The checksum still verifies.
        """
        for frame in self.FRAMES:
            padded = (
                frame + bytes(max(0, 60 - len(frame))) + b"\xde\xad\xbe\xef"
            )
            packet = decode_frame(padded)
            assert packet.consumed == len(frame)
            assert verify(packet[VRRP], ip=packet[IPv4])

    def test_unicast_adverts_use_the_unicast_destination(self):
        """Checksum a unicast advert over its real destination.

        keepalived 2.2.8 puts the peer's address, not 224.0.0.18, in the
        pseudo-header of a unicast VRRPv3 advert.
        """
        for frame in self.FRAMES[-3:]:
            packet = decode_frame(frame)
            ip, vrrp = packet[IPv4], packet[VRRP]
            assert ip.dst == "10.9.20.2"
            assert vrrp.checksum == v3_checksum_v4(ip.src, ip.dst, bytes(vrrp))

    def test_recomputed_checksums_match_the_wire(self):
        # check_fixtures.py, which shares no code with this library,
        # verified every checksum; with_checksums() must agree.
        for frame in self.FRAMES:
            packet = decode_frame(frame)
            assert packet.with_checksums() == packet

    def test_the_ip_headers_are_keepalived_s(self):
        """Carry keepalived's own IPv4 header: TOS 0xc0, TTL 255."""
        for frame in self.FRAMES:
            ip = decode_frame(frame)[IPv4]
            assert (ip.dscp, ip.ttl, ip.protocol) == (48, 255, 112)


class TestChecker:
    """scripts/check_fixtures.py fails a tampered VRRP frame."""

    FRAMES = pcap_frames(FIXTURES / "vrrp.pcap")

    @pytest.fixture(autouse=True)
    def _checker(self, check_fixtures):
        self.checker = check_fixtures

    def check(self, frame: bytes) -> list[str]:
        return self.checker.check_frame(frame, self.checker.Counter())

    @pytest.mark.parametrize("index", [0, 6, 9, 15])
    def test_the_captured_frames_pass(self, index):
        assert self.check(self.FRAMES[index]) == []

    @pytest.mark.parametrize("index", [0, 9, 15])
    def test_a_flipped_address_byte_fails(self, index):
        frame = bytearray(self.FRAMES[index])
        frame[14 + 20 + 8] ^= 0x01
        assert self.check(bytes(frame)) == ["vrrp-checksum"]

    def test_a_bumped_count_fails(self):
        frame = bytearray(self.FRAMES[9])
        frame[14 + 20 + 3] += 1
        assert self.check(bytes(frame)) == ["vrrp-length"]

    @pytest.mark.parametrize("index", [0, 9])
    def test_an_ip_payload_longer_than_the_message_fails(self, index):
        """Fail four bytes inside the IPv4 datagram after the message.

        Total Length grows by 4 and the IPv4 header checksum is
        recomputed, so only the VRRP length check can fire; zeros leave
        a ones'-complement sum unchanged, so the checksum alone would
        not catch them in VRRPv2.
        """
        frame = bytearray(self.FRAMES[index])
        total_length = struct.unpack_from("!H", frame, 16)[0]
        struct.pack_into("!H", frame, 16, total_length + 4)
        frame[24:26] = b"\x00\x00"
        struct.pack_into("!H", frame, 24, ones_complement(bytes(frame[14:34])))
        assert self.check(bytes(frame) + bytes(4)) == ["vrrp-length"]

    def test_an_unknown_version_fails(self):
        frame = bytearray(self.FRAMES[9])
        frame[14 + 20] = 0x41
        assert self.check(bytes(frame)) == ["vrrp-version"]

    def test_vrrpv2_over_ipv6_fails(self):
        message = bytearray(v6_message())
        message[0] = 0x21
        assert self.check(v6_frame(bytes(message))) == ["vrrp-version"]

    def test_the_rfc_9568_ipv4_form_fails(self, raw_vrrpv3_advert):
        """Fail an advert checksummed as RFC 9568 §5.2.8 gives it.

        Without the pseudo-header over IPv4, it fails the checker, as
        it fails verify().
        """
        zeroed = raw_vrrpv3_advert[:6] + b"\x00\x00" + raw_vrrpv3_advert[8:]
        message = (
            zeroed[:6] + struct.pack("!H", ones_complement(zeroed)) + zeroed[8:]
        )
        frame = v4_frame(message)
        assert self.check(frame) == ["vrrp-checksum"]
        packet = decode_frame(frame)
        assert not verify(packet[VRRP], ip=packet[IPv4])

    def test_a_rebuilt_frame_passes(self, raw_vrrpv3_advert):
        layer = VRRP.decode(raw_vrrpv3_advert)
        message = bytes(replace(layer, priority=7))
        message = (
            message[:6]
            + struct.pack(
                "!H", v3_checksum_v4("10.9.20.1", "224.0.0.18", message)
            )
            + message[8:]
        )
        assert self.check(v4_frame(message)) == []
