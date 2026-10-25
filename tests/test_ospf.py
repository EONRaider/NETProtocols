"""OSPFv2 (RFC 2328), IP protocol 89.

The common header, the five message types' accessors, where the packet
ends (Packet Length, plus the digest under cryptographic
authentication, and never the link-layer padding, FCS or LLS block
after it), the framing ``decode`` and construction enforce, the IPv4-only
wiring that keeps an IPv6 packet's OSPFv3 out of this decoder, and the
real FRR capture in ``ospf.pcap`` -- checked by ``scripts/check_fixtures.py``
too, here, against tampering. Checksums are tested in test_checksum.py,
which the mutation audit selects.
"""

import importlib.util
import struct
from collections import Counter
from dataclasses import replace

import pytest

from conftest import FIXTURES, pcap_frames
from netprotocols import (
    OSPF,
    OSPFLSA,
    Ethernet,
    InvalidFieldError,
    IPProtocol,
    IPv4,
    IPv6,
    OSPFDatabaseDescription,
    OSPFHello,
    OSPFLSAHeader,
    OSPFLSRequest,
    Packet,
    ProtocolError,
    Registry,
    TruncatedHeaderError,
    decode_frame,
)
from netprotocols._defaults import IPV4_ONLY_NUMBERS, install
from netprotocols.checksum import verify
from netprotocols.registry import DEFAULT, TABLE_IP_PROTO, TABLE_IP_PROTO_V6
from test_ipip import ethernet, make_ipv4, make_ipv6

FRAMES = pcap_frames(FIXTURES / "ospf.pcap")

#: The published test secrets (tests/fixtures/MANIFEST.md).
SIMPLE_PASSWORD = b"NPospf1\x00"
MD5_KEY = b"NETProtocols-md5"


def lsa_header(**fields) -> OSPFLSAHeader:
    values = {
        "ls_age": 1,
        "options": 2,
        "ls_type": 1,
        "link_state_id": "10.0.0.1",
        "advertising_router": "10.0.0.1",
        "ls_sequence_number": 0x80000001,
        "ls_checksum": 0x1234,
        "length": 20,
    }
    values.update(fields)
    return OSPFLSAHeader(**values)


def make_ospf(type_: int, body: bytes = b"", **fields) -> OSPF:
    values = {
        "version": 2,
        "type": type_,
        "packet_length": 24 + len(body),
        "router_id": "10.0.0.1",
        "area_id": "0.0.0.0",
        "checksum": 0,
        "au_type": 0,
        "authentication": bytes(8),
        "body": body,
    }
    values.update(fields)
    return OSPF(**values)


def hello_body(*neighbors: str, options: int = 0x02) -> bytes:
    return bytes(
        OSPFHello(
            network_mask="255.255.255.0",
            hello_interval=10,
            options=options,
            router_priority=1,
            router_dead_interval=40,
            designated_router="0.0.0.0",
            backup_designated_router="0.0.0.0",
            neighbors=neighbors,
        )
    )


def v4_frame(ospf: OSPF, *, inside: bytes = b"", after: bytes = b"") -> bytes:
    """Build ``Ethernet → IPv4 → OSPF``, checksums computed.

    ``inside`` follows the packet within the IP datagram (an LLS
    block); ``after`` follows the datagram (Ethernet padding, an FCS).
    """
    ip = make_ipv4(
        protocol=IPProtocol.OSPF, payload_len=ospf.header_len + len(inside)
    )
    packet = Packet(ethernet(0x0800), ip, ospf).with_checksums(inside)
    return bytes(packet) + inside + after


def chain(frame: bytes, **kwargs) -> list[type]:
    return [type(layer) for layer in decode_frame(frame, **kwargs)]


class TestWiring:
    def test_protocol_number_and_display_name(self):
        """Check that IPProtocol names 89 OSPF."""
        assert IPProtocol.OSPF == 89
        assert IPProtocol.OSPF.display_name == "OSPF"

    def test_ipv4_dispatches_to_ospf(self):
        """Walk an IPv4 frame with protocol 89 into OSPF."""
        assert DEFAULT.get(TABLE_IP_PROTO, 89) is OSPF
        assert chain(v4_frame(make_ospf(1, hello_body()))) == [
            Ethernet,
            IPv4,
            OSPF,
        ]

    def test_ipv6_does_not_inherit_ospf(self):
        """Check that ip.proto.v6 holds nothing at 89."""
        assert DEFAULT.get(TABLE_IP_PROTO_V6, 89) is None
        assert set(IPV4_ONLY_NUMBERS) == {89}

    def ospfv3_frame(self) -> bytes:
        """Build an IPv6 frame carrying an OSPFv3 Hello (RFC 5340 §A.3.2).

        A 16-byte header (version 3) and a 20-byte Hello body.
        """
        body = struct.pack("!IB3sHH", 5, 1, b"\x00\x00\x13", 10, 40) + bytes(8)
        header = struct.pack(
            "!BBH4s4sHBB", 3, 1, 16 + len(body), bytes(4), bytes(4), 0, 0, 0
        )
        ospfv3 = header + body
        ip = make_ipv6(next_header=89, payload_len=len(ospfv3))
        return bytes(ethernet(0x86DD)) + bytes(ip) + ospfv3

    def test_an_ipv6_ospfv3_packet_ends_the_walk_at_ipv6(self):
        """Withheld, the entry leaves a strict walk to end cleanly.

        Inherited, it would decode OSPFv3 as OSPFv2 and raise on its
        version.
        """
        frame = self.ospfv3_frame()
        packet = decode_frame(frame)
        assert [type(layer) for layer in packet] == [Ethernet, IPv6]
        assert packet.stopped_by is None
        assert packet.consumed == 54

    def test_decoding_ospfv3_as_ospf_on_purpose_is_rejected(self):
        """Reject OSPFv3 at its version when decode_as forces OSPF."""
        frame = self.ospfv3_frame()
        packet = decode_frame(
            frame, decode_as={TABLE_IP_PROTO_V6: {89: OSPF}}, lax=True
        )
        assert [type(layer) for layer in packet] == [Ethernet, IPv6]
        error = packet.stopped_by
        assert isinstance(error, InvalidFieldError)
        assert (error.field, error.offset, error.frame_offset) == (
            "version",
            0,
            54,
        )
        assert (error.expected, error.actual) == (2, 3)

    def test_a_parent_registration_does_not_reach_the_withheld_key(self):
        """Keep an ip.proto override out of the withheld v6 key."""
        registry = Registry.from_defaults()

        class OtherOSPF(OSPF):
            pass

        registry.register(TABLE_IP_PROTO, 89, OtherOSPF, override=True)
        assert registry.get(TABLE_IP_PROTO, 89) is OtherOSPF
        assert registry.get(TABLE_IP_PROTO_V6, 89) is None

    def test_a_direct_v6_registration_fills_the_withheld_key(self):
        """Let a direct ip.proto.v6 registration take the key."""
        registry = Registry.from_defaults()

        class OSPFv3(OSPF):
            pass

        registry.register(TABLE_IP_PROTO_V6, 89, OSPFv3)
        assert registry.get(TABLE_IP_PROTO_V6, 89) is OSPFv3
        assert registry.get(TABLE_IP_PROTO, 89) is OSPF
        # Re-installing the defaults withholds nothing it should not.
        install(registry)
        assert registry.get(TABLE_IP_PROTO_V6, 89) is OSPFv3

    def test_derived_registries_keep_withholding(self):
        """Carry the withheld key into a derived registry."""
        child = DEFAULT.derive()
        child.register(TABLE_IP_PROTO, 89, OSPF)
        assert child.get(TABLE_IP_PROTO_V6, 89) is None
        assert child._withheld[TABLE_IP_PROTO_V6] == {89}

    def test_installing_twice_keeps_the_key_withheld(self):
        """Keep 89 withheld across a second install()."""
        registry = Registry()
        install(registry)
        install(registry)
        assert registry.get(TABLE_IP_PROTO, 89) is OSPF
        assert 89 not in registry.table(TABLE_IP_PROTO_V6)

    def test_ospf_ends_the_chain(self, raw_ospf_hello):
        """Check that OSPF encapsulates nothing."""
        assert OSPF.decode(raw_ospf_hello).next_protocol() is None


class TestHeader:
    def test_fixed_fields(self, raw_ospf_hello):
        """Decode every header field of a captured Hello."""
        ospf = OSPF.decode(raw_ospf_hello)
        assert ospf.version == 2
        assert ospf.type == 1
        assert ospf.type_name == "Hello"
        assert ospf.packet_length == 48 == ospf.header_len
        assert ospf.router_id == "10.0.0.1"
        assert ospf.area_id == "0.0.0.0"
        assert ospf.checksum == 0x8BAC
        assert ospf.checksum_hex_str == "0x8bac"
        assert ospf.au_type == 0
        assert ospf.au_type_name == "Null"
        assert ospf.authentication == bytes(8)
        assert ospf.body == raw_ospf_hello[24:]
        assert ospf.auth_trailer == b""

    def test_wire_to_object_to_wire(self, raw_ospf_hello):
        """Re-encode a decoded Hello to its bytes."""
        assert bytes(OSPF.decode(raw_ospf_hello)) == raw_ospf_hello

    def test_object_to_wire_to_object(self, raw_ospf_hello):
        """Decode a re-encoded Hello to the same instance."""
        ospf = OSPF.decode(raw_ospf_hello)
        assert OSPF.decode(bytes(ospf)) == ospf

    def test_memoryview_is_materialized(self, raw_ospf_hello):
        """Keep no view of a reused decode buffer."""
        buffer = bytearray(raw_ospf_hello)
        ospf = OSPF.decode(memoryview(buffer))
        buffer[:] = bytes(len(buffer))
        assert bytes(ospf) == raw_ospf_hello
        assert isinstance(ospf.body, bytes)
        assert isinstance(ospf.authentication, bytes)

    @pytest.mark.parametrize("type_", [0, 6, 255])
    def test_an_unknown_type_keeps_its_body(self, type_):
        """Keep an unknown message type's body raw, every accessor None."""
        ospf = OSPF.decode(bytes(make_ospf(type_, b"\x01\x02\x03")))
        assert ospf.type_name == f"unknown ({type_})"
        assert ospf.body == b"\x01\x02\x03"
        accessors = (
            ospf.hello,
            ospf.database_description,
            ospf.ls_requests,
            ospf.lsas,
            ospf.ls_acknowledgments,
        )
        assert accessors == (None,) * 5

    def test_type_names(self):
        """Name the message types."""
        assert [make_ospf(t, b"").type_name for t in (3, 5)] == [
            "Link State Request",
            "Link State Acknowledgment",
        ]
        assert make_ospf(3).type_names[2] == "Database Description"
        assert make_ospf(3).type_names[4] == "Link State Update"

    def test_an_unknown_au_type_is_named_and_takes_no_trailer(self):
        """Name an unknown AuType and give it no trailer."""
        ospf = make_ospf(3, au_type=7)
        assert ospf.au_type_name == "unknown (7)"
        assert ospf.header_len == 24
        assert ospf.key_id is None

    def test_the_accessors_answer_only_their_own_type(self, raw_ospf_hello):
        """Answer None from every accessor but the packet's own."""
        ospf = OSPF.decode(raw_ospf_hello)
        assert ospf.hello is not None
        assert ospf.database_description is None
        assert ospf.ls_requests is None
        assert ospf.lsas is None
        assert ospf.ls_acknowledgments is None

    def test_truncated_fixed_header(self, raw_ospf_hello):
        """Raise on a buffer shorter than the 24-byte header."""
        with pytest.raises(TruncatedHeaderError):
            OSPF.decode(raw_ospf_hello[:23])


class TestHello:
    def test_fields(self, raw_ospf_hello):
        """Decode a captured Hello's fields."""
        hello = OSPF.decode(raw_ospf_hello).hello
        assert hello == OSPFHello(
            network_mask="255.255.255.0",
            hello_interval=2,
            options=0x02,
            router_priority=10,
            router_dead_interval=8,
            designated_router="10.9.83.1",
            backup_designated_router="0.0.0.0",
            neighbors=("10.0.0.2",),
        )
        assert hello.options_str == "E"

    def test_the_hello_re_encodes_to_the_body(self, raw_ospf_hello):
        """Re-encode the parsed Hello to the body."""
        ospf = OSPF.decode(raw_ospf_hello)
        assert bytes(ospf.hello) == ospf.body

    def test_a_hello_without_neighbors(self):
        """Router B's first Hello, before it has heard A."""
        hello = decode_frame(FRAMES[0])[OSPF].hello
        assert hello.neighbors == ()
        assert hello.designated_router == "0.0.0.0"

    def test_several_neighbors(self):
        """Decode a neighbor list of three."""
        neighbors = ("10.0.0.2", "10.0.0.3", "192.0.2.9")
        ospf = OSPF.decode(bytes(make_ospf(1, hello_body(*neighbors))))
        assert ospf.hello.neighbors == neighbors

    def test_options_str_names_every_bit(self):
        """Name all eight Options bits, and none."""
        assert OSPF.decode(
            bytes(make_ospf(1, hello_body(options=0xFF)))
        ).hello.options_str == ("DN O DC L N/P MC E MT")
        assert OSPF.decode(
            bytes(make_ospf(1, hello_body(options=0)))
        ).hello.options_str == ("")


class TestDatabaseDescription:
    def test_the_first_packet_of_the_exchange(self):
        """Decode the I/M/MS packet that opens the exchange."""
        dd = decode_frame(FRAMES[2])[OSPF].database_description
        assert dd == OSPFDatabaseDescription(
            interface_mtu=1500,
            options=0x02,
            flags=0x07,
            dd_sequence_number=dd.dd_sequence_number,
            lsa_headers=(),
        )
        assert dd.flags_str == "I M MS"
        assert dd.options_str == "E"

    def test_a_packet_describing_lsas(self):
        """Decode the LSA headers a Database Description carries."""
        packets = [decode_frame(frame)[OSPF] for frame in FRAMES[:18]]
        described = [
            p.database_description
            for p in packets
            if p.database_description is not None
            and p.database_description.lsa_headers
        ]
        headers = [h for dd in described for h in dd.lsa_headers]
        assert {(h.ls_type, h.link_state_id) for h in headers} == {
            (1, "10.0.0.1"),
            (5, "192.0.2.1"),
            (1, "10.0.0.2"),
        }
        assert {h.ls_type_name for h in headers} == {
            "Router-LSA",
            "AS-external-LSA",
        }
        for dd in described:
            assert dd.flags_str in ("", "MS")

    def test_the_body_re_encodes(self):
        """Re-encode every captured Database Description to its body."""
        for frame in FRAMES:
            ospf = decode_frame(frame)[OSPF]
            if ospf.database_description is not None:
                assert bytes(ospf.database_description) == ospf.body


class TestLinkStateRequest:
    def test_the_captured_requests(self):
        """Decode the captured Link State Requests."""
        requests = [
            decode_frame(frame)[OSPF].ls_requests for frame in FRAMES[:18]
        ]
        requests = [r for r in requests if r is not None]
        # B asks for A's router and AS-external LSAs, then A for B's.
        assert requests == [
            (
                OSPFLSRequest(1, "10.0.0.1", "10.0.0.1"),
                OSPFLSRequest(5, "192.0.2.1", "10.0.0.1"),
            ),
            (OSPFLSRequest(1, "10.0.0.2", "10.0.0.2"),),
        ]
        assert requests[0][0].ls_type_name == "Router-LSA"

    def test_an_empty_request(self):
        """Decode a Link State Request with no entries."""
        assert OSPF.decode(bytes(make_ospf(3))).ls_requests == ()

    def test_entries_re_encode(self):
        """Round-trip built request entries through a packet."""
        entries = (
            OSPFLSRequest(7, "198.51.100.0", "10.0.0.9"),
            OSPFLSRequest(0x01020304, "0.0.0.1", "0.0.0.2"),
        )
        body = b"".join(bytes(entry) for entry in entries)
        ospf = OSPF.decode(bytes(make_ospf(3, body)))
        assert ospf.ls_requests == entries
        assert entries[0].ls_type_name == "NSSA-LSA"
        assert entries[1].ls_type_name == f"unknown ({0x01020304})"


class TestLinkStateUpdate:
    def updates(self) -> list[OSPF]:
        """Return the corpus's Link State Updates."""
        packets = [decode_frame(frame)[OSPF] for frame in FRAMES]
        return [p for p in packets if p.lsas is not None]

    def test_the_captured_lsas(self):
        """Decode the captured LSAs' headers, bodies left raw."""
        lsas = [lsa for p in self.updates() for lsa in p.lsas]
        assert len(lsas) == 18
        assert Counter(lsa.header.ls_type for lsa in lsas) == {
            1: 12,
            2: 3,
            5: 3,
        }
        network = next(lsa for lsa in lsas if lsa.header.ls_type == 2)
        assert network.header.link_state_id == "10.9.83.1"
        assert network.header.advertising_router == "10.0.0.1"
        assert network.header.ls_type_name == "Network-LSA"
        assert network.header.length == 32
        # The body stays raw: the mask, then the attached routers.
        assert network.body == bytes.fromhex("ffffff000a0000010a000002")

    def test_every_lsa_body_is_its_declared_length(self):
        """Size every LSA body by its header's length."""
        for update in self.updates():
            for lsa in update.lsas:
                assert len(lsa.body) == lsa.header.length - 20
                assert bytes(lsa) == bytes(lsa.header) + lsa.body

    def test_the_lsas_re_encode_to_the_body(self):
        """Re-encode every update's LSAs to its body."""
        for update in self.updates():
            count = len(update.lsas).to_bytes(4, "big")
            assert count + b"".join(map(bytes, update.lsas)) == update.body

    def test_a_router_lsa_header(self):
        """Decode a captured router LSA's header and raw body."""
        lsa = decode_frame(FRAMES[9])[OSPF].lsas[0]
        assert lsa.header == OSPFLSAHeader(
            ls_age=lsa.header.ls_age,
            options=0x02,
            ls_type=1,
            link_state_id="10.0.0.1",
            advertising_router="10.0.0.1",
            ls_sequence_number=0x80000002,
            ls_checksum=lsa.header.ls_checksum,
            length=36,
        )
        assert lsa.header.options_str == "E"
        assert lsa.header.ls_sequence_number_hex_str == "0x80000002"
        assert lsa.header.ls_checksum_hex_str == (
            f"0x{lsa.header.ls_checksum:04x}"
        )
        # One stub link: the 10.9.83.0/24 network, metric 10.
        assert lsa.body == bytes.fromhex("020000010a095300ffffff000300000a")

    def test_an_update_with_no_lsas(self):
        """Decode an update whose count is zero."""
        ospf = OSPF.decode(bytes(make_ospf(4, bytes(4))))
        assert ospf.lsas == ()

    def test_ls_type_names(self):
        """Name the LS types, unknown ones by number."""
        names = {
            t: lsa_header(ls_type=t).ls_type_name
            for t in (3, 4, 6, 9, 10, 11, 8)
        }
        assert names == {
            3: "Summary-LSA (IP network)",
            4: "Summary-LSA (ASBR)",
            6: "Group-membership-LSA",
            9: "Opaque-LSA (link-local)",
            10: "Opaque-LSA (area-local)",
            11: "Opaque-LSA (AS-wide)",
            8: "unknown (8)",
        }


class TestLinkStateAcknowledgment:
    def test_the_captured_acknowledgments(self):
        """Decode the captured acknowledgments' LSA headers."""
        acks = [
            decode_frame(frame)[OSPF].ls_acknowledgments for frame in FRAMES
        ]
        acks = [a for a in acks if a is not None]
        assert len(acks) == 6
        assert sorted(len(a) for a in acks) == [1, 1, 1, 3, 3, 3]
        types = {h.ls_type for ack in acks for h in ack}
        assert types == {1, 2, 5}

    def test_headers_re_encode(self):
        """Round-trip built LSA headers through an acknowledgment."""
        headers = (lsa_header(), lsa_header(ls_type=2, length=32))
        body = b"".join(map(bytes, headers))
        assert OSPF.decode(bytes(make_ospf(5, body))).ls_acknowledgments == (
            headers
        )


class TestAuthentication:
    def test_simple_password(self):
        """Decode a simple-password packet, which has no trailer."""
        ospf = decode_frame(FRAMES[18])[OSPF]
        assert ospf.au_type == 1
        assert ospf.au_type_name == "Simple Password"
        assert ospf.authentication == SIMPLE_PASSWORD
        assert ospf.auth_trailer == b""
        assert ospf.header_len == ospf.packet_length
        assert ospf.key_id is None
        assert ospf.auth_data_len is None
        assert ospf.crypto_sequence_number is None

    def test_md5_takes_its_digest(self):
        """Take the MD5 digest after Packet Length into the layer."""
        frame = FRAMES[37]
        ospf = decode_frame(frame)[OSPF]
        assert ospf.au_type == 2
        assert ospf.au_type_name == "Cryptographic"
        assert ospf.key_id == 1
        assert ospf.auth_data_len == 16
        assert ospf.crypto_sequence_number == int.from_bytes(
            frame[34 + 20 : 34 + 24], "big"
        )
        assert ospf.checksum == 0
        assert len(ospf.auth_trailer) == 16
        assert ospf.header_len == ospf.packet_length + 16 == len(frame) - 34
        assert bytes(ospf) == frame[34:]

    def test_the_digest_is_keyed_md5_over_the_packet(self):
        """Recompute every captured digest with the published key."""
        # RFC 2328 §D.4.3, computed here and not by the library.
        import hashlib

        for frame in FRAMES[36:]:
            ospf = decode_frame(frame)[OSPF]
            packet = bytes(ospf)[: ospf.packet_length]
            assert ospf.auth_trailer == hashlib.md5(packet + MD5_KEY).digest()

    def test_a_cut_digest_raises(self):
        """Raise on a digest the buffer cuts short."""
        raw = FRAMES[37][34:]
        with pytest.raises(TruncatedHeaderError) as excinfo:
            OSPF.decode(raw[:-1])
        error = excinfo.value
        assert error.field == "auth_trailer"
        assert error.offset == 48
        assert (error.expected, error.actual) == (64, 63)

    def test_auth_data_len_sizes_the_trailer(self):
        """Size the trailer by Auth Data Len, not by MD5's 16."""
        authentication = b"\x00\x00\x03\x14" + bytes(4)  # 20 bytes
        ospf = make_ospf(
            3, au_type=2, authentication=authentication, auth_trailer=bytes(20)
        )
        assert OSPF.decode(bytes(ospf) + b"\xff") == ospf
        assert ospf.header_len == 44
        assert ospf.key_id == 3


class TestWhereThePacketEnds:
    """Packet Length bounds the packet.

    Ethernet padding, an FCS and an LLS block are all left after the
    OSPF layer.
    """

    def ospf(self) -> OSPF:
        """Return an acknowledgment of one LSA header."""
        return make_ospf(5, bytes(lsa_header()))

    @pytest.mark.parametrize("padding", [1, 2, 12])
    def test_zero_padding(self, padding):
        """Leave zero padding after the packet."""
        ospf = self.ospf()
        decoded = OSPF.decode(bytes(ospf) + bytes(padding))
        assert decoded == ospf
        assert decoded.header_len == ospf.packet_length

    def test_a_nonzero_trailer(self):
        """Leave a nonzero 4-byte trailer after the packet."""
        ospf = self.ospf()
        decoded = OSPF.decode(bytes(ospf) + b"\xde\xad\xbe\xef")
        assert decoded == ospf
        assert decoded.header_len == ospf.packet_length

    def test_a_padded_frame_with_an_fcs_walks_to_ospf(self):
        """Walk a padded frame with an FCS, leaving both undecoded."""
        ospf = OSPF.decode(bytes(self.ospf()))
        frame = v4_frame(ospf, after=bytes(6) + b"\x01\x02\x03\x04")
        packet = decode_frame(frame)
        # v4_frame() computed the checksum; everything else is as built.
        assert replace(packet[OSPF], checksum=0) == ospf
        assert frame[packet.consumed :] == bytes(6) + b"\x01\x02\x03\x04"
        assert verify(packet[OSPF])

    def lls_block(self) -> bytes:
        """Build an RFC 5613 LLS data block.

        Its checksum, its length in 32-bit words (header included), then
        one Extended Options TLV (type 1).
        """
        tlv = struct.pack("!HHI", 1, 4, 0x00000001)
        return struct.pack("!HH", 0, (4 + len(tlv)) // 4) + tlv

    def test_an_lls_block_after_an_l_bit_hello(self):
        """Leave an LLS block after an L-bit Hello, out of the checksum."""
        lls = self.lls_block()
        hello = make_ospf(1, hello_body("10.0.0.2", options=0x12))
        frame = v4_frame(hello, inside=lls)
        packet = decode_frame(frame)
        ospf = packet[OSPF]
        assert ospf.hello.options_str == "L E"
        assert ospf.header_len == ospf.packet_length == 48
        assert frame[packet.consumed :] == lls
        # The checksum covers the packet, not the block after it.
        assert verify(ospf)
        assert packet.with_checksums(lls) == packet
        assert packet.with_checksums() == packet


class TestMalformed:
    def test_version_3_is_rejected(self, raw_ospf_hello):
        """Reject version 3 at offset 0."""
        with pytest.raises(InvalidFieldError) as excinfo:
            OSPF.decode(b"\x03" + raw_ospf_hello[1:])
        error = excinfo.value
        assert (error.field, error.offset) == ("version", 0)
        assert "OSPFv3" in str(error)

    @pytest.mark.parametrize("length", [0, 23])
    def test_a_packet_length_below_the_header(self, raw_ospf_hello, length):
        """Reject a Packet Length shorter than the header."""
        lying = (
            raw_ospf_hello[:2] + length.to_bytes(2, "big") + raw_ospf_hello[4:]
        )
        with pytest.raises(InvalidFieldError) as excinfo:
            OSPF.decode(lying)
        error = excinfo.value
        assert (error.field, error.offset) == ("packet_length", 0)
        assert (error.expected, error.actual) == (">=24", length)

    def test_a_packet_length_past_the_buffer(self, raw_ospf_hello):
        """Raise on a Packet Length past the buffer."""
        with pytest.raises(TruncatedHeaderError) as excinfo:
            OSPF.decode(raw_ospf_hello[:-1])
        error = excinfo.value
        assert (error.field, error.offset) == ("packet_length", 0)
        assert (error.expected, error.actual) == (48, 47)

    def test_the_walk_reports_the_frame_offset(self):
        """Rebase a cut packet's error to the frame."""
        frame = v4_frame(make_ospf(1, hello_body()))
        cut = frame[:-1]
        packet = decode_frame(cut, lax=True)
        assert [type(layer) for layer in packet] == [Ethernet, IPv4]
        assert isinstance(packet.stopped_by, TruncatedHeaderError)
        assert packet.stopped_by.frame_offset == 34

    @pytest.mark.parametrize(
        "type_,body_len,position",
        [
            (1, 19, 0),  # Hello: short of its 20 fixed bytes
            (1, 22, 20),  # a partial neighbor
            (2, 7, 0),  # Database Description: short of 8
            (2, 8 + 21, 28),  # a partial LSA header
            (3, 13, 12),  # a partial request
            (5, 19, 0),  # a partial LSA header
        ],
    )
    def test_a_body_without_its_framing(self, type_, body_len, position):
        """Reject a fixed-shape body without its framing, at the bad bytes."""
        raw = struct.pack("!BBH", 2, type_, 24 + body_len) + bytes(20)
        with pytest.raises(InvalidFieldError) as excinfo:
            OSPF.decode(raw + bytes(body_len))
        error = excinfo.value
        assert (error.field, error.offset) == ("body", 24 + position)
        assert error.actual == body_len

    def update(self, body: bytes) -> bytes:
        """Build a Link State Update packet around ``body``."""
        return struct.pack("!BBH", 2, 4, 24 + len(body)) + bytes(20) + body

    def lsa(self, length: int = 20) -> bytes:
        """Build an LSA of ``length`` bytes."""
        return bytes(lsa_header(length=length)) + bytes(length - 20)

    @pytest.mark.parametrize(
        "body,position,fragment",
        [
            (b"\x00\x00\x00", 0, "too short"),
            ((1).to_bytes(4, "big"), 4, "has 0 bytes"),
            ((2).to_bytes(4, "big") + bytes(lsa_header()), 24, "LSA 2"),
            (
                (1).to_bytes(4, "big") + bytes(lsa_header(length=19)),
                4,
                "declares 19",
            ),
            (
                (1).to_bytes(4, "big") + bytes(lsa_header(length=24)),
                4,
                "declares 24",
            ),
            (
                (1).to_bytes(4, "big") + bytes(lsa_header()) + b"\x00",
                24,
                "1 bytes after",
            ),
        ],
        ids=[
            "no-count",
            "count-past-body",
            "second-lsa-missing",
            "lsa-below-header",
            "lsa-past-body",
            "bytes-after-lsas",
        ],
    )
    def test_an_update_that_does_not_walk(self, body, position, fragment):
        """Reject an update whose LSAs do not walk its body exactly."""
        with pytest.raises(InvalidFieldError) as excinfo:
            OSPF.decode(self.update(body))
        error = excinfo.value
        assert (error.field, error.offset) == ("body", 24 + position)
        assert fragment in str(error)

    def test_a_body_error_rebases_onto_the_frame(self):
        """Rebase a decode-time body error by the decode buffer's offset."""
        ospf_bytes = self.update((1).to_bytes(4, "big") + self.lsa())
        # An LSA length of 19 at body offset 4 + 18.
        broken = ospf_bytes[: 24 + 4 + 18] + b"\x00\x13" + ospf_bytes[24 + 24 :]
        ip = make_ipv4(protocol=IPProtocol.OSPF, payload_len=len(broken))
        frame = bytes(ethernet(0x0800)) + bytes(ip) + broken
        packet = decode_frame(frame, lax=True)
        assert [type(layer) for layer in packet] == [Ethernet, IPv4]
        error = packet.stopped_by
        assert isinstance(error, InvalidFieldError)
        assert (error.field, error.offset) == ("body", 24 + 4)
        assert error.frame_offset == 34 + 24 + 4
        with pytest.raises(InvalidFieldError):
            decode_frame(frame)

    def test_a_hostile_lsa_count_is_bounded(self):
        """Stop a huge LSA count at the end of the body."""
        body = (0xFFFFFFFF).to_bytes(4, "big") + self.lsa() * 3
        with pytest.raises(InvalidFieldError) as excinfo:
            OSPF.decode(self.update(body))
        assert excinfo.value.offset == 24 + 4 + 60

    def test_a_count_of_lsas_that_fills_the_body(self):
        """Walk LSAs of differing lengths."""
        body = (3).to_bytes(4, "big") + self.lsa() + self.lsa(28) + self.lsa()
        ospf = OSPF.decode(self.update(body))
        assert [lsa.header.length for lsa in ospf.lsas] == [20, 28, 20]

    def test_every_error_is_a_protocol_error(self):
        """Raise only ProtocolError subclasses."""
        for raw in (b"", b"\x02\x01\x00\x18" + bytes(10)):
            with pytest.raises(ProtocolError):
                OSPF.decode(raw)


class TestConstruction:
    def test_packet_length_must_agree_with_the_body(self):
        """Refuse to construct a Packet Length the body disagrees with."""
        with pytest.raises(InvalidFieldError) as excinfo:
            make_ospf(1, hello_body(), packet_length=24)
        error = excinfo.value
        assert (error.field, error.offset) == ("packet_length", None)
        assert (error.expected, error.actual) == (44, 24)

    def test_only_version_2_constructs(self):
        """Refuse to construct version 3."""
        with pytest.raises(InvalidFieldError) as excinfo:
            make_ospf(1, hello_body(), version=3)
        assert (excinfo.value.field, excinfo.value.offset) == ("version", None)

    @pytest.mark.parametrize("length", [0, 7, 9])
    def test_authentication_is_8_bytes(self, length):
        """Refuse an Authentication field of any size but 8."""
        with pytest.raises(InvalidFieldError) as excinfo:
            make_ospf(3, authentication=bytes(length))
        assert excinfo.value.field == "authentication"
        assert (excinfo.value.expected, excinfo.value.actual) == (8, length)

    def test_the_trailer_is_auth_data_len_bytes_under_au_type_2(self):
        """Refuse a trailer of the wrong size under AuType 2."""
        authentication = b"\x00\x00\x01\x10" + bytes(4)
        with pytest.raises(InvalidFieldError) as excinfo:
            make_ospf(
                3, au_type=2, authentication=authentication, auth_trailer=b"x"
            )
        error = excinfo.value
        assert error.field == "auth_trailer"
        assert (error.expected, error.actual) == (16, 1)

    @pytest.mark.parametrize("au_type", [0, 1])
    def test_no_trailer_without_cryptographic_authentication(self, au_type):
        """Refuse a trailer under AuType 0 and 1."""
        with pytest.raises(InvalidFieldError) as excinfo:
            make_ospf(
                3,
                au_type=au_type,
                authentication=b"\x00\x00\x01\x10" + bytes(4),
                auth_trailer=bytes(16),
            )
        assert (excinfo.value.expected, excinfo.value.actual) == (0, 16)

    def test_a_body_without_its_framing_has_no_offset(self):
        """Raise construction's framing errors with no offset."""
        with pytest.raises(InvalidFieldError) as excinfo:
            make_ospf(1, hello_body() + b"\x01")
        assert (excinfo.value.field, excinfo.value.offset) == ("body", None)
        with pytest.raises(InvalidFieldError) as excinfo:
            make_ospf(4, (1).to_bytes(4, "big"))
        assert (excinfo.value.field, excinfo.value.offset) == ("body", None)

    def test_replace_revalidates(self, raw_ospf_hello):
        """Check the framing again on replace()."""
        ospf = OSPF.decode(raw_ospf_hello)
        with pytest.raises(InvalidFieldError):
            replace(ospf, type=5)  # a Hello body is not whole LSA headers
        assert replace(ospf, checksum=0).checksum == 0

    def test_an_lsa_body_must_match_its_header(self):
        """Refuse an LSA body its header's length disagrees with."""
        with pytest.raises(InvalidFieldError) as excinfo:
            OSPFLSA(lsa_header(length=24), bytes(3))
        error = excinfo.value
        assert error.protocol is OSPFLSA
        assert (error.field, error.expected, error.actual) == ("body", 4, 3)
        assert OSPFLSA(lsa_header(length=24), bytes(4)).body == bytes(4)

    def test_helper_records_build_a_whole_update(self):
        """Build an update from records and decode it back."""
        lsas = (
            OSPFLSA(lsa_header(length=24), b"\x01\x02\x03\x04"),
            OSPFLSA(lsa_header(ls_type=5, length=20)),
        )
        body = len(lsas).to_bytes(4, "big") + b"".join(map(bytes, lsas))
        ospf = make_ospf(4, body)
        assert OSPF.decode(bytes(ospf)).lsas == lsas

    def test_a_database_description_builds_from_records(self):
        """Build a Database Description from records and decode it back."""
        dd = OSPFDatabaseDescription(
            interface_mtu=9000,
            options=0x42,
            flags=0x02,
            dd_sequence_number=7,
            lsa_headers=(lsa_header(), lsa_header(ls_age=3600)),
        )
        ospf = OSPF.decode(bytes(make_ospf(2, bytes(dd))))
        assert ospf.database_description == dd
        assert dd.flags_str == "M"
        assert dd.options_str == "O E"


def load_checker():
    path = FIXTURES.parent.parent / "scripts" / "check_fixtures.py"
    spec = importlib.util.spec_from_file_location("check_fixtures", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestCorpusOSPF:
    """``ospf.pcap``: three adjacencies between two FRR 8.4 routers.

    One per AuType (see tests/fixtures/MANIFEST.md).
    """

    def test_composition(self):
        """Pin the capture: 54 frames, 18 per AuType."""
        packets = [decode_frame(frame) for frame in FRAMES]
        assert len(packets) == 54
        for frame, packet in zip(FRAMES, packets, strict=True):
            assert [type(layer) for layer in packet] == [Ethernet, IPv4, OSPF]
            assert packet.consumed == len(frame)
        segments = [packets[:18], packets[18:36], packets[36:]]
        for au_type, segment in enumerate(segments):
            assert {p[OSPF].au_type for p in segment} == {au_type}
            assert Counter(p[OSPF].type_name for p in segment) == {
                "Hello": 6,
                "Database Description": 5,
                "Link State Request": 2,
                "Link State Update": 3,
                "Link State Acknowledgment": 2,
            }

    def test_the_shared_fixture_is_the_captured_hello(self, raw_ospf_hello):
        """Tie conftest's raw_ospf_hello to the capture."""
        assert FRAMES[1][34:] == raw_ospf_hello

    def test_every_packet_round_trips(self):
        """Round-trip every captured packet both ways."""
        for frame in FRAMES:
            ospf = decode_frame(frame)[OSPF]
            assert bytes(ospf) == frame[34:]
            assert OSPF.decode(bytes(ospf)) == ospf

    def test_the_routers_and_the_area(self):
        """Check the routers, the area and the Hello sizes."""
        packets = [decode_frame(frame)[OSPF] for frame in FRAMES]
        assert {p.router_id for p in packets} == {"10.0.0.1", "10.0.0.2"}
        assert {p.area_id for p in packets} == {"0.0.0.0"}
        # A Hello is 44 bytes with no neighbor, 48 with one.
        assert {p.packet_length for p in packets if p.type == 1} == {44, 48}

    def test_no_packet_sets_the_l_bit(self):
        """Check that FRR sent no L bit, so no LLS."""
        for frame in FRAMES:
            ospf = decode_frame(frame)[OSPF]
            message = ospf.hello or ospf.database_description
            if message is not None:
                assert "L" not in message.options_str.split()

    def test_the_published_secrets_are_the_ones_in_the_manifest(self):
        """Match the test secrets to MANIFEST.md and the checker."""
        manifest = (FIXTURES / "MANIFEST.md").read_text()
        assert SIMPLE_PASSWORD.rstrip(b"\x00").decode() in manifest
        assert MD5_KEY.decode() in manifest
        checker = load_checker()
        assert checker._OSPF_SIMPLE_PASSWORD == SIMPLE_PASSWORD
        assert checker._OSPF_MD5_KEYS == {1: MD5_KEY}


@pytest.fixture(scope="module")
def checker():
    return load_checker()


class TestCheckerCatchesTampering:
    """scripts/check_fixtures.py is the corpus's independent oracle.

    It must pass every captured frame and fail each kind of damage.
    """

    def check(self, checker, frame: bytes) -> list[str]:
        """Run the checker on one frame."""
        return checker.check_frame(frame, Counter())

    def test_every_captured_frame_passes(self, checker):
        """Pass every captured frame."""
        for frame in FRAMES:
            assert self.check(checker, frame) == []

    @staticmethod
    def flip(frame: bytes, offset: int) -> bytes:
        """Flip the low bit of ``frame[offset]``."""
        return (
            frame[:offset] + bytes([frame[offset] ^ 0x01]) + frame[offset + 1 :]
        )

    def test_a_flipped_body_byte_fails_the_packet_checksum(self, checker):
        """Fail a flipped body byte on the packet checksum."""
        assert self.check(checker, self.flip(FRAMES[1], 34 + 30)) == [
            "ospf-checksum"
        ]

    def test_a_flipped_authentication_byte_still_passes_au_type_0(
        self, checker
    ):
        """Pass a flipped Authentication byte under AuType 0."""
        # The checksum excludes the Authentication field.
        assert self.check(checker, self.flip(FRAMES[1], 34 + 20)) == []

    def test_a_wrong_password_fails(self, checker):
        """Fail a password that is not the published one."""
        assert self.check(checker, self.flip(FRAMES[18], 34 + 16)) == [
            "ospf-password"
        ]

    def test_a_flipped_lsa_body_byte_fails_its_fletcher_checksum(self, checker):
        """Fail a flipped LSA byte on the LSA's Fletcher checksum."""
        frame = FRAMES[9]
        assert decode_frame(frame)[OSPF].lsas
        # The first LSA's body starts after the header (24), the count
        # (4) and the LSA header (20). Flipping it breaks the packet
        # checksum too; fix that up so only the LSA's fails.
        damaged = decode_frame(self.flip(frame, 34 + 48))
        restored = damaged.with_checksums()
        assert self.check(checker, bytes(restored)) == ["ospf-lsa-checksum"]

    def test_a_flipped_md5_digest_fails(self, checker):
        """Fail a flipped digest byte."""
        frame = FRAMES[37]
        assert self.check(checker, self.flip(frame, len(frame) - 1)) == [
            "ospf-md5-digest"
        ]

    def test_a_flipped_md5_packet_byte_fails(self, checker):
        """Fail a flipped byte the digest covers."""
        assert self.check(checker, self.flip(FRAMES[37], 34 + 30)) == [
            "ospf-md5-digest"
        ]

    def test_an_unpublished_key_id_fails(self, checker):
        """Fail a Key ID with no published key."""
        assert self.check(checker, self.flip(FRAMES[37], 34 + 18)) == [
            "ospf-unknown-key"
        ]

    def test_a_checksum_under_md5_fails(self, checker):
        """Fail a nonzero packet checksum under MD5."""
        # The digest covers the checksum field too.
        assert self.check(checker, self.flip(FRAMES[37], 34 + 13)) == [
            "ospf-checksum",
            "ospf-md5-digest",
        ]
