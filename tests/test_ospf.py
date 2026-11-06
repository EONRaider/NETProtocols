"""OSPFv2 (RFC 2328), IP protocol 89.

The common header, the five message types' accessors, where the packet
ends (Packet Length, plus the digest under cryptographic
authentication, and never the link-layer padding, FCS or LLS block
after it), the framing ``decode`` and construction enforce, the typed LSA bodies
and their framing, the IPv4-only wiring that keeps an IPv6 packet's
OSPFv3 out of this decoder, and the real FRR captures in ``ospf.pcap``
-- checked by ``scripts/check_fixtures.py`` too, here, against
tampering -- and ``ospf_areas.pcap``, whose LSA bodies are checked
against the link-state database FRR recorded with it. Checksums are
tested in test_checksum.py, which the mutation audit selects.
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
    OSPFExternalLSA,
    OSPFExternalRoute,
    OSPFHello,
    OSPFLSAHeader,
    OSPFLSRequest,
    OSPFNetworkLSA,
    OSPFRouterLink,
    OSPFRouterLinkTOS,
    OSPFRouterLSA,
    OSPFSummaryLSA,
    OSPFSummaryTOS,
    Packet,
    ProtocolError,
    Registry,
    TruncatedHeaderError,
    decode_frame,
)
from netprotocols._defaults import IPV4_ONLY_NUMBERS, install
from netprotocols.checksum import verify, verify_lsa
from netprotocols.registry import DEFAULT, TABLE_IP_PROTO, TABLE_IP_PROTO_V6
from test_ipip import ethernet, make_ipv4, make_ipv6

FRAMES = pcap_frames(FIXTURES / "ospf.pcap")

#: The published test secrets (tests/fixtures/MANIFEST.md).
SIMPLE_PASSWORD = b"NPospf1\x00"
MD5_KEY = b"NETProtocols-md5"


def lsa_header(**fields) -> OSPFLSAHeader:
    """Build an LSA header, of a link-local opaque LSA (LS type 9) unless
    ``fields`` say otherwise: its body is not decoded, so any bytes of
    the length it declares construct."""
    values = {
        "ls_age": 1,
        "options": 2,
        "ls_type": 9,
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
        "instance_id": 0,
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

        class OSPFVariant(OSPF):
            pass

        child = DEFAULT.derive()
        assert child.get(TABLE_IP_PROTO_V6, 89) is None
        child.register(TABLE_IP_PROTO, 89, OSPFVariant, override=True)
        assert child.get(TABLE_IP_PROTO, 89) is OSPFVariant
        assert child.get(TABLE_IP_PROTO_V6, 89) is None

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
        assert ospf.instance_id == 0
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
        """Decode the captured LSAs' headers, and keep the raw bodies."""
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
        # The raw body: the mask, then the attached routers.
        assert network.body == bytes.fromhex("ffffff000a0000010a000002")
        assert network.network == OSPFNetworkLSA(
            "255.255.255.0", ("10.0.0.1", "10.0.0.2")
        )

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
        """Decode a captured router LSA's header and body."""
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
        assert lsa.router == OSPFRouterLSA(
            0x02, (stub("10.9.83.0", "255.255.255.0"),)
        )
        assert lsa.router.flags_str == "E"

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
            # RFC 2328 Appendix D mandates MD5; this only verifies the
            # digest the router sent.
            digest = hashlib.md5(packet + MD5_KEY, usedforsecurity=False)
            assert ospf.auth_trailer == digest.digest()

    def test_a_cut_digest_raises(self):
        """Raise on a digest the buffer cuts short."""
        raw = FRAMES[37][34:]
        with pytest.raises(TruncatedHeaderError) as excinfo:
            OSPF.decode(raw[:-1])
        error = excinfo.value
        assert error.field == "auth_trailer"
        assert error.offset == 48
        assert (error.expected, error.actual) == (64, 63)

    def instance_1_md5(self) -> bytes:
        """Return FRAMES[37] moved to Instance ID 1, digest recomputed."""
        import hashlib

        frame = bytearray(FRAMES[37])
        frame[34 + 14] = 1
        length = int.from_bytes(frame[36:38], "big")
        packet = bytes(frame[34 : 34 + length])
        # RFC 2328 Appendix D mandates MD5; this recomputes a router's digest.
        digest = hashlib.md5(packet + MD5_KEY, usedforsecurity=False)
        frame[34 + length :] = digest.digest()
        return bytes(frame)

    def test_the_instance_id_is_byte_14_and_au_type_byte_15(self):
        """Read Instance ID and AuType as one byte each (RFC 6549 §2)."""
        frame = self.instance_1_md5()
        ospf = decode_frame(frame)[OSPF]
        assert ospf.instance_id == 1
        assert ospf.au_type == 2
        assert ospf.au_type_name == "Cryptographic"
        assert ospf.key_id == 1
        assert ospf.auth_trailer == frame[-16:]
        assert ospf.header_len == ospf.packet_length + 16 == len(frame) - 34
        assert bytes(ospf) == frame[34:]
        assert OSPF.decode(bytes(ospf)) == ospf

    @pytest.mark.parametrize("instance_id", [1, 2, 255])
    def test_an_instance_id_round_trips_under_every_au_type(self, instance_id):
        """Keep the Instance ID apart from the AuType through a round trip."""
        ospf = make_ospf(3, instance_id=instance_id, au_type=1)
        raw = bytes(ospf)
        assert raw[14:16] == bytes([instance_id, 1])
        assert OSPF.decode(raw) == ospf
        assert OSPF.decode(raw).au_type_name == "Simple Password"

    def extended(self, **fields) -> OSPF:
        """Return an AuType 3 request (RFC 7474 §3).

        Key ID 0x01020304, and a 28-byte trailer: the 64-bit sequence
        number, then a 20-byte digest.
        """
        values = {
            "au_type": 3,
            "authentication": b"\x00\x00\x00\x1c\x01\x02\x03\x04",
            "auth_trailer": (5 << 32 | 9).to_bytes(8, "big") + bytes(20),
        }
        values.update(fields)
        return make_ospf(3, **values)

    def test_extended_sequence_numbers_take_their_trailer(self):
        """Take AuType 3's sequence number and digest into the layer."""
        ospf = self.extended()
        assert ospf.au_type_name == (
            "Cryptographic with Extended Sequence Numbers"
        )
        assert ospf.auth_data_len == 28
        assert ospf.header_len == 24 + 28
        assert ospf.key_id == 0x01020304
        assert ospf.crypto_sequence_number == 5 << 32 | 9
        assert OSPF.decode(bytes(ospf) + b"\xff") == ospf

    def test_a_trailer_too_short_for_the_sequence_number(self):
        """Answer None for a sequence number the trailer cannot hold."""
        ospf = self.extended(
            authentication=b"\x00\x00\x00\x07" + bytes(4),
            auth_trailer=bytes(7),
        )
        assert ospf.crypto_sequence_number is None
        assert ospf.key_id == 0
        eight = self.extended(
            authentication=b"\x00\x00\x00\x08" + bytes(4),
            auth_trailer=b"\x00" * 7 + b"\x01",
        )
        assert eight.crypto_sequence_number == 1

    def test_a_cut_extended_trailer_raises(self):
        """Raise on an AuType 3 trailer the buffer cuts short."""
        raw = bytes(self.extended())
        with pytest.raises(TruncatedHeaderError) as excinfo:
            OSPF.decode(raw[:-1])
        assert excinfo.value.field == "auth_trailer"

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
            # Short of the fixed part by whole neighbors: these lengths
            # leave no partial neighbor, so only the fixed-part check
            # rejects them.
            (1, 0, 0),
            (1, 4, 0),
            (1, 8, 0),
            (1, 12, 0),
            (1, 16, 0),
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

    def test_the_trailer_is_auth_data_len_bytes_under_au_type_3(self):
        """Refuse a trailer of the wrong size under AuType 3."""
        with pytest.raises(InvalidFieldError) as excinfo:
            make_ospf(
                3,
                au_type=3,
                authentication=b"\x00\x00\x00\x1c" + bytes(4),
                auth_trailer=bytes(20),
            )
        assert (excinfo.value.expected, excinfo.value.actual) == (28, 20)

    @pytest.mark.parametrize("au_type", [0, 1, 4])
    def test_no_trailer_without_cryptographic_authentication(self, au_type):
        """Refuse a trailer under AuType 0, 1 and an unknown one."""
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
            OSPFLSA(lsa_header(ls_type=11, length=20)),
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

    @pytest.mark.parametrize(
        "build",
        [
            lambda: make_ospf(5, router_id="10.0.0.256"),
            lambda: make_ospf(5, area_id="area 0"),
            lambda: lsa_header(advertising_router="::1"),
        ],
    )
    def test_a_malformed_address_fails_only_in_bytes(self, build):
        """Construct a malformed address; raise OSError from ``bytes()``.

        Like IPv6 and DHCP, OSPF does not check addresses when it is
        built (ARCHITECTURE, *The encode side*).
        """
        record = build()
        with pytest.raises(OSError):
            bytes(record)


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
            "ospf-simple-auth-mismatch"
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

    def test_swapped_lsa_bytes_fail_their_fletcher_checksum(self, checker):
        """Fail two swapped adjacent LSA bytes, which change only C1."""
        frame = FRAMES[9]
        lsa = decode_frame(frame)[OSPF].lsas[0]
        # Two body bytes of the first LSA, which starts at 34 + 28.
        at = 34 + 48
        first, second = frame[at], frame[at + 1]
        assert first != second
        assert {first, second} != {0x00, 0xFF}
        assert lsa.body[:2] == bytes([first, second])
        swapped = frame[:at] + bytes([second, first]) + frame[at + 2 :]
        restored = decode_frame(swapped).with_checksums()
        assert self.check(checker, bytes(restored)) == ["ospf-lsa-checksum"]

    def test_a_c1_preserving_change_fails_its_fletcher_checksum(self, checker):
        """Fail +1 on an LSA's second-to-last byte and -2 on its last.

        That leaves C1 unchanged and moves only C0.
        """
        frame = FRAMES[9]
        lsa = decode_frame(frame)[OSPF].lsas[0]
        end = 34 + 28 + lsa.header.length
        assert frame[end - 2] < 0xFF and frame[end - 1] >= 2
        changed = bytes([frame[end - 2] + 1, frame[end - 1] - 2])
        damaged = frame[: end - 2] + changed + frame[end:]
        restored = decode_frame(damaged).with_checksums()
        assert self.check(checker, bytes(restored)) == ["ospf-lsa-checksum"]

    def update_frame(self, ls_checksum: int) -> bytes:
        """Build an update carrying one LSA whose checksum should be 0xffff."""
        lsa = OSPFLSA(
            lsa_header(ls_checksum=ls_checksum, length=24),
            bytes.fromhex("3e000700"),
        )
        return v4_frame(make_ospf(4, struct.pack("!I", 1) + bytes(lsa)))

    def test_a_zero_lsa_checksum_fails(self, checker):
        """Fail an LS Checksum of 0x0000 (RFC 2328 §12.1.7).

        Its Fletcher sums are zero, as they are for the 0xffff this LSA
        generates (each byte may read 0x00 for 0xff, as 0x00ff and
        0xff00 show), so only the zero rule catches it.
        """
        for passing in (0xFFFF, 0x00FF, 0xFF00):
            assert self.check(checker, self.update_frame(passing)) == []
        assert self.check(checker, self.update_frame(0)) == [
            "ospf-lsa-checksum"
        ]

    def test_a_nonzero_instance_id_passes(self, checker):
        """Pass a valid AuType 2 frame with Instance ID 1 (RFC 6549 §2)."""
        frame = TestAuthentication().instance_1_md5()
        assert self.check(checker, frame) == []
        stats = Counter()
        checker.check_frame(frame, stats)
        assert stats["ospf-md5"] == 1

    def test_a_nonzero_instance_id_passes_under_au_type_0(self, checker):
        """Pass a checksummed AuType 0 frame with Instance ID 7."""
        frame = v4_frame(make_ospf(1, hello_body(), instance_id=7))
        assert frame[34 + 14 : 34 + 16] == b"\x07\x00"
        assert self.check(checker, frame) == []

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


AREA_FRAMES = pcap_frames(FIXTURES / "ospf_areas.pcap")
#: FRR's link-state databases at the end of each segment of
#: ``ospf_areas.pcap``, as ``show ip ospf database <type>`` printed
#: them (tests/fixtures/MANIFEST.md).
AREA_LSDB = (FIXTURES / "ospf_areas_lsdb.txt").read_text()


def lsdb_entries() -> list[dict[str, str]]:
    """Every LSA ``AREA_LSDB`` prints, each as its ``key: value`` lines.

    An entry starts at its ``LS age`` line; a key that repeats within
    one (an attached router) keeps its values comma-separated. Its
    ``scope`` is the area of the section it is printed in, or ``"AS"``
    for an AS-external-LSA.
    """
    entries: list[dict[str, str]] = []
    scope = ""
    for line in AREA_LSDB.splitlines():
        if line.strip().endswith(")") and "Link States (Area " in line:
            scope = line.split("(Area ")[1].split()[0].rstrip(")")
        elif "AS External Link States" in line:
            scope = "AS"
        key, colon, value = line.strip().partition(":")
        if not colon or line.startswith("###"):
            continue
        if key == "LS age":
            entries.append({"scope": scope})
        if entries:
            entry = entries[-1]
            value = value.strip()
            entry[key] = f"{entry[key]},{value}" if key in entry else value
    return entries


def area_lsas() -> list[tuple[int, OSPFLSA]]:
    """Every LSA in ``ospf_areas.pcap``'s updates, with its frame index."""
    return [
        (index, lsa)
        for index, frame in enumerate(AREA_FRAMES)
        for lsa in decode_frame(frame)[OSPF].lsas or ()
    ]


class TestCorpusOSPFAreas:
    """``ospf_areas.pcap``: four FRR 8.4 routers in three areas.

    Area 0, area 0.0.0.1 and NSSA area 0.0.0.2, with one area border
    router; two adjacencies captured in turn (see
    tests/fixtures/MANIFEST.md).
    """

    def test_composition(self):
        """Pin the capture: link 2 (31 frames), then link 0 (21)."""
        packets = [decode_frame(frame) for frame in AREA_FRAMES]
        assert len(packets) == 52
        for frame, packet in zip(AREA_FRAMES, packets, strict=True):
            assert [type(layer) for layer in packet] == [Ethernet, IPv4, OSPF]
            assert packet.consumed == len(frame)
            assert packet[OSPF].au_type == 0
        assert [p[OSPF].area_id for p in packets] == (
            ["0.0.0.2"] * 31 + ["0.0.0.0"] * 21
        )
        for segment in (packets[:31], packets[31:]):
            assert {p[OSPF].type for p in segment} == {1, 2, 3, 4, 5}
        assert {p[OSPF].router_id for p in packets[:31]} == {
            "10.0.0.2",
            "10.0.0.4",
        }
        assert {p[OSPF].router_id for p in packets[31:]} == {
            "10.0.0.1",
            "10.0.0.2",
        }

    def test_every_packet_round_trips(self):
        """Round-trip every captured packet both ways."""
        for frame in AREA_FRAMES:
            ospf = decode_frame(frame)[OSPF]
            assert bytes(ospf) == frame[34:]
            assert OSPF.decode(bytes(ospf)) == ospf
            assert verify(ospf)
            for lsa in ospf.lsas or ():
                assert verify_lsa(lsa)

    def test_the_lsas(self):
        """Pin every LSA the updates carry, by type, ID and originator."""
        found = {
            (
                ospf_area(index),
                lsa.header.ls_type,
                lsa.header.link_state_id,
                lsa.header.advertising_router,
            )
            for index, lsa in area_lsas()
        }
        assert found == {
            ("0.0.0.2", 1, "10.0.0.2", "10.0.0.2"),
            ("0.0.0.2", 1, "10.0.0.4", "10.0.0.4"),
            ("0.0.0.2", 2, "10.9.84.129", "10.0.0.2"),
            ("0.0.0.2", 3, "0.0.0.0", "10.0.0.2"),
            ("0.0.0.2", 3, "10.9.84.0", "10.0.0.2"),
            ("0.0.0.2", 3, "10.9.84.64", "10.0.0.2"),
            ("0.0.0.2", 7, "192.0.2.4", "10.0.0.4"),
            ("0.0.0.0", 1, "10.0.0.1", "10.0.0.1"),
            ("0.0.0.0", 1, "10.0.0.2", "10.0.0.2"),
            ("0.0.0.0", 2, "10.9.84.2", "10.0.0.2"),
            ("0.0.0.0", 3, "10.9.84.64", "10.0.0.2"),
            ("0.0.0.0", 3, "10.9.84.128", "10.0.0.2"),
            ("0.0.0.0", 4, "10.0.0.3", "10.0.0.2"),
            ("0.0.0.0", 5, "192.0.2.3", "10.0.0.3"),
            ("0.0.0.0", 5, "192.0.2.4", "10.0.0.2"),
        }
        assert len(area_lsas()) == 23

    def test_every_lsa_header_is_in_frr_s_database(self):
        """Find each LSA header in the database FRR recorded.

        The database records only the latest instance of each LSA, so
        three earlier instances sent in segment 1 are not there: B's and
        D's Router-LSAs for area 0.0.0.2 from before their adjacency,
        and D's first NSSA-LSA.
        """
        recorded = {
            (
                entry["Link State ID"].split()[0],
                entry["Advertising Router"],
                int(entry["LS Seq Number"], 16),
                int(entry["Checksum"], 16),
                int(entry["Length"]),
            )
            for entry in lsdb_entries()
        }
        missing = set()
        for _, lsa in area_lsas():
            header = lsa.header
            key = (
                header.link_state_id,
                header.advertising_router,
                header.ls_sequence_number,
                header.ls_checksum,
                header.length,
            )
            if key not in recorded:
                missing.add((header.ls_type, *key[:3]))
        assert missing == {
            (1, "10.0.0.2", "10.0.0.2", 0x80000005),
            (1, "10.0.0.4", "10.0.0.4", 0x80000004),
            (7, "192.0.2.4", "10.0.0.4", 0x80000001),
        }

    def test_every_frame_passes_the_checker(self, checker):
        """Pass every captured frame through check_fixtures."""
        for frame in AREA_FRAMES:
            assert checker.check_frame(frame, Counter()) == []


def ospf_area(index: int) -> str:
    """The area of ``ospf_areas.pcap``'s frame ``index``."""
    return decode_frame(AREA_FRAMES[index])[OSPF].area_id


def stub(network: str, mask: str) -> OSPFRouterLink:
    """A stub link of metric 10, as FRR's interfaces here all cost."""
    return OSPFRouterLink(network, mask, 3, 10)


def transit(dr: str, interface: str) -> OSPFRouterLink:
    """A transit link of metric 10."""
    return OSPFRouterLink(dr, interface, 2, 10)


def external(forwarding_address: str = "0.0.0.0") -> OSPFExternalLSA:
    """A /32 with one Type 2 (E bit set) metric of 20, FRR's default
    for a redistributed connected route, and no tag."""
    route = OSPFExternalRoute(True, 0, 20, forwarding_address, 0)
    return OSPFExternalLSA("255.255.255.255", (route,))


MASK_26 = "255.255.255.192"

#: Every LSA body of ``ospf.pcap``, by (LS type, Link State ID,
#: advertising router, LS sequence number). No database was recorded
#: for that capture: the values follow from its script's configuration
#: (10.9.83.0/24 between A and B, A the DR and redistributing
#: 192.0.2.1/32) and :meth:`TestLSABodies.test_a_struct_decode_agrees`
#: checks them against the bytes.
OSPF_BODIES = {
    (1, "10.0.0.1", "10.0.0.1", 0x80000002): OSPFRouterLSA(
        0x02, (stub("10.9.83.0", "255.255.255.0"),)
    ),
    (1, "10.0.0.1", "10.0.0.1", 0x80000003): OSPFRouterLSA(
        0x02, (transit("10.9.83.1", "10.9.83.1"),)
    ),
    (1, "10.0.0.2", "10.0.0.2", 0x80000002): OSPFRouterLSA(
        0x00, (stub("10.9.83.0", "255.255.255.0"),)
    ),
    (1, "10.0.0.2", "10.0.0.2", 0x80000003): OSPFRouterLSA(
        0x00, (transit("10.9.83.1", "10.9.83.2"),)
    ),
    (2, "10.9.83.1", "10.0.0.1", 0x80000001): OSPFNetworkLSA(
        "255.255.255.0", ("10.0.0.1", "10.0.0.2")
    ),
    (5, "192.0.2.1", "10.0.0.1", 0x80000001): external(),
}

#: Every LSA body of ``ospf_areas.pcap``, by (flooding scope, LS type,
#: Link State ID, advertising router, LS sequence number), as FRR's
#: database records them in ``ospf_areas_lsdb.txt``, which holds all
#: but three. The scope is the area, or ``"AS"`` for an
#: AS-external-LSA.
AREA_BODIES = {
    # Area 0.0.0.2, the NSSA; B's and D's first Router-LSAs and D's
    # first NSSA-LSA are not recorded.
    ("0.0.0.2", 1, "10.0.0.2", "10.0.0.2", 0x80000005): OSPFRouterLSA(
        0x03, (stub("10.9.84.128", MASK_26),)
    ),
    ("0.0.0.2", 1, "10.0.0.2", "10.0.0.2", 0x80000006): OSPFRouterLSA(
        0x03, (transit("10.9.84.129", "10.9.84.129"),)
    ),
    ("0.0.0.2", 1, "10.0.0.4", "10.0.0.4", 0x80000004): OSPFRouterLSA(
        0x02, (stub("10.9.84.128", MASK_26),)
    ),
    ("0.0.0.2", 1, "10.0.0.4", "10.0.0.4", 0x80000005): OSPFRouterLSA(
        0x02, (transit("10.9.84.129", "10.9.84.130"),)
    ),
    ("0.0.0.2", 2, "10.9.84.129", "10.0.0.2", 0x80000001): OSPFNetworkLSA(
        MASK_26, ("10.0.0.2", "10.0.0.4")
    ),
    ("0.0.0.2", 3, "0.0.0.0", "10.0.0.2", 0x80000001): OSPFSummaryLSA(
        "0.0.0.0", 1
    ),
    ("0.0.0.2", 3, "10.9.84.0", "10.0.0.2", 0x80000001): OSPFSummaryLSA(
        MASK_26, 10
    ),
    ("0.0.0.2", 3, "10.9.84.64", "10.0.0.2", 0x80000001): OSPFSummaryLSA(
        MASK_26, 10
    ),
    ("0.0.0.2", 7, "192.0.2.4", "10.0.0.4", 0x80000001): external(
        "10.9.84.130"
    ),
    ("0.0.0.2", 7, "192.0.2.4", "10.0.0.4", 0x80000002): external(
        "10.9.84.130"
    ),
    # Area 0, and the AS-external-LSAs.
    ("0.0.0.0", 1, "10.0.0.1", "10.0.0.1", 0x80000002): OSPFRouterLSA(
        0x00, (stub("10.9.84.0", MASK_26),)
    ),
    ("0.0.0.0", 1, "10.0.0.1", "10.0.0.1", 0x80000003): OSPFRouterLSA(
        0x00, (transit("10.9.84.2", "10.9.84.1"),)
    ),
    ("0.0.0.0", 1, "10.0.0.2", "10.0.0.2", 0x80000004): OSPFRouterLSA(
        0x03, (stub("10.9.84.0", MASK_26),)
    ),
    ("0.0.0.0", 1, "10.0.0.2", "10.0.0.2", 0x80000005): OSPFRouterLSA(
        0x03, (transit("10.9.84.2", "10.9.84.2"),)
    ),
    ("0.0.0.0", 2, "10.9.84.2", "10.0.0.2", 0x80000001): OSPFNetworkLSA(
        MASK_26, ("10.0.0.1", "10.0.0.2")
    ),
    ("0.0.0.0", 3, "10.9.84.64", "10.0.0.2", 0x80000001): OSPFSummaryLSA(
        MASK_26, 10
    ),
    ("0.0.0.0", 3, "10.9.84.128", "10.0.0.2", 0x80000001): OSPFSummaryLSA(
        MASK_26, 10
    ),
    ("0.0.0.0", 4, "10.0.0.3", "10.0.0.2", 0x80000001): OSPFSummaryLSA(
        "0.0.0.0", 10
    ),
    ("AS", 5, "192.0.2.3", "10.0.0.3", 0x80000001): external(),
    ("AS", 5, "192.0.2.4", "10.0.0.2", 0x80000003): external("10.9.84.130"),
}

#: An accessor per decoded LS type.
ACCESSOR = {
    1: "router",
    2: "network",
    3: "summary",
    4: "summary",
    5: "external",
    7: "external",
}


def lsa_key(lsa: OSPFLSA) -> tuple[int, str, str, int]:
    header = lsa.header
    return (
        header.ls_type,
        header.link_state_id,
        header.advertising_router,
        header.ls_sequence_number,
    )


def lsa_scope(area_id: str, lsa: OSPFLSA) -> str:
    """The LSA's flooding scope: ``"AS"`` for an AS-external-LSA, else
    the area it was sent in."""
    return "AS" if lsa.header.ls_type == 5 else area_id


def make_lsa(ls_type: int, body: bytes) -> OSPFLSA:
    return OSPFLSA(lsa_header(ls_type=ls_type, length=20 + len(body)), body)


def hand_decode(lsa: OSPFLSA) -> tuple:
    """Decode an LSA body with ``struct`` alone, into plain tuples."""
    body, ls_type = lsa.body, lsa.header.ls_type

    def ip(at: int) -> str:
        return ".".join(map(str, body[at : at + 4]))

    if ls_type == 1:
        flags, count = body[0], struct.unpack_from("!H", body, 2)[0]
        links, at = [], 4
        for _ in range(count):
            kind, tos_count, metric = struct.unpack_from("!BBH", body, at + 8)
            tos = [
                (
                    body[at + 12 + 4 * i],
                    struct.unpack_from("!H", body, at + 14 + 4 * i)[0],
                )
                for i in range(tos_count)
            ]
            links.append((ip(at), ip(at + 4), kind, metric, tos))
            at += 12 + 4 * tos_count
        return flags, links
    if ls_type == 2:
        return ip(0), [ip(at) for at in range(4, len(body), 4)]
    if ls_type in (3, 4):
        return ip(0), [
            (body[at], int.from_bytes(body[at + 1 : at + 4], "big"))
            for at in range(4, len(body), 4)
        ]
    return ip(0), [
        (
            body[at] >> 7,
            body[at] & 0x7F,
            int.from_bytes(body[at + 1 : at + 4], "big"),
            ip(at + 4),
            struct.unpack_from("!I", body, at + 8)[0],
        )
        for at in range(4, len(body), 12)
    ]


def as_tuples(record) -> tuple:
    """Flatten a typed body record into :func:`hand_decode`'s shape."""
    if isinstance(record, OSPFRouterLSA):
        return record.flags, [
            (
                link.link_id,
                link.link_data,
                link.type,
                link.metric,
                [(t.tos, t.metric) for t in link.tos],
            )
            for link in record.links
        ]
    if isinstance(record, OSPFNetworkLSA):
        return record.network_mask, list(record.attached_routers)
    if isinstance(record, OSPFSummaryLSA):
        entries = [(record.reserved, record.metric)]
        entries += [(t.tos, t.metric) for t in record.tos]
        return record.network_mask, entries
    return record.network_mask, [
        (
            int(r.e_bit),
            r.tos,
            r.metric,
            r.forwarding_address,
            r.external_route_tag,
        )
        for r in record.routes
    ]


def all_lsas() -> list[OSPFLSA]:
    """Every LSA in both OSPF captures' updates."""
    return [
        lsa
        for frame in FRAMES + AREA_FRAMES
        for lsa in decode_frame(frame)[OSPF].lsas or ()
    ]


class TestLSABodies:
    """The typed LSA body accessors, over both real captures."""

    @pytest.mark.parametrize(
        "frames,expected,scoped",
        [(FRAMES, OSPF_BODIES, False), (AREA_FRAMES, AREA_BODIES, True)],
        ids=["ospf.pcap", "ospf_areas.pcap"],
    )
    def test_every_captured_body(self, frames, expected, scoped):
        """Decode every LSA body to its expected record."""
        seen = set()
        for frame in frames:
            ospf = decode_frame(frame)[OSPF]
            for lsa in ospf.lsas or ():
                key = lsa_key(lsa)
                if scoped:
                    key = (lsa_scope(ospf.area_id, lsa), *key)
                record = getattr(lsa, ACCESSOR[lsa.header.ls_type])
                assert record == expected[key], key
                assert bytes(record) == lsa.body
                seen.add(key)
        assert seen == set(expected)

    def test_the_captures_hold_every_decoded_type(self):
        """Find LS types 1-5 and 7 among the captured LSAs."""
        assert {lsa.header.ls_type for lsa in all_lsas()} == set(ACCESSOR)

    def test_a_struct_decode_agrees(self):
        """Match every captured body to a ``struct`` hand-decode."""
        for lsa in all_lsas():
            record = getattr(lsa, ACCESSOR[lsa.header.ls_type])
            assert as_tuples(record) == hand_decode(lsa)

    def test_the_expected_bodies_are_frr_s_database(self):
        """Hold ``AREA_BODIES`` to ``ospf_areas_lsdb.txt``.

        Every recorded entry of a captured instance agrees with it,
        field by field, in FRR's own words.
        """
        link_types = {
            "a Transit Network": 2,
            "Stub Network": 3,
            "a Point-to-point Network": 1,
            "a Virtual Link": 4,
        }
        captured = {
            (lsa_scope(ospf_area(index), lsa), *lsa_key(lsa))
            for index, lsa in area_lsas()
        }
        checked = set()
        for entry in lsdb_entries():
            ls_type = {
                "router-LSA": 1,
                "network-LSA": 2,
                "summary-LSA": 3,
                "AS-external-LSA": 5,
                "NSSA-LSA": 7,
            }[entry["LS Type"]]
            lsid, comment = entry["Link State ID"].partition(" ")[::2]
            if "AS Boundary Router" in comment:
                ls_type = 4
            key = (
                entry["scope"],
                ls_type,
                lsid,
                entry["Advertising Router"],
                int(entry["LS Seq Number"], 16),
            )
            record = AREA_BODIES.get(key)
            if record is None:
                # Area 0.0.0.1's LSAs and the earlier ones in no capture.
                assert key[0] == "0.0.0.1" or key not in captured
                continue
            prefix = (
                int(entry["Network Mask"].lstrip("/"))
                if ("Network Mask" in entry)
                else None
            )
            if ls_type == 1:
                (link,) = record.links
                assert int(entry["Flags"].split()[0], 16) == record.flags
                assert int(entry["Number of Links"]) == record.link_count
                assert link_types[entry["Link connected to"]] == link.type
                ids = [v for k, v in entry.items() if k.startswith("(Link ID)")]
                data = [
                    v for k, v in entry.items() if k.startswith("(Link Data)")
                ]
                assert (ids, data) == ([link.link_id], [link.link_data])
                assert int(entry["Number of TOS metrics"]) == link.tos_count
                assert int(entry["TOS 0 Metric"]) == link.metric
            elif ls_type == 2:
                assert entry["Attached Router"].split(",") == list(
                    record.attached_routers
                )
            elif ls_type in (3, 4):
                assert entry["TOS"].split() == [
                    "0",
                    "Metric:",
                    str(record.metric),
                ]
            else:
                (route,) = record.routes
                # An NSSA-LSA's line reads "NSSA: Forward Address: ...".
                forwarding = entry.get("Forward Address") or entry[
                    "NSSA"
                ].removeprefix("Forward Address: ")
                assert entry["Metric Type"].split()[0] == (
                    "2" if route.e_bit else "1"
                )
                assert int(entry["TOS"]) == route.tos
                assert int(entry["Metric"]) == route.metric
                assert forwarding == route.forwarding_address
                assert int(entry["External Route Tag"]) == (
                    route.external_route_tag
                )
            if prefix is not None and ls_type != 4:
                mask = record.network_mask
                assert sum(bin(int(o)).count("1") for o in mask.split(".")) == (
                    prefix
                )
            checked.add(key)
        assert captured - checked == {
            ("0.0.0.2", 1, "10.0.0.2", "10.0.0.2", 0x80000005),
            ("0.0.0.2", 1, "10.0.0.4", "10.0.0.4", 0x80000004),
            ("0.0.0.2", 7, "192.0.2.4", "10.0.0.4", 0x80000001),
        }

    def test_router_flags_and_names(self):
        """Name the Router-LSA flags and link types."""
        abr = AREA_BODIES[("0.0.0.2", 1, "10.0.0.2", "10.0.0.2", 0x80000006)]
        assert (abr.v, abr.e, abr.b, abr.flags_str) == (
            False,
            True,
            True,
            "E B",
        )
        assert abr.links[0].type_name == "Transit"
        everything = OSPFRouterLSA(0xFF)
        assert everything.flags_str == "Nt W V E B"
        assert (everything.v, everything.e, everything.b) == (True,) * 3
        assert OSPFRouterLSA(0).flags_str == ""
        names = [
            OSPFRouterLink("0.0.0.0", "0.0.0.0", t, 1).type_name
            for t in range(6)
        ]
        assert names == [
            "unknown (0)",
            "Point-to-point",
            "Transit",
            "Stub",
            "Virtual link",
            "unknown (5)",
        ]

    def test_tos_entries_and_reserved_bytes_round_trip(self):
        """Decode TOS entries and carry reserved bytes verbatim."""
        router = OSPFRouterLSA(
            0x01,
            (
                OSPFRouterLink(
                    "10.0.0.9",
                    "10.9.84.1",
                    1,
                    5,
                    (OSPFRouterLinkTOS(2, 7), OSPFRouterLinkTOS(4, 9, 0xAA)),
                ),
                stub("192.0.2.0", "255.255.255.0"),
            ),
            reserved=0x55,
        )
        summary = OSPFSummaryLSA(
            MASK_26, 0xABCDEF, (OSPFSummaryTOS(8, 0x123456),), reserved=0x7F
        )
        routes = (
            OSPFExternalRoute(False, 0, 1, "0.0.0.0", 0xDEADBEEF),
            OSPFExternalRoute(True, 0x7F, 0xFFFFFF, "10.9.84.130", 1),
        )
        cases = [
            (1, router),
            (2, OSPFNetworkLSA("255.255.255.0")),
            (3, summary),
            (4, summary),
            (5, OSPFExternalLSA("0.0.0.0", routes)),
            (7, OSPFExternalLSA("0.0.0.0", routes)),
        ]
        for ls_type, record in cases:
            lsa = make_lsa(ls_type, bytes(record))
            assert getattr(lsa, ACCESSOR[ls_type]) == record
            assert as_tuples(record) == hand_decode(lsa)
        assert router.link_count == 2
        assert router.links[0].tos_count == 2
        assert bytes(router)[:4] == bytes.fromhex("01550002")
        assert bytes(summary)[4:12] == bytes.fromhex("7fabcdef08123456")
        assert bytes(routes[1])[:4] == b"\xff\xff\xff\xff"
        assert bytes(routes[0])[:4] == b"\x00\x00\x00\x01"

    @pytest.mark.parametrize("ls_type", [1, 2, 3, 4, 5, 7, 9, 10, 11, 6, 0])
    def test_each_accessor_answers_only_its_own_types(self, ls_type):
        """Answer None from every accessor but the LS type's own."""
        bodies = {
            1: bytes(OSPFRouterLSA(0)),
            2: bytes(OSPFNetworkLSA("0.0.0.0")),
            3: bytes(OSPFSummaryLSA("0.0.0.0", 0)),
            5: bytes(external()),
        }
        bodies[4], bodies[7] = bodies[3], bodies[5]
        lsa = make_lsa(ls_type, bodies.get(ls_type, b"\x01\x02\x03"))
        for name in ("router", "network", "summary", "external"):
            value = getattr(lsa, name)
            assert (value is not None) == (ACCESSOR.get(ls_type) == name)

    def test_other_types_stay_raw(self):
        """Keep an opaque or unknown LSA's body as it is, any length."""
        for ls_type in (6, 8, 9, 10, 11, 255):
            for body in (b"", b"\x01", bytes(13)):
                lsa = make_lsa(ls_type, body)
                assert lsa.body == body
                assert bytes(lsa) == bytes(lsa.header) + body


class TestLSABodyFraming:
    """A decoded LS type's body must have its framing, checked once."""

    @pytest.mark.parametrize(
        "ls_type,body,position,fragment",
        [
            (1, b"", 0, "too short for its 4 fixed bytes"),
            (1, bytes(3), 0, "too short"),
            (1, bytes.fromhex("00000001"), 4, "link 1 has 0 bytes"),
            (1, bytes.fromhex("00000002") + bytes(12), 16, "link 2 has 0"),
            (1, bytes.fromhex("00000001") + bytes(11), 4, "link 1 has 11"),
            (
                1,
                bytes.fromhex("00000001") + bytes(9) + b"\x01" + bytes(2),
                4,
                "1 TOS entries",
            ),
            (
                1,
                bytes.fromhex("00000001") + bytes(9) + b"\x02" + bytes(6),
                4,
                "2 TOS entries",
            ),
            (1, bytes.fromhex("00000000") + bytes(1), 4, "1 bytes after"),
            (1, bytes.fromhex("00000001") + bytes(16), 16, "4 bytes after"),
            (1, bytes.fromhex("0000ffff") + bytes(24), 28, "link 3 has 0"),
            (2, b"", 0, "4 plus whole 4-byte attached routers"),
            (2, bytes(6), 4, "Network-LSA body is 6 bytes"),
            (3, bytes(4), 0, "8 plus whole 4-byte TOS entries"),
            (3, bytes(10), 8, "Summary-LSA (IP network)"),
            (4, bytes(7), 0, "Summary-LSA (ASBR)"),
            (5, bytes(4), 0, "16 plus whole 12-byte TOS entries"),
            (5, bytes(20), 16, "AS-external-LSA"),
            (7, bytes(15), 0, "NSSA-LSA"),
            (7, bytes(27), 16, "NSSA-LSA body is 27 bytes"),
        ],
    )
    def test_a_body_without_its_framing(
        self, ls_type, body, position, fragment
    ):
        """Reject the body at construction, then in an update at decode."""
        header = lsa_header(ls_type=ls_type, length=20 + len(body))
        with pytest.raises(InvalidFieldError) as excinfo:
            OSPFLSA(header, body)
        error = excinfo.value
        assert (error.protocol, error.field, error.offset) == (
            OSPFLSA,
            "body",
            None,
        )
        assert fragment in str(error)
        update = (
            (2).to_bytes(4, "big") + bytes(lsa_header()) + bytes(header) + body
        )
        raw = struct.pack("!BBH", 2, 4, 24 + len(update)) + bytes(20) + update
        with pytest.raises(InvalidFieldError) as excinfo:
            OSPF.decode(raw)
        error = excinfo.value
        assert (error.protocol, error.field) == (OSPF, "body")
        # The packet header, the count, the first LSA, the second's header.
        assert error.offset == 24 + 4 + 20 + 20 + position
        assert fragment in str(error)

    def test_a_framing_error_rebases_onto_the_frame(self):
        """Point a strict walk's error at the frame's bad byte."""
        lsa = OSPFLSA(lsa_header(ls_type=2, length=24), bytes(4))
        raw = bytearray(
            bytes(make_ospf(4, (1).to_bytes(4, "big") + bytes(lsa)))
        )
        # Make the LSA a Router-LSA whose 4-byte body declares one link.
        raw[24 + 4 + 3] = 1
        raw[24 + 4 + 20 + 3] = 1
        ip = make_ipv4(protocol=IPProtocol.OSPF, payload_len=len(raw))
        frame = bytes(ethernet(0x0800)) + bytes(ip) + bytes(raw)
        packet = decode_frame(frame, lax=True)
        assert [type(layer) for layer in packet] == [Ethernet, IPv4]
        error = packet.stopped_by
        assert isinstance(error, InvalidFieldError)
        assert error.offset == 24 + 4 + 20 + 4
        assert error.frame_offset == 34 + error.offset

    def test_a_hostile_link_count_is_bounded(self):
        """Stop a 65535-link count at the end of the body."""
        body = bytes.fromhex("0000ffff") + bytes(12 * 3)
        with pytest.raises(InvalidFieldError) as excinfo:
            make_lsa(1, body)
        assert "link 4 has 0 bytes" in str(excinfo.value)

    def test_the_packet_constructor_checks_its_lsas(self):
        """Refuse an update body whose LSA is badly framed."""
        header = bytes(lsa_header(ls_type=5, length=24))
        with pytest.raises(InvalidFieldError) as excinfo:
            make_ospf(4, (1).to_bytes(4, "big") + header + bytes(4))
        assert (excinfo.value.protocol, excinfo.value.offset) == (OSPF, None)

    def test_replace_revalidates_the_body(self):
        """Check the framing again on replace()."""
        lsa = make_lsa(9, bytes(4))
        with pytest.raises(InvalidFieldError):
            replace(lsa, header=replace(lsa.header, ls_type=5))
        assert replace(lsa, header=replace(lsa.header, ls_type=2)).network == (
            OSPFNetworkLSA("0.0.0.0")
        )
