"""Test TLS record decoding (RFC 9846 §5.1), the ClientHello and its SNI.

Covered: the 5-byte record header, both round trips, truncation at
every length, the decode-time guard against a wrong port guess (each
rejection and its ``field``), records chaining within a segment and
``max_depth``, the ClientHello parsed on demand with every lying length
inside it, the server_name extension (RFC 6066 §3), the display
helpers, construction, dispatch from TCP port 443, and
scripts/check_fixtures.py's TLS checks.

Real bytes come from two captures of the same nginx server
(tests/fixtures/MANIFEST.md): ``tls.pcap``, the corpus frames, each a
whole number of records, and ``tls/tls_session.pcap``, every frame of
the six connections, Chromium's ClientHellos split across two segments
and the bare ACKs included. The session is reassembled with
scripts/extract_http_streams.py's ``extract()``, which takes any port
and shares no code with the library. The unit tests build their records
here, byte by byte; the edge cases the captures do not hold (a
ClientHello without its server_name, one whose extensions block is cut)
are derived from captured bytes in the tests that need them.
"""

import importlib.util
import struct
import sys
from collections import Counter
from pathlib import Path
from types import ModuleType

import pytest

from conftest import FIXTURES, pcap_frames
from netprotocols import (
    HTTP,
    MAX_DEPTH,
    TCP,
    TLS,
    UDP,
    Ethernet,
    InvalidFieldError,
    IPv4,
    IPv6,
    MaxDepthExceededError,
    Packet,
    ProtocolError,
    TLSClientHello,
    TLSExtension,
    TruncatedHeaderError,
    decode_frame,
)
from netprotocols.registry import DEFAULT, TABLE_TCP_PORT, TABLE_UDP_PORT

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"

CORPUS = pcap_frames(FIXTURES / "tls.pcap")
SESSION = pcap_frames(FIXTURES / "tls" / "tls_session.pcap")

#: Ethernet, IPv4 and a TCP header with the timestamps option: where the
#: TLS payload starts in every captured frame.
PAYLOAD_AT = 14 + 20 + 32

#: The server's host name, the SNI every captured client but one sends.
HOST = "tls.np196.test"

CCS, ALERT, HANDSHAKE, APPDATA = 20, 21, 22, 23

#: The server's TLS 1.3 flight: ServerHello, the compatibility
#: ChangeCipherSpec and four encrypted records (EncryptedExtensions,
#: Certificate, CertificateVerify, Finished under application_data).
FLIGHT13 = [HANDSHAKE, CCS, APPDATA, APPDATA, APPDATA, APPDATA]

#: tls.pcap frame by frame (the capture script's selection): who sent
#: it, and the content types of its records.
CAPTURE = [
    ("chromium server", FLIGHT13),
    ("chromium client", [CCS, APPDATA]),
    ("curl client", [HANDSHAKE]),
    ("curl server", FLIGHT13),
    ("gnutls client", [HANDSHAKE]),
    ("gnutls server", FLIGHT13),
    ("nosni client", [HANDSHAKE]),
    ("nosni server", FLIGHT13),
    ("tls12 client", [HANDSHAKE]),
    ("tls12 server", [HANDSHAKE] * 4),
    ("tls12 client", [HANDSHAKE, CCS, HANDSHAKE]),
    ("tls12 server", [CCS, HANDSHAKE]),
    ("tls12 client", [APPDATA]),
    ("tls12 server", [APPDATA]),
    ("tls12 client", [ALERT]),
]

#: tls.pcap's ClientHello frames, and the SNI each carries.
HELLOS = {2: HOST, 4: HOST, 6: None, 8: HOST}

#: tls_session.pcap: Chromium's first connection's ClientHello, split
#: 1448 + 290 bytes, and a bare ACK (the handshake's third segment).
SPLIT_HEAD, SPLIT_TAIL, BARE_ACK = 3, 4, 2

# X25519MLKEM768 (IANA's TLS Supported Groups registry, 4588) and
# X25519 (29).
X25519MLKEM768, X25519 = 0x11EC, 0x001D


def record(
    content_type: int, fragment: bytes = b"", version: int = 0x0303
) -> bytes:
    """A record's bytes: the 5-byte header, then ``fragment``."""
    return struct.pack("!BHH", content_type, version, len(fragment)) + fragment


def handshake(kind: int, body: bytes) -> bytes:
    """A handshake message: its type, 3-byte length and body."""
    return bytes([kind]) + len(body).to_bytes(3, "big") + body


def vector(data: bytes, width: int) -> bytes:
    """``data`` prefixed with its length in ``width`` bytes."""
    return len(data).to_bytes(width, "big") + data


def extension(kind: int, data: bytes) -> bytes:
    """One extension: type, 2-byte length, data."""
    return struct.pack("!HH", kind, len(data)) + data


def sni(*entries: tuple[int, bytes]) -> bytes:
    """A server_name extension holding ``(name_type, name)`` entries."""
    names = b"".join(bytes([kind]) + vector(name, 2) for kind, name in entries)
    return extension(0, vector(names, 2))


def hello_body(
    *,
    session_id: bytes = b"",
    suites: bytes = b"\x13\x01\x13\x02",
    methods: bytes = b"\x00",
    extensions: bytes | None = b"",
) -> bytes:
    """A ClientHello body, version 0x0303 and a Random of bytes 0-31;
    ``extensions`` is the block's contents, or ``None`` for no block."""
    body = (
        b"\x03\x03"
        + bytes(range(32))
        + vector(session_id, 1)
        + vector(suites, 2)
        + vector(methods, 1)
    )
    return body if extensions is None else body + vector(extensions, 2)


def hello_record(body: bytes) -> bytes:
    """A Handshake record (version 0x0301) holding one ClientHello."""
    return record(HANDSHAKE, handshake(1, body), version=0x0301)


def frame(
    payload: bytes,
    *,
    sport: int = 50000,
    dport: int = 443,
    ipv6: bool = False,
) -> bytes:
    """``Ethernet -> IPv4 or IPv6 -> TCP`` carrying ``payload``."""
    if ipv6:
        ip: IPv4 | IPv6 = IPv6(
            version=6,
            traffic_class=0,
            flow_label=0,
            payload_length=20 + len(payload),
            next_header=6,
            hop_limit=64,
            src="2001:db8::1",
            dst="2001:db8::2",
        )
    else:
        ip = IPv4(
            version=4,
            ihl=5,
            dscp=0,
            ecn=0,
            total_length=40 + len(payload),
            identification=0,
            flags=2,
            fragment_offset=0,
            ttl=64,
            protocol=6,
            checksum=0,
            src="192.0.2.1",
            dst="192.0.2.2",
        )
    tcp = TCP(
        src_port=sport,
        dst_port=dport,
        seq=1,
        ack=1,
        data_offset=5,
        reserved=0,
        flags=0x18,
        window=0xFFFF,
        checksum=0,
        urgent_pointer=0,
    )
    ethernet = Ethernet(
        dst="02:00:0a:09:c4:02",
        src="02:00:0a:09:c4:01",
        ethertype=0x86DD if ipv6 else 0x0800,
    )
    return bytes(Packet(ethernet, ip, tcp)) + payload


def tls_layers(packet: Packet) -> list[TLS]:
    return [layer for layer in packet if isinstance(layer, TLS)]


def records_of(stream: bytes) -> list[TLS]:
    """Decode ``stream`` as back-to-back records, to its end."""
    found, cursor = [], 0
    while cursor < len(stream):
        found.append(TLS.decode(stream[cursor:]))
        cursor += found[-1].header_len
    return found


def _load_script(name: str) -> ModuleType:
    """Load scripts/<name>.py, which shares no code with the library."""
    sys.path.insert(0, str(SCRIPTS))
    try:
        spec = importlib.util.spec_from_file_location(
            name, SCRIPTS / f"{name}.py"
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        # @dataclass looks its class's module up in sys.modules.
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.remove(str(SCRIPTS))


@pytest.fixture(scope="module")
def streams() -> list[tuple[bytes, bytes]]:
    """Each session connection's (client, server) byte streams, in the
    order the connections opened."""
    extractor = _load_script("extract_http_streams")
    return extractor.extract(SESSION, 443)


@pytest.fixture(scope="module")
def check_fixtures() -> ModuleType:
    return _load_script("check_fixtures")


# --- The captures ------------------------------------------------------


class TestCapture:
    """tests/fixtures/tls.pcap: fifteen segments of whole records."""

    def test_every_frame_walks_to_its_records(self):
        """Each frame walks Ethernet, IPv4, TCP and then one TLS layer
        per record, consuming the whole frame."""
        assert len(CORPUS) == len(CAPTURE) == 15
        for raw, (_, kinds) in zip(CORPUS, CAPTURE, strict=True):
            packet = decode_frame(raw)
            assert [type(layer) for layer in packet][:3] == [
                Ethernet,
                IPv4,
                TCP,
            ]
            assert [r.content_type for r in tls_layers(packet)] == kinds
            assert packet.consumed == len(raw)
            assert packet.stopped_by is None

    def test_both_round_trips(self):
        """Every captured record re-encodes to its bytes and decodes
        back to itself."""
        for raw in CORPUS:
            cursor = PAYLOAD_AT
            for layer in tls_layers(decode_frame(raw)):
                wire = raw[cursor : cursor + layer.header_len]
                assert bytes(layer) == wire
                assert TLS.decode(wire) == layer
                cursor += layer.header_len

    def test_direction_and_ports(self):
        """Clients send to 443 and the server answers from it."""
        for raw, (who, _) in zip(CORPUS, CAPTURE, strict=True):
            tcp = decode_frame(raw)[TCP]
            assert isinstance(tcp, TCP)
            if who.endswith("client"):
                assert tcp.dst_port == 443
            else:
                assert tcp.src_port == 443

    def test_record_versions(self):
        """ClientHellos say TLS 1.0, but gnutls-cli's TLS 1.2; every
        other record says TLS 1.2, as RFC 9846 §5.1 has TLS 1.3 do."""
        for index, raw in enumerate(CORPUS):
            for layer in tls_layers(decode_frame(raw)):
                if layer.handshake_type == 1 and index != 4:
                    assert layer.legacy_version_name == "TLS 1.0"
                else:
                    assert layer.legacy_version == 0x0303

    def test_a_flight_of_six_records_chains(self):
        """The server's TLS 1.3 flight is one segment of six records,
        each but the last naming the next."""
        layers = tls_layers(decode_frame(CORPUS[3]))
        assert [r.next_protocol() for r in layers] == [TLS] * 5 + [None]
        assert layers[0].handshake_type_name == "server_hello"
        assert layers[1].fragment == b"\x01"
        assert [r.handshake_type for r in layers[1:]] == [None] * 5

    def test_the_tls12_handshake_in_the_clear(self):
        """TLS 1.2 shows its server flight's types, the client's key
        exchange, ChangeCipherSpec each way and an Alert, and its
        encrypted Finished records start with ciphertext."""
        server = tls_layers(decode_frame(CORPUS[9]))
        assert [r.handshake_type_name for r in server] == [
            "server_hello",
            "certificate",
            "server_key_exchange",
            "server_hello_done",
        ]
        assert server[3].length == 4  # ServerHelloDone: a bare header
        client = tls_layers(decode_frame(CORPUS[10]))
        assert client[0].handshake_type_name == "client_key_exchange"
        assert client[1].content_type_name == "change_cipher_spec"
        assert client[2].length == 40  # encrypted Finished
        alert = tls_layers(decode_frame(CORPUS[14]))[0]
        assert alert.content_type_name == "alert"
        assert alert.handshake_type is None

    @pytest.mark.parametrize("index", sorted(HELLOS))
    def test_client_hellos_and_their_sni(self, index):
        """curl, gnutls-cli and the TLS 1.2 curl send the server's name;
        ``openssl s_client -noservername`` sends no server_name."""
        hello_layer = tls_layers(decode_frame(CORPUS[index]))[0]
        assert hello_layer.handshake_type_name == "client_hello"
        assert hello_layer.server_name == HELLOS[index]
        hello = hello_layer.client_hello
        assert isinstance(hello, TLSClientHello)
        assert hello.legacy_version_name == "TLS 1.2"
        assert hello.legacy_compression_methods == b"\x00"
        assert hello.extensions
        names = [ext.type_name for ext in hello.extensions]
        assert ("server_name" in names) == (HELLOS[index] is not None)
        # The parsed ClientHello re-encodes to the message's body.
        fragment = hello_layer.fragment
        assert bytes(hello) == fragment[4:]

    def test_tls12_hello_offers_no_tls13(self):
        """Capped at TLS 1.2, curl's ClientHello has no session ID, no
        supported_versions and no TLS 1.3 suite."""
        hello = tls_layers(decode_frame(CORPUS[8]))[0].client_hello
        assert hello is not None and hello.extensions is not None
        assert hello.legacy_session_id == b""
        assert 43 not in [ext.type for ext in hello.extensions]
        suites = {
            hello.cipher_suites[i : i + 2]
            for i in range(0, len(hello.cipher_suites), 2)
        }
        assert not suites & {b"\x13\x01", b"\x13\x02", b"\x13\x03"}

    def test_curl_pads_its_hello_to_512_bytes(self):
        """OpenSSL's padding extension (21, RFC 7685) makes 512."""
        hello_layer = tls_layers(decode_frame(CORPUS[2]))[0]
        assert hello_layer.length == 512
        hello = hello_layer.client_hello
        assert hello is not None and hello.extensions is not None
        assert hello.extensions[-1].type_name == "padding"

    def test_check_fixtures_passes_and_counts_it(self, check_fixtures):
        """The independent checker passes every frame and counts every
        record by type, and no segment is left unchecked."""
        stats = check_fixtures.Counter()
        for raw in CORPUS:
            assert check_fixtures.check_frame(raw, stats) == []
        assert stats["tls"] == sum(len(kinds) for _, kinds in CAPTURE)
        assert stats["tls-client-hello"] == 4
        assert stats["tls-server-name"] == 3
        assert stats["tls-change-cipher-spec"] == 7
        assert stats["tls-alert"] == 1
        assert stats["tls-unchecked"] == 0


class TestSession:
    """tests/fixtures/tls/tls_session.pcap, segment by segment and
    reassembled with scripts/extract_http_streams.py."""

    def test_six_connections_of_whole_records(self, streams):
        """Each side of each connection reassembles into whole records,
        the first a ClientHello one way and a ServerHello the other."""
        assert len(streams) == 6
        for client, server in streams:
            sent, answered = records_of(client), records_of(server)
            assert sent[0].handshake_type_name == "client_hello"
            assert answered[0].handshake_type_name == "server_hello"

    def test_sni_from_every_client(self, streams):
        """Chromium (both connections), curl, gnutls-cli, s_client
        without SNI and curl capped at TLS 1.2, in that order."""
        names = [TLS.decode(client).server_name for client, _ in streams]
        assert names == [HOST, HOST, HOST, HOST, None, HOST]

    def test_chromium_hellos(self, streams):
        """BoringSSL's ClientHello: GREASE first among the cipher suites
        and the extensions, an X25519MLKEM768 key share beside X25519's,
        and a 1738-byte record, larger than one 1448-byte segment."""
        for client, _ in streams[:2]:
            hello_layer = TLS.decode(client)
            assert hello_layer.header_len == 1738
            hello = hello_layer.client_hello
            assert hello is not None and hello.extensions is not None
            assert (
                TLSExtension(int.from_bytes(hello.cipher_suites[:2])).type_name
                == "GREASE"
            )
            assert hello.extensions[0].type_name == "GREASE"
            assert hello.extensions[-1].type_name == "GREASE"
            shares = next(e.data for e in hello.extensions if e.type == 51)
            groups, cursor = [], 2
            while cursor < len(shares):
                group, size = struct.unpack_from("!HH", shares, cursor)
                groups.append(group)
                cursor += 4 + size
            assert X25519MLKEM768 in groups and X25519 in groups
            pq = shares.index(X25519MLKEM768.to_bytes(2, "big"))
            assert int.from_bytes(shares[pq + 2 : pq + 4]) == 1216

    def test_chromium_permutes_its_extensions(self, streams):
        """The two connections' ClientHellos carry the same extensions,
        GREASE aside, in different orders."""
        orders = []
        for client, _ in streams[:2]:
            hello = TLS.decode(client).client_hello
            assert hello is not None and hello.extensions is not None
            orders.append(
                [e.type for e in hello.extensions if e.type_name != "GREASE"]
            )
        assert sorted(orders[0]) == sorted(orders[1])
        assert orders[0] != orders[1]

    def test_a_split_hello_raises_in_a_strict_walk(self):
        """The first segment holds the record header and 1443 bytes of a
        1733-byte fragment: TruncatedHeaderError at the record."""
        raw = SESSION[SPLIT_HEAD]
        assert len(raw) == PAYLOAD_AT + 1448
        with pytest.raises(TruncatedHeaderError) as caught:
            decode_frame(raw)
        error = caught.value
        assert error.protocol is TLS
        assert error.field == "length"
        assert error.frame_offset == PAYLOAD_AT + 3
        assert (error.expected, error.actual) == (1738, 1448)

    def test_a_split_hello_stops_a_lax_walk_at_tcp(self):
        """Lax keeps Ethernet, IPv4 and TCP and reports the error."""
        packet = decode_frame(SESSION[SPLIT_HEAD], lax=True)
        assert [type(layer) for layer in packet] == [Ethernet, IPv4, TCP]
        assert isinstance(packet.stopped_by, TruncatedHeaderError)
        assert packet.consumed == PAYLOAD_AT

    def test_the_hellos_tail_fails_the_guard(self):
        """The second segment begins inside the record: its first byte
        is no ContentType."""
        raw = SESSION[SPLIT_TAIL]
        assert len(raw) == PAYLOAD_AT + 290
        with pytest.raises(InvalidFieldError) as caught:
            decode_frame(raw)
        assert caught.value.field == "content_type"
        assert caught.value.frame_offset == PAYLOAD_AT
        packet = decode_frame(raw, lax=True)
        assert [type(layer) for layer in packet] == [Ethernet, IPv4, TCP]

    def test_reassembled_the_split_hello_decodes(self):
        """The two segments together are the record, whose SNI reads."""
        payload = (
            SESSION[SPLIT_HEAD][PAYLOAD_AT:] + SESSION[SPLIT_TAIL][PAYLOAD_AT:]
        )
        hello = TLS.decode(payload)
        assert hello.header_len == len(payload)
        assert hello.server_name == HOST

    def test_a_bare_ack_raises_in_a_strict_walk(self):
        """A segment with no payload hands TLS an empty buffer."""
        raw = SESSION[BARE_ACK]
        assert len(raw) == PAYLOAD_AT
        with pytest.raises(TruncatedHeaderError) as caught:
            decode_frame(raw)
        assert caught.value.protocol is TLS
        assert caught.value.actual == 0
        packet = decode_frame(raw, lax=True)
        assert [type(layer) for layer in packet] == [Ethernet, IPv4, TCP]

    def test_the_corpus_frames_are_session_frames(self):
        """tls.pcap is a selection of the session's frames."""
        assert set(CORPUS) <= set(SESSION)

    def test_check_fixtures_leaves_the_split_hellos_unchecked(
        self, check_fixtures
    ):
        """The checker passes the session and counts the four segments
        of Chromium's two split ClientHellos as unchecked."""
        stats = check_fixtures.Counter()
        for raw in SESSION:
            assert check_fixtures.check_frame(raw, stats) == []
        assert stats["tls-unchecked"] == 4
        assert stats["tls-client-hello"] == 4


class TestHTTPSCapture:
    """tests/fixtures/tcp_https.pcap: captured before TLS was decoded."""

    FRAMES = pcap_frames(FIXTURES / "tcp_https.pcap")

    def test_ipv4_frames_are_one_application_data_record_each(self):
        """The 7 IPv4 frames are each exactly one whole record."""
        for raw in self.FRAMES[:5] + self.FRAMES[10:]:
            packet = decode_frame(raw)
            [layer] = tls_layers(packet)
            assert layer.content_type_name == "application_data"
            assert layer.legacy_version_name == "TLS 1.2"
            assert layer.next_protocol() is None
            assert packet.consumed == len(raw)

    def test_ipv6_bare_acks_raise_like_bgps(self):
        """The 5 IPv6 frames carry no payload: a strict walk raises at
        the empty buffer, a lax one keeps TCP."""
        for raw in self.FRAMES[5:10]:
            with pytest.raises(TruncatedHeaderError):
                decode_frame(raw)
            packet = decode_frame(raw, lax=True)
            assert [type(layer) for layer in packet] == [Ethernet, IPv6, TCP]
            assert packet.consumed == len(raw)


# --- The record ---------------------------------------------------------


class TestRecord:
    def test_decode_fields(self):
        raw = record(APPDATA, b"\xaa" * 7)
        tls = TLS.decode(raw)
        assert (tls.content_type, tls.legacy_version, tls.length) == (
            23,
            0x0303,
            7,
        )
        assert tls.fragment == b"\xaa" * 7
        assert tls.header_len == 12
        assert bytes(tls) == raw
        assert tls == TLS(23, 0x0303, 7, b"\xaa" * 7)

    def test_both_round_trips(self, raw_tls_client_hello):
        tls = TLS.decode(raw_tls_client_hello)
        assert bytes(tls) == raw_tls_client_hello
        assert TLS.decode(bytes(tls)) == tls

    def test_a_zero_length_record(self):
        """A bare header: the decoder accepts it for every type, though
        no real record is one. RFC 9846 §5.1's zero-length Application
        Data is a TLSInnerPlaintext's content, which §5.2 protects with
        the inner content type and an AEAD tag."""
        tls = TLS.decode(record(APPDATA))
        assert tls.fragment == b"" and tls.header_len == 5
        assert TLS.decode(record(HANDSHAKE)).handshake_type is None

    def test_the_largest_record(self):
        """2**14 + 2048 is the loosest bound any version sets."""
        tls = TLS.decode(record(APPDATA, bytes(TLS.MAX_LENGTH)))
        assert tls.length == TLS.MAX_LENGTH == 18432

    @pytest.mark.parametrize("version", range(0x0300, 0x0305))
    def test_every_version(self, version):
        """SSL 3.0 to TLS 1.3 in form."""
        tls = TLS.decode(record(ALERT, b"\x02\x28", version))
        assert tls.legacy_version == version

    @pytest.mark.parametrize("kind", range(20, 25))
    def test_every_content_type(self, kind):
        assert TLS.decode(record(kind, b"\x01")).content_type == kind

    def test_class_constants(self):
        assert (
            TLS.CHANGE_CIPHER_SPEC,
            TLS.ALERT,
            TLS.HANDSHAKE,
            TLS.APPLICATION_DATA,
            TLS.HEARTBEAT,
        ) == (20, 21, 22, 23, 24)

    def test_decodes_from_a_memoryview_without_aliasing_it(self):
        buffer = bytearray(record(APPDATA, b"abc"))
        tls = TLS.decode(memoryview(buffer))
        buffer[5:8] = b"xyz"
        assert tls.fragment == b"abc"
        assert isinstance(tls.fragment, bytes)


class TestConstruction:
    def test_length_must_match_the_fragment(self):
        with pytest.raises(InvalidFieldError) as caught:
            TLS(23, 0x0303, 3, b"ab")
        assert caught.value.field == "length"

    @pytest.mark.parametrize("value", [-1, 0x10000])
    def test_length_must_fit_two_bytes(self, value):
        """Reported as out of range, even where the fragment matches."""
        fragment = bytes(max(value, 0))
        with pytest.raises(InvalidFieldError) as caught:
            TLS(23, 0x0303, value, fragment)
        error = caught.value
        assert error.field == "length"
        assert (error.expected, error.actual) == ("0-65535", value)
        assert str(error) == f"TLS length must be within 0-65535, got {value}"

    def test_a_fragment_too_long_for_its_length(self):
        with pytest.raises(InvalidFieldError) as caught:
            TLS(23, 0x0303, 3, bytes(0x10000))
        assert (caught.value.expected, caught.value.actual) == (0x10000, 3)

    @pytest.mark.parametrize("value", [-1, 256])
    def test_content_type_must_fit_a_byte(self, value):
        with pytest.raises(InvalidFieldError) as caught:
            TLS(value, 0x0303, 0, b"")
        assert caught.value.field == "content_type"

    @pytest.mark.parametrize("value", [-1, 0x10000])
    def test_version_must_fit_two_bytes(self, value):
        with pytest.raises(InvalidFieldError) as caught:
            TLS(23, value, 0, b"")
        assert caught.value.field == "legacy_version"

    def test_accepts_what_decode_rejects(self):
        """A test of another stack can build an invalid record."""
        tls = TLS(0x80, 0x0200, 1, b"\x01")
        assert bytes(tls) == b"\x80\x02\x00\x00\x01\x01"
        with pytest.raises(InvalidFieldError):
            TLS.decode(bytes(tls))

    def test_a_built_record_does_not_chain(self):
        assert TLS(23, 0x0303, 0, b"").next_protocol() is None


class TestDecodeGuard:
    """The checks against a wrong port guess, in their order."""

    @pytest.mark.parametrize("first", [0, 19, 25, 0x80, 255])
    def test_content_type(self, first):
        """Judged as soon as one byte is present."""
        for raw in (bytes([first]), bytes([first]) + b"\x03\x03\x00\x00"):
            with pytest.raises(InvalidFieldError) as caught:
                TLS.decode(raw)
            error = caught.value
            assert (error.field, error.offset) == ("content_type", 0)
            assert error.protocol is TLS
            assert (error.expected, error.actual) == ("20-24", first)

    @pytest.mark.parametrize("major", [0, 2, 4, 0x80])
    def test_version_major(self, major):
        for raw in (bytes([22, major]), bytes([22, major, 3, 0, 0])):
            with pytest.raises(InvalidFieldError) as caught:
                TLS.decode(raw)
            error = caught.value
            assert (error.field, error.offset) == ("legacy_version", 1)
            assert (error.expected, error.actual) == ("0x03", major)

    @pytest.mark.parametrize("minor", [5, 0xFE, 0xFF])
    def test_version_minor(self, minor):
        """DTLS's 0xFEFD, for one, is turned away here."""
        for raw in (bytes([22, 3, minor]), bytes([22, 3, minor, 0, 0])):
            with pytest.raises(InvalidFieldError) as caught:
                TLS.decode(raw)
            error = caught.value
            assert (error.field, error.offset) == ("legacy_version", 2)
            assert error.expected == "0x0300-0x0304"
            assert error.actual == 0x0300 + minor

    def test_length_bound(self):
        """A length of 2**14 + 2049 is rejected before the buffer is
        looked at."""
        raw = struct.pack("!BHH", 23, 0x0303, TLS.MAX_LENGTH + 1)
        with pytest.raises(InvalidFieldError) as caught:
            TLS.decode(raw)
        error = caught.value
        assert (error.field, error.offset) == ("length", 3)
        assert (error.expected, error.actual) == ("<=18432", 18433)

    @pytest.mark.parametrize("high", [0x49, 0xFF])
    def test_a_length_judged_only_whole(self, high):
        """The length is judged once both its bytes are present: with
        one, a length over the bound whatever the other byte is still
        reads as a short header."""
        with pytest.raises(TruncatedHeaderError) as caught:
            TLS.decode(bytes([23, 3, 3, high]))
        assert caught.value.actual == 4
        with pytest.raises(InvalidFieldError) as caught:
            TLS.decode(bytes([23, 3, 3, high, 0]))
        assert caught.value.field == "length"

    def test_order(self):
        """Every check fails here; the ContentType is reported."""
        with pytest.raises(InvalidFieldError) as caught:
            TLS.decode(b"\x00\x00\xff\xff\xff")
        assert caught.value.field == "content_type"
        with pytest.raises(InvalidFieldError) as caught:
            TLS.decode(b"\x16\x00\xff\xff\xff")
        assert caught.value.offset == 1

    def test_an_sslv2_compatible_hello(self):
        """RFC 5246 Appendix E.2: a 2-byte length with the top bit set,
        then message type 1, then version 3.1."""
        raw = b"\x80\x2e\x01\x03\x01" + bytes(0x2E - 3)
        with pytest.raises(InvalidFieldError) as caught:
            TLS.decode(raw)
        assert caught.value.field == "content_type"

    def test_empty(self):
        with pytest.raises(TruncatedHeaderError) as caught:
            TLS.decode(b"")
        assert caught.value.actual == 0

    def test_truncated_at_every_length(self, raw_tls_client_hello):
        """Every proper prefix of a valid record passes the guard and is
        too short."""
        for cut in range(len(raw_tls_client_hello)):
            with pytest.raises(TruncatedHeaderError) as caught:
                TLS.decode(raw_tls_client_hello[:cut])
            if cut >= 5:
                assert caught.value.field == "length"
                assert caught.value.offset == 3
                assert caught.value.expected == len(raw_tls_client_hello)
                assert caught.value.actual == cut

    def test_a_lying_record_length(self):
        """The header says 100 bytes; 10 follow."""
        raw = struct.pack("!BHH", 23, 0x0303, 100) + bytes(10)
        with pytest.raises(TruncatedHeaderError) as caught:
            TLS.decode(raw)
        assert (caught.value.expected, caught.value.actual) == (105, 15)


class TestChaining:
    """Records back to back in one segment, and what is not a record."""

    def test_two_records_are_two_layers(self):
        payload = record(CCS, b"\x01") + record(APPDATA, b"x" * 30)
        packet = decode_frame(frame(payload))
        first, second = tls_layers(packet)
        assert first.next_protocol() is TLS
        assert second.next_protocol() is None
        assert packet.consumed == len(frame(payload))

    @pytest.mark.parametrize(
        "rest",
        [b"\x17", b"\x17\x03", b"\x17\x03\x03", b"\x14\x03\x00\x00\x01"],
    )
    def test_the_start_of_a_record_chains(self, rest):
        """As much of a header as is present, passing the guard, chains,
        and the walk then raises at the cut record."""
        raw = frame(record(APPDATA, b"a") + rest)
        assert TLS.decode(record(APPDATA, b"a") + rest).next_protocol() is TLS
        with pytest.raises(TruncatedHeaderError) as caught:
            decode_frame(raw)
        assert caught.value.frame_offset in (54 + 6, 54 + 6 + 3)
        packet = decode_frame(raw, lax=True)
        assert len(tls_layers(packet)) == 1
        assert isinstance(packet.stopped_by, TruncatedHeaderError)
        assert packet.consumed == 54 + 6

    @pytest.mark.parametrize(
        "rest",
        [
            b"",
            b"\x00",
            bytes(6),
            b"\xde\xad\xbe\xef",
            b"\x17\x02",
            b"\x17\x03\x05",
            b"\x19\x03\x03",
            b"GET / HTTP/1.1\r\n",
        ],
    )
    def test_anything_else_ends_the_walk(self, rest):
        """Padding, an FCS, a bad header or text: left undecoded."""
        raw = frame(record(APPDATA, b"a") + rest)
        packet = decode_frame(raw)
        assert len(tls_layers(packet)) == 1
        assert tls_layers(packet)[0].next_protocol() is None
        assert packet.consumed == 54 + 6
        assert packet.stopped_by is None

    def test_a_padded_bare_ack_fails_the_guard(self):
        """Over IPv4 a bare segment with no TCP options is a 54-byte
        frame. Padded to Ethernet's 60-byte minimum, the 6 zero bytes
        reach TLS, since the walk does not end its buffer at IPv4's
        Total Length (#235): a ContentType of 0. Unpadded, the buffer is
        empty. On BGP's port the padding is still too short to judge."""
        bare = frame(b"")
        assert len(bare) == 54
        padded = bare + bytes(6)
        with pytest.raises(InvalidFieldError) as caught:
            decode_frame(padded)
        error = caught.value
        assert (error.protocol, error.field) == (TLS, "content_type")
        assert (error.frame_offset, error.actual) == (54, 0)
        packet = decode_frame(padded, lax=True)
        assert [type(layer) for layer in packet] == [Ethernet, IPv4, TCP]
        with pytest.raises(TruncatedHeaderError) as caught:
            decode_frame(bare)
        assert (caught.value.protocol, caught.value.actual) == (TLS, 0)
        with pytest.raises(TruncatedHeaderError) as caught:
            decode_frame(frame(b"", dport=179) + bytes(6))
        assert caught.value.actual == 6

    def test_equal_records_compare_equal_wherever_found(self):
        """The chaining answer is decode context, not a field."""
        alone = TLS.decode(record(APPDATA, b"a"))
        followed = TLS.decode(record(APPDATA, b"a") + record(APPDATA))
        assert alone == followed and hash(alone) == hash(followed)
        assert alone.next_protocol() is None
        assert followed.next_protocol() is TLS


class TestMaxDepth:
    """A segment of many records against ``max_depth``."""

    #: Bare 5-byte headers: the decoder's worst case, not real records.
    SEGMENT = record(APPDATA) * 40

    #: The smallest TLS 1.3 record with a 16-byte AEAD tag: zero-length
    #: Application Data, protected (RFC 9846 §5.2), 1 inner content type
    #: byte and the tag, 17 bytes of ciphertext behind the header.
    PROTECTED = record(APPDATA, bytes(1 + 16))

    def test_the_smallest_protected_record(self):
        assert len(self.PROTECTED) == 22
        assert TLS.decode(self.PROTECTED).length == 17

    def test_real_records_exceed_the_default_depth(self):
        """29 of them pass; the 30th, 660 bytes in, exceeds the default,
        and a 1,448-byte segment holds 65."""
        assert 1448 // len(self.PROTECTED) == 65
        packet = decode_frame(frame(self.PROTECTED * 29))
        assert len(tls_layers(packet)) == 29
        with pytest.raises(MaxDepthExceededError) as caught:
            decode_frame(frame(self.PROTECTED * 30))
        assert caught.value.frame_offset == 54 + 29 * 22
        packet = decode_frame(frame(self.PROTECTED * 65), max_depth=68)
        assert len(tls_layers(packet)) == 65

    def test_the_default_depth_stops_the_walk(self):
        """29 records after Ethernet, IPv4 and TCP."""
        raw = frame(self.SEGMENT)
        with pytest.raises(MaxDepthExceededError) as caught:
            decode_frame(raw)
        assert caught.value.protocol is TLS
        assert caught.value.frame_offset == 54 + 29 * 5
        packet = decode_frame(raw, lax=True)
        assert len(packet) == MAX_DEPTH
        assert len(tls_layers(packet)) == MAX_DEPTH - 3
        assert isinstance(packet.stopped_by, MaxDepthExceededError)

    def test_a_raised_depth_reaches_every_record(self):
        assert len(decode_frame(frame(self.SEGMENT), max_depth=43)) == 43

    def test_walking_on_from_where_the_walk_stopped(self):
        raw = frame(self.SEGMENT)
        packet = decode_frame(raw, lax=True)
        rest = decode_frame(raw[packet.consumed :], start=TLS)
        assert len(tls_layers(packet)) + len(tls_layers(rest)) == 40

    def test_walking_on_through_a_full_segment_of_ccm_8_records(self):
        """The bgp module's loop takes four walks over 103 records.

        TLS_AES_128_CCM_8_SHA256's smallest record is 14 bytes (header,
        inner content type, 8-byte tag), and 1,448 bytes hold 103. The
        first walk holds 29 after Ethernet, IPv4 and TCP, each walk that
        starts at TLS holds MAX_DEPTH (32), and the fourth takes 10.
        """
        smallest = record(APPDATA, bytes(1 + 8))
        assert len(smallest) == 14
        assert 1448 // len(smallest) == 103
        raw = frame(smallest * 103)
        packet = decode_frame(raw, lax=True)
        records = tls_layers(packet)
        per_walk = [len(records)]
        rest = raw[packet.consumed :]
        while (
            isinstance(packet.stopped_by, MaxDepthExceededError)
            and packet.stopped_by.protocol is TLS
        ):
            packet = decode_frame(rest, start=TLS, lax=True)
            records.extend(packet)
            per_walk.append(len(tls_layers(packet)))
            rest = rest[packet.consumed :]
        assert per_walk == [29, 32, 32, 10]
        assert len(records) == 103
        assert all(bytes(layer) == smallest for layer in records)
        assert packet.stopped_by is None
        assert rest == b""


# --- The ClientHello ----------------------------------------------------


class TestClientHello:
    def test_parse(self, raw_tls_client_hello):
        hello = TLS.decode(raw_tls_client_hello).client_hello
        assert hello == TLSClientHello(
            legacy_version=0x0303,
            random=bytes(range(32)),
            legacy_session_id=b"",
            cipher_suites=b"\x13\x01",
            legacy_compression_methods=b"\x00",
            extensions=(TLSExtension(0, b"\x00\x0e\x00\x00\x0bexample.com"),),
        )

    def test_a_session_id_of_32_bytes(self):
        body = hello_body(session_id=b"s" * 32)
        hello = TLS.decode(hello_record(body)).client_hello
        assert hello is not None and hello.legacy_session_id == b"s" * 32

    def test_no_extensions_block(self):
        """RFC 5246 §7.4.1.2: a ClientHello may end after its
        compression methods; that is None, not ()."""
        tls = TLS.decode(hello_record(hello_body(extensions=None)))
        hello = tls.client_hello
        assert hello is not None and hello.extensions is None
        assert tls.server_name is None
        assert bytes(hello) == hello_body(extensions=None)

    def test_an_empty_extensions_block(self):
        tls = TLS.decode(hello_record(hello_body(extensions=b"")))
        hello = tls.client_hello
        assert hello is not None and hello.extensions == ()
        assert bytes(hello) == hello_body(extensions=b"")

    def test_extensions_in_wire_order(self):
        block = extension(0x0A0A, b"") + extension(43, b"\x02\x03\x04")
        hello = TLS.decode(hello_record(hello_body(extensions=block)))
        assert hello.client_hello is not None
        assert hello.client_hello.extensions == (
            TLSExtension(0x0A0A),
            TLSExtension(43, b"\x02\x03\x04"),
        )

    @pytest.mark.parametrize(
        "ciphertext,error,offset",
        [
            # Its next three bytes, read as a length, exceed the record:
            # the likely case.
            (b"\x01\x8c\x3f\x05" + bytes(36), TruncatedHeaderError, 1),
            # A length of 0: the message ends inside its Random.
            (b"\x01" + bytes(39), InvalidFieldError, 4),
        ],
        ids=["length-past-the-record", "length-zero"],
    )
    def test_an_encrypted_finished_starting_with_1(
        self, ciphertext, error, offset
    ):
        """A TLS 1.2 encrypted Finished (40 bytes under AES-GCM) whose
        ciphertext starts with 1 cannot be told from a ClientHello by
        its first byte, so both accessors raise rather than answer
        None."""
        tls = TLS.decode(record(HANDSHAKE, ciphertext))
        assert tls.length == 40
        assert tls.handshake_type_name == "client_hello"
        for name in ("client_hello", "server_name"):
            with pytest.raises(error) as caught:
                getattr(tls, name)
            assert caught.value.field == "fragment"
            assert caught.value.offset == offset

    def test_a_coalesced_message_after_it_is_ignored(self):
        """Only the first handshake message of a record is looked at."""
        fragment = handshake(1, hello_body()) + handshake(20, bytes(12))
        tls = TLS.decode(record(HANDSHAKE, fragment))
        assert tls.client_hello is not None

    @pytest.mark.parametrize(
        "raw",
        [
            record(APPDATA, handshake(1, hello_body())),
            record(HANDSHAKE, handshake(2, hello_body())),
            record(HANDSHAKE),
        ],
        ids=["application-data", "server-hello", "empty"],
    )
    def test_none_for_anything_else(self, raw):
        tls = TLS.decode(raw)
        assert tls.client_hello is None
        assert tls.server_name is None


def _hello_error(raw: bytes) -> ProtocolError:
    """The error ``client_hello`` raises for ``raw``, checked to be
    positioned in the fragment, and the same from ``server_name``."""
    tls = TLS.decode(raw)
    with pytest.raises(ProtocolError) as caught:
        _ = tls.client_hello
    with pytest.raises(type(caught.value)):
        _ = tls.server_name
    error = caught.value
    assert error.protocol is TLS
    assert error.field == "fragment"
    assert error.offset is not None and 0 <= error.offset <= tls.length
    return error


class TestClientHelloLyingLengths:
    """Every length inside the ClientHello, lying. Offsets count from
    the fragment: the handshake header is 4 bytes, so the session ID's
    length is at 38, the cipher suites' at 39 (with no session ID)."""

    def test_handshake_length_past_the_record(self):
        """The record holds less than the message says: a ClientHello
        fragmented across records, or cut, is TruncatedHeaderError."""
        body = hello_body()
        fragment = b"\x01" + (len(body) + 1).to_bytes(3, "big") + body
        error = _hello_error(record(HANDSHAKE, fragment))
        assert isinstance(error, TruncatedHeaderError)
        assert error.offset == 1
        assert (error.expected, error.actual) == (
            len(fragment) + 1,
            len(fragment),
        )

    @pytest.mark.parametrize("size", [1, 2, 3])
    def test_handshake_header_cut(self, size):
        """The message's 3-byte length, at 1, is itself cut."""
        error = _hello_error(record(HANDSHAKE, b"\x01\x00\x00\x40"[:size]))
        assert isinstance(error, TruncatedHeaderError)
        assert error.offset == 1
        assert (error.expected, error.actual) == (None, size)

    @pytest.mark.parametrize(
        "size,offset,words",
        [
            (20, 4, "ends inside its random"),
            (33, 4, "ends inside its random"),
            (34, 38, "legacy_session_id length runs past"),
        ],
    )
    def test_a_message_too_short_for_its_random(self, size, offset, words):
        """The version and the Random take 34 bytes from 4: a 33-byte
        message ends inside them, at 4; a 34-byte one holds them and
        ends where the session ID's length, at 38, should be."""
        error = _hello_error(record(HANDSHAKE, handshake(1, bytes(size))))
        assert isinstance(error, InvalidFieldError)
        assert error.offset == offset
        assert words in str(error)

    def test_session_id_length(self):
        body = bytearray(hello_body())
        body[34] = 200
        error = _hello_error(hello_record(bytes(body)))
        assert isinstance(error, InvalidFieldError)
        assert error.offset == 38

    def test_session_id_over_32_bytes(self):
        error = _hello_error(hello_record(hello_body(session_id=bytes(33))))
        assert isinstance(error, InvalidFieldError)
        assert "exceeds 32" in str(error)
        assert error.offset == 38

    def test_cipher_suites_length(self):
        body = bytearray(hello_body())
        struct.pack_into("!H", body, 35, 0x1000)
        error = _hello_error(hello_record(bytes(body)))
        assert isinstance(error, InvalidFieldError)
        assert error.offset == 39

    def test_compression_methods_length(self):
        body = bytearray(hello_body())
        body[41] = 9  # after 4 bytes of suites
        error = _hello_error(hello_record(bytes(body)))
        assert isinstance(error, InvalidFieldError)
        assert error.offset == 45

    def test_the_message_ends_inside_a_length(self):
        """One byte where the extensions block's 2-byte length goes."""
        body = hello_body(extensions=None) + b"\x00"
        error = _hello_error(hello_record(body))
        assert isinstance(error, InvalidFieldError)
        assert error.offset == 4 + len(body) - 1

    def test_extensions_block_length_too_long(self):
        body = bytearray(hello_body(extensions=extension(23, b"")))
        struct.pack_into("!H", body, len(body) - 6, 50)
        error = _hello_error(hello_record(bytes(body)))
        assert isinstance(error, InvalidFieldError)
        assert error.offset == 4 + len(body) - 6

    def test_bytes_after_the_extensions_block(self):
        body = hello_body(extensions=extension(23, b"")) + b"\x00\x00"
        error = _hello_error(hello_record(body))
        assert isinstance(error, InvalidFieldError)
        assert "after its extensions" in str(error)
        assert error.offset == 4 + len(body) - 2

    @pytest.mark.parametrize("left", [1, 2, 3])
    def test_an_extension_header_cut(self, left):
        """1-3 bytes after a whole extension: the header they start is
        cut, at its own first byte, whether or not they hold its type."""
        block = extension(23, b"") + b"\x00\x17\x00"[:left]
        error = _hello_error(hello_record(hello_body(extensions=block)))
        assert isinstance(error, InvalidFieldError)
        assert "extension header runs past" in str(error)
        assert error.offset == 4 + len(hello_body(extensions=b"")) + 4

    def test_one_extensions_length(self):
        block = bytearray(extension(23, b"") + extension(43, b"\x02\x03\x04"))
        struct.pack_into("!H", block, 6, 99)
        body = hello_body(extensions=bytes(block))
        error = _hello_error(hello_record(body))
        assert isinstance(error, InvalidFieldError)
        assert error.offset == 4 + len(body) - len(block) + 6


class TestCapturedEdgeCases:
    """Edge cases the captures do not hold, derived from captured bytes:
    curl's ClientHello (tls.pcap frame 3) without its server_name, and
    with its extensions block cut short."""

    @staticmethod
    def curl_hello() -> tuple[bytes, TLSClientHello]:
        raw = CORPUS[2][PAYLOAD_AT:]
        hello = TLS.decode(raw).client_hello
        assert hello is not None and hello.extensions is not None
        assert hello.extensions[0].type == 0
        return raw, hello

    def test_without_its_server_name(self):
        """Drop the extension and fix the three lengths around it."""
        _, hello = self.curl_hello()
        assert hello.extensions is not None
        stripped = TLSClientHello(
            hello.legacy_version,
            hello.random,
            hello.legacy_session_id,
            hello.cipher_suites,
            hello.legacy_compression_methods,
            hello.extensions[1:],
        )
        tls = TLS.decode(hello_record(bytes(stripped)))
        assert tls.server_name is None
        assert tls.client_hello == stripped

    def test_a_truncated_extensions_block(self):
        """The handshake and record lengths shortened with the block, so
        the record decodes and the block's own length overruns: the
        accessor raises, decode does not."""
        raw, hello = self.curl_hello()
        cut = 30
        fragment = raw[5:-cut]
        fragment = (
            fragment[:1] + (len(fragment) - 4).to_bytes(3, "big") + fragment[4:]
        )
        tls = TLS.decode(record(HANDSHAKE, fragment, version=0x0301))
        assert tls.handshake_type == 1
        error = _hello_error(bytes(tls))
        assert isinstance(error, InvalidFieldError)
        assert "extensions block runs past" in str(error)
        # At the block's length, after the fields before it.
        assert error.offset == (
            4
            + 2
            + 32
            + 1
            + len(hello.legacy_session_id)
            + 2
            + len(hello.cipher_suites)
            + 1
            + len(hello.legacy_compression_methods)
        )


class TestServerName:
    def sni_of(self, block: bytes) -> str | None:
        return TLS.decode(
            hello_record(hello_body(extensions=block))
        ).server_name

    def test_reads_the_host_name(self, raw_tls_client_hello):
        assert TLS.decode(raw_tls_client_hello).server_name == "example.com"

    def test_none_without_the_extension(self):
        assert self.sni_of(extension(23, b"")) is None

    def test_found_among_other_extensions(self):
        block = (
            extension(0x1A1A, b"")
            + sni((0, b"a.example"))
            + extension(21, bytes(9))
        )
        assert self.sni_of(block) == "a.example"

    def test_the_first_host_name_wins(self):
        """RFC 6066 allows one name per type; the first is read."""
        assert (
            self.sni_of(sni((0, b"one.example"), (0, b"two.example")))
            == "one.example"
        )

    def test_another_name_type_is_skipped(self):
        assert (
            self.sni_of(sni((7, b"opaque"), (0, b"b.example"))) == "b.example"
        )

    def test_none_when_only_other_types(self):
        assert self.sni_of(sni((7, b"opaque"))) is None

    @pytest.mark.parametrize(
        "name",
        [
            b"10.9.196.2",
            b"trailing.dot.",
            b"UPPER.example",
            b"xn--bcher-kva.example",
        ],
    )
    def test_ascii_is_returned_as_sent(self, name):
        """An IP literal and a trailing dot, which RFC 6066 forbids, are
        reported, not judged; an A-label is just ASCII."""
        assert self.sni_of(sni((0, name))) == name.decode()

    def test_non_ascii_raises(self):
        block = sni((0, "bücher.example".encode()))
        tls = TLS.decode(hello_record(hello_body(extensions=block)))
        # The ClientHello itself parses; only the name is refused.
        assert tls.client_hello is not None
        with pytest.raises(InvalidFieldError) as caught:
            _ = tls.server_name
        assert "ASCII" in str(caught.value)
        # The offset is where the name starts: 4 header + body to the
        # block, 2 block length, 4 extension header, 2 list length, 1
        # type, 2 name length.
        start = 4 + len(hello_body()) + 4 + 2 + 1 + 2
        assert caught.value.offset == start


def _entries(*entries: tuple[int, bytes]) -> bytes:
    """ServerNameList entries: a NameType, then a 2-byte length-prefixed
    name, each."""
    return b"".join(bytes([kind]) + vector(name, 2) for kind, name in entries)


#: Where the server_name extension's data starts in the fragment when
#: it follows a 4-byte extended_main_secret: 4 handshake header, the
#: body to the end of the block's length, 4 for the extension before
#: it and 4 for its own header. Its list's first entry starts 2 later.
SNI_DATA = 4 + len(hello_body(extensions=b"")) + 4 + 4
SNI_ENTRY = SNI_DATA + 2


class TestServerNameErrors:
    """Every way the server_name extension's data can be malformed, and
    the exact offset in the fragment each is reported at: where the
    length or name at fault starts. The extension is the block's second,
    so an offset counted from the extension, or from the block, is
    caught."""

    @pytest.mark.parametrize(
        "data,offset,words",
        [
            (b"", SNI_DATA, "server_name list length runs past"),
            (b"\x00", SNI_DATA, "server_name list length runs past"),
            (
                b"\x00\x28" + _entries((0, b"c.example")),
                SNI_DATA,
                "server_name list runs past",
            ),
            (
                vector(_entries((0, b"c.example")), 2) + b"\x00",
                SNI_DATA,
                "does not fill its extension",
            ),
            (b"\x00\x00", SNI_DATA, "does not fill its extension"),
            (
                b"\x00\x02\x00\x00",
                SNI_ENTRY + 1,
                "server name length runs past",
            ),
            (
                vector(b"\x00\x00\x28c.example", 2),
                SNI_ENTRY + 1,
                "server name runs past",
            ),
            (
                vector(_entries((0, b"")), 2),
                SNI_ENTRY + 1,
                "host_name is empty",
            ),
            (
                vector(_entries((0, "bü.example".encode())), 2),
                SNI_ENTRY + 3,
                "not ASCII",
            ),
            (
                vector(_entries((7, b"opaque")) + b"\x00\x00\x20ab", 2),
                SNI_ENTRY + 9 + 1,
                "server name runs past",
            ),
        ],
        ids=[
            "empty-extension",
            "one-byte",
            "list-too-long",
            "list-too-short",
            "empty-list",
            "name-length-cut",
            "name-too-long",
            "empty-name",
            "non-ascii",
            "second-entry-too-long",
        ],
    )
    def test_offset_in_the_fragment(self, data, offset, words):
        block = extension(23, b"") + extension(0, data)
        tls = TLS.decode(hello_record(hello_body(extensions=block)))
        assert tls.client_hello is not None
        assert tls.fragment[SNI_DATA - 4 : SNI_DATA - 2] == b"\x00\x00"
        with pytest.raises(InvalidFieldError) as caught:
            _ = tls.server_name
        error = caught.value
        assert words in str(error)
        assert (error.protocol, error.field) == (TLS, "fragment")
        assert error.offset == offset


class TestOverrunByOne:
    """Each length-prefixed element, at every level of nesting, claiming
    exactly one byte more than what contains it holds: the error is at
    that length, and says it runs past."""

    #: The ClientHello every case starts from: a 4-byte session ID, two
    #: suites, one method, then extended_main_secret and a server_name
    #: listing an entry of NameType 7 and a host_name.
    BODY = hello_body(
        session_id=b"sess",
        suites=b"\x13\x01\x13\x02",
        extensions=extension(23, b"")
        + extension(0, vector(_entries((7, b"op"), (0, b"a.example")), 2)),
    )

    #: (what, where its length starts in the fragment, its width): the
    #: fragment is 80 bytes, and what contains each element, the
    #: message, the block, the extension's data or the list, ends where
    #: the fragment does.
    LENGTHS = (
        ("legacy_session_id", 38, 1),
        ("cipher_suites", 43, 2),
        ("legacy_compression_methods", 49, 1),
        ("extensions block", 51, 2),
        ("extended_main_secret", 55, 2),
        ("server_name", 59, 2),
        ("server_name list", 61, 2),
        ("first name", 64, 2),
        ("host_name", 69, 2),
    )

    def test_the_layout(self):
        """The positions above, read back from the parsed ClientHello."""
        tls = TLS.decode(hello_record(self.BODY))
        assert tls.length == 4 + len(self.BODY) == 80
        assert tls.server_name == "a.example"
        fragment = tls.fragment
        assert fragment[38] == 4 and fragment[43:45] == b"\x00\x04"
        assert fragment[49] == 1 and fragment[51:53] == b"\x00\x1b"
        assert fragment[53:57] == b"\x00\x17\x00\x00"
        assert fragment[57:61] == b"\x00\x00\x00\x13"
        assert fragment[61:63] == b"\x00\x11"
        assert fragment[63:68] == b"\x07\x00\x02op"
        assert fragment[68:71] == b"\x00\x00\x09"

    @pytest.mark.parametrize(
        "at,width",
        [(at, width) for _, at, width in LENGTHS],
        ids=[what for what, _, _ in LENGTHS],
    )
    def test_one_byte_too_many(self, at, width):
        fragment = bytearray(handshake(1, self.BODY))
        claimed = len(fragment) - (at + width) + 1
        fragment[at : at + width] = claimed.to_bytes(width, "big")
        tls = TLS.decode(record(HANDSHAKE, bytes(fragment), version=0x0301))
        with pytest.raises(InvalidFieldError) as caught:
            _ = tls.server_name
        error = caught.value
        assert error.offset == at
        assert "runs past its message" in str(error)
        assert "length runs past" not in str(error)
        if at < 61:  # outside the server_name extension's data
            with pytest.raises(InvalidFieldError) as caught:
                _ = tls.client_hello
            assert caught.value.offset == at
        else:
            assert tls.client_hello is not None

    @pytest.mark.parametrize(
        "at,width",
        [(at, width) for _, at, width in LENGTHS],
        ids=[what for what, _, _ in LENGTHS],
    )
    def test_exactly_enough(self, at, width):
        """The same length one byte shorter fits: whatever is then
        wrong, it is not that length running past."""
        fragment = bytearray(handshake(1, self.BODY))
        claimed = len(fragment) - (at + width)
        fragment[at : at + width] = claimed.to_bytes(width, "big")
        tls = TLS.decode(record(HANDSHAKE, bytes(fragment), version=0x0301))
        try:
            _ = tls.server_name
        except InvalidFieldError as error:
            assert not (error.offset == at and "runs past" in str(error))


class TestValueObjects:
    def test_extension_bytes(self):
        assert (
            bytes(TLSExtension(43, b"\x02\x03\x04"))
            == b"\x00\x2b\x00\x03\x02\x03\x04"
        )

    @pytest.mark.parametrize("value", [-1, 0x10000])
    def test_extension_type_must_fit(self, value):
        with pytest.raises(InvalidFieldError) as caught:
            TLSExtension(value)
        assert caught.value.field == "type"

    def test_extension_data_must_fit(self):
        with pytest.raises(InvalidFieldError) as caught:
            TLSExtension(0, bytes(0x10000))
        assert caught.value.field == "data"

    @pytest.mark.parametrize(
        "field,value",
        [
            ("legacy_version", 0x10000),
            ("random", bytes(31)),
            ("legacy_session_id", bytes(33)),
            ("cipher_suites", bytes(0x10000)),
            ("legacy_compression_methods", bytes(256)),
            ("extensions", (TLSExtension(0, bytes(0xFFFF)),)),
        ],
    )
    def test_client_hello_fields_must_fit(self, field, value):
        fields = {"legacy_version": 0x0303, "random": bytes(32), field: value}
        with pytest.raises(InvalidFieldError) as caught:
            TLSClientHello(**fields)
        assert caught.value.field == field

    def test_client_hello_extensions_overflow_reports_their_size(self):
        """Each extension adds a 4-byte header to its data."""
        extensions = (TLSExtension(0, bytes(0xFFFF)), TLSExtension(1))
        with pytest.raises(InvalidFieldError) as caught:
            TLSClientHello(0x0303, bytes(32), extensions=extensions)
        error = caught.value
        assert error.field == "extensions"
        assert (error.expected, error.actual) == ("<=65535 bytes", 0x10007)
        assert "65543 bytes" in str(error)

    def test_client_hello_bytes(self):
        hello = TLSClientHello(
            0x0303, bytes(range(32)), cipher_suites=b"\x13\x01\x13\x02"
        )
        assert bytes(hello) == hello_body(extensions=b"")


#: The names expected, written here from the RFCs rather than read from
#: the module, so a wrong name in either is caught. ContentType: RFC 9846
#: §5.1's enum, and heartbeat, RFC 6520 §6.
CONTENT_TYPE_NAMES = {
    20: "change_cipher_spec",
    21: "alert",
    22: "handshake",
    23: "application_data",
    24: "heartbeat",
}

#: SSL 3.0 (RFC 6101) and TLS 1.0 (RFC 2246), 1.1 (RFC 4346), 1.2 (RFC
#: 5246) and 1.3 (RFC 9846).
VERSION_NAMES = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

#: HandshakeType: RFC 9846 Appendix B.3's enum, the ``_RESERVED`` suffix
#: of the types TLS 1.3 retired dropped, then the types it leaves to
#: other RFCs.
HANDSHAKE_TYPE_NAMES = {
    0: "hello_request",
    1: "client_hello",
    2: "server_hello",
    3: "hello_verify_request",
    4: "new_session_ticket",
    5: "end_of_early_data",
    6: "hello_retry_request",
    8: "encrypted_extensions",
    11: "certificate",
    12: "server_key_exchange",
    13: "certificate_request",
    14: "server_hello_done",
    15: "certificate_verify",
    16: "client_key_exchange",
    20: "finished",
    21: "certificate_url",
    22: "certificate_status",
    23: "supplemental_data",
    24: "key_update",
    254: "message_hash",
    9: "request_connection_id",  # RFC 9147
    10: "new_connection_id",  # RFC 9147
    17: "client_certificate_request",  # RFC 9261
    25: "compressed_certificate",  # RFC 8879
    26: "ekt_key",  # RFC 8870
}

#: ExtensionType: RFC 9846 §4.3's enum, then seven it leaves out.
EXTENSION_NAMES = {
    0: "server_name",
    5: "status_request",
    10: "supported_groups",
    13: "signature_algorithms",
    14: "use_srtp",
    15: "heartbeat",
    16: "application_layer_protocol_negotiation",
    19: "client_certificate_type",
    20: "server_certificate_type",
    21: "padding",
    27: "compress_certificate",
    28: "record_size_limit",
    34: "delegated_credential",
    39: "supported_ekt_ciphers",
    41: "pre_shared_key",
    42: "early_data",
    43: "supported_versions",
    44: "cookie",
    45: "psk_key_exchange_modes",
    47: "certificate_authorities",
    48: "oid_filters",
    49: "post_handshake_auth",
    50: "signature_algorithms_cert",
    51: "key_share",
    52: "transparency_info",
    55: "external_id_hash",
    56: "external_session_id",
    57: "quic_transport_parameters",
    58: "ticket_request",
    64768: "ech_outer_extensions",
    65037: "encrypted_client_hello",
    1: "max_fragment_length",  # RFC 6066
    11: "ec_point_formats",  # RFC 8422
    18: "signed_certificate_timestamp",  # RFC 6962
    22: "encrypt_then_mac",  # RFC 7366
    23: "extended_main_secret",  # RFC 7627, renamed by RFC 9846 §11.1
    35: "session_ticket",  # RFC 5077, renamed by RFC 8447
    65281: "renegotiation_info",  # RFC 5746
}

#: RFC 8701 §2's sixteen GREASE values for extensions.
GREASE = {0x0A0A + 0x1010 * i for i in range(16)}


class TestDisplay:
    @pytest.mark.parametrize("kind,name", sorted(CONTENT_TYPE_NAMES.items()))
    def test_content_type_name(self, kind, name):
        assert TLS(kind, 0x0303, 0, b"").content_type_name == name

    def test_every_other_content_type_is_unknown(self):
        for kind in set(range(256)) - set(CONTENT_TYPE_NAMES):
            name = TLS(kind, 0x0303, 0, b"").content_type_name
            assert name == f"unknown ({kind})"

    @pytest.mark.parametrize("version,name", sorted(VERSION_NAMES.items()))
    def test_version_names(self, version, name):
        assert TLS(23, version, 0, b"").legacy_version_name == name
        assert TLSClientHello(version, bytes(32)).legacy_version_name == name

    def test_every_other_version_is_unknown(self):
        """Every other value, 0x0305 and DTLS 1.2's 0xfefd among them,
        is unknown, in four hex digits."""
        assert TLS(23, 0xFEFD, 0, b"").legacy_version_name == (
            "unknown (0xfefd)"
        )
        for version in set(range(0x10000)) - set(VERSION_NAMES):
            name = TLS(23, version, 0, b"").legacy_version_name
            assert name == f"unknown ({version:#06x})"

    @pytest.mark.parametrize("kind,name", sorted(HANDSHAKE_TYPE_NAMES.items()))
    def test_handshake_type_name(self, kind, name):
        tls = TLS.decode(record(HANDSHAKE, bytes([kind])))
        assert tls.handshake_type == kind
        assert tls.handshake_type_name == name

    def test_every_other_handshake_type_is_unknown(self):
        for kind in set(range(256)) - set(HANDSHAKE_TYPE_NAMES):
            tls = TLS(HANDSHAKE, 0x0303, 1, bytes([kind]))
            assert tls.handshake_type_name == f"unknown ({kind})"

    def test_no_handshake_type_outside_handshake_records(self):
        tls = TLS.decode(record(APPDATA, b"\x01"))
        assert tls.handshake_type is None
        assert tls.handshake_type_name is None

    @pytest.mark.parametrize("kind,name", sorted(EXTENSION_NAMES.items()))
    def test_extension_type_name(self, kind, name):
        assert TLSExtension(kind).type_name == name

    @pytest.mark.parametrize(
        "kind,name",
        [
            (0x0A0A, "GREASE"),
            (0xFAFA, "GREASE"),
            (0x0A1A, "unknown (2586)"),
            (0x12E0, "unknown (4832)"),
            (0x44CD, "unknown (17613)"),
            (0xCA34, "unknown (51764)"),
            (0xFFFF, "unknown (65535)"),
        ],
    )
    def test_grease_and_unknown_extension_types(self, kind, name):
        """The three types Chromium sends that are named nowhere here
        (see tests/fixtures/MANIFEST.md) among them."""
        assert TLSExtension(kind).type_name == name

    def test_every_other_extension_type_is_unknown(self):
        for kind in set(range(0x10000)) - set(EXTENSION_NAMES) - GREASE:
            assert TLSExtension(kind).type_name == f"unknown ({kind})"

    def test_every_grease_value(self):
        """RFC 8701's sixteen, and no other value, are GREASE."""
        grease = {
            v for v in range(0x10000) if TLSExtension(v).type_name == "GREASE"
        }
        assert grease == GREASE


class TestDispatch:
    def test_registered_on_tcp_443(self):
        assert DEFAULT.get(TABLE_TCP_PORT, 443) is TLS

    def test_not_on_udp_443(self):
        """QUIC's port is not TLS's record layer."""
        assert DEFAULT.get(TABLE_UDP_PORT, 443) is None

    @pytest.mark.parametrize(
        "sport,dport", [(50000, 443), (443, 50000)], ids=["to", "from"]
    )
    def test_either_direction(self, sport, dport, raw_tls_client_hello):
        for ipv6 in (False, True):
            raw = frame(
                raw_tls_client_hello, sport=sport, dport=dport, ipv6=ipv6
            )
            packet = decode_frame(raw)
            assert [type(layer) for layer in packet][-1] is TLS
            assert packet[TLS].server_name == "example.com"

    @pytest.mark.parametrize("port", [853, 465, 993, 995, 8443])
    def test_other_tls_ports_need_decode_as(self, port, raw_tls_client_hello):
        raw = frame(raw_tls_client_hello, dport=port)
        assert [type(layer) for layer in decode_frame(raw)][-1] is TCP
        packet = decode_frame(raw, decode_as={"tcp.port": {port: TLS}})
        assert packet[TLS].server_name == "example.com"

    def test_decode_as_can_take_the_port_away(self):
        """Port 443 decoded as HTTP for one walk, as a test might."""
        request = b"GET / HTTP/1.1\r\nHost: a\r\n\r\n"
        packet = decode_frame(
            frame(request), decode_as={"tcp.port": {443: HTTP}}
        )
        assert isinstance(packet[HTTP], HTTP)

    def test_udp_443_ends_at_udp(self):
        udp = UDP(src_port=50000, dst_port=443, length=0, checksum=0)
        assert udp.next_protocol() is None


# --- scripts/check_fixtures.py -----------------------------------------


def _ones_complement(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def retouched(raw: bytes, payload: bytes) -> bytes:
    """A captured IPv4/TCP frame with its payload replaced, and its IPv4
    Total Length and header checksum and its TCP checksum rewritten to
    match, so only the TLS checks can fail."""
    ihl = (raw[14] & 0x0F) * 4
    ip = bytearray(raw[14 : 14 + ihl])
    tcp_start = 14 + ihl
    offset = (raw[tcp_start + 12] >> 4) * 4
    tcp = bytearray(raw[tcp_start : tcp_start + offset]) + payload
    struct.pack_into("!H", ip, 2, ihl + len(tcp))
    struct.pack_into("!H", ip, 10, 0)
    struct.pack_into("!H", ip, 10, _ones_complement(bytes(ip)))
    struct.pack_into("!H", tcp, 16, 0)
    pseudo = bytes(ip[12:20]) + struct.pack("!BBH", 0, 6, len(tcp))
    struct.pack_into("!H", tcp, 16, _ones_complement(pseudo + bytes(tcp)))
    return raw[:14] + bytes(ip) + bytes(tcp)


class TestChecker:
    """scripts/check_fixtures.py's _check_tls, each failure on a
    tampered copy of a captured frame, and check_capture_frame and
    main(), which fail a split segment outside a session capture."""

    @pytest.fixture(autouse=True)
    def _checker(self, check_fixtures):
        self.checker = check_fixtures

    def check(self, raw: bytes) -> tuple[list[str], Counter]:
        stats = self.checker.Counter()
        return self.checker.check_frame(raw, stats), stats

    def test_retouching_alone_passes(self):
        raw = CORPUS[2]
        assert self.check(retouched(raw, raw[PAYLOAD_AT:]))[0] == []

    def test_tls_length(self):
        payload = struct.pack("!BHH", 23, 0x0303, 18433) + bytes(20)
        assert self.check(retouched(CORPUS[12], payload))[0] == ["tls-length"]

    @pytest.mark.parametrize("kind", [20, 21, 22])
    def test_tls_empty(self, kind):
        failures, _ = self.check(retouched(CORPUS[12], record(kind)))
        assert failures == ["tls-empty"]

    def test_an_empty_application_data_record_passes(self):
        assert self.check(retouched(CORPUS[12], record(APPDATA)))[0] == []

    def test_tls_ccs(self):
        payload = bytearray(CORPUS[11][PAYLOAD_AT:])
        assert payload[5] == 1
        payload[5] = 2
        assert self.check(retouched(CORPUS[11], bytes(payload)))[0] == [
            "tls-ccs"
        ]

    @pytest.mark.parametrize(
        "body",
        [
            hello_body(session_id=bytes(33)),
            hello_body(extensions=None) + b"\x00",
            hello_body(extensions=b"\x00\x17\x00"),
            hello_body(extensions=extension(23, b"")) + b"\x00",
            hello_body()[:30],
        ],
        ids=["session-id", "cut-length", "cut-extension", "trailing", "short"],
    )
    def test_tls_hello(self, body):
        failures, _ = self.check(retouched(CORPUS[2], hello_record(body)))
        assert failures == ["tls-hello"]

    def test_tls_hello_cut_by_its_record(self):
        fragment = handshake(1, hello_body())[:-3]
        failures, _ = self.check(
            retouched(CORPUS[2], record(HANDSHAKE, fragment))
        )
        assert failures == ["tls-hello"]

    @pytest.mark.parametrize(
        "name",
        [b"10.9.196.2", b"::1", b"trailing.", b"sp ace", "é".encode(), b""],
    )
    def test_tls_sni(self, name):
        body = hello_body(extensions=sni((0, name)))
        failures, stats = self.check(retouched(CORPUS[2], hello_record(body)))
        assert failures == ["tls-sni"]
        assert stats["tls-server-name"] == 1

    def test_a_hello_without_extensions_passes(self):
        body = hello_body(extensions=None)
        failures, stats = self.check(retouched(CORPUS[2], hello_record(body)))
        assert failures == []
        assert stats["tls-client-hello"] == 1

    @staticmethod
    def finished_starting_with_1(index: int) -> tuple[bytes, int]:
        """The payload of CORPUS[index], a TLS 1.2 segment holding a
        ChangeCipherSpec and then the encrypted Finished, with the
        Finished's first ciphertext byte forced to 1, as about one
        Finished in 256 has it; and where that record starts."""
        payload, at = bytearray(CORPUS[index][PAYLOAD_AT:]), 0
        while payload[at] != CCS:
            at += 5 + struct.unpack_from("!H", payload, at + 3)[0]
        at += 6
        assert payload[at] == HANDSHAKE and payload[at + 5] != 1
        payload[at + 5] = 1
        return bytes(payload), at

    @pytest.mark.parametrize("index", [10, 11], ids=["client", "server"])
    def test_a_finished_after_its_ccs_is_not_a_hello(self, index):
        """Records after ChangeCipherSpec are encrypted (RFC 5246
        §7.1): a Finished whose ciphertext starts with 1 is not checked
        as a ClientHello, and is still counted as a Handshake record."""
        payload, _ = self.finished_starting_with_1(index)
        failures, stats = self.check(retouched(CORPUS[index], payload))
        assert failures == []
        assert stats["tls-client-hello"] == 0
        assert stats["tls-handshake"] == CAPTURE[index][1].count(HANDSHAKE)

    @pytest.mark.parametrize("index", [10, 11], ids=["client", "server"])
    def test_the_same_record_before_a_ccs_is_a_hello(self, index):
        """The same record ahead of the segment's ChangeCipherSpec is
        checked as a ClientHello, and fails as one."""
        payload, at = self.finished_starting_with_1(index)
        moved = payload[at:] + payload[:at]
        failures, stats = self.check(retouched(CORPUS[index], moved))
        assert failures == ["tls-hello"]
        assert stats["tls-client-hello"] == 1

    def test_a_handshake_before_the_ccs_is_still_checked(self):
        """The client's ClientKeyExchange, ahead of its ChangeCipherSpec
        in CORPUS[10], is in the clear: given the type of a ClientHello,
        it is checked as one, and fails."""
        payload = bytearray(CORPUS[10][PAYLOAD_AT:])
        assert payload[0] == HANDSHAKE and payload[5] == 16
        payload[5] = 1
        failures, stats = self.check(retouched(CORPUS[10], bytes(payload)))
        assert failures == ["tls-hello"]
        assert stats["tls-client-hello"] == 1

    def test_an_empty_handshake_after_a_ccs_fails(self):
        """Every other check still holds after ChangeCipherSpec."""
        payload = record(CCS, b"\x01") + record(HANDSHAKE)
        failures, _ = self.check(retouched(CORPUS[11], payload))
        assert failures == ["tls-empty"]

    def test_a_segment_starting_inside_a_record_is_unchecked(self):
        failures, stats = self.check(retouched(CORPUS[2], b"\x99" * 30))
        assert failures == []
        assert stats["tls-unchecked"] == 1

    @pytest.mark.parametrize("index", [SPLIT_HEAD, SPLIT_TAIL])
    def test_a_split_segment_fails_outside_a_session(self, index):
        """check_capture_frame, what main() runs, fails a segment that
        is not whole records unless its capture is a session one."""
        for session, failures in ((False, ["tls-split"]), (True, [])):
            stats = self.checker.Counter()
            assert (
                self.checker.check_capture_frame(
                    SESSION[index], stats, session=session
                )
                == failures
            )
            assert stats["tls-unchecked"] == 1

    def test_every_corpus_frame_is_whole_records(self):
        for raw in CORPUS + TestHTTPSCapture.FRAMES:
            stats = self.checker.Counter()
            assert (
                self.checker.check_capture_frame(raw, stats, session=False)
                == []
            )
            assert stats["tls-unchecked"] == 0

    @pytest.mark.parametrize(
        "name,verdict",
        [("tls_session.pcap", 0), ("bgp_session.pcap", 0), ("tls.pcap", 1)],
    )
    def test_main_judges_by_the_capture_name(
        self, tmp_path, monkeypatch, capsys, name, verdict
    ):
        """The session capture passes under a session name, and fails,
        on its four split segments, under any other."""
        (tmp_path / name).write_bytes(
            (FIXTURES / "tls" / "tls_session.pcap").read_bytes()
        )
        monkeypatch.setattr(sys, "argv", ["check_fixtures.py", str(tmp_path)])
        assert self.checker.main() == verdict
        out = capsys.readouterr().out
        assert ("!! tls-split x4" in out) == bool(verdict)
        assert "tls-unchecked=4" in out
