"""Property-based fuzzing of the decode path.

The contract under test: for *any* input bytes, ``decode()`` either
returns an instance or raises a ``ProtocolError`` subclass — never
anything else — and the documented chain walk terminates under the
same rule. Strategies mix pure random bytes with mutations of real
corpus frames (much better at reaching deep decode branches).

The hypothesis profile is deterministic (``derandomize=True``) so an
unrelated pull request can never trip a freshly discovered
counterexample; bump ``max_examples`` locally to explore.
"""

import contextlib

from hypothesis import given, settings
from hypothesis import strategies as st

from conftest import corpus_frames
from netprotocols import (
    ARP,
    DNS,
    IGMP,
    TCP,
    UDP,
    VLAN,
    Ethernet,
    ICMPv4,
    ICMPv6,
    InvalidFieldError,
    IPv4,
    IPv6,
    IPv6DestinationOptions,
    IPv6Fragment,
    IPv6HopByHopOptions,
    IPv6Routing,
    Packet,
    ProtocolError,
)
from test_corpus import walk

settings.register_profile(
    "netprotocols", max_examples=200, deadline=None, derandomize=True
)
settings.load_profile("netprotocols")

ALL_PROTOCOLS = (
    Ethernet,
    VLAN,
    ARP,
    IPv4,
    IPv6,
    IPv6HopByHopOptions,
    IPv6Routing,
    IPv6Fragment,
    IPv6DestinationOptions,
    ICMPv4,
    ICMPv6,
    IGMP,
    TCP,
    UDP,
    DNS,
)

CORPUS_FRAMES = [frame for _, _, frame in corpus_frames()]

random_bytes = st.binary(max_size=128)


@st.composite
def mutated_corpus_frame(draw: st.DrawFn) -> bytes:
    """A real corpus frame with a handful of byte-level mutations."""
    frame = bytearray(draw(st.sampled_from(CORPUS_FRAMES)))
    for _ in range(draw(st.integers(min_value=1, max_value=8))):
        position = draw(st.integers(min_value=0, max_value=len(frame) - 1))
        frame[position] = draw(st.integers(min_value=0, max_value=255))
    cut = draw(st.integers(min_value=0, max_value=len(frame)))
    return bytes(frame[:cut]) if draw(st.booleans()) else bytes(frame)


fuzz_input = st.one_of(random_bytes, mutated_corpus_frame())


class TestDecodeNeverEscapesProtocolError:
    @given(data=fuzz_input)
    def test_every_protocol_class(self, data: bytes) -> None:
        for protocol in ALL_PROTOCOLS:
            with contextlib.suppress(ProtocolError):
                header = protocol.decode(data)
                assert bytes(header)  # serialization must also hold

    @given(data=fuzz_input)
    def test_chain_walk_terminates_under_the_contract(
        self, data: bytes
    ) -> None:
        with contextlib.suppress(ProtocolError):
            layers, consumed = walk(data)
            # Every decode validates its declared length against the
            # buffer, so the walk can never consume past the frame.
            assert consumed <= len(data)
            assert len(layers) <= len(data)  # every layer consumed >= 1 byte


class TestConstrainedRoundTrips:
    @given(
        dst=st.binary(min_size=6, max_size=6),
        src=st.binary(min_size=6, max_size=6),
        ethertype=st.integers(min_value=0, max_value=0xFFFF),
    )
    def test_ethernet(self, dst: bytes, src: bytes, ethertype: int) -> None:
        raw = dst + src + ethertype.to_bytes(2, "big")
        header = Ethernet.decode(raw)
        assert bytes(header) == raw
        assert Ethernet.decode(bytes(header)) == header

    @given(
        src_port=st.integers(min_value=0, max_value=0xFFFF),
        dst_port=st.integers(min_value=0, max_value=0xFFFF),
        length=st.integers(min_value=0, max_value=0xFFFF),
        checksum=st.integers(min_value=0, max_value=0xFFFF),
    )
    def test_udp(
        self, src_port: int, dst_port: int, length: int, checksum: int
    ) -> None:
        header = UDP(
            src_port=src_port,
            dst_port=dst_port,
            length=length,
            checksum=checksum,
        )
        assert UDP.decode(bytes(header)) == header

    @given(
        options_words=st.integers(min_value=0, max_value=10),
        flags=st.integers(min_value=0, max_value=0x1FF),
        content=st.binary(min_size=40, max_size=40),
    )
    def test_tcp_with_options(
        self, options_words: int, flags: int, content: bytes
    ) -> None:
        header = TCP(
            src_port=int.from_bytes(content[0:2], "big"),
            dst_port=int.from_bytes(content[2:4], "big"),
            seq=int.from_bytes(content[4:8], "big"),
            ack=int.from_bytes(content[8:12], "big"),
            data_offset=5 + options_words,
            reserved=0,
            flags=flags,
            window=int.from_bytes(content[12:14], "big"),
            checksum=int.from_bytes(content[14:16], "big"),
            urgent_pointer=int.from_bytes(content[16:18], "big"),
            options=content[18 : 18 + options_words * 4]
            + content[: options_words * 4 - 22]
            if options_words * 4 > 22
            else content[18 : 18 + options_words * 4],
        )
        decoded = TCP.decode(bytes(header) + b"payload")
        assert decoded == header
        assert decoded.header_len == 20 + options_words * 4

    @given(
        next_header=st.integers(min_value=0, max_value=255),
        offset=st.integers(min_value=0, max_value=0x1FFF),
        m_flag=st.integers(min_value=0, max_value=1),
        identification=st.integers(min_value=0, max_value=0xFFFFFFFF),
    )
    def test_ipv6_fragment(
        self, next_header: int, offset: int, m_flag: int, identification: int
    ) -> None:
        header = IPv6Fragment(
            next_header=next_header,
            reserved=0,
            fragment_offset=offset,
            res=0,
            m_flag=m_flag,
            identification=identification,
        )
        assert IPv6Fragment.decode(bytes(header)) == header


class TestPacketProperties:
    @given(data=fuzz_input)
    def test_decoded_layers_recompose(self, data: bytes) -> None:
        """Whatever decodes from a frame must re-serialize into a prefix
        of that frame when packed together."""
        with contextlib.suppress(ProtocolError):
            layers, consumed = walk(data)
            if layers:
                assert bytes(Packet(*layers)) == bytes(data[:consumed])


class TestNDPAccessorSafety:
    @given(data=fuzz_input)
    def test_ndp_accessors_never_hang_or_escape(self, data: bytes) -> None:
        """The NDP accessors parse untrusted TLV bytes (and a zero
        option length must not loop): a tuple/None or InvalidFieldError,
        never anything else — and the target/display helpers never raise
        at all."""
        with contextlib.suppress(ProtocolError):
            icmp = ICMPv6.decode(data)
            _ = icmp.ndp_target_address
            with contextlib.suppress(InvalidFieldError):
                for option in icmp.ndp_options or ():
                    assert option.type_name
                    _ = option.link_layer_address


class TestDNSNameAccessorSafety:
    @given(data=fuzz_input)
    def test_question_name_never_hangs_or_escapes(self, data: bytes) -> None:
        """The name accessor parses untrusted, possibly compression-
        looping bytes: it must return a str/None or raise
        InvalidFieldError, never hang and never raise anything else."""
        with contextlib.suppress(ProtocolError):
            dns = DNS.decode(data)
            with contextlib.suppress(InvalidFieldError):
                name = dns.question_name
                assert name is None or isinstance(name, str)


class TestTCPOptionAccessorSafety:
    @given(data=fuzz_input)
    def test_parsed_options_never_hang_or_escape(self, data: bytes) -> None:
        """The options accessor parses untrusted TLV bytes: it must
        return a tuple or raise InvalidFieldError, never hang and never
        raise anything else — and the per-option display helpers and
        decoded values must never raise at all."""
        with contextlib.suppress(ProtocolError):
            tcp = TCP.decode(data)
            with contextlib.suppress(InvalidFieldError):
                for option in tcp.parsed_options:
                    assert option.kind_name
                    _ = option.value
