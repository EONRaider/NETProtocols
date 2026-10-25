"""Property-based fuzzing of the decode path.

The contract under test: for *any* input bytes, ``decode()`` either
returns an instance or raises a ``ProtocolError`` subclass — never
anything else — and the documented chain walk terminates under the
same rule. Strategies mix pure random bytes with mutations of real
corpus frames (much better at reaching deep decode branches).

Two Hypothesis profiles are registered:

- ``"netprotocols"`` (the default, loaded unless overridden): 200
  examples, ``derandomize=True`` so an unrelated pull request can
  never trip a freshly discovered counterexample.
- ``"nightly"``: 10,000 examples, a real random seed each run
  (``derandomize=False``) — the profile ``.github/workflows/fuzz.yml``
  runs on a schedule, deliberately trading determinism for a moving
  seed that explores new ground on every run instead of replaying the
  same 200 inputs forever (#98).

Select a profile with ``HYPOTHESIS_PROFILE`` (read once, at import
time) — e.g. ``HYPOTHESIS_PROFILE=nightly pytest tests/test_fuzz.py``
reproduces a nightly run locally. The profiles are registered and
loaded in conftest.py rather than here, so every property test in the
suite gets them, including under a test selection that never imports
this file (mutmut's, for one).
"""

import contextlib
import struct
import sys

import pytest
from hypothesis import event, given
from hypothesis import strategies as st

from conftest import FIXTURES, corpus_frames, pcap_frames
from netprotocols import (
    AH,
    ARP,
    BGP,
    DHCP,
    DNS,
    ESP,
    GRE,
    HTTP,
    IGMP,
    OSPF,
    PIM,
    RIP,
    SCTP,
    TCP,
    UDP,
    VLAN,
    VRRP,
    VXLAN,
    AHv6,
    BGPPathAttribute,
    BGPPrefix,
    DNSOverTCP,
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
    PIMHello,
    PIMJoinPrune,
    PIMRegister,
    Protocol,
    ProtocolError,
    RIPAuthentication,
    RIPEntry,
    SCTPChunk,
    TCPOption,
    VRRPv6,
)
from strategies import (
    ROUND_TRIP_STRATEGIES,
    bgp_path_attributes,
    bgp_prefixes,
    http_context_responses,
    http_messages,
    http_wire,
    ospf_packets,
    pim_headers,
    sctp_chunks,
    sctp_headers,
    vrrp_headers,
)
from test_corpus import walk

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
    PIM,
    TCP,
    UDP,
    SCTP,
    DNS,
    DNSOverTCP,
    DHCP,
    GRE,
    ESP,
    AH,
    AHv6,
    HTTP,
    VXLAN,
    OSPF,
    RIP,
    VRRP,
    VRRPv6,
    BGP,
)


def _shipped_protocol_classes() -> set[type[Protocol]]:
    """Every concrete protocol class netprotocols ships, discovered by
    walking Protocol.__subclasses__() to every depth rather than a second
    hand list that could drift the same way ALL_PROTOCOLS can.

    Two artifacts of live-class introspection need filtering:
    * @dataclass(slots=True) rebuilds a class after `class Foo(Protocol):`
      already registered the pre-slots object as a Protocol subclass, so
      both the rebuilt class and an orphaned duplicate stay reachable from
      __subclasses__() forever. Keep only the object actually bound under
      its own name in its defining module.
    * Other test modules (test_registry.py's Fake/OtherFake,
      test_walk.py's NonAdvancing) define their own throwaway Protocol
      subclasses; once those modules are imported (any full-suite run)
      they show up here too. Restrict to classes whose __module__ starts
      with 'netprotocols'.
    * Private intermediate bases (_ICMP, _IPv6OptionsHeader) share a shape
      but are never registered/decoded standalone — excluded by the
      leading-underscore convention the codebase already uses for exactly
      that.
    """
    found: set[type[Protocol]] = set()
    stack = list(Protocol.__subclasses__())
    while stack:
        cls = stack.pop()
        if cls in found:
            continue
        found.add(cls)
        stack.extend(cls.__subclasses__())

    def is_shipped(cls: type[Protocol]) -> bool:
        if not cls.__module__.startswith("netprotocols"):
            return False
        if cls.__name__.startswith("_"):
            return False
        module = sys.modules.get(cls.__module__)
        return module is not None and getattr(module, cls.__name__, None) is cls

    return {cls for cls in found if is_shipped(cls)}


def test_all_protocols_covers_every_shipped_protocol() -> None:
    """ALL_PROTOCOLS must name exactly the concrete protocols this library
    ships: nothing missing (a new protocol silently skipping the
    decode-never-escapes-ProtocolError fuzz property) and nothing stale
    (a renamed/removed class left behind)."""
    shipped = _shipped_protocol_classes()
    assert len(shipped) >= len(ALL_PROTOCOLS), (
        f"protocol discovery found only {len(shipped)} classes, fewer "
        f"than ALL_PROTOCOLS already lists ({len(ALL_PROTOCOLS)}) -- "
        "the introspection is broken, not the list"
    )
    missing = shipped - set(ALL_PROTOCOLS)
    stale = set(ALL_PROTOCOLS) - shipped
    assert not missing, (
        f"not fuzzed -- add to ALL_PROTOCOLS: "
        f"{sorted(c.__name__ for c in missing)}"
    )
    assert not stale, (
        f"ALL_PROTOCOLS lists class(es) no longer shipped: "
        f"{sorted(c.__name__ for c in stale)}"
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


# TCP option kinds a real SYN carries (RFC 9293 §3.2; RFC 7323 for
# Window Scale and Timestamps; RFC 2018 for SACK). The real-capture
# corpus never caught a SYN of a live connection; its only SYNs are the
# script-built ones behind AH, carrying just MSS (tests/fixtures/
# MANIFEST.md). So unlike NOP/Timestamps (kinds 1, 8) and MSS (2),
# window-scale/SACK are otherwise fuzzed only as arbitrary bytes
# inside ``fuzz_input`` above, which essentially never lands on a
# well-formed TLV by chance. This strategy builds one on purpose.
_KIND_NOP = 1
_KIND_MSS = 2
_KIND_WINDOW_SCALE = 3
_KIND_SACK_PERMITTED = 4
_KIND_SACK = 5
_KIND_TIMESTAMPS = 8


@st.composite
def tcp_syn_options(draw: st.DrawFn) -> tuple[bytes, list[TCPOption]]:
    """Well-formed SYN-shaped option bytes (MSS, window scale,
    SACK-Permitted, timestamps, then a 1-2 block SACK, NOP-padded to a
    multiple of 4), paired with the :class:`TCPOption` list
    ``TCP.decode`` should produce from them."""
    mss = draw(st.integers(min_value=0, max_value=0xFFFF))
    shift = draw(st.integers(min_value=0, max_value=0xFF))
    tsval = draw(st.integers(min_value=0, max_value=0xFFFFFFFF))
    tsecr = draw(st.integers(min_value=0, max_value=0xFFFFFFFF))
    # Capped at 2 blocks (not RFC 2018's 4): MSS + window scale +
    # SACK-Permitted + timestamps already spend 19 of the 40 bytes TCP's
    # 4-bit data offset allows for options, leaving room for at most 2
    # 8-byte SACK blocks plus up-to-3 bytes of NOP padding.
    blocks = draw(
        st.lists(
            st.tuples(
                st.integers(min_value=0, max_value=0xFFFFFFFF),
                st.integers(min_value=0, max_value=0xFFFFFFFF),
            ),
            min_size=1,
            max_size=2,
        )
    )
    sack_data = b"".join(
        left.to_bytes(4, "big") + right.to_bytes(4, "big")
        for left, right in blocks
    )

    raw = (
        bytes([_KIND_MSS, 4])
        + mss.to_bytes(2, "big")
        + bytes([_KIND_WINDOW_SCALE, 3, shift])
        + bytes([_KIND_SACK_PERMITTED, 2])
        + bytes([_KIND_TIMESTAMPS, 10])
        + tsval.to_bytes(4, "big")
        + tsecr.to_bytes(4, "big")
        + bytes([_KIND_SACK, 2 + len(sack_data)])
        + sack_data
    )
    padding = (-len(raw)) % 4
    raw += bytes([_KIND_NOP]) * padding

    expected = [
        TCPOption(kind=_KIND_MSS, data=mss.to_bytes(2, "big")),
        TCPOption(kind=_KIND_WINDOW_SCALE, data=bytes([shift])),
        TCPOption(kind=_KIND_SACK_PERMITTED),
        TCPOption(
            kind=_KIND_TIMESTAMPS,
            data=tsval.to_bytes(4, "big") + tsecr.to_bytes(4, "big"),
        ),
        TCPOption(kind=_KIND_SACK, data=sack_data),
        *([TCPOption(kind=_KIND_NOP)] * padding),
    ]
    return raw, expected


class TestTCPSynOptionsRoundTrip:
    @given(drawn=tcp_syn_options())
    def test_synthesized_options_round_trip_and_decode(
        self, drawn: tuple[bytes, list[TCPOption]]
    ) -> None:
        raw, expected_options = drawn
        header = TCP(
            src_port=1234,
            dst_port=443,
            seq=0,
            ack=0,
            data_offset=5 + len(raw) // 4,
            reserved=0,
            flags=0b0_0000_0010,  # SYN
            window=0xFFFF,
            checksum=0,
            urgent_pointer=0,
            options=raw,
        )
        assert TCP.decode(bytes(header)) == header
        assert list(header.parsed_options) == expected_options


class TestGeneralizedRoundTrips:
    """``bytes(decode(x)) == x`` for every protocol, not just the four
    above — one property, parametrized over the strategies in
    strategies.py (#97). The 14 single-example assertions living in
    each protocol's own test file (``test_arp.py::test_round_trip`` and
    similarly for the others) are kept as regression anchors pinned to
    a real captured header, which this property does not replace: a
    fixed example catches a specific regression fast and readably, a
    generated one explores the space the fixed example cannot."""

    @pytest.mark.parametrize("name", sorted(ROUND_TRIP_STRATEGIES))
    @given(data=st.data())
    def test_round_trip(self, name: str, data: st.DataObject) -> None:
        header = data.draw(ROUND_TRIP_STRATEGIES[name])
        raw = bytes(header)
        decoded = type(header).decode(raw)
        assert decoded == header
        assert bytes(decoded) == raw


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


class TestIPv6OptionAccessorSafety:
    @given(data=fuzz_input)
    def test_parsed_options_never_hang_or_escape(self, data: bytes) -> None:
        """The ext-header options accessor parses untrusted TLV bytes:
        it must return a tuple or raise InvalidFieldError, never hang
        and never raise anything else — and the per-option display
        helpers must never raise at all."""
        with contextlib.suppress(ProtocolError):
            header = IPv6HopByHopOptions.decode(data)
            with contextlib.suppress(InvalidFieldError):
                for option in header.parsed_options:
                    assert option.type_name
                    _ = option.unrecognized_action


#: Message bodies from a small alphabet of the values BGP's lengths and
#: flags turn on (prefix lengths at and past 32, the Extended Length
#: flag, RFC 9072's 255), so the body accessors' error paths are hit far
#: more often than free bytes would hit them.
_bgp_body = st.lists(
    st.sampled_from([0, 0, 1, 2, 3, 4, 8, 24, 32, 33, 0x10, 0x40, 0x50, 0xFF]),
    max_size=80,
).map(bytes)


def _sized(raw: bytes, width: int = 2) -> bytes:
    return len(raw).to_bytes(width, "big") + raw


def _attribute(flags: int, code: int, data: bytes) -> bytes:
    return bytes([flags, code]) + _sized(data, 2 if flags & 0x10 else 1)


#: Well-formed path attributes and OPEN parameters, mostly of the
#: types whose values are decoded, with values of every length near the
#: right one.
_bgp_attributes = st.lists(
    st.builds(
        _attribute,
        st.sampled_from([0x40, 0x50, 0x80, 0xC0, 0xD0, 0x20]),
        st.sampled_from([1, 2, 3, 4, 5, 6, 8, 14, 99]),
        st.binary(max_size=6),
    ),
    max_size=5,
).map(b"".join)
_bgp_prefixes = st.lists(bgp_prefixes(), max_size=5).map(
    lambda prefixes: b"".join(map(bytes, prefixes))
)
_bgp_parameters = st.lists(
    st.builds(
        lambda type_, value: bytes([type_]) + _sized(value, 1),
        st.sampled_from([1, 2, 7]),
        st.binary(max_size=6),
    ),
    max_size=4,
).map(b"".join)


@st.composite
def bgp_body(draw: st.DrawFn, type_: int) -> bytes:
    """A body shaped like the type's: an UPDATE's three fields behind
    lengths that fit, an OPEN's fixed fields and parameters behind a
    length that fits (or 255, RFC 9072's marker), from
    :data:`_bgp_body`'s alphabet, so the field walks both succeed and
    fail; and, now and then, one byte overwritten to break a length."""
    if type_ == 2:
        withdrawn = draw(st.one_of(_bgp_prefixes, _bgp_body))
        attributes = draw(st.one_of(_bgp_attributes, _bgp_body))
        nlri = draw(st.one_of(_bgp_prefixes, _bgp_body))
        body = _sized(withdrawn) + _sized(attributes) + nlri
    elif type_ == 1:
        params = draw(st.one_of(_bgp_parameters, _bgp_body))
        declared = draw(st.sampled_from([len(params) % 256, 255]))
        body = draw(st.binary(min_size=9, max_size=9)) + bytes([declared])
        body += params
    else:
        body = draw(_bgp_body)
    if body and not draw(st.integers(0, 3)):
        at = draw(st.integers(0, len(body) - 1))
        byte = draw(st.sampled_from([0x00, 0x01, 0xFF]))
        body = body[:at] + bytes([byte]) + body[at + 1 :]
    return body


@st.composite
def bgp_like(draw: st.DrawFn) -> bytes:
    """A Marker, a Length that matches the body, a Type 1-5 and a body
    from :func:`bgp_body`, sometimes with bytes after it."""
    type_ = draw(st.integers(min_value=1, max_value=5))
    body = draw(bgp_body(type_))
    tail = draw(st.sampled_from([b"", b"\xff" * 3, bytes(4), b"\x01"]))
    header = b"\xff" * 16 + (19 + len(body)).to_bytes(2, "big")
    return header + bytes([type_]) + body + tail


def _read_every_bgp_accessor(msg: BGP) -> None:
    """Read every accessor: the body parsers may raise InvalidFieldError,
    and nothing else may raise at all."""
    for name in (
        "type_name",
        "version",
        "my_as",
        "hold_time",
        "bgp_identifier",
        "extended_optional_parameters",
        "error_code",
        "error_subcode",
        "error_data",
        "error_code_name",
        "error_subcode_name",
        "shutdown_communication",
    ):
        getattr(msg, name)
    with contextlib.suppress(InvalidFieldError):
        for param in msg.optional_parameters or ():
            assert param.type_name
    for name in ("withdrawn_routes", "nlri"):
        with contextlib.suppress(InvalidFieldError):
            for prefix in getattr(msg, name) or ():
                assert str(prefix) == str(prefix.network)
                assert bytes(prefix)
    with contextlib.suppress(InvalidFieldError):
        for attribute in msg.path_attributes or ():
            assert attribute.type_name
            _ = (attribute.value, attribute.value_text, bytes(attribute))
            _ = (attribute.optional, attribute.transitive, attribute.partial)


class TestBGPAccessorSafety:
    @given(data=st.one_of(fuzz_input, bgp_like()))
    def test_accessors_never_hang_or_escape(self, data: bytes) -> None:
        """Decode bounds a message by its own Length, whatever follows
        it; the body accessors raise only InvalidFieldError and the
        rest never raise."""
        try:
            msg = BGP.decode(data)
        except ProtocolError:
            return
        assert bytes(msg) == data[: msg.header_len]
        assert BGP.decode(bytes(msg)) == msg
        _read_every_bgp_accessor(msg)

    @given(
        withdrawn=st.lists(bgp_prefixes(), max_size=6),
        attributes=st.lists(bgp_path_attributes(), max_size=6),
        nlri=st.lists(bgp_prefixes(), max_size=6),
    )
    def test_built_updates_parse_back(
        self,
        withdrawn: list[BGPPrefix],
        attributes: list[BGPPathAttribute],
        nlri: list[BGPPrefix],
    ) -> None:
        """An UPDATE built from prefixes and attributes (either length
        width) parses back into exactly those parts."""
        raw_withdrawn = b"".join(map(bytes, withdrawn))
        raw_attributes = b"".join(map(bytes, attributes))
        body = (
            len(raw_withdrawn).to_bytes(2, "big")
            + raw_withdrawn
            + len(raw_attributes).to_bytes(2, "big")
            + raw_attributes
            + b"".join(map(bytes, nlri))
        )
        msg = BGP.decode(
            b"\xff" * 16 + (19 + len(body)).to_bytes(2, "big") + b"\x02" + body
        )
        assert msg.withdrawn_routes == tuple(withdrawn)
        assert msg.path_attributes == tuple(attributes)
        assert msg.nlri == tuple(nlri)


class TestIPv4OptionAccessorSafety:
    @given(data=fuzz_input)
    def test_parsed_options_never_hang_or_escape(self, data: bytes) -> None:
        """The options accessor parses untrusted TLV bytes: it must
        return a tuple or raise InvalidFieldError, never hang and never
        raise anything else — and the per-option display helper must
        never raise at all."""
        with contextlib.suppress(ProtocolError):
            ip = IPv4.decode(data)
            with contextlib.suppress(InvalidFieldError):
                for option in ip.parsed_options:
                    assert option.kind_name


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


#: Bytes from a small alphabet, so chunk lengths of 4, 8 and below 4,
#: zero tails and cut chunks turn up far more often than in free bytes.
_sctp_like = st.lists(
    st.sampled_from([0, 0, 0, 1, 3, 4, 5, 8, 0xFF]), max_size=96
).map(bytes)


class TestSCTPChunkAccessorSafety:
    @given(data=st.one_of(fuzz_input, _sctp_like))
    def test_decode_never_raises_past_the_common_header(
        self, data: bytes
    ) -> None:
        """Past the 12-byte common header decode() keeps whatever it
        cannot walk, so it raises only on a shorter buffer. It leaves
        undecoded nothing but a zero tail, round-trips exactly the
        bytes it consumed, and the accessor raises only ProtocolError,
        and only when decode() kept an unwalkable remainder."""
        if len(data) < 12:
            with pytest.raises(ProtocolError):
                SCTP.decode(data)
            return
        sctp = SCTP.decode(data)
        assert bytes(sctp) == data[: sctp.header_len]
        assert not any(data[sctp.header_len :])
        assert SCTP.decode(bytes(sctp)) == sctp
        try:
            chunks = sctp.parsed_chunks
        except ProtocolError:
            assert sctp.header_len == len(data)
            return
        for chunk in chunks:
            assert chunk.type_name
            _ = chunk.flags_str
            assert 0 <= chunk.unrecognized_action <= 3

    @given(header=sctp_headers())
    def test_zero_padding_after_a_packet_is_left_undecoded(
        self, header: SCTP
    ) -> None:
        """A well-formed packet followed by Ethernet's zero padding
        decodes to exactly the packet: the zero-tail trim, which the
        free-byte property above rarely reaches. Every padding length up
        to Ethernet's 46-byte maximum is tried rather than drawn, so the
        1-3 byte remainders (too short for a chunk header) are always
        covered whatever the seed."""
        wire = bytes(header)
        for padding in range(47):
            sctp = SCTP.decode(wire + bytes(padding))
            assert sctp == header, padding
            assert sctp.header_len == len(wire), padding

    @given(header=sctp_headers())
    def test_a_nonzero_trailer_is_kept(self, header: SCTP) -> None:
        """Anything but zeros after the packet (an FCS, say) cannot be
        told from a broken chunk, so decode() keeps it all, after any
        number of zeros."""
        for padding in range(47):
            data = bytes(header) + bytes(padding) + b"\x01"
            assert SCTP.decode(data).header_len == len(data), padding

    @given(chunks=st.lists(sctp_chunks(), max_size=6))
    def test_built_chunks_parse_back(self, chunks: list[SCTPChunk]) -> None:
        raw = b"".join(bytes(chunk) for chunk in chunks)
        sctp = SCTP.decode(bytes(12) + raw)
        assert sctp.chunks == raw
        assert list(sctp.parsed_chunks) == chunks


def _read_every_ospf_accessor(ospf: OSPF) -> None:
    """Read every accessor and display helper, checking the records
    re-encode to the body they came from."""
    for name in (
        "type_name",
        "au_type_name",
        "checksum_hex_str",
        "key_id",
        "auth_data_len",
        "crypto_sequence_number",
    ):
        getattr(ospf, name)
    message = ospf.hello or ospf.database_description
    if message is not None:
        assert bytes(message) == ospf.body
        _ = message.options_str
    if ospf.database_description is not None:
        _ = ospf.database_description.flags_str
    for request in ospf.ls_requests or ():
        assert request.ls_type_name
    if ospf.lsas is not None:
        raw = len(ospf.lsas).to_bytes(4, "big")
        assert raw + b"".join(map(bytes, ospf.lsas)) == ospf.body
    headers = [lsa.header for lsa in ospf.lsas or ()]
    headers += ospf.ls_acknowledgments or ()
    for header in headers:
        assert header.ls_type_name
        _ = header.options_str, header.ls_checksum_hex_str
        _ = header.ls_sequence_number_hex_str


#: OSPF-shaped buffers: a version-2 header with a plausible Packet
#: Length, then bytes from a small alphabet, so that bodies with their
#: framing, broken LSA counts and lengths, and cut digests all turn up
#: far more often than in free bytes.
_ospf_like = st.builds(
    lambda type_, instance_id, au_type, auth_len, tail, slack: (
        struct.pack("!BBH", 2, type_, 24 + len(tail) - slack)
        + bytes(10)
        + struct.pack("!BB", instance_id, au_type)
        + bytes(3)
        + bytes([auth_len])
        + bytes(4)
        + tail
    ),
    st.integers(0, 6),
    st.sampled_from([0, 1, 255]),
    st.sampled_from([0, 1, 2, 3]),
    st.sampled_from([0, 4, 8, 16]),
    st.lists(st.sampled_from([0, 0, 1, 2, 4, 20, 24, 0xFF]), max_size=96).map(
        bytes
    ),
    st.integers(0, 8),
)


class TestOSPFAccessorSafety:
    """decode() checks each message's framing, so no accessor of a
    decoded OSPF packet may raise, and the packet round-trips exactly
    the bytes it consumed."""

    @given(data=st.one_of(fuzz_input, _ospf_like))
    def test_decoded_packets(self, data: bytes) -> None:
        try:
            ospf = OSPF.decode(data)
        except ProtocolError:
            return
        assert bytes(ospf) == data[: ospf.header_len]
        assert OSPF.decode(bytes(ospf)) == ospf
        _read_every_ospf_accessor(ospf)

    @given(ospf=ospf_packets())
    def test_built_packets(self, ospf: OSPF) -> None:
        _read_every_ospf_accessor(ospf)
        assert OSPF.decode(bytes(ospf) + b"\xde\xad") == ospf


#: Bytes from a small alphabet, so AFI 0xFFFF, authentication type 3,
#: plausible Packet Lengths and remainders turn up far more often than
#: in free bytes. Led by a header decode accepts.
_rip_like = st.tuples(
    st.sampled_from([b"\x01\x01\x00\x00", b"\x02\x02\x00\x00"]),
    st.lists(
        st.sampled_from([0, 0, 0x18, 0x2C, 0x40, 0xFF, 0xFF, 1, 2, 3]),
        max_size=120,
    ).map(bytes),
).map(b"".join)


#: The captured RIP messages, every one past its UDP header.
_RIP_MESSAGES = [frame[42:] for frame in pcap_frames(FIXTURES / "rip.pcap")]


@st.composite
def _rip_seeded(draw: st.DrawFn) -> bytes:
    """A captured RIP message, a few body bytes changed, cut anywhere
    past the header and followed by nothing, an FCS-like 4 bytes or up
    to 23 more: the authentication entries, a trailer located by a
    real Packet Length, and remainders, which free bytes rarely
    reach."""
    raw = bytearray(draw(st.sampled_from(_RIP_MESSAGES)))
    for _ in range(draw(st.integers(0, 3))):
        position = draw(st.integers(4, len(raw) - 1))
        raw[position] = draw(st.integers(0, 255))
    cut = draw(st.integers(4, len(raw)))
    tail = draw(
        st.one_of(
            st.just(b""), st.just(b"\xde\xad\xbe\xef"), st.binary(max_size=23)
        )
    )
    return bytes(raw[:cut]) + tail


class TestRIPAccessorSafety:
    @given(data=st.one_of(_rip_seeded(), _rip_like, fuzz_input))
    def test_decode_and_every_accessor_are_total(self, data: bytes) -> None:
        """decode() raises only on the 4-byte header (too short, a
        version other than 1 or 2, command 0) and keeps every byte
        after it; the accessors never raise, and the entries, the
        trailer and the remainder they report tile the body exactly."""
        try:
            rip = RIP.decode(data)
        except ProtocolError:
            assert len(data) < 4 or data[1] not in (1, 2) or data[0] == 0
            return
        assert bytes(rip) == data
        assert RIP.decode(bytes(rip)) == rip
        assert rip.command_name
        entries = rip.entries
        trailer = rip.authentication_trailer
        assert trailer is None or b"\xff\xff\x00\x01".startswith(trailer[:4])
        tiled = b"".join(bytes(entry) for entry in entries)
        tiled += rip.remainder + (trailer if trailer is not None else b"")
        assert tiled == rip.body
        assert len(rip.remainder) < 20
        assert rip.routes == tuple(
            e for e in entries if isinstance(e, RIPEntry)
        )
        for entry in entries:
            if isinstance(entry, RIPAuthentication):
                assert entry.auth_type_name
                _ = (entry.password, entry.packet_length, entry.key_id)
                _ = (entry.auth_data_len, entry.sequence_number)
            else:
                assert entry.afi_name
        auth = rip.authentication
        assert auth is None or entries[0] == auth
        event(f"RIP authentication type: {auth and auth.auth_type}")
        event(f"RIP trailer located: {trailer is not None}")
        event(f"RIP remainder: {bool(rip.remainder)}")


#: VRRP's display and per-version accessors, every one of which must
#: answer on any decoded or constructed instance.
_VRRP_ACCESSORS = (
    "type_name",
    "auth_type",
    "auth_type_name",
    "adver_int",
    "reserved",
    "max_adver_int",
    "advertisement_interval",
    "checksum_hex_str",
    "header_len",
)


class TestVRRPAccessorSafety:
    @given(data=fuzz_input)
    def test_decoded_adverts_answer_every_accessor(self, data: bytes) -> None:
        """Whatever decodes, every accessor answers without raising, and
        exactly one of the two versions' interval fields is set."""
        for cls in (VRRP, VRRPv6):
            try:
                vrrp = cls.decode(data)
            except ProtocolError:
                continue
            for name in _VRRP_ACCESSORS:
                getattr(vrrp, name)
            assert (vrrp.adver_int is None) != (vrrp.max_adver_int is None)
            assert bytes(vrrp) == data[: vrrp.header_len]

    @pytest.mark.parametrize("cls", [VRRP, VRRPv6])
    @given(data=st.data())
    def test_trailing_bytes_stay_out_of_the_message(
        self, cls: type[VRRP], data: st.DataObject
    ) -> None:
        """The version and count bound the message, so Ethernet's zero
        padding (every length up to its 46-byte maximum) and a nonzero
        trailer such as a 4-byte FCS are left undecoded."""
        header = data.draw(vrrp_headers(cls))
        wire = bytes(header)
        for trailer in [bytes(n) for n in range(47)] + [b"\xde\xad\xbe\xef"]:
            decoded = cls.decode(wire + trailer)
            assert decoded == header, trailer
            assert decoded.header_len == len(wire), trailer


#: A PIM header (version 2, each type) and then bytes from a small
#: alphabet, so counts, families 1 and 2, encoding 0, short option
#: lengths and zero tails turn up far more often than in free bytes.
_pim_like = st.tuples(
    st.integers(0, 0x0F).map(lambda type_: bytes([0x20 | type_, 0, 0, 0])),
    st.lists(
        st.sampled_from([0, 0, 0, 1, 2, 4, 8, 0x20, 0xFF]), max_size=96
    ).map(bytes),
).map(b"".join)


def _read_pim_message(pim: PIM) -> None:
    """Read every accessor of a PIM message's typed form."""
    message = pim.message
    if isinstance(message, PIMHello):
        for option in message.options:
            assert option.type_name
        for name in (
            "holdtime",
            "lan_prune_delay",
            "dr_priority",
            "generation_id",
            "address_list",
        ):
            with contextlib.suppress(InvalidFieldError, ProtocolError):
                getattr(message, name)
    elif isinstance(message, PIMJoinPrune):
        for group in message.groups:
            _ = group.group.bidirectional, group.group.admin_scope
            for source in group.joined + group.pruned:
                _ = source.sparse, source.wildcard, source.rpt
    elif isinstance(message, PIMRegister):
        _ = message.encapsulated


class TestPIMAccessorSafety:
    @given(data=st.one_of(fuzz_input, _pim_like))
    def test_decode_never_raises_past_the_header(self, data: bytes) -> None:
        """Past the 4-byte header of a version-2 message decode() keeps
        whatever its parser cannot read, so it raises only on a shorter
        buffer or another version. It round-trips exactly the bytes it
        consumed, and the accessors raise only ProtocolError, and
        :attr:`PIM.message` only when decode() kept the whole remainder
        because it would not parse."""
        if len(data) < 4 or data[0] >> 4 != 2:
            with pytest.raises(ProtocolError):
                PIM.decode(data)
            return
        pim = PIM.decode(data)
        assert bytes(pim) == data[: pim.header_len]
        assert PIM.decode(bytes(pim)) == pim
        assert pim.type_name
        assert pim.checksum_hex_str
        try:
            _read_pim_message(pim)
        except ProtocolError:
            assert pim.header_len == len(data)

    @given(header=pim_headers())
    def test_a_zero_tail_is_left_undecoded(self, header: PIM) -> None:
        """Ethernet's zero padding after a well-formed message is never
        part of it, whatever its type bounds it by, except for the types
        whose body runs to the end of the buffer (Register, and the
        types kept raw), which keep it. Every padding length up to
        Ethernet's 46-byte maximum is tried."""
        wire = bytes(header)
        keeps_tail = header.type in (1, 4) or header.type > 7
        for padding in range(47):
            pim = PIM.decode(wire + bytes(padding))
            if keeps_tail:
                assert pim.header_len == len(wire) + padding, padding
            else:
                assert pim == header, padding

    @given(header=pim_headers())
    def test_a_nonzero_trailer_after_a_bounded_message_is_left(
        self, header: PIM
    ) -> None:
        """A message bounded by its own counts and addresses ends there,
        whatever follows it (an FCS, say)."""
        if header.type not in (2, 3, 5, 6, 7):
            return
        wire = bytes(header)
        for trailer in (b"\x01", b"\xde\xad\xbe\xef", bytes(5) + b"\x01"):
            assert PIM.decode(wire + trailer) == header

    @given(header=pim_headers())
    def test_built_messages_parse_back(self, header: PIM) -> None:
        """A body built from a typed message parses back to a message
        that serializes to that same body."""
        message = header.message
        if message is None:
            return
        assert bytes(message) == header.body


def _read_every_accessor(msg: HTTP) -> None:
    for name in (
        "is_response",
        "method",
        "target",
        "http_version",
        "status_code",
        "reason_phrase",
        "fields",
        "framing",
        "connection_disposition",
        "content",
        "trailers",
        "anomalies",
    ):
        getattr(msg, name)
    for field in msg.fields:
        msg.header_values(field.name)
        msg.header(field.name)


http_input = st.one_of(http_wire(), random_bytes)
request_methods = st.sampled_from([None, "HEAD", "CONNECT", "GET", "head"])


class TestHTTPAccessorSafety:
    """Every accessor is a read of the parse decode() already did, so
    none may raise on any instance -- stricter than the TLV accessors
    above, which may raise InvalidFieldError on demand."""

    @given(
        data=http_input, request_method=request_methods, closed=st.booleans()
    )
    def test_decoded_messages(
        self, data: bytes, request_method: str | None, closed: bool
    ) -> None:
        try:
            msg = HTTP.decode(
                data, request_method=request_method, closed=closed
            )
        except ProtocolError:
            return
        _read_every_accessor(msg)
        assert bytes(msg) == data[: msg.header_len]
        again = HTTP.decode(
            bytes(msg), request_method=msg.request_method, closed=True
        )
        assert again == msg
        assert again.anomalies == msg.anomalies


class TestHTTPConstruction:
    @given(msg=http_messages())
    def test_the_context_round_trip(self, msg: HTTP) -> None:
        assert (
            HTTP.decode(
                bytes(msg), request_method=msg.request_method, closed=True
            )
            == msg
        )

    @given(msg=http_context_responses())
    def test_context_bearing_responses_round_trip(self, msg: HTTP) -> None:
        """http_messages() never carries a request_method, so the
        HEAD / CONNECT 2xx contexts get a strategy of their own."""
        assert msg.request_method in ("HEAD", "CONNECT")
        assert msg.raw_body == b""
        assert HTTP.decode(bytes(msg), request_method=msg.request_method) == msg

    @given(
        head=http_input,
        raw_body=st.one_of(http_input, st.binary(max_size=16)),
        request_method=request_methods,
    )
    def test_arbitrary_parts_construct_or_raise(
        self, head: bytes, raw_body: bytes, request_method: str | None
    ) -> None:
        """Any (head, raw_body, request_method) either fails to
        construct with a ProtocolError or round-trips exactly."""
        try:
            msg = HTTP(
                head=head, raw_body=raw_body, request_method=request_method
            )
        except ProtocolError:
            return
        _read_every_accessor(msg)
        assert (msg.head, msg.raw_body) == (head, raw_body)
        assert (
            HTTP.decode(
                head + raw_body, request_method=request_method, closed=True
            )
            == msg
        )
