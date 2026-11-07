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
  runs on a schedule, so each run draws new inputs.

Select a profile with ``HYPOTHESIS_PROFILE`` (read once, at import
time) — e.g. ``HYPOTHESIS_PROFILE=nightly pytest tests/test_fuzz.py``
reproduces a nightly run locally. The profiles are registered and
loaded in conftest.py, so every property test in the
suite gets them, including under a test selection that never imports
this file (mutmut's, for one).
"""

import contextlib
import importlib.util
import struct
import sys
from dataclasses import replace
from ipaddress import IPv6Address
from pathlib import Path

import pytest
from hypothesis import assume, event, example, given
from hypothesis import strategies as st

from conftest import (
    FIXTURES,
    corpus_frames,
    pcap_frames,
    tls_client_hello_record,
)
from netprotocols import (
    AH,
    ARP,
    BGP,
    CDP,
    DHCP,
    DNS,
    ESP,
    GRE,
    HSRP,
    HTTP,
    IGMP,
    LLC,
    LLDP,
    LLDPTLV,
    MPLS,
    NTP,
    NTPMAC,
    OSPF,
    OSPFLSA,
    PIM,
    RADIUS,
    RIP,
    SCTP,
    SNAP,
    STP,
    STUN,
    TCP,
    TFTP,
    TLS,
    UDP,
    VLAN,
    VRRP,
    VXLAN,
    AHv6,
    BGPPathAttribute,
    BGPPrefix,
    DNSOverTCP,
    Ethernet,
    HSRPAdvertise,
    HSRPv2,
    ICMPv4,
    ICMPv6,
    InvalidFieldError,
    IPv4,
    IPv6,
    IPv6DestinationOptions,
    IPv6Fragment,
    IPv6HopByHopOptions,
    IPv6Routing,
    LLDPChassisID,
    LLDPPortID,
    MPLSLabel,
    NTPControl,
    Packet,
    PIMHello,
    PIMJoinPrune,
    PIMRegister,
    Protocol,
    ProtocolError,
    RADIUSAttribute,
    RADIUSVendorAttribute,
    RIPAuthentication,
    RIPEntry,
    SCTPChunk,
    SCTPParameter,
    TCPOption,
    TLSClientHello,
    TLSExtension,
    TLSServerNamePeek,
    TruncatedHeaderError,
    VRRPv6,
    decode_frame,
    peek_server_name,
)
from strategies import (
    OSPF_LSA_BODIES,
    ROUND_TRIP_STRATEGIES,
    bgp_path_attributes,
    bgp_prefixes,
    cdp_pdus,
    hsrp_advertisements,
    hsrp_messages,
    hsrpv2_messages,
    http_context_responses,
    http_messages,
    http_wire,
    lldp_lldpdus,
    mpls_stacks,
    ospf_lsa_headers,
    ospf_lsas,
    ospf_packets,
    pim_headers,
    sctp_chunks,
    sctp_headers,
    stp_headers,
    stp_mst_config_ids,
    stp_msti_messages,
    tls_client_hellos,
    tls_records,
    vrrp_headers,
)
from test_corpus import walk
from test_sctp import ACCESSOR_TYPES

ALL_PROTOCOLS = (
    Ethernet,
    VLAN,
    LLC,
    SNAP,
    LLDP,
    STP,
    CDP,
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
    MPLS,
    VXLAN,
    OSPF,
    RIP,
    RADIUS,
    NTP,
    NTPControl,
    HSRP,
    HSRPAdvertise,
    HSRPv2,
    VRRP,
    VRRPv6,
    BGP,
    TFTP,
    STUN,
    TLS,
)


def _shipped_protocol_classes() -> set[type[Protocol]]:
    """Every concrete protocol class netprotocols ships, discovered by
    walking Protocol.__subclasses__() to every depth, independently of
    the ALL_PROTOCOLS list.

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
# well-formed TLV by chance. This strategy builds well-formed ones.
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
    strategies.py. Each protocol's own test file also round-trips a
    real captured header (``test_arp.py::test_round_trip`` and similarly
    for the others): a fixed example, beside the space this property
    explores."""

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


#: Routing headers of every type this library resolves, with arbitrary
#: type-specific data (any CmprI/CmprE/Pad/Last Entry) of a legal
#: length; the destinations include a malformed one.
_routing_headers = st.builds(
    lambda routing_type, segments_left, blocks, seed: IPv6Routing(
        next_header=59,
        hdr_ext_len=blocks,
        routing_type=routing_type,
        segments_left=segments_left,
        data=(seed * (4 + blocks * 8))[: 4 + blocks * 8],
    ),
    routing_type=st.integers(0, 5),
    segments_left=st.integers(0, 255),
    blocks=st.integers(0, 8),
    seed=st.binary(min_size=1, max_size=16),
)
_destinations = st.sampled_from(["2001:db8::1", "::", "not an address", ""])


class TestIPv6RoutingFinalDestinationSafety:
    @given(data=fuzz_input, dst=_destinations)
    def test_decoded_header_never_raises(self, data: bytes, dst: str) -> None:
        """``final_destination`` returns an address string or ``None``
        on whatever bytes a Routing header decodes from."""
        with contextlib.suppress(ProtocolError):
            header = IPv6Routing.decode(data)
            final = header.final_destination(dst)
            assert final is None or isinstance(IPv6Address(final), IPv6Address)

    @given(header=_routing_headers, dst=_destinations)
    def test_every_type_and_shape_never_raises(
        self, header: IPv6Routing, dst: str
    ) -> None:
        final = header.final_destination(dst)
        assert final is None or isinstance(IPv6Address(final), IPv6Address)

    @given(header=_routing_headers)
    def test_memoryview_decode_agrees(self, header: IPv6Routing) -> None:
        raw = bytes(header)
        view = IPv6Routing.decode(memoryview(raw))
        assert view.final_destination(
            "2001:db8::1"
        ) == header.final_destination("2001:db8::1")


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


@st.composite
def _sctp_init_chunks(draw: st.DrawFn) -> SCTPChunk:
    """An INIT or INIT ACK: 16 drawn fixed bytes and parameters built to
    tile, a State Cookie among the types drawn, the last parameter's
    padding perhaps dropped, then left whole or given 1-3 changed
    bytes, a cut, or a 1-3-byte tail."""
    parameters = draw(
        st.lists(
            st.builds(
                SCTPParameter,
                st.one_of(
                    st.just(7),
                    st.sampled_from([5, 6, 9, 11, 12, 0x8000, 0x8008, 0xC000]),
                    st.integers(0, 0xFFFF),
                ),
                st.binary(max_size=24),
            ),
            max_size=5,
        )
    )
    raw = bytearray(draw(st.binary(min_size=16, max_size=16)))
    raw += b"".join(map(bytes, parameters))
    if parameters and draw(st.booleans()):
        padding = -parameters[-1].length % 4
        del raw[len(raw) - padding :]
    damage = draw(st.sampled_from(["none", "none", "mutate", "cut", "tail"]))
    if damage == "mutate":
        for _ in range(draw(st.integers(1, 3))):
            at = draw(st.integers(0, len(raw) - 1))
            raw[at] = draw(st.integers(0, 255))
    elif damage == "cut":
        raw = raw[: draw(st.integers(0, len(raw)))]
    elif damage == "tail":
        raw += draw(st.binary(min_size=1, max_size=3))
    event(f"SCTP INIT chunk: {damage}")
    return SCTPChunk(
        draw(st.sampled_from([1, 2])), draw(st.integers(0, 255)), bytes(raw)
    )


class TestSCTPChunkAccessorSafety:
    @given(
        data=st.one_of(
            fuzz_input,
            _sctp_like,
            _sctp_init_chunks().map(lambda chunk: bytes(12) + bytes(chunk)),
        )
    )
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
            _read_every_sctp_chunk_accessor(chunk)

    @given(
        chunk=st.one_of(
            st.builds(
                SCTPChunk,
                type=st.sampled_from([0, 1, 2, 3, 64]),
                flags=st.integers(0, 0xFF),
                value=st.one_of(
                    st.binary(max_size=64),
                    st.lists(
                        st.sampled_from([0, 0, 1, 2, 4, 7, 8, 0xFF]),
                        max_size=64,
                    ).map(bytes),
                ),
            ),
            _sctp_init_chunks(),
        )
    )
    def test_typed_accessors_answer_and_parameters_tile_or_raise(
        self, chunk: SCTPChunk
    ) -> None:
        """Every typed accessor but parameters answers a value or None
        for any value of the five chunk types they read. The parameters
        either tile the value after the 16 fixed bytes exactly, each but
        the last padded to 4 bytes and the last with its padding or
        without it, or raise InvalidFieldError, where the reference walk
        says so."""
        _read_every_sctp_chunk_accessor(chunk)
        blocks = chunk.gap_ack_blocks
        if blocks is not None:
            assert len(blocks) == chunk.num_gap_ack_blocks

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


#: Every typed SCTPChunk accessor but parameters, each of which must
#: answer a value or None on any chunk.
_SCTP_CHUNK_ACCESSORS = (
    "immediate",
    "unordered",
    "beginning_fragment",
    "ending_fragment",
    "tsn",
    "stream_id",
    "stream_sequence_number",
    "message_id",
    "ppid",
    "fragment_sequence_number",
    "user_data",
    "initiate_tag",
    "a_rwnd",
    "outbound_streams",
    "inbound_streams",
    "initial_tsn",
    "state_cookie",
    "cumulative_tsn_ack",
    "num_gap_ack_blocks",
    "num_duplicate_tsns",
    "gap_ack_blocks",
    "duplicate_tsns",
)


def _read_every_sctp_chunk_accessor(chunk: SCTPChunk) -> None:
    """Read every typed accessor, check the parameters against
    _reference_parameter_walk, and decode the user data through the
    default, empty ``sctp.ppid`` table."""
    for name in _SCTP_CHUNK_ACCESSORS:
        getattr(chunk, name)
    _read_sctp_parameters(chunk)
    assert chunk.decode_user_data() is None


def _reference_parameter_walk(
    chunk: SCTPChunk,
) -> tuple[tuple[int, bytes], ...] | int | None:
    """Walk an INIT or INIT ACK's parameters independently of
    netprotocols: ``None`` for another chunk type or a value shorter
    than the 16 fixed bytes, the offset in the value of the parameter
    that does not walk, and the ``(type, value)`` pairs otherwise. The
    padding after each parameter is skipped unread, and the value may
    end inside the last parameter's padding."""
    if chunk.type not in (1, 2) or len(chunk.value) < 16:
        return None
    value, offset, pairs = chunk.value, 16, []
    while offset < len(value):
        if len(value) - offset < 4:
            return offset
        type_ = int.from_bytes(value[offset : offset + 2])
        length = int.from_bytes(value[offset + 2 : offset + 4])
        if length < 4 or offset + length > len(value):
            return offset
        pairs.append((type_, value[offset + 4 : offset + length]))
        offset += length + -length % 4
    return tuple(pairs)


def _read_sctp_parameters(chunk: SCTPChunk) -> None:
    """Read an SCTP chunk's parameters: they raise InvalidFieldError at
    the offset _reference_parameter_walk gives, are None, or are the
    parameters exactly where it says so, and they tile the value after
    the 16 fixed bytes. The State Cookie never raises: it is an INIT
    ACK's first State Cookie parameter's value, and None wherever the
    parameters raise."""
    expected = _reference_parameter_walk(chunk)
    cookie = chunk.state_cookie
    try:
        parameters = chunk.parameters
    except InvalidFieldError as error:
        assert isinstance(expected, int)
        assert error.field == "value"
        assert error.offset == expected
        assert cookie is None
        event("SCTP parameters: malformed")
        return
    if parameters is None:
        assert expected is None
        event("SCTP parameters: none")
        return
    assert tuple((p.type, p.value) for p in parameters) == expected
    cookies = [p.value for p in parameters if p.type == 7]
    if chunk.type == 2 and cookies:
        assert cookie == cookies[0]
        event("SCTP State Cookie: read")
    else:
        assert cookie is None
    rest = len(chunk.value) - 16
    padded = [len(bytes(parameter)) for parameter in parameters]
    if parameters:
        assert sum(padded[:-1]) + parameters[-1].length <= rest
    assert rest <= sum(padded)
    for parameter in parameters:
        assert parameter.type_name
    count = "2+" if len(parameters) >= 2 else len(parameters)
    event(f"SCTP parameters: {count}")


def test_the_sctp_accessor_lists_name_every_property() -> None:
    """_SCTP_CHUNK_ACCESSORS and parameters, which
    _read_sctp_parameters reads, and test_sctp.py's ACCESSOR_TYPES,
    cover every SCTPChunk property beyond the display helpers the walk
    property reads itself."""
    properties = {
        name
        for name, attr in vars(SCTPChunk).items()
        if isinstance(attr, property)
    }
    display = {"length", "type_name", "flags_str", "unrecognized_action"}
    assert properties - display == {*_SCTP_CHUNK_ACCESSORS, "parameters"}
    assert properties - display == set(ACCESSOR_TYPES)


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
    for lsa in ospf.lsas or ():
        _read_every_lsa_accessor(lsa)
    headers = [lsa.header for lsa in ospf.lsas or ()]
    headers += ospf.ls_acknowledgments or ()
    for header in headers:
        assert header.ls_type_name
        _ = header.options_str, header.ls_checksum_hex_str
        _ = header.ls_sequence_number_hex_str


#: Each LSA body accessor and the LS types it answers for.
_LSA_ACCESSORS = {
    "router": {1},
    "network": {2},
    "summary": {3, 4},
    "external": {5, 7},
}


def _read_every_lsa_accessor(lsa: OSPFLSA) -> None:
    """Read every LSA body accessor and its records' display helpers:
    the one for the LSA's type re-encodes to its body, the others are
    None."""
    for name, ls_types in _LSA_ACCESSORS.items():
        record = getattr(lsa, name)
        if lsa.header.ls_type not in ls_types:
            assert record is None
            continue
        assert bytes(record) == lsa.body
    router = lsa.router
    if router is not None:
        _ = router.flags_str, router.v, router.e, router.b
        assert router.link_count == len(router.links)
        for link in router.links:
            assert link.type_name
            assert link.tos_count == len(link.tos)


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


class TestOSPFLSABodies:
    """The constructor checks a decoded LS type's body framing, so it
    raises only InvalidFieldError, and an LSA it accepts answers every
    body accessor; a body built from records parses back to them."""

    @given(
        ls_type=st.sampled_from([1, 2, 3, 4, 5, 7, 9]),
        body=st.one_of(
            st.binary(max_size=64),
            st.lists(
                st.sampled_from([0, 0, 1, 2, 3, 4, 12, 0xFF]), max_size=64
            ).map(bytes),
        ),
        header=ospf_lsa_headers(),
    )
    def test_arbitrary_bodies(self, ls_type, body, header) -> None:
        header = replace(header, ls_type=ls_type, length=20 + len(body))
        try:
            lsa = OSPFLSA(header, body)
        except InvalidFieldError as error:
            assert error.field == "body"
            assert error.offset is None
            return
        _read_every_lsa_accessor(lsa)

    @given(data=st.data(), ls_type=st.sampled_from(sorted(OSPF_LSA_BODIES)))
    def test_records_round_trip(self, data, ls_type) -> None:
        record = data.draw(OSPF_LSA_BODIES[ls_type])
        body = bytes(record)
        header = replace(
            data.draw(ospf_lsa_headers()),
            ls_type=ls_type,
            length=20 + len(body),
        )
        lsa = OSPFLSA(header, body)
        accessor = next(
            name for name, types in _LSA_ACCESSORS.items() if ls_type in types
        )
        assert getattr(lsa, accessor) == record
        _read_every_lsa_accessor(lsa)

    @given(lsa=ospf_lsas())
    def test_drawn_lsas_decode_in_an_update(self, lsa: OSPFLSA) -> None:
        body = (1).to_bytes(4, "big") + bytes(lsa)
        ospf = OSPF.decode(
            struct.pack("!BBH", 2, 4, 24 + len(body)) + bytes(20) + body
        )
        assert ospf.lsas == (lsa,)
        _read_every_lsa_accessor(ospf.lsas[0])


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


#: The captured TFTP messages, every one past its UDP header: requests
#: with and without options, DATA, ACK, ERROR and OACK.
_TFTP_MESSAGES = [frame[42:] for frame in pcap_frames(FIXTURES / "tftp.pcap")]

#: Bytes from a small alphabet, zero bytes frequent, so strings,
#: empty strings and option pairs turn up far more often than in free
#: bytes. Led by an opcode decode accepts.
_tftp_like = st.tuples(
    st.sampled_from([bytes([0, opcode]) for opcode in range(1, 7)]),
    st.lists(
        st.sampled_from([0, 0, 0, 0x61, 0x62, 0x31, 0x32, 0xFF]),
        max_size=40,
    ).map(bytes),
).map(b"".join)


@st.composite
def _tftp_seeded(draw: st.DrawFn) -> bytes:
    """A captured TFTP message, a few bytes past the opcode changed
    (often to zero), cut anywhere and followed by nothing, Ethernet-like
    zero padding, an FCS-like 4 bytes or a few free bytes."""
    raw = bytearray(draw(st.sampled_from(_TFTP_MESSAGES)))
    for _ in range(draw(st.integers(0, 3))):
        position = draw(st.integers(2, len(raw) - 1))
        raw[position] = draw(st.sampled_from([0, draw(st.integers(0, 255))]))
    cut = draw(st.integers(0, len(raw)))
    tail = draw(
        st.one_of(
            st.just(b""),
            st.binary(min_size=1, max_size=14).map(lambda b: bytes(len(b))),
            st.just(b"\xde\xad\xbe\xef"),
            st.binary(max_size=8),
        )
    )
    return bytes(raw[:cut]) + tail


@st.composite
def _tftp_long_numbers(draw: st.DrawFn) -> bytes:
    """A request or an OACK whose number option holds a run of digits,
    as often past int()'s 4,300-digit limit as short, leading zeros or
    not."""
    opcode = draw(st.sampled_from([1, 2, 6]))
    name = draw(st.sampled_from(["blksize", "TIMEOUT", "tsize", "windowSize"]))
    zeros = draw(st.sampled_from([0, 1, 4300, 5000]))
    width = draw(
        st.one_of(
            st.integers(0, 25), st.integers(4290, 4310), st.integers(4311, 6000)
        )
    )
    digit = draw(st.sampled_from("0123456789"))
    value = "0" * zeros + digit * width
    request = b"" if opcode == 6 else b"f\x00octet\x00"
    option = f"{name}\x00{value}\x00".encode()
    return bytes([0, opcode]) + request + option


def _tftp_rebuilt(tftp: TFTP) -> bytes:
    """Rebuild a decoded message's body from its accessors alone.

    Exact for a body of ASCII bytes, which the accessors read verbatim;
    an accessor answering None for its own opcode fails the rebuild.
    """
    options = b"".join(
        f"{name}\x00{value}\x00".encode() for name, value in tftp.options
    )
    if tftp.opcode in (1, 2):
        return f"{tftp.filename}\x00{tftp.mode}\x00".encode() + options
    if tftp.opcode == 6:
        return options
    if tftp.opcode == 5:
        message = f"{tftp.error_message}\x00".encode()
        return tftp.error_code.to_bytes(2, "big") + message
    tail = tftp.data if tftp.opcode == 3 else b""
    return tftp.block.to_bytes(2, "big") + tail


class TestTFTPAccessorSafety:
    @given(
        data=st.one_of(
            _tftp_seeded(), _tftp_like, _tftp_long_numbers(), fuzz_input
        )
    )
    def test_decode_and_every_accessor_are_total(self, data: bytes) -> None:
        """decode() raises only for an opcode other than 1-6 or a
        mandatory field cut short, keeps a prefix of the buffer that
        round-trips, and every accessor answers; for an ASCII body the
        accessors describe every byte of it."""
        try:
            tftp = TFTP.decode(data)
        except ProtocolError:
            return
        assert 1 <= tftp.opcode <= 6
        assert bytes(tftp) == data[: tftp.header_len]
        assert TFTP.decode(bytes(tftp)) == tftp
        assert tftp.opcode_name
        _ = (tftp.blksize, tftp.timeout, tftp.tsize, tftp.windowsize)
        _ = (tftp.error_name, tftp.option("blksize"))
        rebuilt = _tftp_rebuilt(tftp)
        assert rebuilt == tftp.body or not tftp.body.isascii()
        event(f"TFTP opcode: {tftp.opcode_name}")
        event(f"TFTP options: {len(tftp.options)}")
        event(f"TFTP left undecoded: {len(data) > tftp.header_len}")


#: The captured RADIUS packets, every one past its UDP header.
_RADIUS_PACKETS = [
    frame[42:] for frame in pcap_frames(FIXTURES / "radius.pcap")
]


@st.composite
def _radius_seeded(draw: st.DrawFn) -> bytes:
    """A captured RADIUS packet, a few bytes changed (the Length and
    the attribute headers among them), cut anywhere and followed by
    nothing, an FCS-like 4 bytes or up to 23 more: well-formed and
    broken attribute lists, and Lengths near the buffer's, which free
    bytes rarely reach."""
    raw = bytearray(draw(st.sampled_from(_RADIUS_PACKETS)))
    for _ in range(draw(st.integers(0, 3))):
        position = draw(st.integers(0, len(raw) - 1))
        raw[position] = draw(st.integers(0, 255))
    cut = draw(st.integers(0, len(raw)))
    tail = draw(
        st.one_of(
            st.just(b""), st.just(b"\xde\xad\xbe\xef"), st.binary(max_size=23)
        )
    )
    return bytes(raw[:cut]) + tail


def _read_every_radius_attribute(radius: RADIUS) -> None:
    """Walk the attributes and read every value and display accessor:
    the walk either tiles the attributes exactly or raises
    InvalidFieldError, and nothing else raises; so does each
    Vendor-Specific's sub-attribute walk (see _read_vendor_attributes)."""
    try:
        attributes = radius.parsed_attributes
    except InvalidFieldError:
        event("RADIUS attributes: malformed")
        return
    assert b"".join(map(bytes, attributes)) == radius.attributes
    for found in attributes:
        assert found.type_name
        _ = found.value
        _read_vendor_attributes(found)
    _ = (radius.user_name, radius.nas_ip_address)
    _ = (radius.nas_port, radius.framed_ip_address)
    event(f"RADIUS attributes: {len(attributes)}")


#: The Vendor-Ids whose sub-attributes are in a format other than RFC
#: 2865 §5.26's (FreeRADIUS 3.2.5's dictionaries): USR, Alcatel-ESAM,
#: Lucent, Telrad, Starent, Kineto and WiMAX.
_NONSTANDARD_VENDOR_IDS = frozenset({429, 637, 4846, 5323, 8164, 16445, 24757})

#: The reference walk's answer for a Vendor-Specific it rejects.
_RAISES = "raises"


def _reference_vendor_walk(
    found: RADIUSAttribute,
) -> tuple[tuple[int, bytes], ...] | str | None:
    """Walk a RADIUS attribute's Vendor-Specific String independently
    of netprotocols: ``None`` for a type other than 26, ``_RAISES`` for
    data under 5 bytes, ``None`` for a non-standard Vendor-Id,
    ``_RAISES`` for a String the sub-attributes do not tile, and the
    ``(Vendor-Type, value)`` pairs otherwise."""
    if found.type != 26:
        return None
    if len(found.data) < 5:
        return _RAISES
    if int.from_bytes(found.data[:4], "big") in _NONSTANDARD_VENDOR_IDS:
        return None
    string, offset, pairs = found.data[4:], 0, []
    while offset < len(string):
        if offset + 1 == len(string):
            return _RAISES
        length = string[offset + 1]
        if length < 2 or offset + length > len(string):
            return _RAISES
        pairs.append((string[offset], string[offset + 2 : offset + length]))
        offset += length
    return tuple(pairs)


def _read_vendor_attributes(found: RADIUSAttribute) -> None:
    """Read a RADIUS attribute's Vendor-Specific accessors: the
    Vendor-Id is its first 4 bytes or None, never raising; the
    sub-attribute walk raises InvalidFieldError, is None, or is the
    sub-attributes exactly where _reference_vendor_walk says so."""
    vendor = found.vendor_id
    name = found.vendor_name
    if found.type == 26 and len(found.data) >= 4:
        assert vendor == int.from_bytes(found.data[:4], "big")
        assert name is not None
    else:
        assert (vendor, name) == (None, None)
    expected = _reference_vendor_walk(found)
    try:
        subs = found.vendor_attributes
    except InvalidFieldError:
        assert expected == _RAISES
        event("RADIUS Vendor-Specific: malformed")
        return
    if subs is None:
        assert expected is None
        event(f"RADIUS Vendor-Specific: kept raw ({found.type == 26})")
        return
    assert tuple((sub.type, sub.data) for sub in subs) == expected
    event(f"RADIUS Vendor-Specific sub-attributes: {len(subs)}")


@st.composite
def _radius_vendor_specifics(draw: st.DrawFn) -> RADIUSAttribute:
    """A Vendor-Specific: a captured or hand-picked Vendor-Id (a
    non-standard one among them) and sub-attributes built to tile, a
    few bytes then changed and the whole perhaps cut short, or free
    bytes."""
    vendor = draw(
        st.one_of(
            st.sampled_from(sorted(_NONSTANDARD_VENDOR_IDS | {9, 311, 14122})),
            st.integers(0, 0xFFFFFFFF),
        )
    )
    string = draw(
        st.one_of(
            st.lists(
                st.builds(
                    RADIUSVendorAttribute,
                    st.integers(0, 255),
                    st.binary(max_size=20),
                ),
                max_size=4,
            ).map(lambda found: b"".join(map(bytes, found))),
            st.binary(max_size=24),
        )
    )
    raw = bytearray(vendor.to_bytes(4, "big") + string)
    for _ in range(draw(st.integers(0, 2))):
        if raw:
            raw[draw(st.integers(0, len(raw) - 1))] = draw(st.integers(0, 255))
    if draw(st.booleans()):
        raw = raw[: draw(st.integers(0, len(raw)))]
    return RADIUSAttribute(26, bytes(raw))


class TestRADIUSVendorSpecificSafety:
    @given(found=_radius_vendor_specifics())
    @example(
        found=RADIUSAttribute(26, (429).to_bytes(4, "big") + b"\x01\x03\x00")
    )
    @example(
        found=RADIUSAttribute(26, (637).to_bytes(4, "big") + b"\x01\x03\x00")
    )
    @example(
        found=RADIUSAttribute(26, (4846).to_bytes(4, "big") + b"\x01\x03\x00")
    )
    @example(
        found=RADIUSAttribute(26, (5323).to_bytes(4, "big") + b"\x01\x03\x00")
    )
    @example(
        found=RADIUSAttribute(26, (8164).to_bytes(4, "big") + b"\x01\x03\x00")
    )
    @example(
        found=RADIUSAttribute(26, (16445).to_bytes(4, "big") + b"\x01\x03\x00")
    )
    @example(
        found=RADIUSAttribute(26, (24757).to_bytes(4, "big") + b"\x01\x03\x00")
    )
    def test_every_vendor_accessor_is_total(
        self, found: RADIUSAttribute
    ) -> None:
        """A Vendor-Specific's sub-attribute walk raises
        InvalidFieldError, is None, or is the sub-attributes exactly
        where an independent reference walk says so (see
        _read_vendor_attributes), and the attribute round-trips inside
        a packet."""
        _read_vendor_attributes(found)
        attributes = bytes(found)
        radius = RADIUS(
            code=1,
            identifier=0,
            length=20 + len(attributes),
            attributes=attributes,
        )
        assert RADIUS.decode(bytes(radius)).parsed_attributes == (found,)


class TestRADIUSAccessorSafety:
    @given(data=st.one_of(_radius_seeded(), fuzz_input))
    def test_decode_and_every_accessor_are_total(self, data: bytes) -> None:
        """decode() raises only for a Length below 20 or past the
        buffer, and keeps exactly the bytes the Length covers; the
        attribute walk and the accessors are total (see
        _read_every_radius_attribute)."""
        try:
            radius = RADIUS.decode(data)
        except ProtocolError:
            length = int.from_bytes(data[2:4]) if len(data) >= 4 else 0
            assert len(data) < 20 or not 20 <= length <= len(data)
            return
        assert bytes(radius) == data[: radius.length]
        assert RADIUS.decode(bytes(radius)) == radius
        assert radius.code_name
        _read_every_radius_attribute(radius)


#: The captured STUN messages, each TCP segment's as one stream.
_STUN_MESSAGES = [
    frame[66:] if frame[23] == 6 else frame[42:]
    for frame in pcap_frames(FIXTURES / "stun.pcap")
]

#: Bytes from a small alphabet behind a header decode accepts, so
#: attribute headers, lengths that fit or overrun, the address families
#: and FINGERPRINT's and XOR-MAPPED-ADDRESS's types turn up far more
#: often than in free bytes.
_stun_like = st.tuples(
    st.sampled_from([b"\x00\x01", b"\x01\x01", b"\x01\x11"]),
    st.lists(
        st.sampled_from([0, 0, 1, 2, 4, 8, 9, 0x0A, 0x20, 0x28, 0x80, 0xFF]),
        max_size=120,
    ).map(bytes),
).map(
    lambda parts: (
        parts[0]
        + (len(parts[1]) - len(parts[1]) % 4).to_bytes(2, "big")
        + b"\x21\x12\xa4\x42"
        + bytes(range(12))
        + parts[1]
    )
)


@st.composite
def _stun_seeded(draw: st.DrawFn) -> bytes:
    """A captured message, a few bytes past the header changed, whole
    or cut anywhere, and followed by nothing or a few more bytes."""
    raw = bytearray(draw(st.sampled_from(_STUN_MESSAGES)))
    for _ in range(draw(st.integers(0, 3)) if len(raw) > 20 else 0):
        position = draw(st.integers(20, len(raw) - 1))
        raw[position] = draw(st.integers(0, 255))
    cut = draw(st.one_of(st.just(len(raw)), st.integers(0, len(raw))))
    return bytes(raw[:cut]) + draw(st.binary(max_size=12))


class TestSTUNAccessorSafety:
    @given(data=st.one_of(_stun_seeded(), _stun_like, fuzz_input))
    def test_decode_and_every_accessor_are_total(self, data: bytes) -> None:
        """decode() raises only a ProtocolError and keeps the message's
        bytes exactly; parsed_attributes raises only InvalidFieldError,
        and when it does not, the attributes tile the raw bytes but for
        their padding; every other accessor never raises."""
        try:
            stun = STUN.decode(data)
        except ProtocolError:
            return
        assert bytes(stun) == data[: stun.header_len]
        assert STUN.decode(bytes(stun)) == stun
        assert stun.message_type_name and stun.class_name
        _ = (stun.mapped_address, stun.xor_mapped_address, stun.software)
        _ = (stun.error_code, stun.error_reason, stun.unknown_attributes)
        _ = (stun.message_integrity, stun.fingerprint, stun.next_protocol())
        try:
            attributes = stun.parsed_attributes
        except InvalidFieldError:
            event("STUN attributes malformed")
            assert stun.fingerprint is None
            return
        cursor = 0
        for attribute in attributes:
            wire = bytes(attribute)
            assert stun.attributes[cursor : cursor + 4] == wire[:4]
            end = cursor + 4 + len(attribute.value)
            assert stun.attributes[cursor + 4 : end] == attribute.value
            assert attribute.type_name
            _ = (attribute.address, stun.xor_address(attribute))
            cursor += len(wire)
        assert cursor == stun.length
        event(f"STUN fingerprint: {stun.fingerprint is not None}")
        event(f"STUN attributes: {min(len(attributes), 3)}")


#: The captured NTP messages, every one past its UDP header.
_NTP_MESSAGES = [frame[42:] for frame in pcap_frames(FIXTURES / "ntp.pcap")]

#: The extension field Lengths and MAC Key IDs a walk has to weigh,
#: and bytes of either, so that small alphabets reach them.
_ntp_tail = st.lists(
    st.sampled_from([0, 0, 0x10, 0x14, 0x18, 0x1C, 0x24, 0x01, 0x04, 0xFF]),
    max_size=80,
).map(bytes)


@st.composite
def _ntp_seeded(draw: st.DrawFn) -> bytes:
    """A captured NTP message, a few bytes after the header changed,
    cut anywhere past it and followed by nothing, an FCS-like 4 bytes
    or bytes from a small alphabet: real extension fields and MACs,
    with Lengths and remainders that free bytes rarely reach."""
    raw = bytearray(draw(st.sampled_from(_NTP_MESSAGES)))
    for _ in range(draw(st.integers(0, 3))):
        if len(raw) > 48:
            position = draw(st.integers(48, len(raw) - 1))
            raw[position] = draw(st.integers(0, 255))
    cut = draw(st.integers(48, len(raw)))
    tail = draw(
        st.one_of(st.just(b""), st.just(b"\xde\xad\xbe\xef"), _ntp_tail)
    )
    return bytes(raw[:cut]) + tail


#: NTP's display accessors, every one of which must answer on any
#: decoded instance.
_NTP_ACCESSORS = (
    "leap_name",
    "mode_name",
    "stratum_name",
    "poll_seconds",
    "precision_seconds",
    "root_delay_seconds",
    "root_dispersion_seconds",
    "kiss_code",
    "reference_id_str",
    "reference_time",
    "origin_time",
    "receive_time",
    "transmit_time",
)


def _ntp_rejection(data: bytes) -> str | None:
    """What NTP.decode() must reject ``data`` for, judged in its order:
    ``"version"`` outside 1-4, then ``"mode"`` 6 or 7, at any length;
    then ``"truncated"``, shorter than 48 bytes; or ``None``."""
    if data:
        version, mode = (data[0] >> 3) & 7, data[0] & 7
        if not 1 <= version <= 4:
            return "version"
        if mode in (6, 7):
            return "mode"
    return "truncated" if len(data) < 48 else None


def _ntp_decode(data: bytes) -> NTP | str:
    """Decode ``data``, or say what NTP.decode() rejected it for, in
    :func:`_ntp_rejection`'s words."""
    try:
        return NTP.decode(data)
    except TruncatedHeaderError:
        return "truncated"
    except InvalidFieldError as error:
        return str(error.field)


def _assert_ntp_body_tiles(ntp: NTP) -> None:
    """The extension fields, the MAC and the remainder tile the body,
    and every field the walk accepted keeps RFC 7822's Length rules."""
    fields, mac = ntp.extension_fields, ntp.mac
    tiled = b"".join(bytes(field) for field in fields)
    tiled += (bytes(mac) if mac is not None else b"") + ntp.remainder
    assert tiled == ntp.body
    assert mac is None or not ntp.remainder
    assert ntp.version == 4 or not fields
    for field in fields:
        assert len(bytes(field)) >= 16 and len(bytes(field)) % 4 == 0
        assert field.type_name


class TestNTPAccessorSafety:
    @given(data=st.one_of(_ntp_seeded(), fuzz_input))
    def test_decode_and_every_accessor_are_total(self, data: bytes) -> None:
        """decode() raises only on the 48-byte header, for the first
        reason that applies (a version outside 1-4, then mode 6 or 7,
        at any length, then too short), and keeps every byte after it;
        the accessors never raise, and the extension fields, the MAC
        and the remainder tile the body exactly."""
        ntp = _ntp_decode(data)
        if not isinstance(ntp, NTP):
            assert ntp == _ntp_rejection(data)
            return
        assert _ntp_rejection(data) is None
        assert bytes(ntp) == data
        assert NTP.decode(bytes(ntp)) == ntp
        _assert_ntp_body_tiles(ntp)
        for name in _NTP_ACCESSORS:
            getattr(ntp, name)
        mac = ntp.mac
        event(f"NTP extension fields: {len(ntp.extension_fields)}")
        event(f"NTP MAC: {None if mac is None else len(bytes(mac))}")
        event(f"NTP remainder: {bool(ntp.remainder)}")


#: NTP control messages built by hand (a read variables request, a
#: response with variables, an error response, and a request and an
#: error response each with a MAC), then every captured one, past its
#: UDP header.
_NTP_CONTROL_MESSAGES = [
    bytes(NTPControl(leap=3, opcode=2, sequence=1)),
    bytes(
        NTPControl(
            leap=3,
            response=True,
            opcode=2,
            sequence=1,
            status=0xC016,
            data=b'version="ntpd ntpsec-1.2.2"\r\n',
            padding=bytes(3),
        )
    ),
    bytes(NTPControl(response=True, error=True, opcode=2, status=0x0500)),
    bytes(
        NTPControl(
            opcode=8,
            data=b"logconfig =syncall",
            padding=bytes(2),
            mac=NTPMAC(3, bytes(range(16))),
        )
    ),
    bytes(
        NTPControl(
            response=True,
            error=True,
            opcode=8,
            status=0x0100,
            mac=NTPMAC(4, bytes(range(20))),
        )
    ),
    *(frame[42:] for frame in pcap_frames(FIXTURES / "ntp_control.pcap")),
]


@st.composite
def _ntp_control_seeded(draw: st.DrawFn) -> bytes:
    """A captured control message with a few bytes changed anywhere, its
    Count among them, cut anywhere and followed by nothing, 4 bytes or
    a run of bytes that a MAC or padding could be."""
    raw = bytearray(draw(st.sampled_from(_NTP_CONTROL_MESSAGES)))
    for _ in range(draw(st.integers(0, 3))):
        position = draw(st.integers(1, len(raw) - 1))
        raw[position] = draw(st.integers(0, 255))
    cut = draw(st.integers(0, len(raw)))
    tail = draw(
        st.one_of(
            st.just(b""),
            st.just(b"\xde\xad\xbe\xef"),
            st.binary(min_size=16, max_size=28),
        )
    )
    return bytes(raw[:cut]) + tail


#: NTPControl's display accessors, every one of which must answer on
#: any decoded instance.
_NTP_CONTROL_ACCESSORS = (
    "mode",
    "count",
    "leap_name",
    "opcode_name",
    "system_status",
    "error_code",
    "error_name",
    "variables",
)


def _ntp_control_rejection(data: bytes) -> str | None:
    """What NTPControl.decode() must reject ``data`` for, judged in its
    order: ``"version"`` outside 1-4, then ``"mode"`` other than 6, at
    any length; then ``"truncated"``, shorter than 12 bytes; then
    ``"count"`` above 468; then ``"truncated"``, a Count past the end;
    or ``None``."""
    if data:
        if not 1 <= (data[0] >> 3) & 7 <= 4:
            return "version"
        if data[0] & 7 != 6:
            return "mode"
    if len(data) < 12:
        return "truncated"
    count = struct.unpack_from("!H", data, 10)[0]
    if count > 468:
        return "count"
    return "truncated" if 12 + count > len(data) else None


class TestNTPControlAccessorSafety:
    @given(data=st.one_of(_ntp_control_seeded(), fuzz_input))
    def test_decode_and_every_accessor_are_total(self, data: bytes) -> None:
        """decode() raises only for the first reason that applies, and
        otherwise keeps every byte: the data, padding, MAC and remainder
        tile the message; the accessors never raise."""
        try:
            message = NTPControl.decode(data)
        except TruncatedHeaderError:
            assert _ntp_control_rejection(data) == "truncated"
            return
        except InvalidFieldError as error:
            assert _ntp_control_rejection(data) == error.field
            return
        assert _ntp_control_rejection(data) is None
        assert bytes(message) == data
        assert message.header_len == len(data)
        assert NTPControl.decode(bytes(message)) == message
        assert message.count == struct.unpack_from("!H", data, 10)[0]
        assert message.mac is None or not message.remainder
        for name in _NTP_CONTROL_ACCESSORS:
            getattr(message, name)
        event(f"NTPControl MAC: {message.mac is not None}")
        event(f"NTPControl remainder: {bool(message.remainder)}")


#: Constructed HSRP messages, packed by hand, not cut from
#: tests/fixtures/hsrp.pcap: every Op Code in every one of RFC 2281's
#: States, under the default Authentication Data, a configured password
#: and an empty one, with the recommended timers.
_HSRP_MESSAGES = [
    bytes([0, opcode, state, 3, 10, 100, 1, 0]) + auth + bytes([192, 0, 2, 1])
    for opcode in (0, 1, 2)
    for state in (0, 1, 2, 4, 8, 16)
    for auth in (b"cisco\x00\x00\x00", b"spark\x00\x00\x00", bytes(8))
]

#: A hand-built MD5 Authentication TLV in the layout of Wireshark's
#: packet-hsrp.c: Type 4, Length 28, Algorithm 1, Padding 0, Flags 0,
#: the sender's address 192.0.2.11, Key ID 1 and a 16-byte digest.
_HSRP_MD5_TLV = bytes.fromhex("041c 01 00 0000 c000020b 00000001") + bytes(
    range(16)
)

#: The values the Type and Length bytes of an MD5 Authentication TLV
#: are redrawn from: the ones decode() reads it at, the ones beside
#: them, and a few others.
_hsrp_md5_lead = st.sampled_from([0, 3, 4, 5, 27, 28, 29, 255])

#: The values HSRP.decode() weighs in its first three bytes, the ones
#: either side of what it accepts among them, and a few others.
_hsrp_lead = st.sampled_from([0, 1, 2, 3, 4, 5, 8, 15, 16, 17, 255])


@st.composite
def _hsrp_seeded(draw: st.DrawFn) -> bytes:
    """A constructed HSRP message, half the time with an MD5
    Authentication TLV after it whose Type and Length are now and then
    redrawn near the ones decode() reads it at, now and then a Version,
    Op Code or State redrawn near the values decode() accepts and a
    later byte changed, cut anywhere and followed by nothing, an
    FCS-like 4 bytes or free bytes: the guard's boundaries, the 50-byte
    rule's, which free bytes rarely reach, and every length."""
    raw = bytearray(draw(st.sampled_from(_HSRP_MESSAGES)))
    if draw(st.booleans()):
        raw += _HSRP_MD5_TLV
        for position in (20, 21):
            if draw(st.integers(0, 3)) == 0:
                raw[position] = draw(_hsrp_md5_lead)
    for position in range(3):
        if draw(st.integers(0, 3)) == 0:
            raw[position] = draw(_hsrp_lead)
    if draw(st.booleans()):
        raw[draw(st.integers(3, len(raw) - 1))] = draw(st.integers(0, 255))
    cut = draw(st.integers(0, len(raw)))
    tail = draw(
        st.one_of(
            st.just(b""), st.just(b"\xde\xad\xbe\xef"), st.binary(max_size=40)
        )
    )
    return bytes(raw[:cut]) + tail


#: HSRP's display accessors, every one of which must answer on any
#: decoded or constructed instance.
_HSRP_ACCESSORS = (
    "opcode_name",
    "state_name",
    "password",
    "auth_data_str",
    "is_default_auth",
    "virtual_mac",
    "header_len",
    "md5_authentication",
)


def _hsrp_rejection(data: bytes) -> str | None:
    """What HSRP.decode() must reject ``data`` for, judged in its order,
    each once its byte is present: ``"version"`` other than 0, then
    ``"opcode"`` outside 0-2, then ``"state"`` not one of RFC 2281's
    six; then ``"truncated"``, shorter than 20 bytes; or ``None``."""
    if len(data) > 0 and data[0] != 0:
        return "version"
    if len(data) > 1 and data[1] > 2:
        return "opcode"
    if len(data) > 2 and data[2] not in (0, 1, 2, 4, 8, 16):
        return "state"
    return "truncated" if len(data) < 20 else None


def _hsrp_decode(data: bytes) -> HSRP | str:
    """Decode ``data``, or say what HSRP.decode() rejected it for, in
    :func:`_hsrp_rejection`'s words."""
    try:
        return HSRP.decode(data)
    except TruncatedHeaderError:
        return "truncated"
    except InvalidFieldError as error:
        return str(error.field)


class TestHSRPAccessorSafety:
    @given(data=st.one_of(_hsrp_seeded(), fuzz_input))
    def test_decode_and_every_accessor_are_total(self, data: bytes) -> None:
        """decode() raises only for the first reason that applies (a
        Version other than 0, then an Op Code outside 0-2, then an
        unknown State, at any length, then too short), takes all 50
        bytes of a 50-byte buffer whose bytes 20-21 are 04 1c and
        exactly 20 of any other, and leaves the rest; the accessors
        never raise."""
        hsrp = _hsrp_decode(data)
        if not isinstance(hsrp, HSRP):
            assert hsrp == _hsrp_rejection(data)
            event(f"HSRP rejected: {hsrp}")
            return
        assert _hsrp_rejection(data) is None
        md5 = len(data) == 50 and data[20:22] == b"\x04\x1c"
        assert hsrp.header_len == (50 if md5 else 20)
        assert (hsrp.md5_authentication is not None) is md5
        assert bytes(hsrp) == data[: hsrp.header_len]
        assert HSRP.decode(bytes(hsrp)) == hsrp
        for name in _HSRP_ACCESSORS:
            getattr(hsrp, name)
        if hsrp.md5_authentication is not None:
            assert bytes(hsrp.md5_authentication) == data[20:]
            assert hsrp.md5_authentication.algorithm_name
        assert hsrp.virtual_mac.endswith(f":{hsrp.group:02x}")
        assert hsrp.password == hsrp.auth_data.rstrip(b"\x00")
        event(f"HSRP {hsrp.opcode_name} in {hsrp.state_name}")
        event(f"HSRP MD5 Authentication TLV: {md5}")

    @given(header=hsrp_messages(), trailer=st.binary(max_size=60))
    def test_trailing_bytes_stay_out_of_the_message(
        self, header: HSRP, trailer: bytes
    ) -> None:
        """Short of a 30-byte trailer opening with 04 1c, which is the
        MD5 Authentication TLV, the 20 bytes are the message, whatever
        follows them (an FCS, a TLV in a buffer of another length,
        anything); a message with the TLV followed by any byte keeps
        only its 20."""
        bare = replace(header, md5_authentication=None)
        assume(len(trailer) != 30 or trailer[:2] != b"\x04\x1c")
        decoded = HSRP.decode(bytes(bare) + trailer)
        assert decoded == bare
        assert decoded.header_len == 20
        if header.md5_authentication is not None and trailer:
            assert HSRP.decode(bytes(header) + trailer) == bare

    @given(header=hsrp_messages())
    def test_a_message_with_the_md5_tlv_round_trips(self, header: HSRP) -> None:
        """A message built with any MD5 Authentication TLV is 50 bytes,
        and decode() reads all 50 back, the TLV with them."""
        raw = bytes(header)
        assert len(raw) == header.header_len
        assert len(raw) == (20 if header.md5_authentication is None else 50)
        assert HSRP.decode(raw) == header
        assert HSRP.decode(memoryview(raw)) == header

    @given(
        opcode=st.integers(3, 0xFF),
        state=st.integers(0, 0xFF).filter(
            lambda value: value not in (0, 1, 2, 4, 8, 16)
        ),
    )
    def test_constructed_unknown_values_display(
        self, opcode: int, state: int
    ) -> None:
        """Construction accepts values decode() rejects, and the display
        helpers name them as unknown rather than raising."""
        hsrp = HSRP(0, opcode, state, 3, 10, 100, 1, 0, bytes(8), "0.0.0.0")
        assert hsrp.opcode_name == f"unknown ({opcode})"
        assert hsrp.state_name == f"unknown ({state})"
        for name in _HSRP_ACCESSORS:
            getattr(hsrp, name)


#: Hand-built HSRP interface-state Advertises, packed here in the layout
#: of Wireshark's packet-hsrp.c, not built by the library: both TLV
#: Types in each of the three States, with a few group counts.
_HSRP_ADVERTISES = [
    bytes([0, 3]) + struct.pack("!HHBBHHI", kind, 14, state, 0, active, 0, 0)
    for kind in (1, 2)
    for state in (1, 2, 3)
    for active in (0, 1, 256)
]

#: The values HSRPAdvertise.decode() weighs in its Version, Op Code, the
#: TLV Type's low byte and the State, the ones either side of what it
#: accepts among them, and a few others.
_hsrp_advertise_lead = st.sampled_from([0, 1, 2, 3, 4, 5, 16, 255])


@st.composite
def _hsrp_advertise_seeded(draw: st.DrawFn) -> bytes:
    """A hand-built Advertise, now and then a judged byte redrawn near
    the values decode() accepts and a later byte changed, cut anywhere
    and followed by nothing, an FCS-like 4 bytes or free bytes."""
    raw = bytearray(draw(st.sampled_from(_HSRP_ADVERTISES)))
    for position in (0, 1, 2, 3, 6):
        if draw(st.integers(0, 3)) == 0:
            raw[position] = draw(_hsrp_advertise_lead)
    if draw(st.booleans()):
        raw[draw(st.integers(4, 15))] = draw(st.integers(0, 255))
    cut = draw(st.integers(0, len(raw)))
    tail = draw(
        st.one_of(
            st.just(b""), st.just(b"\xde\xad\xbe\xef"), st.binary(max_size=40)
        )
    )
    return bytes(raw[:cut]) + tail


#: HSRPAdvertise's display accessors, every one of which must answer on
#: any decoded or constructed instance.
_HSRP_ADVERTISE_ACCESSORS = (
    "opcode_name",
    "tlv_type_name",
    "state_name",
    "header_len",
)


def _hsrp_advertise_rejection(data: bytes) -> str | None:
    """What HSRPAdvertise.decode() must reject ``data`` for, judged in
    its order, each once its bytes are present: ``"version"`` other than
    0, ``"opcode"`` other than 3, ``"tlv_type"`` other than 1 or 2
    (its high byte alone when the low one is missing), ``"state"``
    outside 1-3; then ``"truncated"``, shorter than 16 bytes; or
    ``None``."""
    if len(data) > 0 and data[0] != 0:
        return "version"
    if len(data) > 1 and data[1] != 3:
        return "opcode"
    if len(data) > 3 and int.from_bytes(data[2:4]) not in (1, 2):
        return "tlv_type"
    if len(data) == 3 and data[2] != 0:
        return "tlv_type"
    if len(data) > 6 and data[6] not in (1, 2, 3):
        return "state"
    return "truncated" if len(data) < 16 else None


class TestHSRPAdvertiseAccessorSafety:
    @given(data=st.one_of(_hsrp_advertise_seeded(), fuzz_input))
    def test_decode_and_every_accessor_are_total(self, data: bytes) -> None:
        """decode() raises only for the first reason that applies, takes
        exactly 16 bytes and leaves the rest; the accessors never
        raise."""
        try:
            advertise = HSRPAdvertise.decode(data)
        except TruncatedHeaderError:
            assert _hsrp_advertise_rejection(data) == "truncated"
            event("HSRPAdvertise rejected: truncated")
            return
        except InvalidFieldError as error:
            assert _hsrp_advertise_rejection(data) == error.field
            event(f"HSRPAdvertise rejected: {error.field}")
            return
        assert _hsrp_advertise_rejection(data) is None
        assert bytes(advertise) == data[:16]
        assert HSRPAdvertise.decode(bytes(advertise)) == advertise
        for name in _HSRP_ADVERTISE_ACCESSORS:
            getattr(advertise, name)
        assert advertise.opcode_name == "Advertise"
        event(f"HSRPAdvertise {advertise.state_name}")

    @given(header=hsrp_advertisements(), trailer=st.binary(max_size=60))
    def test_trailing_bytes_stay_out_of_the_message(
        self, header: HSRPAdvertise, trailer: bytes
    ) -> None:
        """The message is always 16 bytes, so whatever follows is left
        undecoded, and HSRP hands its first two bytes to HSRPAdvertise."""
        raw = bytes(header) + trailer
        decoded = HSRPAdvertise.decode(raw)
        assert decoded == header
        assert decoded.header_len == 16
        assert HSRP._for_payload(int.from_bytes(raw[:2])) is HSRPAdvertise
        with pytest.raises(InvalidFieldError, match="HSRPAdvertise"):
            HSRP.decode(raw)

    @given(
        opcode=st.integers(4, 0xFF),
        tlv_type=st.integers(3, 0xFFFF),
        state=st.sampled_from([0, *range(4, 256)]),
    )
    def test_constructed_unknown_values_display(
        self, opcode: int, tlv_type: int, state: int
    ) -> None:
        """Construction accepts values decode() rejects, and the display
        helpers name them as unknown rather than raising."""
        advertise = HSRPAdvertise(0, opcode, tlv_type, 0, state, 0, 0, 0, 0)
        assert advertise.opcode_name == f"unknown ({opcode})"
        assert advertise.tlv_type_name == f"unknown ({tlv_type})"
        assert advertise.state_name == f"unknown ({state})"
        for name in _HSRP_ADVERTISE_ACCESSORS:
            getattr(advertise, name)


#: Hand-built HSRPv2 messages, packed here in the layout of Wireshark's
#: packet-hsrp.c, not built by the library: a Group State TLV for IPv4
#: and for IPv6 in every State, alone or followed by a Text
#: Authentication, an MD5 Authentication or an Interface State TLV.
_HSRPV2_MESSAGES = [
    bytes([1, 40, 2, opcode, state, ip_version, 0, 1])
    + bytes.fromhex("02000a09c30b")
    + (100).to_bytes(4, "big")
    + (3000).to_bytes(4, "big")
    + (10000).to_bytes(4, "big")
    + bytes(range(16))
    + tail
    for opcode in (0, 1, 2)
    for state in range(7)
    for ip_version in (4, 6)
    for tail in (
        b"",
        bytes([3, 8]) + b"cisco\x00\x00\x00",
        bytes([4, 28, 1, 0, 0, 0, 192, 0, 2, 11, 0, 0, 0, 1]) + bytes(16),
        bytes([2, 4, 0, 1, 0, 0]),
    )
]

#: Values near those HSRPv2.decode() judges in the Group State TLV's
#: first eight bytes.
_hsrpv2_lead = st.sampled_from([0, 1, 2, 3, 4, 5, 6, 7, 15, 16, 39, 40, 255])


@st.composite
def _hsrpv2_seeded(draw: st.DrawFn) -> bytes:
    """A hand-built HSRPv2 message, now and then a judged byte redrawn
    near the values decode() accepts, a later byte changed, cut anywhere
    and followed by nothing or free bytes."""
    raw = bytearray(draw(st.sampled_from(_HSRPV2_MESSAGES)))
    for position in range(8):
        if draw(st.integers(0, 7)) == 0:
            raw[position] = draw(_hsrpv2_lead)
    if draw(st.booleans()):
        raw[draw(st.integers(8, len(raw) - 1))] = draw(st.integers(0, 255))
    cut = draw(st.integers(0, len(raw)))
    tail = draw(st.one_of(st.just(b""), st.binary(max_size=40)))
    return bytes(raw[:cut]) + tail


#: HSRPv2's display accessors, every one of which must answer on any
#: decoded message.
_HSRPV2_ACCESSORS = (
    "group_state",
    "interface_state",
    "text_authentication",
    "md5_authentication",
    "header_len",
)

#: The display accessors of each TLV class.
_HSRPV2_TLV_ACCESSORS = {
    "HSRPv2GroupState": (
        "opcode_name",
        "state_name",
        "ip_version_name",
        "virtual_mac",
    ),
    "HSRPv2TextAuthentication": (
        "password",
        "auth_data_str",
        "is_default_auth",
    ),
    "HSRPv2InterfaceState": (),
    "HSRPv2MD5Authentication": ("algorithm_name",),
    "HSRPv2TLV": ("type_name",),
}


class TestHSRPv2AccessorSafety:
    @given(data=st.one_of(_hsrpv2_seeded(), fuzz_input))
    def test_decode_and_every_accessor_are_total(self, data: bytes) -> None:
        """decode() raises only InvalidFieldError or
        TruncatedHeaderError, the latter only for a buffer shorter than
        the 42-byte Group State TLV; what it accepts round-trips whole,
        and the accessors never raise."""
        try:
            message = HSRPv2.decode(data)
        except TruncatedHeaderError:
            assert len(data) < 42
            event("HSRPv2 rejected: truncated")
            return
        except InvalidFieldError as error:
            event(f"HSRPv2 rejected: {error.field}")
            return
        assert bytes(message) == data
        assert HSRPv2.decode(bytes(message)) == message
        assert message.header_len == len(data)
        for name in _HSRPV2_ACCESSORS:
            getattr(message, name)
        for tlv in message.tlvs:
            for name in _HSRPV2_TLV_ACCESSORS[type(tlv).__name__]:
                getattr(tlv, name)
        event(f"HSRPv2 TLVs: {len(message.tlvs)}")

    @given(message=hsrpv2_messages())
    def test_hsrp_hands_every_message_to_hsrpv2(self, message: HSRPv2) -> None:
        """A message's first byte is 1, which HSRP answers HSRPv2 for,
        and HSRP decoded on it raises naming HSRPv2."""
        raw = bytes(message)
        assert HSRP._for_payload(int.from_bytes(raw[:2])) is HSRPv2
        with pytest.raises(InvalidFieldError, match="HSRPv2"):
            HSRP.decode(raw)


def _tcp_payload(frame: bytes) -> bytes:
    """The payload of an Ethernet/IPv4/TCP frame, by its two lengths."""
    tcp = 14 + (frame[14] & 0x0F) * 4
    return frame[tcp + (frame[tcp + 12] >> 4) * 4 :]


def _chromium_hellos() -> list[bytes]:
    """Chromium's two ClientHello records, which tests/fixtures/tls/
    tls_session.pcap carries split across two segments each, from the
    client streams scripts/extract_http_streams.py's ``extract()``
    reassembles (stdlib only, sharing no code with the library)."""
    scripts = Path(__file__).resolve().parent.parent / "scripts"
    sys.path.insert(0, str(scripts))
    try:
        spec = importlib.util.spec_from_file_location(
            "extract_http_streams", scripts / "extract_http_streams.py"
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        # @dataclass looks its class's module up in sys.modules.
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(scripts))
    streams = module.extract(
        pcap_frames(FIXTURES / "tls" / "tls_session.pcap"), 443
    )
    hellos = [
        client[: 5 + int.from_bytes(client[3:5], "big")]
        for client, _ in streams[:2]
    ]
    assert [len(hello) for hello in hellos] == [1738, 1738]
    return hellos


#: The ClientHello records seeded: tests/fixtures/tls.pcap's (curl,
#: gnutls-cli, openssl s_client without SNI and curl capped at TLS 1.2),
#: Chromium's two from the session capture, GREASE and a post-quantum
#: key share among their extensions, and the constructed one
#: tests/conftest.py builds.
_TLS_CAPTURED_HELLOS = [
    *(
        payload
        for payload in map(_tcp_payload, pcap_frames(FIXTURES / "tls.pcap"))
        if payload[:1] == b"\x16" and payload[5:6] == b"\x01"
    ),
    *_chromium_hellos(),
    tls_client_hello_record(),
]
assert len(_TLS_CAPTURED_HELLOS) == 7

#: The bytes TLS.decode() and the chaining predicate weigh in a record
#: header's first three, the ones either side of what they accept, and
#: a few others.
_tls_lead = st.sampled_from([0, 1, 2, 3, 4, 5, 19, 20, 22, 24, 25, 0x80, 255])


@st.composite
def _tls_seeded(draw: st.DrawFn) -> bytes:
    """A captured ClientHello record, now and then a header byte redrawn
    near the values decode() accepts, a length or another byte of the
    fragment changed, cut anywhere and followed by nothing, a record
    header or free bytes: the guard's boundaries, the ClientHello's
    lying lengths and the chaining predicate, which free bytes rarely
    reach."""
    raw = bytearray(draw(st.sampled_from(_TLS_CAPTURED_HELLOS)))
    for position in range(3):
        if draw(st.integers(0, 3)) == 0:
            raw[position] = draw(_tls_lead)
    for _ in range(draw(st.integers(0, 3))):
        raw[draw(st.integers(3, len(raw) - 1))] = draw(st.integers(0, 255))
    cut = draw(st.integers(0, len(raw)))
    tail = draw(
        st.one_of(
            st.just(b""),
            st.binary(min_size=1, max_size=3).map(
                lambda head: bytes([0x17, 0x03, 0x03])[: len(head)]
            ),
            st.binary(max_size=40),
        )
    )
    return bytes(raw[:cut]) + tail


def _tls_rejection(data: bytes) -> str | None:
    """What TLS.decode() must reject ``data`` for, judged in its order,
    each once its bytes are present: ``"content_type"`` outside 20-24,
    then ``"legacy_version"`` not starting 3 or above 0x0304, then a
    ``"length"`` above 2**14 + 2048; then ``"truncated"``, shorter than
    the header or the record; or ``None``."""
    if len(data) > 0 and not 20 <= data[0] <= 24:
        return "content_type"
    if len(data) > 1 and data[1] != 3:
        return "legacy_version"
    if len(data) > 2 and data[2] > 4:
        return "legacy_version"
    if len(data) < 5:
        return "truncated"
    length = int.from_bytes(data[3:5], "big")
    if length > 2**14 + 2048:
        return "length"
    return "truncated" if 5 + length > len(data) else None


def _tls_decode(data: bytes) -> TLS | str:
    """Decode ``data``, or say what TLS.decode() rejected it for, in
    :func:`_tls_rejection`'s words."""
    try:
        return TLS.decode(data)
    except TruncatedHeaderError:
        return "truncated"
    except InvalidFieldError as error:
        return str(error.field)


@st.composite
def _tls_mutated_hello(draw: st.DrawFn) -> bytes:
    """A captured ClientHello record, whole, with up to three of its
    bytes after the header's first three changed: prefixes of it reach
    peek_server_name's answers, where _tls_seeded's cut seldom leaves
    the server_name extension whole."""
    raw = bytearray(draw(st.sampled_from(_TLS_CAPTURED_HELLOS)))
    for _ in range(draw(st.integers(0, 3))):
        raw[draw(st.integers(3, len(raw) - 1))] = draw(st.integers(0, 255))
    return bytes(raw)


def _tls_strict_server_name(data: bytes) -> str | ProtocolError | None:
    """TLS.decode(data).server_name, or the error either raises."""
    try:
        return TLS.decode(data).server_name
    except ProtocolError as error:
        return error


def _tls_peek(data: bytes) -> TLSServerNamePeek | InvalidFieldError:
    """peek_server_name(data), or the InvalidFieldError it raises, the
    only exception it may."""
    try:
        return peek_server_name(data)
    except InvalidFieldError as error:
        return error


#: TLS's display accessors, every one of which must answer on any
#: decoded or constructed instance.
_TLS_DISPLAY = (
    "content_type_name",
    "legacy_version_name",
    "handshake_type",
    "handshake_type_name",
    "header_len",
)


class TestTLSAccessorSafety:
    @given(data=st.one_of(_tls_seeded(), fuzz_input))
    def test_decode_and_every_accessor_are_total(self, data: bytes) -> None:
        """decode() raises only for the first reason that applies, at
        any length; a record keeps its own bytes and chains exactly when
        what follows begins like a record; the display accessors never
        raise, and the ClientHello parsers raise only TruncatedHeaderError
        or InvalidFieldError on the fragment."""
        tls = _tls_decode(data)
        if not isinstance(tls, TLS):
            assert tls == _tls_rejection(data)
            event(f"TLS rejected: {tls}")
            return
        assert _tls_rejection(data) is None
        assert bytes(tls) == data[: tls.header_len]
        assert TLS.decode(bytes(tls)) == tls
        rest = data[tls.header_len : tls.header_len + 3]
        follows = bool(rest) and _tls_rejection(rest) in ("truncated", None)
        assert (tls.next_protocol() is TLS) == follows
        for name in _TLS_DISPLAY:
            getattr(tls, name)
        for name in ("client_hello", "server_name"):
            try:
                getattr(tls, name)
            except (TruncatedHeaderError, InvalidFieldError) as error:
                assert error.field == "fragment"
                assert error.offset is not None
                assert 0 <= error.offset <= tls.length
        event(f"TLS {tls.content_type_name}, hello: {tls.handshake_type == 1}")

    @given(
        data=st.one_of(_tls_mutated_hello(), _tls_seeded(), fuzz_input),
        cuts=st.data(),
    )
    def test_peek_server_name_is_total(
        self, data: bytes, cuts: st.DataObject
    ) -> None:
        """peek_server_name on two prefixes of any bytes, the second the
        longer: only InvalidFieldError escapes, positioned as the strict
        path positions it, and only where the strict path raises for the
        whole; a complete answer holds for every longer prefix, as a
        raise does, and is the strict path's answer where that has
        one. A fragment offset lies within the handshake message, past
        the record only for a message fragmented across records."""
        short = cuts.draw(st.integers(0, len(data)), label="short")
        long = cuts.draw(
            st.one_of(st.just(len(data)), st.integers(short, len(data))),
            label="long",
        )
        strict = _tls_strict_server_name(data)
        first = _tls_peek(data[:short])
        second = _tls_peek(data[:long])
        for answer in (first, second):
            if isinstance(answer, InvalidFieldError):
                assert isinstance(strict, ProtocolError)
                if answer.field == "fragment":
                    # Within the handshake message, which may run past
                    # its record (fragmented across records).
                    message = 4 + int.from_bytes(data[6:9])
                    assert answer.offset is not None
                    assert 0 <= answer.offset <= message
                else:
                    assert (answer.field, answer.offset, answer.actual) == (
                        strict.field,
                        strict.offset,
                        strict.actual,
                    )
            elif answer.complete and not isinstance(strict, ProtocolError):
                assert answer.server_name == strict
        if isinstance(first, InvalidFieldError):
            assert isinstance(second, InvalidFieldError)
            assert (second.field, second.offset, str(second)) == (
                first.field,
                first.offset,
                str(first),
            )
        elif first.complete:
            assert second == first
        event(
            "peek: "
            + (
                type(second).__name__
                if isinstance(second, InvalidFieldError)
                else "found"
                if second.server_name is not None
                else "absent"
                if second.complete
                else "not reached"
            )
        )

    @given(hello=tls_client_hellos(), version=st.integers(0x0300, 0x0304))
    def test_built_client_hellos_parse_back(
        self, hello: TLSClientHello, version: int
    ) -> None:
        """A ClientHello built from fields, in a record of any version,
        parses back into exactly those fields."""
        body = bytes(hello)
        handshake = b"\x01" + len(body).to_bytes(3, "big") + body
        tls = TLS.decode(
            bytes([22])
            + version.to_bytes(2, "big")
            + len(handshake).to_bytes(2, "big")
            + handshake
        )
        assert tls.client_hello == hello

    @given(
        name=st.text(
            alphabet=st.characters(min_codepoint=0, max_codepoint=0x7F),
            min_size=1,
            max_size=40,
        )
    )
    def test_any_ascii_host_name_reads_back(self, name: str) -> None:
        """Every ASCII host_name is returned as sent, unjudged."""
        raw = name.encode("ascii")
        entry = b"\x00" + len(raw).to_bytes(2, "big") + raw
        data = len(entry).to_bytes(2, "big") + entry
        hello = TLSClientHello(
            0x0303, bytes(32), extensions=(TLSExtension(0, data),)
        )
        body = bytes(hello)
        handshake = b"\x01" + len(body).to_bytes(3, "big") + body
        tls = TLS(22, 0x0301, len(handshake), handshake)
        assert TLS.decode(bytes(tls)).server_name == name

    @given(record=tls_records(), trailer=st.binary(max_size=60))
    def test_trailing_bytes_stay_out_of_the_record(
        self, record: TLS, trailer: bytes
    ) -> None:
        """A record ends where its length says, whatever follows."""
        try:
            decoded = TLS.decode(bytes(record) + trailer)
        except ProtocolError:
            raise AssertionError("a canonical record must decode") from None
        assert decoded == record
        assert decoded.header_len == 5 + record.length

    @given(
        content_type=st.integers(0, 0xFF).filter(
            lambda value: not 20 <= value <= 24
        ),
        version=st.integers(0, 0xFFFF).filter(
            lambda value: not 0x0300 <= value <= 0x0304
        ),
        kind=st.integers(0, 0xFF),
    )
    def test_constructed_unknown_values_display(
        self, content_type: int, version: int, kind: int
    ) -> None:
        """Construction accepts values decode() rejects, and the display
        helpers name them as unknown rather than raising."""
        tls = TLS(content_type, version, 1, bytes([kind]))
        assert tls.content_type_name == f"unknown ({content_type})"
        assert tls.legacy_version_name == f"unknown ({version:#06x})"
        assert tls.handshake_type is None
        handshake = TLS(22, version, 1, bytes([kind]))
        assert handshake.handshake_type == kind
        assert handshake.handshake_type_name
        for name in _TLS_DISPLAY:
            getattr(tls, name)


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


def _length_fields(frame: bytes) -> list[int]:
    """Return the frame offsets of the IPv4 Total Length, IPv6 Payload
    Length and UDP Length fields a walk of ``frame`` reads."""
    offsets = []
    at = 0
    for layer in decode_frame(frame, lax=True):
        if isinstance(layer, IPv4):
            offsets.append(at + 2)
        elif isinstance(layer, (IPv6, UDP)):
            offsets.append(at + 4)
        at += layer.header_len
    return offsets


_LENGTH_FIELD_FRAMES = [
    (frame, offsets)
    for frame in CORPUS_FRAMES
    if (offsets := _length_fields(frame))
]


@st.composite
def relengthed_frames(draw: st.DrawFn) -> bytes:
    """A captured frame with IPv4, IPv6 or UDP lengths redrawn: zero,
    inside the header, near the true value or anything, then a trailer
    and sometimes a snap-length cut."""
    frame, offsets = draw(st.sampled_from(_LENGTH_FIELD_FRAMES))
    out = bytearray(frame)
    for at in offsets:
        if draw(st.booleans()):
            (current,) = struct.unpack_from("!H", out, at)
            value = draw(
                st.one_of(
                    st.integers(0, 8),
                    st.integers(0, 64),
                    st.integers(max(0, current - 16), current + 16),
                    st.integers(0, 0xFFFF),
                )
            )
            struct.pack_into("!H", out, at, value)
    out += draw(st.one_of(st.binary(max_size=24), st.just(bytes(18))))
    if draw(st.booleans()):
        del out[draw(st.integers(0, len(out))) :]
    return bytes(out)


class TestDeclaredLengthBounds:
    """The walk splits a frame into its layers, the bytes the last
    layer carries that no decoder read, and the trailer, whatever the
    IPv4, IPv6 and UDP lengths say."""

    @given(frame=st.one_of(relengthed_frames(), fuzz_input))
    def test_frame_is_layers_then_undecoded_then_trailer(
        self, frame: bytes
    ) -> None:
        packet = decode_frame(frame, lax=True)
        trailer = packet.trailer
        assert type(trailer) is bytes
        assert packet.consumed + len(trailer) <= len(frame)
        assert frame.endswith(trailer)
        undecoded = frame[packet.consumed : len(frame) - len(trailer)]
        assert frame == bytes(packet) + undecoded + trailer
        stop = packet.stopped_by
        if isinstance(stop, InvalidFieldError) and (
            stop.protocol,
            stop.field,
        ) in {
            (IPv4, "total_length"),
            (UDP, "length"),
        }:
            event(f"lying {stop.protocol.__name__} {stop.field}")
            assert stop.offset is None
            assert stop.frame_offset == packet.consumed - (
                packet.layers[-1].header_len
            )
            header = stop.protocol.decode(frame[stop.frame_offset :])
            assert getattr(header, stop.field) == stop.actual
            assert type(packet.layers[-1]) is stop.protocol
        event(f"trailer: {bool(trailer)}")

    @given(frame=relengthed_frames())
    def test_strict_and_lax_agree(self, frame: bytes) -> None:
        """A strict walk raises only ProtocolError, the one that stopped
        the lax walk, or returns the lax walk's packet."""
        lax = decode_frame(frame, lax=True)
        try:
            strict = decode_frame(frame)
        except ProtocolError as error:
            assert type(error) is type(lax.stopped_by)
            assert str(error) == str(lax.stopped_by)
            assert error.frame_offset == lax.stopped_by.frame_offset
        else:
            assert strict == lax
            assert lax.stopped_by is None


#: The 802.3 frames of the LLC fixture (BPDUs, CDP, RFC 1042, 802.1H,
#: a tagged frame, Novell raw 802.3, the 1501 frame), and of the STP
#: fixture (MST, RST, Configuration and TCN BPDUs).
_LLC_FRAMES = pcap_frames(FIXTURES / "llc.pcap")
_STP_FRAMES = pcap_frames(FIXTURES / "stp.pcap")


@st.composite
def llc_frames(draw: st.DrawFn) -> bytes:
    """A captured 802.3 frame, its Length redrawn now and then, a few
    bytes changed, and a trailer of zeros or random bytes appended."""
    frame = bytearray(draw(st.sampled_from(_LLC_FRAMES + _STP_FRAMES)))
    if draw(st.booleans()):
        frame[12:14] = draw(st.integers(0, 1600)).to_bytes(2, "big")
    for _ in range(draw(st.integers(0, 4))):
        position = draw(st.integers(min_value=14, max_value=len(frame) - 1))
        frame[position] = draw(st.integers(0, 255))
    trailer = draw(st.one_of(st.binary(max_size=12), st.just(bytes(8))))
    return bytes(frame) + trailer


class TestLLCProperties:
    @given(data=st.one_of(fuzz_input, llc_frames()))
    def test_accessors_never_raise(self, data: bytes) -> None:
        """Decode raises only ProtocolError; every accessor of LLC, SNAP
        and the type/length helpers of Ethernet answers, never raises."""
        with contextlib.suppress(ProtocolError):
            eth = Ethernet.decode(data)
            _ = (eth.is_length, eth.length, eth.next_protocol())
            event(f"type/length class: {eth.next_protocol()}")
        with contextlib.suppress(ProtocolError):
            tag = VLAN.decode(data)
            _ = (tag.is_length, tag.length, tag.next_protocol())
        with contextlib.suppress(ProtocolError):
            llc = LLC.decode(data)
            _ = (
                llc.header_len,
                llc.control_format,
                llc.is_group,
                llc.is_response,
                llc.is_raw_ipx,
                llc.dsap_name,
                llc.ssap_name,
                llc.dsap_enum,
                llc.next_protocol(),
            )
            assert LLC.decode(bytes(llc)) == llc
        with contextlib.suppress(ProtocolError):
            snap = SNAP.decode(data)
            _ = (snap.carries_ethertype, snap.snap_key, snap.oui_str)
            _ = snap.next_protocol()

    @given(frame=llc_frames())
    def test_no_layer_reads_past_the_8023_length(self, frame: bytes) -> None:
        """Every layer after an 802.3 Length lies inside the PDU it
        bounds, and the walk never reads past the frame."""
        with contextlib.suppress(ProtocolError):
            packet = decode_frame(frame)
            assert packet.consumed <= len(frame)
            assert bytes(packet) == frame[: packet.consumed]
            eth = packet[Ethernet]
            if eth.length is not None:
                assert packet.consumed <= 14 + eth.length
            event(f"layers: {len(packet)}")


def _cdp_tlv(tlv_type: int, value: bytes) -> bytes:
    """Return the on-wire CDP TLV, its Length counting its header."""
    return struct.pack("!HH", tlv_type, 4 + len(value)) + value


@st.composite
def cdp_address_values(draw: st.DrawFn) -> bytes:
    """An Addresses value: a count, then entries, often well formed,
    sometimes cut short or followed by stray bytes."""
    entries = b""
    for _ in range(draw(st.integers(0, 3))):
        protocol = draw(
            st.sampled_from([b"\xcc", b"\xaa\xaa\x03\x00\x00\x00\x86\xdd"])
            | st.binary(max_size=9)
        )
        address = draw(st.binary(min_size=4, max_size=4))
        address = draw(st.just(address) | st.binary(max_size=17))
        entries += (
            bytes((draw(st.integers(0, 3)), len(protocol)))
            + protocol
            + len(address).to_bytes(2)
            + address
        )
    count = draw(st.integers(0, 4) | st.integers(0, 0xFFFFFFFF))
    value = count.to_bytes(4) + entries + draw(st.binary(max_size=3))
    return value[: draw(st.integers(0, len(value)))]


@st.composite
def cdp_bodies(draw: st.DrawFn) -> bytes:
    """A CDP header, TLVs of the types the accessors read (and others),
    a few bytes changed now and then, and a trailer."""
    tlvs = b""
    for _ in range(draw(st.integers(0, 6))):
        tlv_type = draw(
            st.sampled_from([1, 2, 3, 4, 5, 6, 0x16]) | st.integers(0, 0xFFFF)
        )
        if tlv_type in (2, 0x16):
            value = draw(cdp_address_values())
        else:
            value = draw(st.binary(max_size=12))
        tlvs += _cdp_tlv(tlv_type, value)
    data = bytearray(draw(st.binary(min_size=4, max_size=4)) + tlvs)
    for _ in range(draw(st.integers(0, 2))):
        position = draw(st.integers(0, len(data) - 1))
        data[position] = draw(st.integers(0, 255))
    trailer = draw(st.one_of(st.binary(max_size=8), st.just(bytes(8))))
    return bytes(data) + trailer


@st.composite
def cdp_nonzero_trailers(draw: st.DrawFn) -> bytes:
    """A trailer holding a nonzero byte by construction: random bytes
    around one nonzero byte, or whole TLVs (each Length at least 4, so
    never all zero) followed by up to 3 zeros, which decode as phantom
    TLVs."""
    if draw(st.booleans()):
        return (
            draw(st.binary(max_size=6))
            + bytes((draw(st.integers(1, 255)),))
            + draw(st.binary(max_size=5))
        )
    tlvs = b""
    for _ in range(draw(st.integers(1, 2))):
        tlvs += _cdp_tlv(
            draw(st.integers(0, 0xFFFF)), draw(st.binary(max_size=4))
        )
    return tlvs + bytes(draw(st.integers(0, 3)))


class TestCDPProperties:
    @given(data=st.one_of(fuzz_input, cdp_bodies()))
    def test_accessors_never_raise(self, data: bytes) -> None:
        """Whatever decodes answers every accessor, and round-trips."""
        try:
            cdp = CDP.decode(data)
        except ProtocolError:
            return
        _ = (
            cdp.header_len,
            cdp.checksum_hex_str,
            cdp.device_id,
            cdp.port_id,
            cdp.software_version,
            cdp.platform,
            cdp.capabilities,
            cdp.capability_names,
            cdp.next_protocol(),
        )
        for tlv in cdp.tlvs:
            _ = (tlv.type_name, tlv.length)
        for addresses in (cdp.addresses, cdp.management_addresses):
            event(f"addresses: {'none' if addresses is None else 'parsed'}")
            for address in addresses or ():
                _ = (address.ip, address.protocol_type_name, bytes(address))
        assert bytes(cdp) == data[: cdp.header_len]
        assert not any(data[cdp.header_len :])
        assert CDP.decode(bytes(cdp)) == cdp

    @given(pdu=cdp_pdus())
    def test_zero_padding_stays_out_of_the_pdu(self, pdu: CDP) -> None:
        """Every length of padding Ethernet adds, up to 46 bytes, is
        left undecoded by a standalone decode."""
        wire = bytes(pdu)
        for count in range(47):
            decoded = CDP.decode(wire + bytes(count))
            assert decoded == pdu, count
            assert decoded.header_len == len(wire), count

    @given(pdu=cdp_pdus(), trailer=cdp_nonzero_trailers())
    @example(pdu=CDP(2, 180), trailer=b"\xde\xad\x00\x04")
    def test_a_nonzero_trailer_is_never_left_out(
        self, pdu: CDP, trailer: bytes
    ) -> None:
        """A standalone decode raises, or reads the trailer as TLVs: it
        never stops where the PDU ends and drops nonzero bytes."""
        wire = bytes(pdu)
        try:
            decoded = CDP.decode(wire + trailer)
        except ProtocolError:
            event("raised")
            return
        event("phantom TLVs")
        assert decoded.tlvs[: len(pdu.tlvs)] == pdu.tlvs
        assert decoded.header_len > len(wire)

    @given(pdu=cdp_pdus(), trailer=st.binary(max_size=12))
    def test_a_walk_hands_cdp_exactly_its_pdu(
        self, pdu: CDP, trailer: bytes
    ) -> None:
        """Behind an 802.3 Length any trailer stays outside the PDU."""
        snap = b"\xaa\xaa\x03\x00\x00\x0c\x20\x00" + bytes(pdu)
        if len(snap) > 1500:
            return
        frame = bytes(12) + len(snap).to_bytes(2) + snap
        packet = decode_frame(frame + trailer)
        assert packet[CDP] == pdu
        assert packet.consumed == len(frame)


#: STP's display and per-type accessors, every one of which must answer
#: on any decoded or constructed BPDU.
_STP_ACCESSORS = (
    "header_len",
    "bpdu_type_name",
    "version_name",
    "topology_change",
    "topology_change_ack",
    "proposal",
    "learning",
    "forwarding",
    "agreement",
    "port_role",
    "port_role_name",
    "root_priority_component",
    "root_system_id_extension",
    "bridge_priority_component",
    "bridge_system_id_extension",
    "root_id_str",
    "bridge_id_str",
    "port_priority",
    "port_number",
    "message_age_seconds",
    "max_age_seconds",
    "hello_time_seconds",
    "forward_delay_seconds",
    "version_3_length",
    "mst_config_id",
    "cist_internal_root_path_cost",
    "cist_bridge_priority",
    "cist_bridge_mac",
    "cist_bridge_id_str",
    "cist_regional_root_priority",
    "cist_regional_root_mac",
    "cist_regional_root_id_str",
    "cist_external_root_path_cost",
    "cist_remaining_hops",
    "msti_messages",
)

#: The accessors of the two MST records.
_MST_CONFIG_ID_ACCESSORS = ("name_str", "digest_hex_str")
_MSTI_ACCESSORS = (
    "msti_id",
    "regional_root_priority_component",
    "regional_root_id_str",
    "bridge_priority_component",
    "port_priority_component",
    "topology_change",
    "proposal",
    "learning",
    "forwarding",
    "agreement",
    "master",
    "port_role",
    "port_role_name",
)


def _read_every_stp_accessor(stp: STP) -> None:
    """Read every accessor of ``stp`` and of its MST records: the MST
    ones are None exactly when ``mst`` is empty, and the records
    re-encode to their octets of ``mst``."""
    for name in _STP_ACCESSORS:
        getattr(stp, name)
    config_id, mstis = stp.mst_config_id, stp.msti_messages
    if stp.port_role == 0:
        assert stp.port_role_name == ("Master" if stp.mst else "Unknown")
    if not stp.mst:
        assert config_id is None and mstis is None
        assert stp.cist_regional_root_id_str is None
        assert stp.cist_external_root_path_cost is None
        return
    assert stp.cist_regional_root_id_str == stp.bridge_id_str
    assert stp.cist_external_root_path_cost == stp.root_path_cost
    assert config_id is not None and mstis is not None
    for name in _MST_CONFIG_ID_ACCESSORS:
        getattr(config_id, name)
    for message in mstis:
        for name in _MSTI_ACCESSORS:
            getattr(message, name)
    assert stp.version_3_length == len(stp.mst) - 2
    assert bytes(config_id) == stp.mst[2:53]
    assert b"".join(map(bytes, mstis)) == stp.mst[66:]


#: The BPDUs of the LLC and STP fixtures, after their Ethernet and LLC
#: headers: Configuration, TCN, RST and MST BPDUs.
_BPDUS = [frame[17:] for frame in _LLC_FRAMES[:5] + _STP_FRAMES]


@st.composite
def bpdus(draw: st.DrawFn) -> bytes:
    """A BPDU of the fixtures, cut, a few bytes changed (the type, the
    version and an MST BPDU's Version 3 Length among them, now and
    then), and a trailer of zeros or random bytes."""
    bpdu = bytearray(draw(st.sampled_from(_BPDUS)))
    for _ in range(draw(st.integers(0, 3))):
        position = draw(st.integers(0, len(bpdu) - 1))
        bpdu[position] = draw(st.integers(0, 255))
    if draw(st.booleans()):
        bpdu[3] = draw(st.sampled_from([0x00, 0x02, 0x80, 0x01]))
    if draw(st.booleans()):
        bpdu[2] = draw(st.sampled_from([0, 2, 3, 4]))
    if len(bpdu) >= 38 and draw(st.booleans()):
        length = draw(st.sampled_from([0, 2, 63, 64, 80, 95, 96, 97, 112]))
        bpdu[36:38] = length.to_bytes(2, "big")
    cut = draw(st.one_of(st.just(len(bpdu)), st.integers(0, len(bpdu))))
    trailer = draw(st.one_of(st.binary(max_size=12), st.just(bytes(8))))
    return bytes(bpdu[:cut]) + trailer


class TestSTPAccessorSafety:
    @given(data=st.one_of(fuzz_input, bpdus()))
    def test_decoded_bpdus_answer_every_accessor(self, data: bytes) -> None:
        """Whatever decodes, every accessor answers without raising, the
        BPDU round-trips through its own length, and the per-type flag
        accessors are set exactly where the type defines their bit."""
        try:
            stp = STP.decode(data)
        except ProtocolError:
            return
        _read_every_stp_accessor(stp)
        assert bytes(stp) == data[: stp.header_len]
        assert STP.decode(bytes(stp)) == stp
        assert (stp.proposal is None) == (stp.bpdu_type != 0x02)
        assert (stp.topology_change_ack is None) == (stp.bpdu_type != 0x00)
        event(f"BPDU type: {stp.bpdu_type_name}")
        event(f"MST part: {bool(stp.mst)}")

    @given(data=st.data())
    def test_trailing_bytes_stay_out_of_the_bpdu(
        self, data: st.DataObject
    ) -> None:
        """The type bounds the BPDU, so Ethernet's zero padding (every
        length up to its 46-byte maximum) and a nonzero trailer such as
        a 4-byte FCS are left undecoded."""
        header = data.draw(stp_headers())
        wire = bytes(header)
        for trailer in [bytes(n) for n in range(47)] + [b"\xde\xad\xbe\xef"]:
            decoded = STP.decode(wire + trailer)
            assert decoded == header, trailer
            assert decoded.header_len == len(wire), trailer
        _read_every_stp_accessor(header)
        event(f"MST part: {bool(header.mst)}")

    @given(
        config_id=stp_mst_config_ids(),
        mstis=st.lists(stp_msti_messages(), max_size=4),
        cist=st.binary(min_size=13, max_size=13),
        version=st.integers(3, 0xFF),
    )
    def test_mst_records_round_trip(
        self, config_id, mstis, cist, version
    ) -> None:
        """An MST part built from records decodes back to them, and so
        does the BPDU carrying it in a walk."""
        mst = (
            struct.pack("!H", 64 + 16 * len(mstis))
            + bytes(config_id)
            + cist
            + b"".join(map(bytes, mstis))
        )
        bpdu = b"\x00\x00" + bytes((version,)) + _BPDUS[5][3:36] + mst
        stp = STP.decode(bpdu)
        assert stp.mst == mst
        assert stp.mst_config_id == config_id
        assert stp.msti_messages == tuple(mstis)
        _read_every_stp_accessor(stp)
        frame = bytes(12) + (3 + len(bpdu)).to_bytes(2, "big") + b"BB\x03"
        packet = decode_frame(frame + bpdu + bytes(4))
        assert packet[STP] == stp
        assert packet.consumed == len(frame) + len(bpdu)


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


#: TLVs of a few common types (End, Chassis ID, Port ID, TTL, System
#: Name, organizationally specific, a reserved one), short values, then
#: free bytes, so the walk goes deep and the mandatory positions are
#: often of the right type but the wrong length.
_lldp_like = st.tuples(
    st.lists(
        st.tuples(
            st.sampled_from([0, 1, 2, 3, 3, 5, 9, 127]),
            st.binary(max_size=4),
        ).map(
            lambda tlv: struct.pack("!H", (tlv[0] << 9) | len(tlv[1])) + tlv[1]
        ),
        max_size=8,
    ).map(b"".join),
    st.binary(max_size=6),
).map(b"".join)


class TestLLDPAccessorSafety:
    @given(data=st.one_of(fuzz_input, _lldp_like))
    def test_decoded_lldpdus_answer_every_accessor(self, data: bytes) -> None:
        """Whatever decodes, every accessor answers without raising, and
        the typed views agree with the TLVs they are read from."""
        try:
            lldp = LLDP.decode(data)
        except ProtocolError:
            return
        assert bytes(lldp) == data[: lldp.header_len]
        assert all(tlv.type for tlv in lldp.tlvs[:-1])
        for tlv in lldp.tlvs:
            assert tlv.type_name
            assert lldp.tlv(tlv.type) is not None
        chassis_id, port_id, ttl = lldp.chassis_id, lldp.port_id, lldp.ttl
        if isinstance(chassis_id, LLDPChassisID):
            assert chassis_id.tlv == lldp.tlvs[0]
            assert chassis_id.subtype_name
        if isinstance(port_id, LLDPPortID):
            assert port_id.tlv == lldp.tlvs[1]
            assert port_id.subtype_name
        if ttl is not None:
            assert ttl == int.from_bytes(lldp.tlvs[2].value[:2])
        assert lldp.is_shutdown is (ttl == 0)
        assert lldp.has_mandatory_tlvs is (
            None not in (chassis_id, port_id, ttl)
        )
        event(f"LLDP mandatory TLVs: {lldp.has_mandatory_tlvs}")
        event(f"LLDP ends with End: {lldp.tlvs[-1].type == 0}")

    @given(lldp=lldp_lldpdus())
    def test_trailing_bytes_stay_out_of_the_lldpdu(self, lldp: LLDP) -> None:
        """An End of LLDPDU TLV bounds the LLDPDU, so Ethernet's zero
        padding (every length up to its 46-byte maximum) and a nonzero
        trailer such as a 4-byte FCS are left undecoded."""
        if lldp.tlvs[-1].type != 0:
            lldp = LLDP(tlvs=(*lldp.tlvs, LLDPTLV(0)))
        wire = bytes(lldp)
        for trailer in [bytes(n) for n in range(47)] + [b"\xde\xad\xbe\xef"]:
            decoded = LLDP.decode(wire + trailer)
            assert decoded == lldp, trailer
            assert decoded.header_len == len(wire), trailer


#: A built label stack and then a few bytes, so the payload nibble
#: and every bottom-label rule turn up far more often than in free bytes.
_mpls_like = st.tuples(mpls_stacks(), st.binary(max_size=8)).map(
    lambda parts: bytes(parts[0]) + parts[1]
)


class TestMPLSAccessorSafety:
    @given(data=st.one_of(fuzz_input, _mpls_like))
    def test_decoded_stacks_answer_every_accessor(self, data: bytes) -> None:
        """Whatever decodes round-trips, and every accessor answers
        without raising; the payload is IPv4, IPv6 or nothing."""
        try:
            mpls = MPLS.decode(data)
        except ProtocolError:
            return
        assert bytes(mpls) == data[: mpls.header_len]
        assert MPLS.decode(bytes(mpls)) == mpls
        assert mpls.bottom is mpls.labels[-1]
        assert mpls.next_protocol() in (None, IPv4, IPv6)
        event(f"MPLS payload: {mpls.payload_ethertype!r}")
        for entry in mpls.labels:
            assert MPLSLabel.from_word(entry.word) == entry
            assert entry.label_name is None or entry.is_special_purpose

    @given(header=mpls_stacks())
    def test_trailing_bytes_stay_out_of_the_stack(self, header: MPLS) -> None:
        """The S bit bounds the stack, so Ethernet's zero padding (every
        length up to its 46-byte maximum) and a nonzero trailer such as
        a 4-byte FCS are left undecoded."""
        wire = bytes(header)
        for trailer in [bytes(n) for n in range(47)] + [b"\xde\xad\xbe\xef"]:
            decoded = MPLS.decode(wire + trailer)
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
