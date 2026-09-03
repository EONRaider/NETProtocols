"""Structured parse diagnostics on ProtocolError (#91).

Every raise site in ``src/`` attaches ``protocol`` and, where
meaningful, ``offset``/``field``/``expected``/``actual`` — this file
pins the contract itself (defaults, message text unchanged) and spot
checks representative raise sites across the three shapes that exist:
a ``decode()``-time raise (offset relative to the ``data`` argument), a
``__post_init__`` raise (no buffer, so no offset), and an on-demand
property parsing an already-materialized ``bytes`` attribute (offset
relative to that attribute, named by ``field``).
"""

from dataclasses import replace

import pytest

from netprotocols import (
    ARP,
    DHCP,
    DNS,
    GRE,
    IGMP,
    TCP,
    UDP,
    VLAN,
    Ethernet,
    ICMPv4,
    InvalidFieldError,
    InvalidIPv4AddressError,
    InvalidMACAddressError,
    InvalidManufacturerCodeError,
    IPv4,
    IPv6HopByHopOptions,
    MaxDepthExceededError,
    Packet,
    Protocol,
    ProtocolError,
    TruncatedHeaderError,
    checksum,
    decode_frame,
    random_mac,
)
from netprotocols.utils.mac import validate_mac_addr


class TestBaseContract:
    def test_all_fields_default_to_none(self):
        err = ProtocolError("plain message")
        assert err.protocol is None
        assert err.offset is None
        assert err.field is None
        assert err.expected is None
        assert err.actual is None
        assert err.frame_offset is None

    def test_message_text_is_unaffected_by_the_kwargs(self):
        err = ProtocolError(
            "boom",
            protocol=IPv4,
            offset=3,
            field="ihl",
            expected=5,
            actual=0,
        )
        assert str(err) == "boom"
        assert err.args == ("boom",)

    def test_every_kwarg_round_trips(self):
        err = ProtocolError(
            "x",
            protocol=TCP,
            offset=1,
            field="options",
            expected=">=2",
            actual=1,
            frame_offset=15,
        )
        assert err.protocol is TCP
        assert err.offset == 1
        assert err.field == "options"
        assert err.expected == ">=2"
        assert err.actual == 1
        assert err.frame_offset == 15

    def test_subclasses_inherit_the_same_init(self):
        for cls in (
            TruncatedHeaderError,
            InvalidFieldError,
            InvalidMACAddressError,
            InvalidIPv4AddressError,
            InvalidManufacturerCodeError,
            MaxDepthExceededError,
        ):
            err = cls("m", protocol=IPv4, field="x")
            assert err.protocol is IPv4
            assert err.field == "x"
            assert isinstance(err, ProtocolError)


class TestDecodeTimeRaises:
    """offset is relative to the `data` argument passed to decode()."""

    def test_unpack_fixed_truncation(self):
        with pytest.raises(TruncatedHeaderError) as excinfo:
            Ethernet.decode(b"\x00\x01\x02\x03")
        err = excinfo.value
        assert err.protocol is Ethernet
        assert err.offset == 0
        assert err.expected == Ethernet._struct.size
        assert err.actual == 4
        assert err.field is None
        assert str(err) == "Ethernet header needs 14 bytes, buffer holds 4"

    def test_ipv4_ihl_below_5(self, raw_ipv4_header):
        garbage = b"\x40" + raw_ipv4_header[1:]
        with pytest.raises(InvalidFieldError) as excinfo:
            IPv4.decode(garbage)
        err = excinfo.value
        assert err.protocol is IPv4
        assert err.offset == 0
        assert err.field == "ihl"
        assert err.expected == ">=5"
        assert err.actual == 0

    def test_ipv4_declared_length_exceeds_buffer(self, raw_ipv4_header):
        # IHL 15 (0x4F) declares 60 bytes; the fixture buffer is 20.
        garbage = b"\x4f" + raw_ipv4_header[1:]
        with pytest.raises(TruncatedHeaderError) as excinfo:
            IPv4.decode(garbage)
        err = excinfo.value
        assert err.protocol is IPv4
        assert err.field == "ihl"
        assert err.expected == 60
        assert err.actual == len(raw_ipv4_header)

    def test_tcp_data_offset_below_5(self, raw_tcp_header_with_options):
        garbage = (
            raw_tcp_header_with_options[:12]
            + b"\x40"
            + raw_tcp_header_with_options[13:]
        )
        with pytest.raises(InvalidFieldError) as excinfo:
            TCP.decode(garbage)
        err = excinfo.value
        assert err.protocol is TCP
        assert err.field == "data_offset"
        assert err.offset == 0

    def test_gre_truncation_names_the_fields_attribute(self):
        # flags with Checksum-Present set, but no bytes for it.
        with pytest.raises(TruncatedHeaderError) as excinfo:
            GRE.decode(b"\x80\x00\x08\x00")
        err = excinfo.value
        assert err.protocol is GRE
        assert err.field == "fields"
        assert err.offset == 0

    def test_ipv6_extension_header_truncation(self):
        lying = b"\x3a\x02" + b"\x00" * 6  # declares 24 bytes, holds 8
        with pytest.raises(TruncatedHeaderError) as excinfo:
            IPv6HopByHopOptions.decode(lying)
        err = excinfo.value
        assert err.protocol is IPv6HopByHopOptions
        assert err.field == "hdr_ext_len"
        assert err.expected == 24
        assert err.actual == 8


class TestConstructionTimeRaises:
    """__post_init__ sees field values, not bytes — no offset."""

    def test_ipv4_ihl_options_disagreement_has_no_offset(self):
        with pytest.raises(InvalidFieldError) as excinfo:
            IPv4(
                version=4,
                ihl=6,
                dscp=0,
                ecn=0,
                total_length=20,
                identification=1,
                flags=0,
                fragment_offset=0,
                ttl=64,
                protocol=6,
                checksum=0,
                src="10.0.0.1",
                dst="10.0.0.2",
                options=b"",
            )
        err = excinfo.value
        assert err.protocol is IPv4
        assert err.field == "ihl"
        assert err.offset is None
        assert err.expected == 4
        assert err.actual == 0

    def test_vlan_field_names_are_precise(self):
        with pytest.raises(InvalidFieldError) as excinfo:
            VLAN(pcp=9, dei=0, vid=1, ethertype=0x0800)
        assert excinfo.value.field == "pcp"
        with pytest.raises(InvalidFieldError) as excinfo:
            VLAN(pcp=0, dei=2, vid=1, ethertype=0x0800)
        assert excinfo.value.field == "dei"
        with pytest.raises(InvalidFieldError) as excinfo:
            VLAN(pcp=0, dei=0, vid=9999, ethertype=0x0800)
        assert excinfo.value.field == "vid"

    def test_icmp_rest_of_header_length(self):
        with pytest.raises(InvalidFieldError) as excinfo:
            ICMPv4(type=8, code=0, checksum=0, rest=b"\x00\x00")
        err = excinfo.value
        assert err.protocol is ICMPv4
        assert err.field == "rest"
        assert err.expected == 4
        assert err.actual == 2

    def test_ethernet_bad_mac_names_the_field(self):
        with pytest.raises(InvalidMACAddressError) as excinfo:
            Ethernet(dst="not-a-mac", src="00:11:22:33:44:55", ethertype=0x0800)
        err = excinfo.value
        assert err.protocol is Ethernet
        assert err.field == "dst"
        assert err.actual == "not-a-mac"

    def test_arp_bad_address_names_the_field(self):
        with pytest.raises(InvalidIPv4AddressError) as excinfo:
            ARP(
                htype=1,
                ptype=0x0800,
                hlen=6,
                plen=4,
                oper=1,
                sha="00:11:22:33:44:55",
                spa="not-an-ip",
                tha="00:00:00:00:00:00",
                tpa="10.0.0.1",
            )
        assert excinfo.value.field == "spa"


class TestOnDemandPropertyRaises:
    """Offset relative to the already-materialized bytes attribute
    named by `field`, not to any decode() buffer."""

    def test_tcp_option_offset_is_relative_to_options(
        self, raw_tcp_header_with_options
    ):
        tcp = TCP.decode(raw_tcp_header_with_options)
        # Three NOPs, then a Timestamps kind byte with no length byte —
        # 4 bytes total, matching data_offset 6 (5 + 4 // 4).
        bad = replace(tcp, data_offset=6, options=b"\x01\x01\x01\x08")
        with pytest.raises(InvalidFieldError) as excinfo:
            _ = bad.parsed_options
        err = excinfo.value
        assert err.protocol is TCP
        assert err.field == "options"
        assert err.offset == 3

    def test_ipv4_option_offset_is_relative_to_options(self):
        ip = IPv4(
            version=4,
            ihl=6,
            dscp=0,
            ecn=0,
            total_length=24,
            identification=1,
            flags=0,
            fragment_offset=0,
            ttl=64,
            protocol=6,
            checksum=0,
            src="10.0.0.1",
            dst="10.0.0.2",
            # Three NOPs, then a Record Route kind byte with no length
            # byte — 4 bytes total, matching ihl 6 (5 + 4 // 4).
            options=b"\x01\x01\x01\x07",
        )
        with pytest.raises(InvalidFieldError) as excinfo:
            _ = ip.parsed_options
        err = excinfo.value
        assert err.field == "options"
        assert err.offset == 3

    def test_dhcp_option_offset_is_relative_to_options(self):
        dhcp = DHCP(
            op=2,
            htype=1,
            hlen=6,
            hops=0,
            xid=1,
            secs=0,
            flags=0,
            ciaddr="0.0.0.0",
            yiaddr="0.0.0.0",
            siaddr="0.0.0.0",
            giaddr="0.0.0.0",
            chaddr="00:11:22:33:44:55",
            sname="",
            file="",
            options=b"\x63\x82\x53\x63\x35",  # cookie + option 53, no length
        )
        with pytest.raises(InvalidFieldError) as excinfo:
            _ = dhcp.option_map
        err = excinfo.value
        assert err.protocol is DHCP
        assert err.field == "options"
        assert err.offset == 5

    def test_dns_name_offset_is_relative_to_sections(self):
        dns = DNS(
            transaction_id=1,
            flags=0,
            qdcount=1,
            ancount=0,
            nscount=0,
            arcount=0,
            sections=b"\xff",  # reserved length-prefix bits set
        )
        with pytest.raises(InvalidFieldError) as excinfo:
            _ = dns.question_name
        err = excinfo.value
        assert err.protocol is DNS
        assert err.field == "sections"
        assert err.offset == 0

    def test_igmp_group_record_offset_is_relative_to_body(self):
        # v3 report (type 0x22), reserved word, count=1, then a
        # truncated group record.
        igmp = IGMP(
            type=0x22,
            max_resp_code=0,
            checksum=0,
            body=b"\x00\x00\x00\x01\x00\x00",
        )
        with pytest.raises(InvalidFieldError) as excinfo:
            _ = igmp.group_records
        err = excinfo.value
        assert err.protocol is IGMP
        assert err.field == "body"
        assert err.offset == 4


class TestPacketAndChecksumRaises:
    def test_packet_rejects_a_non_protocol_layer(self):
        with pytest.raises(InvalidFieldError) as excinfo:
            Packet("not a header")  # type: ignore[arg-type]
        err = excinfo.value
        assert err.protocol is str
        assert err.expected is Protocol
        assert err.actual is str

    def test_checksum_missing_enclosing_ip(self, raw_udp_header):
        udp = UDP.decode(raw_udp_header)
        with pytest.raises(InvalidFieldError) as excinfo:
            checksum.compute(udp)
        err = excinfo.value
        assert err.protocol is UDP
        assert err.field == "checksum"

    def test_checksum_gre_without_checksum_present(self):
        gre = GRE(flags=0, protocol_type=0x0800, fields=b"")
        with pytest.raises(InvalidFieldError) as excinfo:
            checksum.compute(gre)
        assert excinfo.value.protocol is GRE

    def test_checksum_layer_without_a_checksum_field(self, raw_arp_header):
        arp = ARP.decode(raw_arp_header)
        with pytest.raises(InvalidFieldError) as excinfo:
            checksum.compute(arp)
        assert excinfo.value.protocol is ARP


#: Exception class names this sweep checks. Kept separate from the
#: library's own exception hierarchy so this test does not need to
#: import every module to enumerate subclasses.
_PROTOCOL_ERROR_NAMES = frozenset(
    {
        "TruncatedHeaderError",
        "InvalidFieldError",
        "InvalidMACAddressError",
        "InvalidIPv4AddressError",
        "InvalidManufacturerCodeError",
        "ProtocolError",
        "MaxDepthExceededError",
    }
)

#: The one raise site with no protocol=: random_mac()'s manufacturer
#: check validates a free-standing argument that belongs to no header.
#: See TestUtilityFunctionsWithoutAProtocol below.
_EXEMPT_FROM_PROTOCOL = frozenset({"netprotocols/utils/mac.py:71"})


def _every_protocol_error_raise() -> list[tuple[str, set[str]]]:
    """``(f"{path}:{lineno}", {keyword names})`` for every raise of a
    ProtocolError subclass under ``src/netprotocols/``."""
    import ast
    import pathlib

    src = pathlib.Path(__file__).parent.parent / "src" / "netprotocols"
    sites = []
    for path in sorted(src.rglob("*.py")):
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Raise)
                and isinstance(node.exc, ast.Call)
                and isinstance(node.exc.func, ast.Name)
                and node.exc.func.id in _PROTOCOL_ERROR_NAMES
            ):
                continue
            rel = path.relative_to(src.parent)
            site = f"{rel}:{node.lineno}"
            sites.append((site, {kw.arg for kw in node.exc.keywords}))
    return sites


class TestEveryRaiseSiteIsInstrumented:
    """The acceptance criterion, enforced structurally rather than by
    eyeballing a diff: every ProtocolError subclass raised anywhere in
    src/ sets protocol=, except the one documented exception."""

    def test_every_raise_site_sets_protocol(self):
        sites = _every_protocol_error_raise()
        assert len(sites) >= 60, f"expected ~62 raise sites, found {len(sites)}"
        missing = [
            site
            for site, kwargs in sites
            if "protocol" not in kwargs and site not in _EXEMPT_FROM_PROTOCOL
        ]
        assert not missing, f"raise sites missing protocol=: {missing}"

    def test_the_exemption_list_names_a_real_site(self):
        """A stale exemption (the code moved, or started setting
        protocol=) would otherwise hide a real gap silently."""
        sites = dict(_every_protocol_error_raise())
        for exempt in _EXEMPT_FROM_PROTOCOL:
            assert exempt in sites, f"{exempt} no longer exists"
            assert "protocol" not in sites[exempt], (
                f"{exempt} now sets protocol=; drop it from the exemption list"
            )


class TestUtilityFunctionsWithoutAProtocol:
    """random_mac() validates a free-standing argument, not a header
    field — the one raise site with no protocol= (verified by an AST
    sweep during development; documented here as the reason)."""

    def test_manufacturer_code_has_no_protocol_but_has_a_field(self):
        with pytest.raises(InvalidManufacturerCodeError) as excinfo:
            random_mac(manufacturer="not-an-oui")
        err = excinfo.value
        assert err.protocol is None
        assert err.field == "manufacturer"
        assert err.actual == "not-an-oui"

    def test_validate_mac_addr_accepts_optional_context(self):
        with pytest.raises(InvalidMACAddressError) as excinfo:
            validate_mac_addr("garbage", protocol=Ethernet, field="dst")
        err = excinfo.value
        assert err.protocol is Ethernet
        assert err.field == "dst"

    def test_validate_mac_addr_context_is_optional(self):
        with pytest.raises(InvalidMACAddressError) as excinfo:
            validate_mac_addr("garbage")
        assert excinfo.value.protocol is None
        assert excinfo.value.field is None


class TestDecodeFrameRebasing:
    """decode_frame is the only code with the cursor to rebase a
    layer-relative offset to the whole frame."""

    @pytest.fixture
    def eth_ipv4_header(self) -> bytes:
        """An Ethernet header pointing at IPv4 (0x0800) — unlike
        ``raw_eth_header``, which points at ARP (0x0806)."""
        return bytes(
            Ethernet(
                dst="ff:ff:ff:ff:ff:ff",
                src="00:11:22:33:44:55",
                ethertype=0x0800,
            )
        )

    def test_a_nested_layer_error_is_rebased(
        self, eth_ipv4_header, raw_ipv4_header
    ):
        truncated = eth_ipv4_header + raw_ipv4_header[:3]
        packet = decode_frame(truncated, lax=True)
        err = packet.stopped_by
        assert isinstance(err, TruncatedHeaderError)
        assert err.protocol is IPv4
        assert err.offset == 0  # relative to IPv4's own decode() buffer
        assert err.frame_offset == len(eth_ipv4_header)

    def test_rebasing_happens_in_strict_mode_too(
        self, eth_ipv4_header, raw_ipv4_header
    ):
        truncated = eth_ipv4_header + raw_ipv4_header[:3]
        with pytest.raises(TruncatedHeaderError) as excinfo:
            decode_frame(truncated)
        assert excinfo.value.frame_offset == len(eth_ipv4_header)

    def test_max_depth_error_is_already_absolute(
        self, raw_eth_header, raw_arp_header
    ):
        frame = raw_eth_header + raw_arp_header
        with pytest.raises(MaxDepthExceededError) as excinfo:
            decode_frame(frame, max_depth=1)
        err = excinfo.value
        assert err.offset == len(raw_eth_header)
        assert err.frame_offset == len(raw_eth_header)

    def test_a_bare_decode_call_never_sets_frame_offset(self, raw_ipv4_header):
        garbage = b"\x40" + raw_ipv4_header[1:]
        with pytest.raises(InvalidFieldError) as excinfo:
            IPv4.decode(garbage)
        assert excinfo.value.frame_offset is None

    def test_a_field_level_error_rebases_by_adding_its_offset(
        self, eth_ipv4_header, raw_tcp_header_with_options
    ):
        # A minimal IPv4 header (IHL 5) directly encapsulating a TCP
        # segment whose options are corrupt.
        ipv4 = IPv4(
            version=4,
            ihl=5,
            dscp=0,
            ecn=0,
            total_length=20 + len(raw_tcp_header_with_options),
            identification=1,
            flags=0,
            fragment_offset=0,
            ttl=64,
            protocol=6,
            checksum=0,
            src="10.0.0.1",
            dst="10.0.0.2",
        )
        # Exactly the 20-byte fixed portion: _unpack_fixed succeeds,
        # but data_offset (8, from the fixed header) declares 32 bytes
        # that the truncated buffer does not hold.
        frame = eth_ipv4_header + bytes(ipv4) + raw_tcp_header_with_options[:20]
        packet = decode_frame(frame, lax=True)
        err = packet.stopped_by
        assert isinstance(err, TruncatedHeaderError)
        assert err.field == "data_offset"
        # TCP's own decode() buffer starts right after Ethernet+IPv4.
        tcp_start = len(eth_ipv4_header) + 20
        assert err.frame_offset == tcp_start + err.offset
