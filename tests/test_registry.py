"""The public dispatch registry: registration, conflicts, table
inheritance, and isolation from the process-wide default."""

import copy
import tomllib
from pathlib import Path

import pytest

import netprotocols
import netprotocols.registry as registry_module
from netprotocols import (
    AH,
    CDP,
    DNS,
    OSPF,
    SCTP,
    SNAP,
    STP,
    TCP,
    UDP,
    AHv6,
    Ethernet,
    InvalidRegistryKeyError,
    IPv4,
    IPv6,
    Protocol,
    TruncatedHeaderError,
    decode_frame,
)
from netprotocols._defaults import (
    FAMILY_SPECIFIC_NUMBERS,
    IPV4_ONLY_NUMBERS,
    IPV6_ONLY_NUMBERS,
    install,
)
from netprotocols.registry import (
    DEFAULT,
    TABLE_ETHERTYPE,
    TABLE_IP_PROTO,
    TABLE_IP_PROTO_V6,
    TABLE_LLC_DSAP,
    TABLE_LLC_SNAP,
    TABLE_TCP_PORT,
    TABLE_UDP_PORT,
    TABLES,
    WITHHELD,
    Registry,
    RegistryConflictError,
    UnknownTableError,
    WithheldType,
    register,
    register_all,
)


class Fake(Protocol):
    """A stand-in decoder: the registry stores classes and never calls
    them, so nothing here needs to work."""


class OtherFake(Protocol):
    pass


@pytest.fixture
def registry() -> Registry:
    """A registry seeded with the built-ins, isolated from DEFAULT."""
    return Registry.from_defaults()


class TestTableNames:
    def test_every_table_declares_its_parent(self):
        assert set(TABLES) == {
            TABLE_ETHERTYPE,
            TABLE_LLC_DSAP,
            TABLE_LLC_SNAP,
            TABLE_IP_PROTO,
            TABLE_IP_PROTO_V6,
            TABLE_UDP_PORT,
            TABLE_TCP_PORT,
        }

    def test_only_the_v6_table_inherits(self):
        parents = {name: of for name, of in TABLES.items() if of is not None}
        assert parents == {TABLE_IP_PROTO_V6: TABLE_IP_PROTO}

    def test_an_unknown_table_raises_and_lists_the_real_ones(self, registry):
        with pytest.raises(UnknownTableError) as excinfo:
            registry.register("udp.ports", 6969, Fake)
        message = str(excinfo.value)
        assert "udp.ports" in message
        assert TABLE_UDP_PORT in message

    def test_an_unknown_table_raises_on_lookup_too(self, registry):
        with pytest.raises(UnknownTableError):
            registry.get("ethertypes", 0x0800)


class TestRegistration:
    def test_a_registered_class_is_dispatched(self, registry):
        registry.register(TABLE_ETHERTYPE, 0x88B5, Fake)
        assert registry.get(TABLE_ETHERTYPE, 0x88B5) is Fake

    def test_an_unregistered_key_answers_none(self, registry):
        assert registry.get(TABLE_ETHERTYPE, 0x88B5) is None

    def test_register_returns_the_class_unchanged_as_a_decorator(self):
        isolated = Registry()

        @register(TABLE_ETHERTYPE, 0x88B5, registry=isolated)
        class Decorated(Protocol):
            pass

        assert isolated.get(TABLE_ETHERTYPE, 0x88B5) is Decorated
        assert issubclass(Decorated, Protocol)

    def test_register_as_a_direct_call_returns_none(self):
        isolated = Registry()
        assert register(TABLE_IP_PROTO, 253, Fake, registry=isolated) is None
        assert isolated.get(TABLE_IP_PROTO, 253) is Fake

    def test_register_all_covers_several_keys(self):
        isolated = Registry()
        register_all(TABLE_UDP_PORT, (6969, 7000), Fake, registry=isolated)
        assert isolated.get(TABLE_UDP_PORT, 6969) is Fake
        assert isolated.get(TABLE_UDP_PORT, 7000) is Fake


class TestConflicts:
    def test_a_duplicate_key_raises_and_names_the_incumbent(self, registry):
        with pytest.raises(RegistryConflictError) as excinfo:
            registry.register(TABLE_UDP_PORT, 53, Fake)
        message = str(excinfo.value)
        assert "netprotocols.layer7.dns.DNS" in message
        assert "override=True" in message

    def test_the_incumbent_survives_a_refused_registration(self, registry):
        with pytest.raises(RegistryConflictError):
            registry.register(TABLE_UDP_PORT, 53, Fake)
        assert registry.get(TABLE_UDP_PORT, 53) is DNS

    def test_override_replaces_the_incumbent(self, registry):
        registry.register(TABLE_UDP_PORT, 53, Fake, override=True)
        assert registry.get(TABLE_UDP_PORT, 53) is Fake

    def test_registering_the_same_class_twice_is_a_no_op(self, registry):
        """A decorator re-runs whenever its module is re-executed —
        reload, doctest collection, a test rerun — so an identical
        registration must not raise."""
        registry.register(TABLE_UDP_PORT, 53, DNS)
        registry.register(TABLE_UDP_PORT, 53, DNS)
        assert registry.get(TABLE_UDP_PORT, 53) is DNS

    def test_a_different_class_on_the_same_key_still_raises(self, registry):
        registry.register(TABLE_ETHERTYPE, 0x88B5, Fake)
        with pytest.raises(RegistryConflictError):
            registry.register(TABLE_ETHERTYPE, 0x88B5, OtherFake)

    def test_installing_the_defaults_twice_is_a_no_op(self):
        registry = Registry()
        install(registry)
        before = dict(registry.table(TABLE_IP_PROTO_V6))
        install(registry)
        assert registry.table(TABLE_IP_PROTO_V6) == before


class TestTableInheritance:
    def test_a_shared_registration_reaches_the_v6_table(self, registry):
        registry.register(TABLE_IP_PROTO, 253, Fake)
        assert registry.get(TABLE_IP_PROTO, 253) is Fake
        assert registry.get(TABLE_IP_PROTO_V6, 253) is Fake

    def test_a_v6_registration_stays_out_of_the_base_table(self, registry):
        registry.register(TABLE_IP_PROTO_V6, 139, Fake)
        assert registry.get(TABLE_IP_PROTO_V6, 139) is Fake
        assert registry.get(TABLE_IP_PROTO, 139) is None

    def test_a_v6_override_is_not_clobbered_by_a_later_parent_write(
        self, registry
    ):
        """Inheritance must not overwrite an explicit child entry,
        whichever order the two registrations arrive in."""
        registry.register(TABLE_IP_PROTO_V6, 253, OtherFake)
        registry.register(TABLE_IP_PROTO, 253, Fake)
        assert registry.get(TABLE_IP_PROTO, 253) is Fake
        assert registry.get(TABLE_IP_PROTO_V6, 253) is OtherFake

    def test_the_built_in_extension_headers_are_v6_only(self, registry):
        for number in IPV6_ONLY_NUMBERS:
            assert registry.get(TABLE_IP_PROTO, number) is None
            assert registry.get(TABLE_IP_PROTO_V6, number) is not None

    def test_the_v6_table_is_the_base_table_plus_the_v6_only_numbers(self):
        """...less the IPv4-only numbers, which it withholds."""
        registry = Registry()
        install(registry)
        base = registry.table(TABLE_IP_PROTO)
        v6 = registry.table(TABLE_IP_PROTO_V6)
        assert set(v6) - set(base) == set(IPV6_ONLY_NUMBERS)
        # Pinned literally, like FAMILY_SPECIFIC_NUMBERS below.
        assert set(IPV4_ONLY_NUMBERS) == {89}
        assert set(base) - set(v6) == set(IPV4_ONLY_NUMBERS)

    def test_a_withheld_key_is_not_inherited(self, registry):
        """A withheld key owns no class: a parent write skips it, as it
        skips an override, and a direct registration fills it."""
        registry.register(TABLE_IP_PROTO_V6, 253, WITHHELD)
        registry.register(TABLE_IP_PROTO, 253, Fake)
        assert registry.get(TABLE_IP_PROTO, 253) is Fake
        assert registry.get(TABLE_IP_PROTO_V6, 253) is None
        registry.register(TABLE_IP_PROTO_V6, 253, OtherFake)
        assert registry.get(TABLE_IP_PROTO_V6, 253) is OtherFake

    def test_withholding_removes_an_inherited_entry(self, registry):
        registry.register(TABLE_IP_PROTO, 253, Fake)
        registry.register(TABLE_IP_PROTO_V6, 253, WITHHELD)
        assert registry.get(TABLE_IP_PROTO_V6, 253) is None
        assert registry.get(TABLE_IP_PROTO, 253) is Fake

    def test_withholding_leaves_a_direct_registration_alone(self, registry):
        registry.register(TABLE_IP_PROTO_V6, 253, OtherFake)
        registry.register(TABLE_IP_PROTO_V6, 253, WITHHELD)
        assert registry.get(TABLE_IP_PROTO_V6, 253) is OtherFake

    def test_withholding_an_unknown_table_raises(self, registry):
        with pytest.raises(UnknownTableError):
            registry.register("ip.proto.v7", 89, WITHHELD)

    def test_a_derived_registry_copies_what_is_withheld(self, registry):
        registry.register(TABLE_IP_PROTO_V6, 253, WITHHELD)
        child = registry.derive({TABLE_IP_PROTO: {253: Fake}})
        assert child.get(TABLE_IP_PROTO_V6, 253) is None
        # ...independently: withholding in the child leaves the parent.
        child.register(TABLE_IP_PROTO_V6, 254, WITHHELD)
        registry.register(TABLE_IP_PROTO, 254, Fake)
        assert registry.get(TABLE_IP_PROTO_V6, 254) is Fake

    def test_shared_numbers_differ_only_where_the_family_matters(self):
        """Every number both tables hold names the same class, except
        the family-specific ones, whose v6 entry is the table's own."""
        # FAMILY_SPECIFIC_NUMBERS only describes the wiring, and the
        # comparison below trusts it: pinned literally, so widening it
        # (and with it what this test allows) takes an edit here;
        # editing _defaults alone does not.
        assert set(FAMILY_SPECIFIC_NUMBERS) == {51, 112}  # AH, VRRP
        registry = Registry()
        install(registry)
        base = registry.table(TABLE_IP_PROTO)
        v6 = registry.table(TABLE_IP_PROTO_V6)
        differing = {n for n in base if n in v6 and v6[n] is not base[n]}
        assert differing == set(FAMILY_SPECIFIC_NUMBERS)
        for number in FAMILY_SPECIFIC_NUMBERS:
            assert issubclass(v6[number], base[number])


class TestPortDispatch:
    def test_the_destination_port_is_tried_first(self, registry):
        registry.register(TABLE_UDP_PORT, 6969, Fake)
        assert registry.get_port(TABLE_UDP_PORT, 6969, 53) is DNS
        assert registry.get_port(TABLE_UDP_PORT, 53, 6969) is Fake

    def test_the_source_port_is_the_fallback(self, registry):
        assert registry.get_port(TABLE_UDP_PORT, 53, 40000) is DNS

    def test_neither_port_known_answers_none(self, registry):
        assert registry.get_port(TABLE_UDP_PORT, 40000, 40001) is None


class TestIsolation:
    def test_from_defaults_carries_the_built_ins(self, registry):
        assert registry.get(TABLE_ETHERTYPE, 0x0800) is IPv4
        assert registry.get(TABLE_IP_PROTO, 6) is TCP

    def test_a_bare_registry_is_empty(self):
        empty = Registry()
        for name in TABLES:
            assert empty.table(name) == {}

    def test_registering_on_a_copy_leaves_the_default_alone(self, registry):
        registry.register(TABLE_ETHERTYPE, 0x88B5, Fake)
        assert DEFAULT.get(TABLE_ETHERTYPE, 0x88B5) is None

    def test_registering_on_the_default_does_not_reach_an_earlier_copy(
        self, registry
    ):
        DEFAULT.register(TABLE_ETHERTYPE, 0x88B5, Fake)
        try:
            assert registry.get(TABLE_ETHERTYPE, 0x88B5) is None
        finally:
            del DEFAULT.table(TABLE_ETHERTYPE)[0x88B5]

    def test_derive_applies_overrides_without_a_conflict(self, registry):
        child = registry.derive({TABLE_UDP_PORT: {53: Fake}})
        assert child.get(TABLE_UDP_PORT, 53) is Fake
        assert registry.get(TABLE_UDP_PORT, 53) is DNS

    def test_derive_is_the_decode_as_primitive(self):
        """DNS read on a nonstandard port for one caller, with the rest
        of the process unaffected."""
        child = DEFAULT.derive({TABLE_UDP_PORT: {6969: DNS}})
        assert child.get_port(TABLE_UDP_PORT, 40000, 6969) is DNS
        assert DEFAULT.get_port(TABLE_UDP_PORT, 40000, 6969) is None

    def test_a_derived_registry_inherits_across_tables(self, registry):
        child = registry.derive({TABLE_IP_PROTO: {253: Fake}})
        assert child.get(TABLE_IP_PROTO_V6, 253) is Fake

    def test_derive_without_overrides_is_a_plain_copy(self, registry):
        child = registry.derive()
        for name in TABLES:
            assert child.table(name) == registry.table(name)
            assert child.table(name) is not registry.table(name)


class TestTableIsLive:
    """The layer modules bind the flat dicts at import, so registration
    has to mutate them in place rather than rebind."""

    def test_the_layer_module_sees_a_later_registration(self):
        from netprotocols.layer2.ethernet import _ETHERTYPE_CLASSES

        assert _ETHERTYPE_CLASSES is DEFAULT.table(TABLE_ETHERTYPE)
        DEFAULT.register(TABLE_ETHERTYPE, 0x88B5, Fake)
        try:
            assert _ETHERTYPE_CLASSES[0x88B5] is Fake
        finally:
            del _ETHERTYPE_CLASSES[0x88B5]

    def test_a_registration_changes_what_next_protocol_answers(self):
        frame = bytes.fromhex("ffffffffffff000c29b1c2d3") + b"\x88\xb5"
        header = Ethernet.decode(frame)
        assert header.next_protocol() is None
        DEFAULT.register(TABLE_ETHERTYPE, 0x88B5, Fake)
        try:
            assert header.next_protocol() is Fake
        finally:
            del DEFAULT.table(TABLE_ETHERTYPE)[0x88B5]

    def test_the_ports_table_is_live_too(self):
        from netprotocols.layer4._ports import _UDP_APP_CLASSES

        assert _UDP_APP_CLASSES is DEFAULT.table(TABLE_UDP_PORT)

    def test_the_v6_table_is_live_too(self):
        from netprotocols.layer3.ip import (
            _IPV4_PROTOCOL_CLASSES,
            _IPV6_PROTOCOL_CLASSES,
        )

        assert _IPV4_PROTOCOL_CLASSES is DEFAULT.table(TABLE_IP_PROTO)
        assert _IPV6_PROTOCOL_CLASSES is DEFAULT.table(TABLE_IP_PROTO_V6)


class TestBuiltInsUnchanged:
    """The registry is the dispatch mechanism, so the built-in map has
    to come out of it byte for byte."""

    def test_ethertypes(self):
        assert DEFAULT.get(TABLE_ETHERTYPE, 0x0800) is IPv4
        assert DEFAULT.get(TABLE_ETHERTYPE, 0x86DD) is IPv6
        assert DEFAULT.get(TABLE_ETHERTYPE, 0x0806).__name__ == "ARP"
        for tag in (0x8100, 0x88A8, 0x9100):
            assert DEFAULT.get(TABLE_ETHERTYPE, tag).__name__ == "VLAN"

    def test_ip_protocols(self):
        assert DEFAULT.get(TABLE_IP_PROTO, 6) is TCP
        assert DEFAULT.get(TABLE_IP_PROTO, 17) is UDP
        assert DEFAULT.get(TABLE_IP_PROTO, 1).__name__ == "ICMPv4"
        assert DEFAULT.get(TABLE_IP_PROTO, 58).__name__ == "ICMPv6"
        assert DEFAULT.get(TABLE_IP_PROTO, 47).__name__ == "GRE"
        assert DEFAULT.get(TABLE_IP_PROTO, 2).__name__ == "IGMP"
        assert DEFAULT.get(TABLE_IP_PROTO, 4) is IPv4
        assert DEFAULT.get(TABLE_IP_PROTO, 41) is IPv6
        assert DEFAULT.get(TABLE_IP_PROTO, 132) is SCTP
        assert DEFAULT.get(TABLE_IP_PROTO_V6, 132) is SCTP
        assert DEFAULT.get(TABLE_IP_PROTO, 50).__name__ == "ESP"
        assert DEFAULT.get(TABLE_IP_PROTO_V6, 50).__name__ == "ESP"
        assert DEFAULT.get(TABLE_IP_PROTO, 51).__name__ == "AH"
        assert DEFAULT.get(TABLE_IP_PROTO, 112).__name__ == "VRRP"
        assert DEFAULT.get(TABLE_IP_PROTO_V6, 112).__name__ == "VRRPv6"
        assert DEFAULT.get(TABLE_IP_PROTO_V6, 51).__name__ == "AHv6"
        assert DEFAULT.get(TABLE_IP_PROTO, 89).__name__ == "OSPF"
        assert DEFAULT.get(TABLE_IP_PROTO_V6, 89) is None

    def test_llc(self):
        """SNAP and STP are the built-in LLC entries, and CDP, at Cisco's
        OUI 00-00-0C and PID 0x2000, the one built-in llc.snap entry."""
        assert DEFAULT.table(TABLE_LLC_DSAP) == {0xAA: SNAP, 0x42: STP}
        assert DEFAULT.table(TABLE_LLC_SNAP) == {0x00000C2000: CDP}

    def test_ports(self):
        assert DEFAULT.get(TABLE_UDP_PORT, 53) is DNS
        assert DEFAULT.get(TABLE_UDP_PORT, 67).__name__ == "DHCP"
        assert DEFAULT.get(TABLE_UDP_PORT, 68).__name__ == "DHCP"
        assert DEFAULT.get(TABLE_UDP_PORT, 4789).__name__ == "VXLAN"
        assert DEFAULT.get(TABLE_TCP_PORT, 53).__name__ == "DNSOverTCP"
        assert DEFAULT.get(TABLE_TCP_PORT, 179).__name__ == "BGP"


class TestRepr:
    def test_repr_reports_the_table_sizes(self):
        text = repr(Registry())
        assert "Registry" in text
        for name in TABLES:
            assert f"{name}=0" in text


class TestKeyRanges:
    """The LLC tables refuse a key their field cannot carry; the others
    accept any key, ``ethertype`` included."""

    @pytest.mark.parametrize(
        "key",
        [0, 0x0004, 0x0026, 0x00FE, 0x0200, 1500, 1501, 1535, -1, 0x10000],
    )
    def test_ethertype_accepts_any_key_as_2_5_0_did(self, registry, key):
        """GRE and SNAP read ``ethertype`` whatever the value, and RFC
        1701 assigns GRE Protocol Types 0x0004, 0x00FE and 0x0200; a
        negative key or one past 0xFFFF is accepted, though no 16-bit
        field reaches it."""
        registry.register(TABLE_ETHERTYPE, key, Fake)
        assert registry.get(TABLE_ETHERTYPE, key) is Fake

    @pytest.mark.parametrize("key", [0x0600, 0x88B5, 0xFFFF])
    def test_ethertype_accepts_every_type_value(self, registry, key):
        registry.register(TABLE_ETHERTYPE, key, Fake)
        assert registry.get(TABLE_ETHERTYPE, key) is Fake

    @pytest.mark.parametrize(
        "table,bad,good",
        [
            (TABLE_LLC_DSAP, 0x100, 0xFF),
            (TABLE_LLC_DSAP, -1, 0),
            (TABLE_LLC_SNAP, 1 << 40, (1 << 40) - 1),
            (TABLE_LLC_SNAP, -1, 0),
        ],
    )
    def test_the_llc_tables_take_their_field_width(
        self, registry, table, bad, good
    ):
        with pytest.raises(InvalidRegistryKeyError) as excinfo:
            registry.register(table, bad, Fake)
        assert table in str(excinfo.value)
        assert registry.get(table, bad) is None
        registry.register(table, good, Fake)
        assert registry.get(table, good) is Fake

    def test_every_way_to_register_refuses_too(self):
        isolated = Registry()
        with pytest.raises(InvalidRegistryKeyError):
            register(TABLE_LLC_DSAP, 0x100, registry=isolated)(Fake)
        with pytest.raises(InvalidRegistryKeyError):
            register_all(TABLE_LLC_DSAP, (0x42, 0x100), Fake, registry=isolated)
        # Not atomic: the key before the refused one stays registered.
        assert isolated.get(TABLE_LLC_DSAP, 0x42) is Fake
        with pytest.raises(InvalidRegistryKeyError):
            isolated.derive({TABLE_LLC_SNAP: {1 << 40: Fake}})
        with pytest.raises(InvalidRegistryKeyError):
            decode_frame(bytes(14), decode_as={TABLE_LLC_DSAP: {0x100: Fake}})
        with pytest.raises(InvalidRegistryKeyError):
            decode_frame(
                bytes(14), lax=True, decode_as={TABLE_LLC_DSAP: {-1: Fake}}
            )

    def test_every_way_to_register_accepts_a_low_ethertype(self):
        isolated = Registry()
        register(TABLE_ETHERTYPE, 0x0026, registry=isolated)(Fake)
        register_all(TABLE_ETHERTYPE, (0x0004, 0x0200), Fake, registry=isolated)
        child = isolated.derive({TABLE_ETHERTYPE: {0x00FE: Fake}})
        for key in (0x0004, 0x0026, 0x00FE, 0x0200):
            assert child.get(TABLE_ETHERTYPE, key) is Fake
        # Ethernet reads type/length 0 as a Length: LLC, which has no
        # bytes here. The override is accepted and never consulted.
        packet = decode_frame(
            bytes(14), lax=True, decode_as={TABLE_ETHERTYPE: {0x26: Fake}}
        )
        assert [type(layer) for layer in packet.layers] == [Ethernet]
        assert isinstance(packet.stopped_by, TruncatedHeaderError)

    def test_the_other_tables_accept_any_key(self, registry):
        registry.register(TABLE_UDP_PORT, 0x10000, Fake)
        registry.register(TABLE_IP_PROTO, 300, Fake)
        assert registry.get(TABLE_UDP_PORT, 0x10000) is Fake
        assert registry.get(TABLE_IP_PROTO, 300) is Fake


ROOT = Path(__file__).resolve().parent.parent


def dns_frame(*, src_port=50000, dst_port=53, v6=False):
    """An ``Ethernet → IP → UDP → DNS`` query with no questions."""
    dns = bytes.fromhex("123401000000000000000000")
    udp = (
        src_port.to_bytes(2, "big")
        + dst_port.to_bytes(2, "big")
        + (8 + len(dns)).to_bytes(2, "big")
        + bytes(2)
    )
    if v6:
        ethertype = "86dd"
        ip = (
            bytes.fromhex("60000000")
            + len(udp + dns).to_bytes(2, "big")
            + bytes.fromhex("1140")
            + bytes.fromhex("20010db8" + "0" * 23 + "1")
            + bytes.fromhex("20010db8" + "0" * 23 + "2")
        )
    else:
        ethertype = "0800"
        ip = (
            bytes.fromhex("4500")
            + (20 + len(udp + dns)).to_bytes(2, "big")
            + bytes.fromhex("0000400040110000c0000201c0000202")
        )
    eth = bytes.fromhex("020000000002020000000001" + ethertype)
    return eth + ip + udp + dns


def layer_types(packet):
    return [type(layer) for layer in packet]


class TestWithheldSentinel:
    def test_withheld_is_the_only_member_of_its_type(self):
        assert list(WithheldType) == [WITHHELD]
        assert WITHHELD is WithheldType.WITHHELD
        assert repr(WITHHELD) == "WITHHELD"

    def test_withheld_survives_copying_as_the_same_object(self):
        decode_as = {TABLE_UDP_PORT: {53: WITHHELD}}
        assert copy.copy(WITHHELD) is WITHHELD
        assert copy.deepcopy(decode_as)[TABLE_UDP_PORT][53] is WITHHELD

    def test_withheld_is_exported_by_the_registry_module(self):
        assert "WITHHELD" in registry_module.__all__
        assert "WithheldType" in registry_module.__all__

    def test_withheld_stays_out_of_the_top_level_package(self):
        """The top level re-exports the registry's functions and errors,
        not its values, like the table-name constants."""
        assert "WITHHELD" not in netprotocols.__all__
        assert "TABLE_UDP_PORT" not in netprotocols.__all__

    def test_mypy_checks_the_typed_call_sites(self):
        pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text())
        assert "tests/typecheck" in pyproject["tool"]["mypy"]["files"]
        assert (ROOT / "tests" / "typecheck" / "withheld.py").is_file()


class TestWithheldPerWalk:
    def test_the_frame_decodes_dns_without_an_override(self):
        packet = decode_frame(dns_frame())
        assert layer_types(packet) == [Ethernet, IPv4, UDP, DNS]

    def test_decode_as_withholds_a_key_for_one_walk(self):
        frame = dns_frame()
        packet = decode_frame(frame, decode_as={TABLE_UDP_PORT: {53: WITHHELD}})
        assert layer_types(packet) == [Ethernet, IPv4, UDP]
        assert packet.stopped_by is None
        assert packet.consumed == 42
        assert DEFAULT.get(TABLE_UDP_PORT, 53) is DNS
        assert layer_types(decode_frame(frame))[-1] is DNS

    def test_a_withheld_key_ends_the_walk_like_an_unregistered_one(self):
        withheld = decode_frame(
            dns_frame(), decode_as={TABLE_UDP_PORT: {53: WITHHELD}}
        )
        unregistered = decode_frame(dns_frame(dst_port=6969))
        assert DEFAULT.get(TABLE_UDP_PORT, 6969) is None
        assert layer_types(withheld) == layer_types(unregistered)
        assert withheld.consumed == unregistered.consumed
        assert withheld.trailer == unregistered.trailer == b""
        assert withheld.stopped_by is unregistered.stopped_by is None

    def test_a_withheld_port_falls_back_to_the_other_port(self, registry):
        """As for an unregistered destination, the source port is tried."""
        child = registry.derive({TABLE_UDP_PORT: {6969: WITHHELD}})
        assert child.get_port(TABLE_UDP_PORT, 53, 6969) is DNS
        packet = decode_frame(
            dns_frame(src_port=53, dst_port=6969),
            decode_as={TABLE_UDP_PORT: {6969: WITHHELD}},
        )
        assert layer_types(packet) == [Ethernet, IPv4, UDP, DNS]

    def test_decode_as_withholding_a_parent_key_reaches_the_child(self):
        frame = dns_frame(v6=True)
        assert layer_types(decode_frame(frame))[-1] is DNS
        packet = decode_frame(frame, decode_as={TABLE_IP_PROTO: {17: WITHHELD}})
        assert layer_types(packet) == [Ethernet, IPv6]
        assert DEFAULT.get(TABLE_IP_PROTO_V6, 17) is UDP

    def test_a_per_walk_withhold_overrides_a_global_entry(self, registry):
        assert registry.get(TABLE_UDP_PORT, 53) is DNS
        packet = decode_frame(
            dns_frame(),
            registry=registry,
            decode_as={TABLE_UDP_PORT: {53: WITHHELD}},
        )
        assert layer_types(packet) == [Ethernet, IPv4, UDP]
        assert registry.get(TABLE_UDP_PORT, 53) is DNS
        assert (
            layer_types(decode_frame(dns_frame(), registry=registry))[-1] is DNS
        )

    def test_a_per_walk_class_overrides_a_global_withhold(self, registry):
        registry.register(TABLE_UDP_PORT, 53, WITHHELD, override=True)
        packet = decode_frame(
            dns_frame(),
            registry=registry,
            decode_as={TABLE_UDP_PORT: {53: DNS}},
        )
        assert layer_types(packet) == [Ethernet, IPv4, UDP, DNS]
        assert registry.get(TABLE_UDP_PORT, 53) is None
        packet = decode_frame(dns_frame(), registry=registry)
        assert layer_types(packet) == [Ethernet, IPv4, UDP]

    def test_derive_withholds_whatever_the_parent_holds(self, registry):
        child = registry.derive(
            {TABLE_UDP_PORT: {53: WITHHELD}, TABLE_IP_PROTO_V6: {51: WITHHELD}}
        )
        assert child.get(TABLE_UDP_PORT, 53) is None
        assert child.get(TABLE_IP_PROTO_V6, 51) is None
        assert registry.get(TABLE_UDP_PORT, 53) is DNS
        assert registry.get(TABLE_IP_PROTO_V6, 51) is AHv6


class TestWithheldGlobally:
    def test_register_withholds_on_the_default_registry(self, monkeypatch):
        fresh = DEFAULT.derive()
        monkeypatch.setattr(registry_module, "DEFAULT", fresh)
        assert register(TABLE_IP_PROTO_V6, 253, WITHHELD) is None
        register(TABLE_IP_PROTO, 253, Fake)
        assert fresh.get(TABLE_IP_PROTO, 253) is Fake
        assert fresh.get(TABLE_IP_PROTO_V6, 253) is None
        assert DEFAULT.get(TABLE_IP_PROTO, 253) is None

    def test_register_all_withholds_every_key(self, registry):
        register_all(
            TABLE_UDP_PORT,
            (53, 67, 6969),
            WITHHELD,
            override=True,
            registry=registry,
        )
        for port in (53, 67, 6969):
            assert registry.get(TABLE_UDP_PORT, port) is None
        assert registry.get(TABLE_UDP_PORT, 68).__name__ == "DHCP"

    def test_a_global_withhold_ends_every_walk_through_it(self, registry):
        register(TABLE_UDP_PORT, 53, WITHHELD, override=True, registry=registry)
        packet = decode_frame(dns_frame(), registry=registry)
        assert layer_types(packet) == [Ethernet, IPv4, UDP]
        assert packet.stopped_by is None

    def test_withholding_is_idempotent(self, registry):
        for _ in range(2):
            registry.register(TABLE_IP_PROTO_V6, 253, WITHHELD)
            assert registry.get(TABLE_IP_PROTO_V6, 253) is None
        registry.register(TABLE_IP_PROTO_V6, 253, WITHHELD, override=True)
        registry.register(TABLE_IP_PROTO, 253, Fake)
        assert registry.get(TABLE_IP_PROTO, 253) is Fake
        assert registry.get(TABLE_IP_PROTO_V6, 253) is None
        before = registry.table(TABLE_IP_PROTO_V6).copy()
        registry.register(TABLE_IP_PROTO_V6, 89, WITHHELD)
        assert registry.table(TABLE_IP_PROTO_V6) == before

    def test_withholding_never_undoes_a_direct_entry(self, registry):
        registry.register(TABLE_UDP_PORT, 6969, Fake)
        registry.register(TABLE_UDP_PORT, 6969, WITHHELD)
        assert registry.get(TABLE_UDP_PORT, 6969) is Fake
        registry.register(TABLE_UDP_PORT, 53, WITHHELD)
        assert registry.get(TABLE_UDP_PORT, 53) is DNS
        assert (
            layer_types(decode_frame(dns_frame(), registry=registry))[-1] is DNS
        )

    def test_override_lets_a_withhold_replace_a_direct_entry(self, registry):
        registry.register(TABLE_UDP_PORT, 6969, Fake)
        registry.register(TABLE_UDP_PORT, 6969, WITHHELD, override=True)
        assert registry.get(TABLE_UDP_PORT, 6969) is None

    def test_a_class_registered_after_a_withhold_fills_the_key(self, registry):
        """No override is needed: a withheld key holds no class."""
        registry.register(TABLE_UDP_PORT, 6969, WITHHELD)
        registry.register(TABLE_UDP_PORT, 6969, Fake)
        assert registry.get(TABLE_UDP_PORT, 6969) is Fake
        # ...and is the deliberate entry a later withhold leaves alone.
        registry.register(TABLE_UDP_PORT, 6969, WITHHELD)
        assert registry.get(TABLE_UDP_PORT, 6969) is Fake

    def test_withholding_a_parent_key_reaches_an_inheriting_child(
        self, registry
    ):
        registry.register(TABLE_IP_PROTO, 17, WITHHELD, override=True)
        assert registry.get(TABLE_IP_PROTO, 17) is None
        assert registry.get(TABLE_IP_PROTO_V6, 17) is None
        # A later class in the parent is inherited again.
        registry.register(TABLE_IP_PROTO, 17, Fake)
        assert registry.get(TABLE_IP_PROTO_V6, 17) is Fake

    def test_withholding_a_parent_key_spares_a_child_override(self, registry):
        registry.register(TABLE_IP_PROTO, 51, WITHHELD, override=True)
        assert registry.get(TABLE_IP_PROTO, 51) is None
        assert registry.get(TABLE_IP_PROTO_V6, 51) is AHv6
        registry.register(TABLE_IP_PROTO, 51, AH)
        assert registry.get(TABLE_IP_PROTO_V6, 51) is AHv6

    def test_withholding_checks_the_key_range(self, registry):
        with pytest.raises(InvalidRegistryKeyError):
            registry.register(TABLE_LLC_DSAP, 0x100, WITHHELD)

    def test_the_defaults_withhold_ospf_from_ipv6(self):
        assert DEFAULT.get(TABLE_IP_PROTO, 89) is OSPF
        assert DEFAULT.get(TABLE_IP_PROTO_V6, 89) is None
        child = DEFAULT.derive()
        child.register(TABLE_IP_PROTO, 89, Fake, override=True)
        assert child.get(TABLE_IP_PROTO, 89) is Fake
        assert child.get(TABLE_IP_PROTO_V6, 89) is None


class TestNoneIsRefused:
    def assert_names_the_key(self, excinfo, table, key):
        message = str(excinfo.value)
        assert f"{table} {key}" in message
        assert "None" in message
        assert "WITHHELD" in message

    @pytest.mark.parametrize("lax", [False, True])
    def test_decode_as_refuses_none(self, lax):
        with pytest.raises(TypeError) as excinfo:
            decode_frame(
                dns_frame(), lax=lax, decode_as={TABLE_UDP_PORT: {1812: None}}
            )
        self.assert_names_the_key(excinfo, TABLE_UDP_PORT, 1812)
        assert DEFAULT.get(TABLE_UDP_PORT, 1812).__name__ == "RADIUS"

    def test_derive_refuses_none(self, registry):
        with pytest.raises(TypeError) as excinfo:
            registry.derive({TABLE_IP_PROTO_V6: {89: None}})
        self.assert_names_the_key(excinfo, TABLE_IP_PROTO_V6, 89)

    def test_registering_none_globally_is_refused(self, monkeypatch):
        fresh = DEFAULT.derive()
        monkeypatch.setattr(registry_module, "DEFAULT", fresh)
        with pytest.raises(TypeError) as excinfo:
            registry_module.DEFAULT.register(
                TABLE_UDP_PORT, 53, None, override=True
            )
        self.assert_names_the_key(excinfo, TABLE_UDP_PORT, 53)
        assert fresh.get(TABLE_UDP_PORT, 53) is DNS
        # 53 still holds a direct entry, which a withhold leaves in place.
        register(TABLE_UDP_PORT, 53, WITHHELD)
        assert fresh.get(TABLE_UDP_PORT, 53) is DNS
        with pytest.raises(TypeError) as excinfo:
            register_all(TABLE_IP_PROTO_V6, (253,), None)
        self.assert_names_the_key(excinfo, TABLE_IP_PROTO_V6, 253)
        # 253 holds no entry of its own, so it inherits from ip.proto.
        register(TABLE_IP_PROTO, 253, Fake)
        assert fresh.get(TABLE_IP_PROTO_V6, 253) is Fake
        assert DEFAULT.get(TABLE_IP_PROTO, 253) is None

    def test_none_is_refused_after_the_table_and_key_are_checked(
        self, registry
    ):
        with pytest.raises(UnknownTableError):
            registry.register("udp.ports", 53, None)
        with pytest.raises(InvalidRegistryKeyError):
            registry.register(TABLE_LLC_DSAP, 0x100, None)
