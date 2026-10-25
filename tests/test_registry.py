"""The public dispatch registry (#87): registration, conflicts, table
inheritance, and isolation from the process-wide default."""

import pytest

from netprotocols import (
    DNS,
    SCTP,
    SNAP,
    TCP,
    UDP,
    Ethernet,
    InvalidRegistryKeyError,
    IPv4,
    IPv6,
    Protocol,
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
    Registry,
    RegistryConflictError,
    UnknownTableError,
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
        registry.register(TABLE_ETHERTYPE, 0x8847, Fake)
        assert registry.get(TABLE_ETHERTYPE, 0x8847) is Fake

    def test_an_unregistered_key_answers_none(self, registry):
        assert registry.get(TABLE_ETHERTYPE, 0x8847) is None

    def test_register_returns_the_class_unchanged_as_a_decorator(self):
        isolated = Registry()

        @register(TABLE_ETHERTYPE, 0x8847, registry=isolated)
        class Decorated(Protocol):
            pass

        assert isolated.get(TABLE_ETHERTYPE, 0x8847) is Decorated
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
        registry.register(TABLE_ETHERTYPE, 0x8847, Fake)
        with pytest.raises(RegistryConflictError):
            registry.register(TABLE_ETHERTYPE, 0x8847, OtherFake)

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
        """Inheritance must not overwrite a deliberate child entry,
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
        registry._withhold(TABLE_IP_PROTO_V6, 253)
        registry.register(TABLE_IP_PROTO, 253, Fake)
        assert registry.get(TABLE_IP_PROTO, 253) is Fake
        assert registry.get(TABLE_IP_PROTO_V6, 253) is None
        registry.register(TABLE_IP_PROTO_V6, 253, OtherFake)
        assert registry.get(TABLE_IP_PROTO_V6, 253) is OtherFake

    def test_withholding_removes_an_inherited_entry(self, registry):
        registry.register(TABLE_IP_PROTO, 253, Fake)
        registry._withhold(TABLE_IP_PROTO_V6, 253)
        assert registry.get(TABLE_IP_PROTO_V6, 253) is None
        assert registry.get(TABLE_IP_PROTO, 253) is Fake

    def test_withholding_leaves_a_direct_registration_alone(self, registry):
        registry.register(TABLE_IP_PROTO_V6, 253, OtherFake)
        registry._withhold(TABLE_IP_PROTO_V6, 253)
        assert registry.get(TABLE_IP_PROTO_V6, 253) is OtherFake

    def test_withholding_an_unknown_table_raises(self, registry):
        with pytest.raises(UnknownTableError):
            registry._withhold("ip.proto.v7", 89)

    def test_a_derived_registry_copies_what_is_withheld(self, registry):
        registry._withhold(TABLE_IP_PROTO_V6, 253)
        child = registry.derive({TABLE_IP_PROTO: {253: Fake}})
        assert child.get(TABLE_IP_PROTO_V6, 253) is None
        # ...independently: withholding in the child leaves the parent.
        child._withhold(TABLE_IP_PROTO_V6, 254)
        registry.register(TABLE_IP_PROTO, 254, Fake)
        assert registry.get(TABLE_IP_PROTO_V6, 254) is Fake

    def test_shared_numbers_differ_only_where_the_family_matters(self):
        """Every number both tables hold names the same class, except
        the family-specific ones, whose v6 entry is the table's own."""
        # FAMILY_SPECIFIC_NUMBERS only describes the wiring, and the
        # comparison below trusts it: pinned literally, so widening it
        # (and with it what this test allows) is a deliberate change
        # here, not a side effect of editing _defaults.
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
        registry.register(TABLE_ETHERTYPE, 0x8847, Fake)
        assert DEFAULT.get(TABLE_ETHERTYPE, 0x8847) is None

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
        """The shape #88 will spend: DNS read on a nonstandard port for
        one caller, with the rest of the process unaffected."""
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
        """SNAP is the one built-in LLC entry; the llc.snap table starts
        empty, for CDP and other OUIs' protocols to register in."""
        assert DEFAULT.table(TABLE_LLC_DSAP) == {0xAA: SNAP}
        assert DEFAULT.table(TABLE_LLC_SNAP) == {}

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
    """A key its wire field cannot carry is refused at registration."""

    @pytest.mark.parametrize("key", [0, 46, 1500, 1501, 1535, -1, 0x10000])
    def test_ethertype_refuses_lengths_and_the_undefined_gap(
        self, registry, key
    ):
        """An Ethernet header reads 1500 or less as an 802.3 Length and
        1501-1535 as undefined, so an entry there would never be
        reached from Ethernet."""
        with pytest.raises(InvalidRegistryKeyError) as excinfo:
            registry.register(TABLE_ETHERTYPE, key, Fake)
        assert TABLE_ETHERTYPE in str(excinfo.value)
        assert registry.get(TABLE_ETHERTYPE, key) is None

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
        with pytest.raises(InvalidRegistryKeyError):
            registry.register(table, bad, Fake)
        registry.register(table, good, Fake)
        assert registry.get(table, good) is Fake

    def test_the_decorator_and_derive_and_decode_as_refuse_too(self):
        isolated = Registry()
        with pytest.raises(InvalidRegistryKeyError):
            register(TABLE_ETHERTYPE, 0x0026, registry=isolated)(Fake)
        with pytest.raises(InvalidRegistryKeyError):
            isolated.derive({TABLE_ETHERTYPE: {0x0026: Fake}})
        with pytest.raises(InvalidRegistryKeyError):
            decode_frame(bytes(14), decode_as={TABLE_ETHERTYPE: {38: Fake}})

    def test_the_other_tables_accept_any_key(self, registry):
        registry.register(TABLE_UDP_PORT, 0x10000, Fake)
        registry.register(TABLE_IP_PROTO, 300, Fake)
        assert registry.get(TABLE_UDP_PORT, 0x10000) is Fake
        assert registry.get(TABLE_IP_PROTO, 300) is Fake
