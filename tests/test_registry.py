"""The public dispatch registry (#87): registration, conflicts, table
inheritance, and isolation from the process-wide default."""

import pytest

from netprotocols import DNS, TCP, UDP, Ethernet, IPv4, IPv6, Protocol
from netprotocols._defaults import IPV6_ONLY_NUMBERS, install
from netprotocols.registry import (
    DEFAULT,
    TABLE_ETHERTYPE,
    TABLE_IP_PROTO,
    TABLE_IP_PROTO_V6,
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
        assert register(TABLE_IP_PROTO, 132, Fake, registry=isolated) is None
        assert isolated.get(TABLE_IP_PROTO, 132) is Fake

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
        registry.register(TABLE_IP_PROTO, 132, Fake)
        assert registry.get(TABLE_IP_PROTO, 132) is Fake
        assert registry.get(TABLE_IP_PROTO_V6, 132) is Fake

    def test_a_v6_registration_stays_out_of_the_base_table(self, registry):
        registry.register(TABLE_IP_PROTO_V6, 139, Fake)
        assert registry.get(TABLE_IP_PROTO_V6, 139) is Fake
        assert registry.get(TABLE_IP_PROTO, 139) is None

    def test_a_v6_override_is_not_clobbered_by_a_later_parent_write(
        self, registry
    ):
        """Inheritance must not overwrite a deliberate child entry,
        whichever order the two registrations arrive in."""
        registry.register(TABLE_IP_PROTO_V6, 132, OtherFake)
        registry.register(TABLE_IP_PROTO, 132, Fake)
        assert registry.get(TABLE_IP_PROTO, 132) is Fake
        assert registry.get(TABLE_IP_PROTO_V6, 132) is OtherFake

    def test_the_built_in_extension_headers_are_v6_only(self, registry):
        for number in IPV6_ONLY_NUMBERS:
            assert registry.get(TABLE_IP_PROTO, number) is None
            assert registry.get(TABLE_IP_PROTO_V6, number) is not None

    def test_the_v6_table_is_the_base_table_plus_the_v6_only_numbers(self):
        registry = Registry()
        install(registry)
        base = registry.table(TABLE_IP_PROTO)
        v6 = registry.table(TABLE_IP_PROTO_V6)
        assert set(v6) - set(base) == set(IPV6_ONLY_NUMBERS)


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
        child = registry.derive({TABLE_IP_PROTO: {132: Fake}})
        assert child.get(TABLE_IP_PROTO_V6, 132) is Fake

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

    def test_ports(self):
        assert DEFAULT.get(TABLE_UDP_PORT, 53) is DNS
        assert DEFAULT.get(TABLE_UDP_PORT, 67).__name__ == "DHCP"
        assert DEFAULT.get(TABLE_UDP_PORT, 68).__name__ == "DHCP"
        assert DEFAULT.get(TABLE_TCP_PORT, 53).__name__ == "DNSOverTCP"


class TestRepr:
    def test_repr_reports_the_table_sizes(self):
        text = repr(Registry())
        assert "Registry" in text
        for name in TABLES:
            assert f"{name}=0" in text
