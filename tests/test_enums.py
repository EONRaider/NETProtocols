"""Enum lockstep: every ``IPProtocol``/``EtherType``/``LLCSAP`` member
must carry a display name (CONTRIBUTING.md's enum-lockstep enforcement
point)."""

from netprotocols import LLCSAP, EtherType, IPProtocol


class TestEnumCompleteness:
    def test_every_ip_protocol_member_has_a_display_name(self):
        for member in IPProtocol:
            assert member.display_name

    def test_every_ethertype_member_has_a_display_name(self):
        for member in EtherType:
            assert member.display_name

    def test_extension_header_display_names(self):
        assert IPProtocol.HOPOPT.display_name == "IPv6 Hop-by-Hop Options"
        assert IPProtocol.IPV6_FRAG.display_name == "IPv6 Fragment"

    def test_ipsec_display_names(self):
        assert IPProtocol.ESP.display_name == "ESP"
        assert IPProtocol.AH.display_name == "AH"

    def test_routing_protocol_display_names(self):
        assert IPProtocol.OSPF.display_name == "OSPF"

    def test_vrrp_display_name(self):
        assert IPProtocol.VRRP == 112
        assert IPProtocol.VRRP.display_name == "VRRP"


class TestLLCSAP:
    def test_every_member_has_a_display_name(self):
        for member in LLCSAP:
            assert member.display_name

    def test_the_members_are_the_ieee_assignments(self):
        """The IEEE RA's individual LSAP assignments and the global
        DSAP, fetched 2026-10-25 (see _enums.py)."""
        assert {member.value for member in LLCSAP} == {
            0x00, 0x02, 0x06, 0x0A, 0x0E, 0x42, 0x4E, 0x7E,
            0x82, 0x8E, 0xA6, 0xAA, 0xE6, 0xFE, 0xFF,
        }  # fmt: skip
        assert LLCSAP.SPANNING_TREE.display_name == "Bridge Spanning Tree"
        assert LLCSAP.SNAP.display_name == "SNAP"
