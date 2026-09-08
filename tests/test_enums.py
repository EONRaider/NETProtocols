"""Enum lockstep: every ``IPProtocol``/``EtherType`` member must carry a
display name (CONTRIBUTING.md's enum-lockstep enforcement point)."""

from netprotocols import EtherType, IPProtocol


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
