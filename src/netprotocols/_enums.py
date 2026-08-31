"""Protocol number registries.

This module is intentionally dependency-free: it must never import from
the layer modules, so that any protocol class can import an enum from
here without creating an import cycle.
"""

from enum import IntEnum

__all__ = ["ARPHardwareType", "ARPOperation", "EtherType", "IPProtocol"]


class EtherType(IntEnum):
    """EtherType values (IEEE 802.3) recognized by this library."""

    IPV4 = 0x0800
    ARP = 0x0806
    VLAN_TAG = 0x8100
    VLAN_TAG_QINQ = 0x88A8
    VLAN_TAG_9100 = 0x9100
    IPV6 = 0x86DD

    @property
    def display_name(self) -> str:
        return _ETHERTYPE_NAMES[self]


_ETHERTYPE_NAMES = {
    EtherType.IPV4: "IPv4",
    EtherType.ARP: "ARP",
    EtherType.VLAN_TAG: "802.1Q VLAN tag",
    EtherType.VLAN_TAG_QINQ: "802.1ad S-TAG (QinQ)",
    EtherType.VLAN_TAG_9100: "VLAN double tag (legacy)",
    EtherType.IPV6: "IPv6",
}


class IPProtocol(IntEnum):
    """IP protocol numbers (RFC 790 / IANA) recognized by this library.

    The number space is shared between IPv4 ``protocol`` and IPv6
    ``next_header``, so a single registry serves both.
    """

    HOPOPT = 0x00
    ICMP = 0x01
    IGMP = 0x02
    TCP = 0x06
    UDP = 0x11
    IPV6_ROUTE = 0x2B
    IPV6_FRAG = 0x2C
    GRE = 0x2F
    IPV6_ICMP = 0x3A
    IPV6_DSTOPTS = 0x3C

    @property
    def display_name(self) -> str:
        return _IP_PROTOCOL_NAMES[self]


_IP_PROTOCOL_NAMES = {
    IPProtocol.HOPOPT: "IPv6 Hop-by-Hop Options",
    IPProtocol.ICMP: "ICMP",
    IPProtocol.IGMP: "IGMP",
    IPProtocol.TCP: "TCP",
    IPProtocol.UDP: "UDP",
    IPProtocol.IPV6_ROUTE: "IPv6 Routing",
    IPProtocol.IPV6_FRAG: "IPv6 Fragment",
    IPProtocol.GRE: "GRE",
    IPProtocol.IPV6_ICMP: "IPv6-ICMP",
    IPProtocol.IPV6_DSTOPTS: "IPv6 Destination Options",
}


class ARPOperation(IntEnum):
    """ARP operation codes (RFC 826)."""

    REQUEST = 1
    REPLY = 2

    @property
    def display_name(self) -> str:
        return self.name.lower()


class ARPHardwareType(IntEnum):
    """ARP hardware types (RFC 826 / IANA); only Ethernet is common."""

    ETHERNET = 1

    @property
    def display_name(self) -> str:
        return self.name.capitalize()
