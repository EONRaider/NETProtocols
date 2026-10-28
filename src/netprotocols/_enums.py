"""Protocol number registries.

This module is intentionally dependency-free: it must never import from
the layer modules, so that any protocol class can import an enum from
here without creating an import cycle.
"""

from enum import IntEnum

__all__ = [
    "LLCSAP",
    "ARPHardwareType",
    "ARPOperation",
    "EtherType",
    "IPProtocol",
]


class EtherType(IntEnum):
    """EtherType values (IEEE 802.3) recognized by this library."""

    IPV4 = 0x0800
    ARP = 0x0806
    VLAN_TAG = 0x8100
    VLAN_TAG_QINQ = 0x88A8
    VLAN_TAG_9100 = 0x9100
    IPV6 = 0x86DD
    MPLS = 0x8847
    MPLS_UPSTREAM_ASSIGNED = 0x8848
    LLDP = 0x88CC

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
    # IANA's names (ieee-802-numbers, fetched 2026-10-25): RFC 5332 §4
    # retired 0x8848's original "MPLS multicast" meaning.
    EtherType.MPLS: "MPLS",
    EtherType.MPLS_UPSTREAM_ASSIGNED: "MPLS with upstream-assigned label",
    EtherType.LLDP: "LLDP",
}


class LLCSAP(IntEnum):
    """IEEE 802.2 LLC service access point (LSAP) addresses.

    Every value the IEEE Registration Authority lists as assigned in its
    "Current Assignment of Individual LSAP Address Values" and "Group
    LSAP Address Values" tables
    (https://standards.ieee.org/products-programs/regauth/llc/public/,
    fetched 2026-10-25): the fourteen assigned individual addresses and
    the global DSAP. The values unlisted there are reserved, or for
    unreserved use (an individual address whose second least significant
    bit is 0, such as Novell's 0xE0 and NetBIOS's 0xF0, which the IEEE
    does not list). The least significant bit of a DSAP is the
    individual/group bit and of an SSAP the command/response bit, so an
    SSAP's name is that of the value with that bit clear.
    """

    NULL = 0x00
    LLC_SUBLAYER_MANAGEMENT = 0x02
    IP = 0x06
    SDE = 0x0A
    PROWAY_NETWORK_MANAGEMENT = 0x0E
    SPANNING_TREE = 0x42
    MMS = 0x4E
    X25_PLP = 0x7E
    BACNET = 0x82
    PROWAY_ACTIVE_STATION_LIST = 0x8E
    SOURCE_ROUTING_RDE = 0xA6
    SNAP = 0xAA
    IEC_62056_46 = 0xE6
    ISO_NETWORK_LAYER = 0xFE
    GLOBAL = 0xFF

    @property
    def display_name(self) -> str:
        return _LLC_SAP_NAMES[self]


# The documents each assignment cites in the IEEE listing above.
_LLC_SAP_NAMES = {
    LLCSAP.NULL: "Null",  # ISO/IEC 8802-2
    LLCSAP.LLC_SUBLAYER_MANAGEMENT: "LLC Sublayer Management",  # 802.1B
    LLCSAP.IP: "ARPANET IP",  # RFC 791
    LLCSAP.SDE: "802.10 Secure Data Exchange",  # IEEE 802.10B
    LLCSAP.PROWAY_NETWORK_MANAGEMENT: "PROWAY Network Management",  # IEC 955
    LLCSAP.SPANNING_TREE: "Bridge Spanning Tree",  # ISO/IEC 10038
    LLCSAP.MMS: "Manufacturing Message Service",  # ISO 9506
    LLCSAP.X25_PLP: "X.25 Packet Layer",  # ISO/IEC 8208
    LLCSAP.BACNET: "BACnet",  # ANSI/ASHRAE 135
    LLCSAP.PROWAY_ACTIVE_STATION_LIST: "PROWAY Active Station List",  # IEC 955
    LLCSAP.SOURCE_ROUTING_RDE: "Source Routing RDE",  # ISO/IEC 8802-2
    LLCSAP.SNAP: "SNAP",  # IEEE Std 802
    LLCSAP.IEC_62056_46: "IEC 62056-46",  # IEC 62056-46
    LLCSAP.ISO_NETWORK_LAYER: "ISO Network Layer",  # ISO/IEC TR 9577
    LLCSAP.GLOBAL: "Global",  # ISO/IEC 8802-2, global DSAP
}


class IPProtocol(IntEnum):
    """IP protocol numbers (RFC 790 / IANA) recognized by this library.

    The number space is shared between IPv4 ``protocol`` and IPv6
    ``next_header``, so a single registry serves both.
    """

    HOPOPT = 0x00
    ICMP = 0x01
    IGMP = 0x02
    IPIP = 0x04
    TCP = 0x06
    UDP = 0x11
    IPV6 = 0x29
    IPV6_ROUTE = 0x2B
    IPV6_FRAG = 0x2C
    GRE = 0x2F
    ESP = 0x32
    AH = 0x33
    IPV6_ICMP = 0x3A
    IPV6_DSTOPTS = 0x3C
    OSPF = 0x59
    PIM = 0x67
    VRRP = 0x70
    SCTP = 0x84

    @property
    def display_name(self) -> str:
        return _IP_PROTOCOL_NAMES[self]


_IP_PROTOCOL_NAMES = {
    IPProtocol.HOPOPT: "IPv6 Hop-by-Hop Options",
    IPProtocol.ICMP: "ICMP",
    IPProtocol.IGMP: "IGMP",
    IPProtocol.IPIP: "IPv4 encapsulation",
    IPProtocol.TCP: "TCP",
    IPProtocol.UDP: "UDP",
    IPProtocol.IPV6: "IPv6 encapsulation",
    IPProtocol.IPV6_ROUTE: "IPv6 Routing",
    IPProtocol.IPV6_FRAG: "IPv6 Fragment",
    IPProtocol.GRE: "GRE",
    IPProtocol.ESP: "ESP",
    IPProtocol.AH: "AH",
    IPProtocol.IPV6_ICMP: "IPv6-ICMP",
    IPProtocol.IPV6_DSTOPTS: "IPv6 Destination Options",
    IPProtocol.OSPF: "OSPF",
    IPProtocol.PIM: "PIM",
    IPProtocol.VRRP: "VRRP",
    IPProtocol.SCTP: "SCTP",
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
