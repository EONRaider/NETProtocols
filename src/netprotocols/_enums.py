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
    IPV6 = 0x86DD

    @property
    def display_name(self) -> str:
        return _ETHERTYPE_NAMES[self]


_ETHERTYPE_NAMES = {
    EtherType.IPV4: "IPv4",
    EtherType.ARP: "ARP",
    EtherType.IPV6: "IPv6",
}


class IPProtocol(IntEnum):
    """IP protocol numbers (RFC 790 / IANA) recognized by this library.

    The number space is shared between IPv4 ``protocol`` and IPv6
    ``next_header``, so a single registry serves both.
    """

    ICMP = 0x01
    IGMP = 0x02
    TCP = 0x06
    UDP = 0x11
    IPV6_ICMP = 0x3A

    @property
    def display_name(self) -> str:
        return _IP_PROTOCOL_NAMES[self]


_IP_PROTOCOL_NAMES = {
    IPProtocol.ICMP: "ICMP",
    IPProtocol.IGMP: "IGMP",
    IPProtocol.TCP: "TCP",
    IPProtocol.UDP: "UDP",
    IPProtocol.IPV6_ICMP: "IPv6-ICMP",
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
