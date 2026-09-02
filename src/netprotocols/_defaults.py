"""The decoders this library ships, and the wire values that reach them.

:func:`install` is the whole default dispatch map in one place — what
used to be four dict literals scattered across the layer modules. It
runs once, from ``netprotocols/__init__.py``, after every protocol class
has been imported.

The imports are function-local for the reason they always were: layer
modules name each other's classes, and importing them at module level
here would put this module in the middle of that cycle (see
ARCHITECTURE.md). Nothing is deferred for *speed* — by the time anything
dispatches, the package import has already pulled in every protocol
module.
"""

from __future__ import annotations

from netprotocols._enums import EtherType, IPProtocol
from netprotocols.registry import (
    TABLE_ETHERTYPE,
    TABLE_IP_PROTO,
    TABLE_IP_PROTO_V6,
    TABLE_TCP_PORT,
    TABLE_UDP_PORT,
    Registry,
    register_all,
)

__all__ = ["install"]

#: EtherType values that mark a VLAN tag shim rather than a payload. A
#: tag dispatches to VLAN, whose own ``next_protocol`` comes back to the
#: same table with the inner EtherType, so stacked tags (QinQ) decode as
#: one VLAN layer per tag.
VLAN_TAG_ETHERTYPES = frozenset(
    {EtherType.VLAN_TAG, EtherType.VLAN_TAG_QINQ, EtherType.VLAN_TAG_9100}
)

#: Protocol numbers that only make sense inside an IPv6 chain (RFC 8200
#: §4.3-4.6): extension headers follow the IPv6 fixed header or one
#: another, never an IPv4 header. They are registered in
#: ``ip.proto.v6`` alone, which is what keeps them unreachable from
#: IPv4 — the gating is the table's shape, not a test on the hot path.
IPV6_ONLY_NUMBERS = frozenset(
    {
        IPProtocol.HOPOPT,
        IPProtocol.IPV6_ROUTE,
        IPProtocol.IPV6_FRAG,
        IPProtocol.IPV6_DSTOPTS,
    }
)


def install(registry: Registry) -> None:
    """Register every built-in decoder on ``registry``.

    Idempotent: re-registering the same class to the same key is a
    no-op, so calling this twice on the same registry changes nothing.
    """
    from netprotocols.layer2.arp import ARP
    from netprotocols.layer2.vlan import VLAN
    from netprotocols.layer3.gre import GRE
    from netprotocols.layer3.icmp import ICMPv4, ICMPv6
    from netprotocols.layer3.igmp import IGMP
    from netprotocols.layer3.ip import IPv4, IPv6
    from netprotocols.layer3.ipv6_ext import (
        IPv6DestinationOptions,
        IPv6Fragment,
        IPv6HopByHopOptions,
        IPv6Routing,
    )
    from netprotocols.layer4.tcp import TCP
    from netprotocols.layer4.udp import UDP
    from netprotocols.layer7.dhcp import DHCP
    from netprotocols.layer7.dns import DNS, DNSOverTCP

    add = registry.register

    add(TABLE_ETHERTYPE, EtherType.ARP, ARP)
    add(TABLE_ETHERTYPE, EtherType.IPV4, IPv4)
    add(TABLE_ETHERTYPE, EtherType.IPV6, IPv6)
    register_all(TABLE_ETHERTYPE, VLAN_TAG_ETHERTYPES, VLAN, registry=registry)

    # Shared by IPv4 and IPv6: registering in ip.proto reaches
    # ip.proto.v6 too, because the latter inherits it.
    add(TABLE_IP_PROTO, IPProtocol.ICMP, ICMPv4)
    add(TABLE_IP_PROTO, IPProtocol.IGMP, IGMP)
    add(TABLE_IP_PROTO, IPProtocol.TCP, TCP)
    add(TABLE_IP_PROTO, IPProtocol.UDP, UDP)
    add(TABLE_IP_PROTO, IPProtocol.GRE, GRE)
    add(TABLE_IP_PROTO, IPProtocol.IPV6_ICMP, ICMPv6)

    # IPv6 chain only — see IPV6_ONLY_NUMBERS.
    add(TABLE_IP_PROTO_V6, IPProtocol.HOPOPT, IPv6HopByHopOptions)
    add(TABLE_IP_PROTO_V6, IPProtocol.IPV6_ROUTE, IPv6Routing)
    add(TABLE_IP_PROTO_V6, IPProtocol.IPV6_FRAG, IPv6Fragment)
    add(TABLE_IP_PROTO_V6, IPProtocol.IPV6_DSTOPTS, IPv6DestinationOptions)

    add(TABLE_UDP_PORT, 53, DNS)
    register_all(TABLE_UDP_PORT, (67, 68), DHCP, registry=registry)

    # DNS over TCP carries a 2-byte length prefix (RFC 1035 §4.2.2), so
    # port 53 names the shim that consumes it and then chains to the DNS
    # message, keeping the chain walk uniform.
    add(TABLE_TCP_PORT, 53, DNSOverTCP)
