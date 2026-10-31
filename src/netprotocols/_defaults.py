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

from netprotocols._enums import LLCSAP, EtherType, IPProtocol
from netprotocols.registry import (
    TABLE_ETHERTYPE,
    TABLE_IP_PROTO,
    TABLE_IP_PROTO_V6,
    TABLE_LLC_DSAP,
    TABLE_LLC_SNAP,
    TABLE_TCP_PORT,
    TABLE_UDP_PORT,
    Registry,
    register_all,
)

__all__ = ["install"]

#: Cisco's OUI, 00-00-0C, and the PID it assigns CDP under it (SNAP
#: 00-00-0C 0x2000: Wireshark's packet-cisco-pid.h, CISCO_PID_CDP).
CISCO_OUI = 0x00000C
CDP_PID = 0x2000

#: EtherType values that mark a VLAN tag shim rather than a payload. A
#: tag dispatches to VLAN, whose own ``next_protocol`` comes back to the
#: same table with the inner EtherType, so stacked tags (QinQ) decode as
#: one VLAN layer per tag.
VLAN_TAG_ETHERTYPES = frozenset(
    {EtherType.VLAN_TAG, EtherType.VLAN_TAG_QINQ, EtherType.VLAN_TAG_9100}
)

#: EtherType values that carry an MPLS label stack (RFC 3032 §5): 0x8847
#: for every MPLS frame but one whose top label is upstream-assigned in
#: a multicast frame, which takes 0x8848 (RFC 5332 §4). The stack has
#: the same format under both, so both dispatch to one class.
MPLS_ETHERTYPES = frozenset({EtherType.MPLS, EtherType.MPLS_UPSTREAM_ASSIGNED})

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

#: Protocol numbers both IP families reach, but through a different
#: class in each: the ``ip.proto.v6`` entry deliberately overrides the
#: one ``ip.proto`` would pass down, because something the header does
#: not say for itself depends on the family that carried it.
#:
#: * AH (RFC 4302) has the same wire format after IPv4 and IPv6, but
#:   chains onward through its own ``next_header``, and must do so
#:   through its own family's table — or IPv4 -> AH -> 0 would conjure
#:   a Hop-by-Hop layer, and IPv6 -> AH -> Destination Options (RFC
#:   8200 §4.1) would stop dead.
#: * VRRP (RFC 5798) carries a list of virtual addresses whose width,
#:   4 bytes or 16, nothing in its header gives: only the IP family
#:   does.
FAMILY_SPECIFIC_NUMBERS = frozenset({IPProtocol.AH, IPProtocol.VRRP})

#: Protocol numbers this library decodes after IPv4 alone: the
#: ``ip.proto`` entry is withheld from ``ip.proto.v6``, which would
#: otherwise inherit it. IPv4's protocol 89 is OSPFv2 (RFC 2328) and
#: IPv6's is OSPFv3 (RFC 5340), whose header and messages differ, and
#: this library has no OSPFv3 class: inherited, the entry would make
#: every OSPFv3 packet fail to decode as OSPFv2, where without it the
#: walk ends cleanly at the IPv6 header.
IPV4_ONLY_NUMBERS = frozenset({IPProtocol.OSPF})


def install(registry: Registry) -> None:
    """Register every built-in decoder on ``registry``.

    Idempotent: re-registering the same class to the same key is a
    no-op, so calling this twice on the same registry changes nothing.
    """
    from netprotocols.layer2.arp import ARP
    from netprotocols.layer2.cdp import CDP
    from netprotocols.layer2.llc import SNAP
    from netprotocols.layer2.lldp import LLDP
    from netprotocols.layer2.mpls import MPLS
    from netprotocols.layer2.stp import STP
    from netprotocols.layer2.vlan import VLAN
    from netprotocols.layer3.ah import AH, AHv6
    from netprotocols.layer3.esp import ESP
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
    from netprotocols.layer3.ospf import OSPF
    from netprotocols.layer3.pim import PIM
    from netprotocols.layer3.vrrp import VRRP, VRRPv6
    from netprotocols.layer4.sctp import SCTP
    from netprotocols.layer4.tcp import TCP
    from netprotocols.layer4.udp import UDP
    from netprotocols.layer7.bgp import BGP
    from netprotocols.layer7.dhcp import DHCP
    from netprotocols.layer7.dns import DNS, DNSOverTCP
    from netprotocols.layer7.radius import RADIUS
    from netprotocols.layer7.rip import RIP
    from netprotocols.layer7.tftp import TFTP
    from netprotocols.layer7.vxlan import VXLAN

    add = registry.register

    add(TABLE_ETHERTYPE, EtherType.ARP, ARP)
    add(TABLE_ETHERTYPE, EtherType.IPV4, IPv4)
    add(TABLE_ETHERTYPE, EtherType.IPV6, IPv6)
    register_all(TABLE_ETHERTYPE, VLAN_TAG_ETHERTYPES, VLAN, registry=registry)
    # LLDP (IEEE 802.1AB): an LLDPDU follows the Ethernet header, or a
    # VLAN tag, directly, and ends the walk.
    add(TABLE_ETHERTYPE, EtherType.LLDP, LLDP)

    # MPLS (RFC 3032): its stack names no payload protocol, so MPLS
    # chains onward through this same table, at IPv4's or IPv6's
    # EtherType, by the convention its module docstring describes.
    register_all(TABLE_ETHERTYPE, MPLS_ETHERTYPES, MPLS, registry=registry)

    # SNAP (IEEE Std 802, RFC 1042) extends the LLC header at the SNAP
    # SAP. LLC.next_protocol reaches this entry only when the SSAP is
    # 0xAA too and the Control is UI; SNAP then reads its PID in
    # ethertype (OUI 00-00-00, 00-00-F8) or llc.snap (any other OUI).
    add(TABLE_LLC_DSAP, LLCSAP.SNAP, SNAP)
    # Spanning Tree BPDUs (IEEE 802.1D, 802.1w) at the Bridge Spanning
    # Tree SAP. BPDUs are UI PDUs sent from SSAP 0x42 too, but the SSAP
    # is not checked: any UI or I-format PDU at DSAP 0x42 dispatches.
    add(TABLE_LLC_DSAP, LLCSAP.SPANNING_TREE, STP)
    # CDP is Cisco's own PID 0x2000 under Cisco's OUI 00-00-0C, keyed
    # (oui << 16) | pid; it is not EtherType 0x2000.
    add(TABLE_LLC_SNAP, CISCO_OUI << 16 | CDP_PID, CDP)

    # Shared by IPv4 and IPv6: registering in ip.proto reaches
    # ip.proto.v6 too, because the latter inherits it.
    add(TABLE_IP_PROTO, IPProtocol.ICMP, ICMPv4)
    add(TABLE_IP_PROTO, IPProtocol.IGMP, IGMP)
    add(TABLE_IP_PROTO, IPProtocol.TCP, TCP)
    add(TABLE_IP_PROTO, IPProtocol.UDP, UDP)
    add(TABLE_IP_PROTO, IPProtocol.GRE, GRE)
    add(TABLE_IP_PROTO, IPProtocol.IPV6_ICMP, ICMPv6)
    add(TABLE_IP_PROTO, IPProtocol.SCTP, SCTP)
    # PIM (RFC 7761) is one class for both families: its encoded
    # addresses name their own family, and only the checksum's IPv6
    # pseudo-header depends on the IP header around it.
    add(TABLE_IP_PROTO, IPProtocol.PIM, PIM)

    # IP-in-IP has no header of its own: protocol 4 (RFC 2003, RFC 2473)
    # or 41 (RFC 4213, RFC 2473) says the payload is a whole IPv4 or
    # IPv6 packet, so the outer header dispatches straight to it. Shared
    # like the rest, because IPv6 can carry either.
    add(TABLE_IP_PROTO, IPProtocol.IPIP, IPv4)
    add(TABLE_IP_PROTO, IPProtocol.IPV6, IPv6)

    # IPsec ESP (RFC 4303) is the same header after either IP version,
    # and a dead end after both: its payload is opaque without the keys.
    add(TABLE_IP_PROTO, IPProtocol.ESP, ESP)

    # IPsec AH (RFC 4302) — see FAMILY_SPECIFIC_NUMBERS. The v6 entry is
    # registered first: it is then the v6 table's own, so the ip.proto
    # entry that follows is not inherited over it (and does not
    # conflict with it).
    add(TABLE_IP_PROTO_V6, IPProtocol.AH, AHv6)
    add(TABLE_IP_PROTO, IPProtocol.AH, AH)

    # IPv4 chain only — see IPV4_ONLY_NUMBERS. Withheld from the v6
    # table first, so the ip.proto entry is not inherited into it.
    registry._withhold(TABLE_IP_PROTO_V6, IPProtocol.OSPF)
    add(TABLE_IP_PROTO, IPProtocol.OSPF, OSPF)

    # VRRP (RFC 3768, RFC 5798) — see FAMILY_SPECIFIC_NUMBERS. Wired the
    # same way as AH, the v6 entry first, so each family reads its own
    # address width.
    add(TABLE_IP_PROTO_V6, IPProtocol.VRRP, VRRPv6)
    add(TABLE_IP_PROTO, IPProtocol.VRRP, VRRP)

    # IPv6 chain only — see IPV6_ONLY_NUMBERS.
    add(TABLE_IP_PROTO_V6, IPProtocol.HOPOPT, IPv6HopByHopOptions)
    add(TABLE_IP_PROTO_V6, IPProtocol.IPV6_ROUTE, IPv6Routing)
    add(TABLE_IP_PROTO_V6, IPProtocol.IPV6_FRAG, IPv6Fragment)
    add(TABLE_IP_PROTO_V6, IPProtocol.IPV6_DSTOPTS, IPv6DestinationOptions)

    add(TABLE_UDP_PORT, 53, DNS)
    register_all(TABLE_UDP_PORT, (67, 68), DHCP, registry=registry)
    # VXLAN's IANA port (RFC 7348 §5). An encapsulating endpoint normally
    # sends to it and hashes the source port from the inner flow, so the
    # destination-first lookup finds it whatever that source port is.
    # Linux's pre-IANA 8472 is not registered: decode_as adds it per walk.
    add(TABLE_UDP_PORT, 4789, VXLAN)
    # RIP (RFC 1058, RFC 2453): routers send from and to port 520, and
    # answer a Request from another port back to it, from 520.
    add(TABLE_UDP_PORT, 520, RIP)
    # TFTP (RFC 1350 §4): only a request goes to port 69. The server
    # answers from an ephemeral port, its transfer identifier, and the
    # rest of the transfer runs between two ephemeral ports, which no
    # port table can name: a stateless walk reaches TFTP for the request
    # alone (see layer7/tftp.py; decode_as names the server's port).
    add(TABLE_UDP_PORT, 69, TFTP)
    # RADIUS (RFC 2865, RFC 2866): IANA's authentication and accounting
    # ports. A client sends from an ephemeral port and the server
    # answers from the one it was sent to, so the destination-first
    # lookup finds both directions. The legacy 1645 and 1646 and
    # Dynamic Authorization's 3799 (RFC 5176) are not registered:
    # decode_as adds them per walk.
    register_all(TABLE_UDP_PORT, (1812, 1813), RADIUS, registry=registry)

    # DNS over TCP carries a 2-byte length prefix (RFC 1035 §4.2.2), so
    # port 53 names the shim that consumes it and then chains to the DNS
    # message, keeping the chain walk uniform.
    add(TABLE_TCP_PORT, 53, DNSOverTCP)

    # BGP-4 (RFC 4271 §8.2.1): a speaker listens on 179 and the peer that
    # opened the connection sends from an ephemeral port, so the
    # destination-first lookup finds it in both directions. Each message
    # decodes as one layer and chains to the next one in the segment.
    add(TABLE_TCP_PORT, 179, BGP)
