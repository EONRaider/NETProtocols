"""netprotocols: low-level implementations of common networking protocols.

Decode raw header bytes into typed, immutable protocol objects — or
build those objects from field values and serialize them back to their
exact on-wire form.
"""

from netprotocols._base import Protocol
from netprotocols._enums import (
    ARPHardwareType,
    ARPOperation,
    EtherType,
    IPProtocol,
)
from netprotocols.checksum import compute, internet_checksum, verify
from netprotocols.layer2.arp import ARP
from netprotocols.layer2.ethernet import Ethernet
from netprotocols.layer2.vlan import VLAN
from netprotocols.layer3.gre import GRE
from netprotocols.layer3.icmp import ICMPv4, ICMPv6
from netprotocols.layer3.igmp import IGMP, IGMPv3GroupRecord
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
from netprotocols.layer7.dns import DNS, DNSResourceRecord
from netprotocols.packet import Packet
from netprotocols.utils.exceptions import (
    InvalidFieldError,
    InvalidIPv4AddressError,
    InvalidMACAddressError,
    InvalidManufacturerCodeError,
    ProtocolError,
    TruncatedHeaderError,
)
from netprotocols.utils.ipv4 import validate_ipv4_addr
from netprotocols.utils.mac import random_mac, validate_mac_addr

__version__ = "1.2.0"

__all__ = [
    "ARP",
    "DHCP",
    "DNS",
    "GRE",
    "IGMP",
    "TCP",
    "UDP",
    "VLAN",
    "ARPHardwareType",
    "ARPOperation",
    "DNSResourceRecord",
    "EtherType",
    "Ethernet",
    "ICMPv4",
    "ICMPv6",
    "IGMPv3GroupRecord",
    "IPProtocol",
    "IPv4",
    "IPv6",
    "IPv6DestinationOptions",
    "IPv6Fragment",
    "IPv6HopByHopOptions",
    "IPv6Routing",
    "InvalidFieldError",
    "InvalidIPv4AddressError",
    "InvalidMACAddressError",
    "InvalidManufacturerCodeError",
    "Packet",
    "Protocol",
    "ProtocolError",
    "TruncatedHeaderError",
    "__version__",
    "compute",
    "internet_checksum",
    "random_mac",
    "validate_ipv4_addr",
    "validate_mac_addr",
    "verify",
]
