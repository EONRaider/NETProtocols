"""netprotocols: low-level implementations of common networking protocols.

Decode raw header bytes into typed, immutable protocol objects — or
build those objects from field values and serialize them back to their
exact on-wire form.
"""

from netprotocols import _defaults
from netprotocols._base import Protocol
from netprotocols._enums import (
    ARPHardwareType,
    ARPOperation,
    EtherType,
    IPProtocol,
)
from netprotocols.checksum import compute, internet_checksum, verify
from netprotocols.flow import FlowKey, flow_key
from netprotocols.layer2.arp import ARP
from netprotocols.layer2.ethernet import Ethernet
from netprotocols.layer2.vlan import VLAN
from netprotocols.layer3.gre import GRE
from netprotocols.layer3.icmp import ICMPv4, ICMPv6, NDPOption
from netprotocols.layer3.igmp import IGMP, IGMPv3GroupRecord
from netprotocols.layer3.ip import IPv4, IPv4Option, IPv6
from netprotocols.layer3.ipv6_ext import (
    IPv6DestinationOptions,
    IPv6Fragment,
    IPv6HopByHopOptions,
    IPv6Option,
    IPv6Routing,
)
from netprotocols.layer4.tcp import TCP, TCPOption
from netprotocols.layer4.udp import UDP
from netprotocols.layer7.dhcp import DHCP
from netprotocols.layer7.dns import DNS, DNSOverTCP, DNSResourceRecord
from netprotocols.packet import Packet
from netprotocols.registry import (
    DEFAULT,
    Registry,
    RegistryConflictError,
    UnknownTableError,
    register,
    register_all,
)
from netprotocols.utils.exceptions import (
    InvalidFieldError,
    InvalidIPv4AddressError,
    InvalidMACAddressError,
    InvalidManufacturerCodeError,
    MaxDepthExceededError,
    ProtocolError,
    TruncatedHeaderError,
)
from netprotocols.utils.ipv4 import validate_ipv4_addr
from netprotocols.utils.mac import random_mac, validate_mac_addr
from netprotocols.walk import MAX_DEPTH, decode_frame

# Populate the default dispatch registry now that every protocol class
# above has been imported. This must stay after those imports: the
# registrations name the classes. See netprotocols/_defaults.py.
_defaults.install(DEFAULT)

__version__ = "2.0.0"

__all__ = [
    "ARP",
    "DEFAULT",
    "DHCP",
    "DNS",
    "GRE",
    "IGMP",
    "MAX_DEPTH",
    "TCP",
    "UDP",
    "VLAN",
    "ARPHardwareType",
    "ARPOperation",
    "DNSOverTCP",
    "DNSResourceRecord",
    "EtherType",
    "Ethernet",
    "FlowKey",
    "ICMPv4",
    "ICMPv6",
    "IGMPv3GroupRecord",
    "IPProtocol",
    "IPv4",
    "IPv4Option",
    "IPv6",
    "IPv6DestinationOptions",
    "IPv6Fragment",
    "IPv6HopByHopOptions",
    "IPv6Option",
    "IPv6Routing",
    "InvalidFieldError",
    "InvalidIPv4AddressError",
    "InvalidMACAddressError",
    "InvalidManufacturerCodeError",
    "MaxDepthExceededError",
    "NDPOption",
    "Packet",
    "Protocol",
    "ProtocolError",
    "Registry",
    "RegistryConflictError",
    "TCPOption",
    "TruncatedHeaderError",
    "UnknownTableError",
    "__version__",
    "compute",
    "decode_frame",
    "flow_key",
    "internet_checksum",
    "random_mac",
    "register",
    "register_all",
    "validate_ipv4_addr",
    "validate_mac_addr",
    "verify",
]
