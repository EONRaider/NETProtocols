"""netprotocols: low-level implementations of common networking protocols.

Decode raw header bytes into typed, immutable protocol objects — or
build those objects from field values and serialize them back to their
exact on-wire form.
"""

from netprotocols import _defaults
from netprotocols._base import Protocol
from netprotocols._enums import (
    LLCSAP,
    ARPHardwareType,
    ARPOperation,
    EtherType,
    IPProtocol,
)
from netprotocols.checksum import (
    compute,
    crc32c,
    fletcher_checksum,
    internet_checksum,
    lsa_checksum,
    verify,
    verify_lsa,
)
from netprotocols.flow import FlowKey, flow_key
from netprotocols.layer2.arp import ARP
from netprotocols.layer2.cdp import CDP, CDPTLV, CDPAddress
from netprotocols.layer2.ethernet import Ethernet
from netprotocols.layer2.llc import LLC, SNAP
from netprotocols.layer2.lldp import LLDP, LLDPTLV, LLDPChassisID, LLDPPortID
from netprotocols.layer2.mpls import MPLS, MPLSLabel
from netprotocols.layer2.stp import STP
from netprotocols.layer2.vlan import VLAN
from netprotocols.layer3.ah import AH, AHv6
from netprotocols.layer3.esp import ESP
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
from netprotocols.layer3.ospf import (
    OSPF,
    OSPFLSA,
    OSPFDatabaseDescription,
    OSPFHello,
    OSPFLSAHeader,
    OSPFLSRequest,
)
from netprotocols.layer3.pim import (
    PIM,
    PIMAssert,
    PIMEncodedGroup,
    PIMEncodedSource,
    PIMEncodedUnicast,
    PIMGroupSet,
    PIMHello,
    PIMHelloOption,
    PIMJoinPrune,
    PIMLANPruneDelay,
    PIMRegister,
    PIMRegisterStop,
)
from netprotocols.layer3.vrrp import VRRP, VRRPv6
from netprotocols.layer4.sctp import SCTP, SCTPChunk
from netprotocols.layer4.tcp import TCP, TCPOption
from netprotocols.layer4.udp import UDP
from netprotocols.layer7.bgp import (
    BGP,
    BGPOptionalParameter,
    BGPPathAttribute,
    BGPPrefix,
)
from netprotocols.layer7.dhcp import DHCP, DHCPOption
from netprotocols.layer7.dns import (
    DNS,
    DNSOverTCP,
    DNSQuestion,
    DNSResourceRecord,
    MXRecord,
    SOARecord,
)
from netprotocols.layer7.http import (
    HTTP,
    HTTPAnomaly,
    HTTPAnomalyKind,
    HTTPDisposition,
    HTTPFraming,
    HTTPHeaderField,
)
from netprotocols.layer7.ntp import NTP, NTPMAC, NTPExtensionField
from netprotocols.layer7.radius import RADIUS, RADIUSAttribute
from netprotocols.layer7.rip import RIP, RIPAuthentication, RIPEntry
from netprotocols.layer7.stun import STUN, STUNAddress, STUNAttribute
from netprotocols.layer7.tftp import TFTP
from netprotocols.layer7.vxlan import VXLAN
from netprotocols.packet import Packet
from netprotocols.pcap import (
    CapturedFrame,
    read_captures,
    read_pcap,
    read_pcapng,
)
from netprotocols.registry import (
    DEFAULT,
    InvalidRegistryKeyError,
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
    MalformedCaptureError,
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

__version__ = "2.6.0"

__all__ = [
    "AH",
    "ARP",
    "BGP",
    "CDP",
    "CDPTLV",
    "DEFAULT",
    "DHCP",
    "DNS",
    "ESP",
    "GRE",
    "HTTP",
    "IGMP",
    "LLC",
    "LLCSAP",
    "LLDP",
    "LLDPTLV",
    "MAX_DEPTH",
    "MPLS",
    "NTP",
    "NTPMAC",
    "OSPF",
    "OSPFLSA",
    "PIM",
    "RADIUS",
    "RIP",
    "SCTP",
    "SNAP",
    "STP",
    "STUN",
    "TCP",
    "TFTP",
    "UDP",
    "VLAN",
    "VRRP",
    "VXLAN",
    "AHv6",
    "ARPHardwareType",
    "ARPOperation",
    "BGPOptionalParameter",
    "BGPPathAttribute",
    "BGPPrefix",
    "CDPAddress",
    "CapturedFrame",
    "DHCPOption",
    "DNSOverTCP",
    "DNSQuestion",
    "DNSResourceRecord",
    "EtherType",
    "Ethernet",
    "FlowKey",
    "HTTPAnomaly",
    "HTTPAnomalyKind",
    "HTTPDisposition",
    "HTTPFraming",
    "HTTPHeaderField",
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
    "InvalidRegistryKeyError",
    "LLDPChassisID",
    "LLDPPortID",
    "MPLSLabel",
    "MXRecord",
    "MalformedCaptureError",
    "MaxDepthExceededError",
    "NDPOption",
    "NTPExtensionField",
    "OSPFDatabaseDescription",
    "OSPFHello",
    "OSPFLSAHeader",
    "OSPFLSRequest",
    "PIMAssert",
    "PIMEncodedGroup",
    "PIMEncodedSource",
    "PIMEncodedUnicast",
    "PIMGroupSet",
    "PIMHello",
    "PIMHelloOption",
    "PIMJoinPrune",
    "PIMLANPruneDelay",
    "PIMRegister",
    "PIMRegisterStop",
    "Packet",
    "Protocol",
    "ProtocolError",
    "RADIUSAttribute",
    "RIPAuthentication",
    "RIPEntry",
    "Registry",
    "RegistryConflictError",
    "SCTPChunk",
    "SOARecord",
    "STUNAddress",
    "STUNAttribute",
    "TCPOption",
    "TruncatedHeaderError",
    "UnknownTableError",
    "VRRPv6",
    "__version__",
    "compute",
    "crc32c",
    "decode_frame",
    "fletcher_checksum",
    "flow_key",
    "internet_checksum",
    "lsa_checksum",
    "random_mac",
    "read_captures",
    "read_pcap",
    "read_pcapng",
    "register",
    "register_all",
    "validate_ipv4_addr",
    "validate_mac_addr",
    "verify",
    "verify_lsa",
]
