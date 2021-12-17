#!/usr/bin/env python3
# https://github.com/EONRaider/Protocols

__author__ = "EONRaider @ keybase.io/eonraider"

from ctypes import c_ubyte, c_uint16

from protocols import Protocol


class Ethernet(Protocol):       # IEEE 802.3 standard
    _fields_ = [
        ("_dst", c_ubyte * 6),  # Destination hardware address
        ("_src", c_ubyte * 6),  # Source hardware address
        ("_eth", c_uint16)      # Ethertype
    ]
    header_len = 14
    ethertypes = {0x0806: "ARP", 0x0800: "IPv4", 0x86dd: "IPv6"}

    def __init__(self, *, dst: str, src: str, eth: int):
        super().__init__()
        self.dst = self.hdwr_to_addr_array(dst)
        self.src = self.hdwr_to_addr_array(src)
        self.eth = eth

    @classmethod
    def decode(cls, packet: bytes):
        header = cls.from_buffer_copy(packet)
        header.src = cls.addr_array_to_hdwr(header._src)
        header.dst = cls.addr_array_to_hdwr(header._dst)
        header.eth = header._eth
        return header

    @property
    def encapsulated_proto(self):
        return self.ethertypes.get(self.eth, None)
