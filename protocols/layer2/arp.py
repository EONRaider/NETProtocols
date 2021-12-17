#!/usr/bin/env python3
# https://github.com/EONRaider/Protocols

__author__ = 'EONRaider @ keybase.io/eonraider'


from ctypes import c_ubyte, c_uint8, c_uint16

from protocols import Protocol


class ARP(Protocol):           # IETF RFC 826
    _fields_ = [
        ("htype", c_uint16),   # Hardware type
        ("ptype", c_uint16),   # Protocol type
        ("hlen", c_uint8),     # Hardware length
        ("plen", c_uint8),     # Protocol length
        ("oper", c_uint16),    # Operation code
        ("sha", c_ubyte * 6),  # Sender hardware address
        ("spa", c_ubyte * 4),  # Sender protocol address
        ("tha", c_ubyte * 6),  # Target hardware address
        ("tpa", c_ubyte * 4),  # Target protocol address
    ]
    header_len = 28

    def __init__(self, *,
                 htype: int,
                 ptype: int,
                 hlen: int,
                 plen: int,
                 oper: int,
                 sha: str,
                 spa: str,
                 tha: str,
                 tpa: str):
        super().__init__()
        self.htype = htype
        self.ptype = ptype
        self.hlen = hlen
        self.plen = plen
        self.oper = oper
        self.sha = self.hdwr_to_addr_array(sha)
        self.spa = self.proto_addr_to_array(spa)
        self.tha = self.hdwr_to_addr_array(tha)
        self.tpa = self.proto_addr_to_array(tpa)
