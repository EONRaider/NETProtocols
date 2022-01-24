#!/usr/bin/env python3
# https://github.com/EONRaider/NETProtocols

__author__ = 'EONRaider @ keybase.io/eonraider'


from ctypes import c_ubyte, c_uint8, c_uint16

from netprotocols import Protocol


class ARP(Protocol):            # IETF RFC 826
    _fields_ = [
        ("htype", c_uint16),    # Hardware type
        ("ptype", c_uint16),    # Protocol type
        ("hlen", c_uint8),      # Hardware length
        ("plen", c_uint8),      # Protocol length
        ("oper", c_uint16),     # Operation code
        ("_sha", c_ubyte * 6),  # Sender hardware address
        ("_spa", c_ubyte * 4),  # Sender protocol address
        ("_tha", c_ubyte * 6),  # Target hardware address
        ("_tpa", c_ubyte * 4),  # Target protocol address
    ]
    header_len = 28             # Length of the header in bytes

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

    @classmethod
    def decode(cls, packet: bytes):
        header = cls.from_buffer_copy(packet)
        header.sha = cls.addr_array_to_hdwr(header._sha)
        header.spa = cls.array_to_proto_addr(header._spa)
        header.tha = cls.addr_array_to_hdwr(header._tha)
        header.tpa = cls.array_to_proto_addr(header._tpa)
        return header
