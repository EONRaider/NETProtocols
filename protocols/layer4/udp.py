#!/usr/bin/env python3
# https://github.com/EONRaider/Protocols

__author__ = "EONRaider @ keybase.io/eonraider"

from ctypes import c_uint16

from protocols import Protocol


class UDP(Protocol):          # IETF RFC 768
    _fields_ = [
        ("sport", c_uint16),  # Source port
        ("dport", c_uint16),  # Destination port
        ("len", c_uint16),    # Header length
        ("chksum", c_uint16)  # Header checksum
    ]
    header_len = 8

    def __init__(self, *,
                 sport: int,
                 dport: int,
                 len: int,
                 chksum: int):
        super().__init__()
        self.sport = sport
        self.dport = dport
        self.len = len
        self.chksum = chksum

    @property
    def encapsulated_proto(self) -> str:
        """The string representation of the name of the encapsulated
        protocol. Returns 'undefined' due to the fact that UDP is by
        design agnostic about the protocols it carries at higher
        layers."""
        return "Undefined"
