#!/usr/bin/env python3
# https://github.com/EONRaider/NETProtocols

__author__ = "EONRaider @ keybase.io/eonraider"

import re
import socket
from ctypes import (
    BigEndianStructure,
    create_string_buffer,
    c_ubyte,
    sizeof
)
from socket import inet_ntop, inet_pton, AF_INET
from typing import Union


class Protocol(BigEndianStructure):
    _pack_ = 1

    def __new__(cls, *args, **kwargs):
        return super().__new__(cls)

    def __init__(self, *args):
        super().__init__()

    def __str__(self):
        return create_string_buffer(sizeof(self))[:]

    @classmethod
    def decode(cls, packet: bytes):
        """Decode a raw network packet into a new instance of the
        protocol."""
        header = cls.from_buffer_copy(packet)
        return header

    @property
    def encapsulated_proto(self) -> Union[None, str]:
        """The string representation of the name of the encapsulated
        protocol. Overwrite as required by the specific protocol being
        implemented."""
        return None

    @staticmethod
    def addr_array_to_hdwr(addr_array: str) -> str:
        """
        Convert a c_ubyte array of 6 bytes to IEEE 802 MAC address.
        Ex: From b"\xceP\x9a\xcc\x8c\x9d" to "ce:50:9a:cc:8c:9d"
        """
        return ":".join(format(octet, "02x") for octet in bytes(addr_array))

    @staticmethod
    def hdwr_to_addr_array(hdwr_addr: str):
        """Convert an IEEE 802 MAC address to c_ubyte array of 6
        bytes."""
        mac_to_bytes = b"".join(bytes.fromhex(octet)
                                for octet in re.split("[:-]", hdwr_addr))
        return (c_ubyte * 6)(*mac_to_bytes)

    @staticmethod
    def proto_addr_to_array(proto_addr: str,
                            addr_family: socket.AddressFamily = AF_INET):
        """Convert an IPv4 address string in dotted-decimal notation
        to a c_ubyte array of 4 bytes or an IPv6 address string to a
        c_ubyte array of 16 bytes."""
        try:
            addr_to_bytes = inet_pton(addr_family, proto_addr)
        except OSError:
            raise TypeError("Only addresses of family AF_INET and AF_INET6 are "
                            "supported.")
        return (c_ubyte * 4)(*addr_to_bytes) if addr_family == AF_INET else \
            (c_ubyte * 16)(*addr_to_bytes)

    @staticmethod
    def array_to_proto_addr(addr_array: str,
                            addr_family: socket.AddressFamily = AF_INET) -> str:
        """Convert a packed IPv4/IPv6 address to string format."""
        try:
            return inet_ntop(addr_family, bytes(addr_array))
        except OSError:
            raise TypeError("Only addresses of family AF_INET and AF_INET6 are "
                            "supported.")
