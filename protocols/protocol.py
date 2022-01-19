#!/usr/bin/env python3
# https://github.com/EONRaider/Protocols

__author__ = "EONRaider @ keybase.io/eonraider"

import re
from ctypes import (
    BigEndianStructure,
    create_string_buffer,
    c_ubyte,
    sizeof
)
from socket import inet_ntop, inet_pton, AF_INET


class Protocol(BigEndianStructure):
    _pack_ = 1

    def __new__(cls, *args, **kwargs):
        return super().__new__(cls)

    def __init__(self, *args):
        super().__init__()

    def __str__(self):
        return create_string_buffer(sizeof(self))[:]

    @staticmethod
    def addr_array_to_hdwr(addr_array: str) -> str:
        """
        Converts a c_ubyte array of 6 bytes to IEEE 802 MAC address.
        Ex: From b"\xceP\x9a\xcc\x8c\x9d" to "ce:50:9a:cc:8c:9d"
        """
        return ":".join(format(octet, "02x") for octet in bytes(addr_array))

    @staticmethod
    def hdwr_to_addr_array(hdwr_addr: str):
        """Converts an IEEE 802 MAC address to c_ubyte array of 6
        bytes."""
        mac_to_bytes = b"".join(bytes.fromhex(octet)
                                for octet in re.split("[:-]", hdwr_addr))
        return (c_ubyte * 6)(*mac_to_bytes)

    @staticmethod
    def proto_addr_to_array(proto_addr: str):
        """Converts an IPv4 address string in dotted-decimal notation
        to a c_ubyte array of 4 bytes."""
        addr_to_bytes = inet_pton(AF_INET, proto_addr)
        return (c_ubyte * 4)(*addr_to_bytes)

    @staticmethod
    def array_to_proto_addr(addr_array: str) -> str:
        """Converts a packed IPv4 address to string format."""
        return inet_ntop(AF_INET, bytes(addr_array))

    @staticmethod
    def hex_format(value: int, str_length: int) -> str:
        """
        Fills a hex value with zeroes to the left for compliance with
        the presentation of codes used in Internet protocols.
        Ex: From "0x800" to "0x0800"
        """
        return format(value, "#0{}x".format(str_length))
