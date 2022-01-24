#!/usr/bin/env python3
# https://github.com/EONRaider/NETProtocols

__author__ = "EONRaider @ keybase.io/eonraider"

from ctypes import c_uint16, c_uint32

from netprotocols import Protocol


class TCP(Protocol):                # IETF RFC 793
    _fields_ = [
        ("sport", c_uint16),        # Source port
        ("dport", c_uint16),        # Destination port
        ("seq", c_uint32),          # Sequence number
        ("ack", c_uint32),          # Acknowledgement number
        ("offset", c_uint16, 4),    # Data offset
        ("reserved", c_uint16, 3),  # Reserved field
        ("flags", c_uint16, 9),     # TCP flag codes
        ("window", c_uint16),       # Window size
        ("chksum", c_uint16),       # TCP header checksum
        ("urg", c_uint16),          # Urgent pointer
    ]
    header_len = 32
    flag_names = "NS", "CWR", "ECE", "URG", "ACK", "PSH", "RST", "SYN", "FIN"

    def __init__(self, *,
                 sport: int,
                 dport: int,
                 seq: int,
                 ack: int,
                 offset: int,
                 reserved: int,
                 flags: int,
                 window: int,
                 chksum: int,
                 urg: int):
        super().__init__()
        self.sport = sport
        self.dport = dport
        self.seq = seq
        self.ack = ack
        self.offset = offset
        self.reserved = reserved
        self.flags = flags
        self.window = window
        self.chksum = chksum
        self.urg = urg

    @property
    def flags_hex(self) -> str:
        """
        Gets a string representation of the hexadecimal value of the
        TCP flags set on the segment.
        Ex: '0x018' or '0x010'
        """
        return format(self.flags, "#0{}x".format(5))

    @property
    def flag_bits(self):
        """
        Gets a string representation of the binary value of the TCP
        flags set on the segment.
        Ex: '000011000' for 'PSH ACK' flags set.
        """
        return format(self.flags, "09b")

    @property
    def flags_txt(self) -> str:
        """
        Gets a string representation of the names of the TCP flags
        set on the segment in space-separated format.
        Ex: 'SYN ACK' or 'PSH ACK'
        """
        flags = tuple(flag_name for flag_name, flag_bit in
                      zip(self.flag_names, self.flag_bits) if flag_bit == "1")
        return " ".join(reversed(flags))

    @property
    def encapsulated_proto(self) -> str:
        """The string representation of the name of the encapsulated
        protocol. Returns 'undefined' due to the fact that TCP is by
        design agnostic about the protocols it carries at higher
        layers."""
        return "Undefined"
