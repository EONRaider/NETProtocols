"""DHCP message (RFC 2131/2132), carried in a UDP datagram.

DHCP extends the fixed BOOTP frame: a 236-byte header (op through the
128-byte boot-file name) followed by a 4-byte magic cookie and a
variable list of TLV options. The fixed header is decoded in full; the
options are kept raw and parsed on demand, so ``bytes(DHCP.decode(x))
== x`` holds by construction and a message with unusual or vendor
options still round-trips exactly. ``option_map`` walks the TLV list
into a ``{code: value}`` dict; ``parsed_options`` wraps the same walk
into a tuple of typed :class:`DHCPOption`; ``message_type`` reads the
DHCP message type (option 53) that distinguishes a DISCOVER from an
ACK.

DHCP rides UDP between the server port (67) and the client port (68);
it is terminal — it never encapsulates another protocol.
"""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Address
from struct import Struct
from typing import ClassVar, Self

from netprotocols._base import (
    Protocol,
    bytes_to_ipv4,
    bytes_to_mac,
    ipv4_to_bytes,
)
from netprotocols._enums import ARPHardwareType
from netprotocols.utils.exceptions import InvalidFieldError

__all__ = ["DHCP", "DHCPOption"]

#: The four-byte value that begins the options field (RFC 2131 §3;
#: the dotted form 99.130.83.99).
_MAGIC_COOKIE = b"\x63\x82\x53\x63"

#: Single-byte options that carry no length or value (RFC 2132 §3.1-3.2).
_OPT_PAD = 0
_OPT_END = 255

#: The DHCP Message Type option (RFC 2132 §9.6).
_OPT_MESSAGE_TYPE = 53

#: Option codes whose value is a single IPv4 address (RFC 2132 §3.3
#: Subnet Mask, §9.1 Requested IP Address, §9.7 Server Identifier).
_SINGLE_ADDRESS_CODES = frozenset({1, 50, 54})

#: Option codes whose value is one or more IPv4 addresses, most
#: preferred first (RFC 2132 §3.5 Router, §3.8 Domain Name Server).
_ADDRESS_LIST_CODES = frozenset({3, 6})

#: The IP Address Lease Time option: a 32-bit seconds count (RFC 2132
#: §9.2).
_OPT_LEASE_TIME = 51

_OP_NAMES: dict[int, str] = {1: "BOOTREQUEST", 2: "BOOTREPLY"}

_MESSAGE_TYPE_NAMES: dict[int, str] = {
    1: "DISCOVER",
    2: "OFFER",
    3: "REQUEST",
    4: "DECLINE",
    5: "ACK",
    6: "NAK",
    7: "RELEASE",
    8: "INFORM",
}

#: DHCP option codes this library names (RFC 2132); unknown codes fall
#: back to their numeric value.
_OPTION_CODE_NAMES: dict[int, str] = {
    1: "Subnet Mask",
    3: "Router",
    6: "Domain Name Server",
    50: "Requested IP Address",
    51: "IP Address Lease Time",
    53: "Message Type",
    54: "Server Identifier",
}


@dataclass(frozen=True, slots=True)
class DHCPOption:
    """One DHCP option (RFC 2132), already RFC-3396-concatenated if it
    appeared more than once — see :attr:`DHCP.option_map`, which
    :attr:`DHCP.parsed_options` wraps.

    :param code: Option code — ``1`` Subnet Mask, ``3`` Router, ``6``
        Domain Name Server, ``50`` Requested IP Address, ``51`` IP
        Address Lease Time, ``53`` Message Type, ``54`` Server
        Identifier, ... (see :attr:`code_name`).
    :param data: The option's value bytes, kept raw.
    """

    code: int
    data: bytes = b""

    @property
    def code_name(self) -> str:
        """Display name of the option code, e.g. ``"Subnet Mask"``;
        falls back to ``"unknown (n)"`` for codes this library does
        not name."""
        return _OPTION_CODE_NAMES.get(self.code, f"unknown ({self.code})")

    @property
    def value(
        self,
    ) -> int | IPv4Address | tuple[IPv4Address, ...] | None:
        """The decoded value, for the codes this library understands:
        a single :class:`~ipaddress.IPv4Address` for Subnet Mask (1),
        Requested IP Address (50) and Server Identifier (54); a tuple
        of one or more, most preferred first, for Router (3) and
        Domain Name Server (6) (RFC 2132 permits repeating either); the
        integer seconds for IP Address Lease Time (51); the raw
        message-type byte as an ``int`` for Message Type (53, see
        :attr:`DHCP.message_type`). ``None`` — read :attr:`data` raw
        instead — for codes this library does not decode and data
        whose length does not match its code (degrades, never
        raises)."""
        if self.code in _SINGLE_ADDRESS_CODES and len(self.data) == 4:
            return IPv4Address(bytes_to_ipv4(self.data))
        if (
            self.code in _ADDRESS_LIST_CODES
            and self.data
            and len(self.data) % 4 == 0
        ):
            return tuple(
                IPv4Address(bytes_to_ipv4(self.data[i : i + 4]))
                for i in range(0, len(self.data), 4)
            )
        if self.code == _OPT_LEASE_TIME and len(self.data) == 4:
            return int.from_bytes(self.data, "big")
        if self.code == _OPT_MESSAGE_TYPE and len(self.data) == 1:
            return self.data[0]
        return None


@dataclass(frozen=True, slots=True)
class DHCP(Protocol):
    """A DHCP/BOOTP message.

    :param op: Message op code — ``1`` request (client→server), ``2``
        reply (server→client).
    :param htype: Hardware address type (``1`` = Ethernet; see
        :class:`~netprotocols.ARPHardwareType` — the same registry
        :class:`~netprotocols.ARP` uses).
    :param hlen: Hardware address length (``6`` for Ethernet).
    :param hops: Relay hop count.
    :param xid: Transaction identifier correlating a request and reply.
    :param secs: Seconds since the client began address acquisition.
    :param flags: Flags word; bit 15 is the broadcast flag.
    :param ciaddr: Client IP address (dotted-decimal), set when the
        client already holds a lease.
    :param yiaddr: "Your" IP address — the address the server assigns.
    :param siaddr: Next-server IP address (dotted-decimal).
    :param giaddr: Relay-agent (gateway) IP address (dotted-decimal).
    :param chaddr: Client hardware address, 16 raw bytes (the first
        ``hlen`` are significant); read via :attr:`client_mac`.
    :param sname: Optional server host name, 64 raw bytes; read via
        :attr:`server_name`.
    :param file: Optional boot-file name, 128 raw bytes; read via
        :attr:`boot_file`.
    :param options: The magic cookie and TLV options, kept raw; read via
        :attr:`option_map` and :attr:`message_type`.
    """

    op: int
    htype: int
    hlen: int
    hops: int
    xid: int
    secs: int
    flags: int
    ciaddr: str
    yiaddr: str
    siaddr: str
    giaddr: str
    chaddr: bytes = b"\x00" * 16
    sname: bytes = b"\x00" * 64
    file: bytes = b"\x00" * 128
    options: bytes = b""

    #: Curated positional form for `match`/`case` (#94): declared by
    #: hand because the auto-generated tuple would list all 15 fields,
    #: unusable positionally. ``op`` gives message direction
    #: (BOOTREQUEST/BOOTREPLY); ``chaddr`` is the client's persistent
    #: hardware identity, correlating a client across an exchange more
    #: reliably than ``xid`` alone (RFC 2131 §4.1); ``yiaddr`` is the
    #: assigned/offered lease address — the fields a consumer walking a
    #: DORA exchange actually keys on.
    __match_args__ = ("op", "chaddr", "yiaddr")

    _struct: ClassVar[Struct] = Struct("!4BIHH4s4s4s4s16s64s128s")

    @classmethod
    def decode(cls, data: bytes | memoryview) -> Self:
        (
            op,
            htype,
            hlen,
            hops,
            xid,
            secs,
            flags,
            ciaddr,
            yiaddr,
            siaddr,
            giaddr,
            chaddr,
            sname,
            file,
        ) = cls._unpack_fixed(data)
        return cls(
            op=op,
            htype=htype,
            hlen=hlen,
            hops=hops,
            xid=xid,
            secs=secs,
            flags=flags,
            ciaddr=bytes_to_ipv4(ciaddr),
            yiaddr=bytes_to_ipv4(yiaddr),
            siaddr=bytes_to_ipv4(siaddr),
            giaddr=bytes_to_ipv4(giaddr),
            chaddr=bytes(chaddr),
            sname=bytes(sname),
            file=bytes(file),
            options=bytes(data[cls._struct.size :]),
        )

    def __bytes__(self) -> bytes:
        return (
            self._struct.pack(
                self.op,
                self.htype,
                self.hlen,
                self.hops,
                self.xid,
                self.secs,
                self.flags,
                ipv4_to_bytes(self.ciaddr),
                ipv4_to_bytes(self.yiaddr),
                ipv4_to_bytes(self.siaddr),
                ipv4_to_bytes(self.giaddr),
                self.chaddr,
                self.sname,
                self.file,
            )
            + self.options
        )

    @property
    def header_len(self) -> int:
        # A DHCP message is the whole UDP payload: consume it all so the
        # chain ends here with no stray payload.
        return self._struct.size + len(self.options)

    @property
    def op_name(self) -> str:
        """Display name of the op code, e.g. ``"BOOTREQUEST"``."""
        return _OP_NAMES.get(self.op, f"unknown ({self.op:#04x})")

    @property
    def htype_name(self) -> str:
        """Display name of the hardware type, e.g. ``"Ethernet"``; falls
        back to the numeric value for types this library does not
        name."""
        try:
            return ARPHardwareType(self.htype).display_name
        except ValueError:
            return f"unknown ({self.htype})"

    @property
    def htype_enum(self) -> ARPHardwareType | None:
        """The hardware type as an
        :class:`~netprotocols.ARPHardwareType`, or ``None`` for a value
        this library does not enumerate; :attr:`htype` stays the
        canonical ``int`` (see :attr:`htype_name` for the display
        form)."""
        try:
            return ARPHardwareType(self.htype)
        except ValueError:
            return None

    @property
    def is_broadcast(self) -> bool:
        """Whether the broadcast flag (bit 15 of ``flags``) is set."""
        return bool(self.flags & 0x8000)

    @property
    def client_mac(self) -> str | None:
        """The client hardware address as a MAC string, for Ethernet
        (``htype`` 1, ``hlen`` 6); ``None`` for other link types."""
        if self.htype == 1 and self.hlen == 6:
            return bytes_to_mac(self.chaddr[:6])
        return None

    @property
    def server_name(self) -> str:
        """The optional server host name (``sname``), NUL-trimmed."""
        return self.sname.split(b"\x00", 1)[0].decode("ascii", "replace")

    @property
    def boot_file(self) -> str:
        """The optional boot-file name (``file``), NUL-trimmed."""
        return self.file.split(b"\x00", 1)[0].decode("ascii", "replace")

    @property
    def ciaddr_address(self) -> IPv4Address:
        """The client address as a stdlib
        :class:`~ipaddress.IPv4Address`, for comparison, subnet
        membership, and arithmetic; :attr:`ciaddr` stays the canonical
        string form (likewise the three accessors below)."""
        return IPv4Address(self.ciaddr)

    @property
    def yiaddr_address(self) -> IPv4Address:
        """The "your" (assigned) address as a stdlib
        :class:`~ipaddress.IPv4Address` (see :attr:`ciaddr_address`)."""
        return IPv4Address(self.yiaddr)

    @property
    def siaddr_address(self) -> IPv4Address:
        """The next-server address as a stdlib
        :class:`~ipaddress.IPv4Address` (see :attr:`ciaddr_address`)."""
        return IPv4Address(self.siaddr)

    @property
    def giaddr_address(self) -> IPv4Address:
        """The relay-agent address as a stdlib
        :class:`~ipaddress.IPv4Address` (see :attr:`ciaddr_address`)."""
        return IPv4Address(self.giaddr)

    @property
    def has_magic_cookie(self) -> bool:
        """Whether the options begin with the DHCP magic cookie — false
        for a plain BOOTP message that carries none."""
        return self.options[:4] == _MAGIC_COOKIE

    @property
    def option_map(self) -> dict[int, bytes]:
        """The TLV options after the magic cookie as a ``{code: value}``
        map. An option split across several appearances is concatenated
        (RFC 3396); ``pad`` (0) and ``end`` (255) are consumed, not
        returned. Empty when the message carries no options.

        :raises InvalidFieldError: if the options are present but do not
            begin with the magic cookie, or an option's length runs past
            the buffer (bounded — never hangs or over-reads).
        """
        raw = self.options
        if not raw:
            return {}
        if raw[:4] != _MAGIC_COOKIE:
            raise InvalidFieldError(
                "DHCP options missing the magic cookie",
                protocol=type(self),
                field="options",
                offset=0,
            )
        parsed: dict[int, bytes] = {}
        cursor = 4
        while cursor < len(raw):
            code = raw[cursor]
            cursor += 1
            if code == _OPT_PAD:
                continue
            if code == _OPT_END:
                break
            if cursor >= len(raw):
                raise InvalidFieldError(
                    "DHCP option missing its length byte",
                    protocol=type(self),
                    field="options",
                    offset=cursor,
                )
            length = raw[cursor]
            cursor += 1
            if cursor + length > len(raw):
                raise InvalidFieldError(
                    "DHCP option value runs past the buffer",
                    protocol=type(self),
                    field="options",
                    offset=cursor,
                )
            parsed[code] = parsed.get(code, b"") + raw[cursor : cursor + length]
            cursor += length
        return parsed

    @property
    def parsed_options(self) -> tuple[DHCPOption, ...]:
        """The TLV options as a tuple of :class:`DHCPOption`, one per
        option code, in first-appearance wire order — a typed view
        over :attr:`option_map` (an option split across several
        appearances is concatenated there already, per RFC 3396).
        Empty when the message carries no options.

        :raises InvalidFieldError: if the options are malformed (see
            :attr:`option_map`).
        """
        return tuple(
            DHCPOption(code=code, data=data)
            for code, data in self.option_map.items()
        )

    @property
    def message_type(self) -> int | None:
        """The DHCP message type (option 53) — ``1`` DISCOVER, ``2``
        OFFER, ``3`` REQUEST, ``5`` ACK, ... — or ``None`` for a plain
        BOOTP message that carries no such option.

        :raises InvalidFieldError: if the options are malformed (see
            :attr:`option_map`).
        """
        value = self.option_map.get(_OPT_MESSAGE_TYPE)
        if value is None or len(value) != 1:
            return None
        return value[0]

    @property
    def message_type_name(self) -> str | None:
        """Display name of the DHCP message type, e.g. ``"DISCOVER"``;
        ``None`` when no message-type option is present."""
        message_type = self.message_type
        if message_type is None:
            return None
        return _MESSAGE_TYPE_NAMES.get(
            message_type, f"unknown ({message_type:#04x})"
        )
