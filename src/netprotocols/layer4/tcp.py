"""TCP segment header (RFC 793 / 9293).

The header is decoded in full, with the options kept as raw ``bytes``
(data-offset aware) so ``bytes(TCP.decode(x)) == x`` holds by
construction. The ``parsed_options`` accessor walks the option TLV list
on demand and never re-encodes: the common kinds — MSS, window scale,
SACK-Permitted, SACK, and timestamps (RFC 9293 §3.2, RFC 7323,
RFC 2018) — decode to typed values, and unknown kinds keep their raw
data.
"""

from __future__ import annotations

from dataclasses import dataclass
from struct import Struct
from typing import ClassVar, Self

from netprotocols._base import Protocol
from netprotocols.layer4._ports import tcp_app_class
from netprotocols.registry import Registry
from netprotocols.utils.exceptions import (
    InvalidFieldError,
    TruncatedHeaderError,
)

__all__ = ["TCP", "TCPOption"]

#: Single-byte option kinds that carry no length or value (RFC 9293
#: §3.2): End of Option List terminates the parse, No-Operation pads.
_OPT_EOL = 0
_OPT_NOP = 1

#: Kind/length/value option kinds this library decodes.
_OPT_MSS = 2
_OPT_WINDOW_SCALE = 3
_OPT_SACK_PERMITTED = 4
_OPT_SACK = 5
_OPT_TIMESTAMPS = 8

#: TCP option kinds this library names (RFC 9293 §3.2; RFC 7323 for
#: Window Scale and Timestamps; RFC 2018 for SACK); unknown kinds fall
#: back to their numeric value.
_OPTION_KIND_NAMES: dict[int, str] = {
    _OPT_EOL: "End of Option List",
    _OPT_NOP: "No-Operation",
    _OPT_MSS: "Maximum Segment Size",
    _OPT_WINDOW_SCALE: "Window Scale",
    _OPT_SACK_PERMITTED: "SACK Permitted",
    _OPT_SACK: "SACK",
    _OPT_TIMESTAMPS: "Timestamps",
}


@dataclass(frozen=True, slots=True)
class TCPOption:
    """One TCP option (RFC 9293 §3.1).

    :param kind: Option kind — ``0`` End of Option List, ``1``
        No-Operation, ``2`` MSS, ``3`` Window Scale, ``4``
        SACK-Permitted, ``5`` SACK, ``8`` Timestamps (see
        :attr:`kind_name`).
    :param data: The option's value bytes, kept raw; empty for the
        single-byte kinds (EOL, NOP) and for SACK-Permitted.
    """

    kind: int
    data: bytes = b""

    @property
    def kind_name(self) -> str:
        """Display name of the option kind, e.g. ``"Timestamps"``; falls
        back to ``"unknown (n)"`` for kinds this library does not name."""
        return _OPTION_KIND_NAMES.get(self.kind, f"unknown ({self.kind})")

    @property
    def value(
        self,
    ) -> int | tuple[int, int] | tuple[tuple[int, int], ...] | None:
        """The decoded value, for the kinds this library understands:
        the segment size for MSS, the shift count for Window Scale, a
        ``(tsval, tsecr)`` pair for Timestamps, and a tuple of
        ``(left_edge, right_edge)`` pairs for SACK. ``None`` — read
        :attr:`data` raw instead — for the single-byte kinds,
        SACK-Permitted (its presence is its meaning), kinds this
        library does not decode, and data whose length does not match
        its kind (degrades, never raises)."""
        if self.kind == _OPT_MSS and len(self.data) == 2:
            return int.from_bytes(self.data, "big")
        if self.kind == _OPT_WINDOW_SCALE and len(self.data) == 1:
            return self.data[0]
        if self.kind == _OPT_TIMESTAMPS and len(self.data) == 8:
            return (
                int.from_bytes(self.data[:4], "big"),
                int.from_bytes(self.data[4:], "big"),
            )
        if self.kind == _OPT_SACK and self.data and len(self.data) % 8 == 0:
            return tuple(
                (
                    int.from_bytes(self.data[block : block + 4], "big"),
                    int.from_bytes(self.data[block + 4 : block + 8], "big"),
                )
                for block in range(0, len(self.data), 8)
            )
        return None


@dataclass(frozen=True, slots=True)
class TCP(Protocol):
    """A TCP header.

    :param src_port: Source port.
    :param dst_port: Destination port.
    :param seq: Sequence number.
    :param ack: Acknowledgement number.
    :param data_offset: Header length in 32-bit words; ``5``-``15``,
        and must equal ``5 + len(options) // 4``.
    :param reserved: Reserved field (3 bits).
    :param flags: Flag bits, NS through FIN (9 bits).
    :param window: Window size.
    :param checksum: Checksum, carried verbatim (this library neither
        computes nor verifies checksums).
    :param urgent_pointer: Urgent pointer.
    :param options: Raw options bytes; length must be a multiple of 4
        consistent with ``data_offset``. Parsed on demand via
        :attr:`parsed_options`.
    """

    src_port: int
    dst_port: int
    seq: int
    ack: int
    data_offset: int
    reserved: int
    flags: int
    window: int
    checksum: int
    urgent_pointer: int
    options: bytes = b""

    #: Curated positional form for `match`/`case` (#94): declared by
    #: hand because the auto-generated tuple would list all 11 fields,
    #: unusable positionally. ``src_port``/``dst_port`` identify the
    #: connection, ``flags`` says what kind of segment this is (SYN,
    #: SYN-ACK, ...) — mirrors :attr:`~netprotocols.IPv4.__match_args__`.
    __match_args__ = ("src_port", "dst_port", "flags")

    _struct: ClassVar[Struct] = Struct("!HHIIHHHH")

    #: Flag names by bit position, least-significant first.
    flag_names: ClassVar[tuple[str, ...]] = (
        "FIN",
        "SYN",
        "RST",
        "PSH",
        "ACK",
        "URG",
        "ECE",
        "CWR",
        "NS",
    )

    def __post_init__(self) -> None:
        if not 5 <= self.data_offset <= 15:
            raise InvalidFieldError(
                f"TCP data offset must be within 5-15, got {self.data_offset}",
                protocol=type(self),
                field="data_offset",
                expected="5-15",
                actual=self.data_offset,
            )
        if (
            self.data_offset != 5 + len(self.options) // 4
            or len(self.options) % 4
        ):
            raise InvalidFieldError(
                f"TCP data offset {self.data_offset} disagrees with options "
                f"length {len(self.options)} (expected "
                f"{(self.data_offset - 5) * 4} bytes)",
                protocol=type(self),
                field="data_offset",
                expected=(self.data_offset - 5) * 4,
                actual=len(self.options),
            )

    @classmethod
    def decode(cls, data: bytes | memoryview) -> Self:
        (
            src_port,
            dst_port,
            seq,
            ack,
            offset_flags,
            window,
            checksum,
            urgent_pointer,
        ) = cls._unpack_fixed(data)
        data_offset = offset_flags >> 12
        if data_offset < 5:
            raise InvalidFieldError(
                f"TCP data offset must be at least 5, got {data_offset}",
                protocol=cls,
                offset=0,
                field="data_offset",
                expected=">=5",
                actual=data_offset,
            )
        if data_offset * 4 > len(data):
            raise TruncatedHeaderError(
                f"TCP header declares {data_offset * 4} bytes, buffer holds "
                f"{len(data)}",
                protocol=cls,
                offset=0,
                field="data_offset",
                expected=data_offset * 4,
                actual=len(data),
            )
        return cls(
            src_port=src_port,
            dst_port=dst_port,
            seq=seq,
            ack=ack,
            data_offset=data_offset,
            reserved=(offset_flags >> 9) & 0b111,
            flags=offset_flags & 0x1FF,
            window=window,
            checksum=checksum,
            urgent_pointer=urgent_pointer,
            options=bytes(data[cls._struct.size : data_offset * 4]),
        )

    def __bytes__(self) -> bytes:
        return (
            self._struct.pack(
                self.src_port,
                self.dst_port,
                self.seq,
                self.ack,
                (self.data_offset << 12) | (self.reserved << 9) | self.flags,
                self.window,
                self.checksum,
                self.urgent_pointer,
            )
            + self.options
        )

    @property
    def header_len(self) -> int:
        return self.data_offset * 4

    def next_protocol(
        self, registry: Registry | None = None
    ) -> type[Protocol] | None:
        """The application protocol carried by this segment, chosen by
        well-known port (best-effort — see
        :mod:`netprotocols.layer4._ports`); ``None`` when neither port is
        recognized. DNS over TCP is length-prefixed, so it chains through
        a :class:`~netprotocols.DNSOverTCP` shim."""
        return tcp_app_class(self.src_port, self.dst_port, registry)

    @property
    def flags_str(self) -> str:
        """Space-separated names of the flags set on the segment, e.g.
        ``"SYN ACK"``."""
        return " ".join(
            name
            for shift, name in enumerate(self.flag_names)
            if (self.flags >> shift) & 1
        )

    @property
    def flags_hex_str(self) -> str:
        """The flag bits as a hexadecimal string, e.g. ``"0x012"``."""
        return f"{self.flags:#05x}"

    @property
    def checksum_hex_str(self) -> str:
        """The checksum as a hexadecimal string, e.g. ``"0x2e5b"``."""
        return f"{self.checksum:#06x}"

    # -- options TLV list (parsed on demand, never re-encoded) --

    @property
    def parsed_options(self) -> tuple[TCPOption, ...]:
        """The options as a tuple of :class:`TCPOption`, in wire order,
        parsed on demand (RFC 9293 §3.1). The single-byte kinds (EOL,
        NOP) carry no data; an End of Option List option ends the parse,
        so whatever follows it is padding and is not returned. Empty for
        a header without options.

        :raises InvalidFieldError: if an option's declared length is
            below the 2-byte TLV minimum or runs past the options bytes
            (bounded — never hangs or over-reads).
        """
        raw = self.options
        parsed: list[TCPOption] = []
        cursor = 0
        while cursor < len(raw):
            kind = raw[cursor]
            if kind in (_OPT_EOL, _OPT_NOP):
                parsed.append(TCPOption(kind=kind))
                if kind == _OPT_EOL:
                    break
                cursor += 1
                continue
            if cursor + 1 >= len(raw):
                raise InvalidFieldError(
                    "TCP option missing its length byte",
                    protocol=type(self),
                    field="options",
                    offset=cursor,
                )
            length = raw[cursor + 1]
            if length < 2:
                raise InvalidFieldError(
                    f"TCP option length must be at least 2, got {length}",
                    protocol=type(self),
                    field="options",
                    offset=cursor,
                    expected=">=2",
                    actual=length,
                )
            if cursor + length > len(raw):
                raise InvalidFieldError(
                    "TCP option value runs past the options bytes",
                    protocol=type(self),
                    field="options",
                    offset=cursor,
                )
            parsed.append(
                TCPOption(kind=kind, data=raw[cursor + 2 : cursor + length])
            )
            cursor += length
        return tuple(parsed)
