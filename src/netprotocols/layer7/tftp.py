"""TFTP — the Trivial File Transfer Protocol (RFC 1350), with options.

TFTP (RFC 1350) moves a file over UDP in lockstep: one block in flight,
each acknowledged before the next is sent. Every message starts with a
2-byte opcode (§5), and what follows depends on it::

    RRQ / WRQ   2 bytes    string    1 byte   string   1 byte
               +--------+----------+-------+--------+-------+
               | 01/02  | Filename |   0   |  Mode  |   0   |  [options]
               +--------+----------+-------+--------+-------+

    DATA        2 bytes    2 bytes    n bytes
               +--------+----------+----------+
               |   03   | Block #  |   Data   |
               +--------+----------+----------+

    ACK         2 bytes    2 bytes
               +--------+----------+
               |   04   | Block #  |
               +--------+----------+

    ERROR       2 bytes    2 bytes      string    1 byte
               +--------+------------+----------+-------+
               |   05   | ErrorCode  |  ErrMsg  |   0   |
               +--------+------------+----------+-------+

    OACK        2 bytes    string   1 byte  string   1 byte
               +--------+--------+-------+--------+-------+
               |   06   |  opt1  |   0   | value1 |   0   |  ...
               +--------+--------+-------+--------+-------+

Strings are terminated by a zero byte, not prefixed by a length, so
they are found with ``bytes.find`` rather than the TLV walker other
modules share. The mode is ``netascii``, ``octet`` or ``mail`` (§5, in
any case; §1 calls ``mail`` obsolete). Option negotiation (RFC 2347) appends
name/value string pairs to a request, and the server answers with an
OACK (opcode 6) naming the options it accepted, or ignores them; the
values are decimal strings for the options defined so far:
``blksize`` (RFC 2348), ``timeout`` and ``tsize`` (RFC 2349) and
``windowsize`` (RFC 7440). Option names and values are
case-insensitive ASCII (RFC 2347), so :meth:`TFTP.option` matches
names in any case. A client that refuses an OACK sends ERROR code 8
(RFC 2347).

:class:`TFTP` keeps the opcode and the raw message after it as
:attr:`TFTP.body`, and its accessors read the opcode's fields from it on
demand: :attr:`~TFTP.filename`, :attr:`~TFTP.mode` and
:attr:`~TFTP.options` for a request, :attr:`~TFTP.block` and
:attr:`~TFTP.data` for DATA, :attr:`~TFTP.block` for ACK,
:attr:`~TFTP.error_code` and :attr:`~TFTP.error_message` for ERROR, and
:attr:`~TFTP.options` for OACK. Each answers ``None`` (``()`` for the
options) for an opcode that does not carry it. The strings are read as
ASCII, the netascii RFC 1350 asks for, and a byte outside it reads as a
backslash escape, and a number option's value over 20 digits (leading
zeros aside) reads as ``None``, so no accessor raises and no byte is
lost.

Dispatch: only the request reaches TFTP by port
-----------------------------------------------

A client sends its RRQ or WRQ to port 69, from a port it chose, its
transfer identifier (TID). The server answers from a port of its own
choosing, not 69, and the rest of the transfer, every DATA, ACK, OACK
and ERROR, runs between those two ephemeral ports (RFC 1350 §4). The
``udp.port`` table therefore registers 69 alone, and a stateless walk
reaches :class:`TFTP` for the requests only: the replies end the walk
at UDP, as any datagram between two unregistered ports does, and
nothing in a datagram says it belongs to a TFTP transfer. A caller who
follows the transfer knows the server's TID from the first reply to the
request (its source port) and can decode the rest by naming it, either
per walk, ``decode_frame(frame, decode_as={"udp.port": {tid: TFTP}})``,
which catches both directions because one of their two ports is the
server's TID, or directly, ``TFTP.decode(frame[packet.consumed:])``
after a walk that ended at UDP. Tracking transfers is the caller's, as
reassembling a TCP stream is for ``HTTP`` and ``BGP``. A server that
answers from port 69 itself, which RFC 1350 does not allow, has its
whole transfer dispatched.

The message's extent
--------------------

TFTP has no length field, and the chain walk does not trim a frame to
UDP's declared length (#235), so anything after the datagram, an
Ethernet frame's zero padding or an FCS a capture kept, reaches the
decoder. Each opcode bounds itself as far as its structure allows, and
leaves what follows undecoded, past :attr:`TFTP.header_len`, so
``bytes(TFTP.decode(x)) == x[:header_len]``:

- An ACK is exactly 4 bytes (in an untagged Ethernet frame over IPv4
  with no IP options, the frame is padded with 14 zero bytes; over
  IPv6 it already fills the minimum).
- An ERROR ends at the zero byte after its message.
- A request ends after its mode, or after the last whole option pair,
  a name of at least one byte and a value, each with its zero byte. A
  zero byte where a name would start ends the options, so padding after
  whole pairs is left undecoded. An option cut short by a snap length
  cannot be told from a trailer, so it is left undecoded too.
- An OACK ends after its last whole option pair, the same way.
- DATA runs to the end of the buffer: its data has no terminator, so
  bytes after the datagram join :attr:`TFTP.data`. In an untagged
  Ethernet frame over IPv4 with no IP options, a final block shorter
  than 14 bytes is padded on the wire, and only the UDP length
  (``udp.length - 12``) says how much of the data is real.
  For the same reason, and because the block size an OACK negotiated
  is not in the DATA itself, no accessor says whether a block is the
  last one (RFC 1350 §6: a block shorter than the block size is).

Structure bounds a request or an OACK only so far; two trailers still
read as options, and only the UDP length could tell them apart (#235):

- A message whose options end with a name and no value (an odd number
  of option strings) takes the first byte of zero padding after it as
  that value's terminator: ``...tsize\x00`` plus padding decodes the
  option ``("tsize", "")`` and keeps one padding byte, where without
  the padding the name is left undecoded as an option cut short.
- A trailer that holds a name, a zero byte, a value and a zero byte
  reads as one more option: an FCS ``12 00 34 00`` decodes as
  ``("\x12", "4")``. An FCS that starts with a zero byte, or holds
  fewer than two, is left undecoded.

Decoding a guess
----------------

TFTP is reached through ``udp.port``, which is best-effort (see
:mod:`netprotocols.registry`), and :meth:`TFTP.decode` rejects what no
TFTP message carries: an opcode other than 1-6 raises
:class:`InvalidFieldError`, which 65,530 of the 65,536 two-byte
prefixes fail. Past the opcode it raises :class:`TruncatedHeaderError`
for an opcode's mandatory fields cut short: a block number or error
code under 2 bytes, and a filename, mode or error message with no zero
byte after it, the terminator RFC 1350 §5 puts after every string (a
missing terminator is how a request cut short looks). Nothing else is
checked: an empty filename, a mode RFC 1350 does not name, an unknown
error code and any option decode, so a capture of a client probing a
server can be read.

Construction checks only that the opcode fits its 16 bits, so a
message decode would reject, or one whose body holds bytes past its
structural end, builds; ``TFTP.decode(bytes(message))`` then raises for
it, or decodes a shorter body, which ARCHITECTURE.md's round-trip
guarantee allows: it covers canonical messages, which those are not.
"""

from __future__ import annotations

from dataclasses import dataclass
from struct import Struct
from typing import ClassVar, Self

from netprotocols._base import Protocol
from netprotocols.utils.exceptions import (
    InvalidFieldError,
    TruncatedHeaderError,
)

__all__ = ["TFTP"]

#: Opcodes (RFC 1350 §5; RFC 2347 for OACK).
_RRQ = 1
_WRQ = 2
_DATA = 3
_ACK = 4
_ERROR = 5
_OACK = 6

_OPCODE_NAMES: dict[int, str] = {
    _RRQ: "RRQ",
    _WRQ: "WRQ",
    _DATA: "DATA",
    _ACK: "ACK",
    _ERROR: "ERROR",
    _OACK: "OACK",
}

#: Error codes (RFC 1350's appendix; RFC 2347 for 8).
_ERROR_NAMES: dict[int, str] = {
    0: "Not defined",
    1: "File not found",
    2: "Access violation",
    3: "Disk full or allocation exceeded",
    4: "Illegal TFTP operation",
    5: "Unknown transfer ID",
    6: "File already exists",
    7: "No such user",
    8: "Terminate transfer due to option negotiation",
}

_NUL = b"\x00"

#: The most significant digits a number option's value may have before
#: its accessor answers ``None`` rather than call ``int()``, which
#: raises ``ValueError`` for a string over 4,300 digits
#: (``sys.get_int_max_str_digits``). tsize, a file's size in octets, is
#: the largest value the options carry, and RFC 2349 does not bound it;
#: 20 digits hold any 64-bit size (2**64 - 1 has 20). Leading zeros do
#: not count, as for HTTP's Content-Length.
_MAX_OPTION_DIGITS = 20


def _text(raw: bytes) -> str:
    """Read a TFTP string as ASCII; other bytes as backslash escapes."""
    return raw.decode("ascii", "backslashreplace")


def _option_pairs(
    raw: bytes, start: int
) -> tuple[list[tuple[bytes, bytes]], int]:
    """Walk the name/value pairs in ``raw`` from ``start`` (RFC 2347).

    Return the whole pairs and where the last one ends. The walk stops,
    without raising, at the first pair that is not whole: a name with no
    zero byte after it, an empty name (a zero byte where a name would
    start, as Ethernet padding is), or a value with no zero byte after
    it.
    """
    pairs: list[tuple[bytes, bytes]] = []
    end = start
    while True:
        name_end = raw.find(_NUL, end)
        if name_end <= end:
            return pairs, end
        value_end = raw.find(_NUL, name_end + 1)
        if value_end < 0:
            return pairs, end
        pairs.append((raw[end:name_end], raw[name_end + 1 : value_end]))
        end = value_end + 1


@dataclass(frozen=True, slots=True)
class TFTP(Protocol):
    """A TFTP message (RFC 1350 §5; RFC 2347 for OACK and options).

    Construction accepts any opcode that fits 16 bits and any body;
    :meth:`decode` is stricter (see the module docstring).

    :param opcode: ``1`` RRQ, ``2`` WRQ, ``3`` DATA, ``4`` ACK, ``5``
        ERROR, ``6`` OACK (see :attr:`opcode_name`).
    :param body: Everything after the opcode up to the message's end,
        kept raw, e.g. ``b"boot.bin\\x00octet\\x00"`` for an RRQ or
        ``b"\\x00\\x01"`` for an ACK of block 1; read by the accessors.
    """

    opcode: int
    body: bytes = b""

    _struct: ClassVar[Struct] = Struct("!H")

    def __post_init__(self) -> None:
        """Check the opcode's width."""
        if not 0 <= self.opcode <= 0xFFFF:
            raise InvalidFieldError(
                f"TFTP opcode must be within 0-65535, got {self.opcode}",
                protocol=type(self),
                field="opcode",
                expected="0-65535",
                actual=self.opcode,
            )

    @classmethod
    def decode(cls, data: bytes | memoryview) -> Self:
        """Decode the message at the start of ``data``.

        The body ends where the opcode's structure does (see the module
        docstring); the rest of ``data`` is left undecoded.

        :raises TruncatedHeaderError: ``data`` is shorter than the
            opcode, a DATA or ACK has no 2-byte block number (``field``
            ``"block"``), an ERROR no 2-byte error code
            (``"error_code"``), or a filename, mode or error message
            has no zero byte after it (``"filename"``, ``"mode"``,
            ``"error_message"``); ``offset`` is where the field starts.
        :raises InvalidFieldError: the opcode is not 1-6 (``field``
            ``"opcode"``, ``offset`` ``0``).
        """
        (opcode,) = cls._unpack_fixed(data)
        end = cls._message_end(opcode, data)
        return cls(opcode=opcode, body=bytes(data[cls._struct.size : end]))

    @classmethod
    def _message_end(cls, opcode: int, data: bytes | memoryview) -> int:
        """Return where the message ``data`` starts ends (see decode)."""
        if opcode in (_DATA, _ACK, _ERROR):
            return cls._numbered_end(opcode, data)
        if opcode in (_RRQ, _WRQ):
            raw = bytes(data)
            mode_start = cls._string_end(raw, 2, "filename")
            mode_end = cls._string_end(raw, mode_start, "mode")
            return _option_pairs(raw, mode_end)[1]
        if opcode == _OACK:
            return _option_pairs(bytes(data), 2)[1]
        raise InvalidFieldError(
            f"TFTP opcode must be 1-6, got {opcode}",
            protocol=cls,
            field="opcode",
            offset=0,
            expected="1-6",
            actual=opcode,
        )

    @classmethod
    def _numbered_end(cls, opcode: int, data: bytes | memoryview) -> int:
        """Return where a DATA, ACK or ERROR message ends (see decode).

        Each holds a 2-byte number after its opcode: a block number, or
        an ERROR's error code.
        """
        if len(data) < 4:
            raise TruncatedHeaderError(
                f"TFTP {_OPCODE_NAMES[opcode]} needs 4 bytes, buffer holds "
                f"{len(data)}",
                protocol=cls,
                field="error_code" if opcode == _ERROR else "block",
                offset=2,
                expected=4,
                actual=len(data),
            )
        if opcode == _DATA:
            return len(data)
        if opcode == _ACK:
            return 4
        return cls._string_end(bytes(data), 4, "error_message")

    @classmethod
    def _string_end(cls, raw: bytes, start: int, field: str) -> int:
        """Return the offset past the zero byte ending the string at
        ``start``.

        :raises TruncatedHeaderError: no zero byte follows ``start``.
        """
        nul = raw.find(_NUL, start)
        if nul < 0:
            raise TruncatedHeaderError(
                f"TFTP {field} at offset {start} has no terminating zero "
                f"byte in the {len(raw)}-byte buffer",
                protocol=cls,
                field=field,
                offset=start,
                expected="a terminating zero byte",
                actual=len(raw),
            )
        return nul + 1

    def __bytes__(self) -> bytes:
        """Serialize the opcode and the body, verbatim."""
        return self._struct.pack(self.opcode) + self.body

    @property
    def header_len(self) -> int:
        """Return the opcode's 2 bytes plus the body.

        The body is the whole message: TFTP is terminal.
        """
        return self._struct.size + len(self.body)

    @property
    def opcode_name(self) -> str:
        """Name the opcode, e.g. ``"RRQ"``.

        Falls back to ``"unknown (n)"`` for an opcode not named here.
        """
        return _OPCODE_NAMES.get(self.opcode, f"unknown ({self.opcode})")

    @property
    def _request(self) -> tuple[bytes, bytes, int] | None:
        """Return a request's filename, mode and where its options start.

        ``None`` for another opcode, or a body that does not hold both
        strings whole (which only construction can give).
        """
        if self.opcode not in (_RRQ, _WRQ):
            return None
        body = self.body
        filename_end = body.find(_NUL)
        mode_end = body.find(_NUL, filename_end + 1)
        if filename_end < 0 or mode_end < 0:
            return None
        return (
            body[:filename_end],
            body[filename_end + 1 : mode_end],
            (mode_end + 1),
        )

    @property
    def filename(self) -> str | None:
        """Return an RRQ's or WRQ's filename, e.g. ``"boot.bin"``.

        ``None`` for another opcode.
        """
        request = self._request
        return None if request is None else _text(request[0])

    @property
    def mode(self) -> str | None:
        """Return an RRQ's or WRQ's mode as sent, e.g. ``"octet"``.

        RFC 1350 §5 makes the mode case-insensitive, so compare it
        lowercased. ``None`` for another opcode.
        """
        request = self._request
        return None if request is None else _text(request[1])

    @property
    def options(self) -> tuple[tuple[str, str], ...]:
        """Return the option name/value pairs, in wire order (RFC 2347).

        A request's options follow its mode, and an OACK is nothing but
        options. Empty for a request without options and for the other
        opcodes. Names and values are kept as sent; :meth:`option`
        matches names in any case.
        """
        if self.opcode == _OACK:
            start = 0
        else:
            request = self._request
            if request is None:
                return ()
            start = request[2]
        pairs = _option_pairs(self.body, start)[0]
        return tuple((_text(name), _text(value)) for name, value in pairs)

    def option(self, name: str) -> str | None:
        """Return the value of the first option named ``name``, or ``None``.

        The name matches in any case (RFC 2347), so ``option("BlkSize")``
        finds ``blksize``.
        """
        wanted = name.lower()
        return next(
            (value for key, value in self.options if key.lower() == wanted),
            None,
        )

    def _int_option(self, name: str) -> int | None:
        """Return option ``name`` read as a decimal number, or ``None``.

        ``None`` too past :data:`_MAX_OPTION_DIGITS` significant digits.
        """
        value = self.option(name)
        if value is None or not (value.isascii() and value.isdigit()):
            return None
        significant = value.lstrip("0")
        if len(significant) > _MAX_OPTION_DIGITS:
            return None
        return int(significant or "0")

    @property
    def blksize(self) -> int | None:
        """Return the ``blksize`` option, in octets (RFC 2348).

        A client asks for 8-65464; an OACK gives the size the server
        chose. ``None`` when absent, not a decimal number, or over 20
        digits (leading zeros aside).
        """
        return self._int_option("blksize")

    @property
    def timeout(self) -> int | None:
        """Return the ``timeout`` option, in seconds (RFC 2349).

        ``None`` when absent, not a decimal number, or over 20 digits
        (leading zeros aside).
        """
        return self._int_option("timeout")

    @property
    def tsize(self) -> int | None:
        """Return the ``tsize`` option, the file's size in octets (RFC 2349).

        An RRQ sends 0 and the server's OACK the size; a WRQ sends the
        size. ``None`` when absent, not a decimal number, or over 20
        digits (leading zeros aside).
        """
        return self._int_option("tsize")

    @property
    def windowsize(self) -> int | None:
        """Return the ``windowsize`` option, in blocks (RFC 7440).

        ``None`` when absent, not a decimal number, or over 20 digits
        (leading zeros aside).
        """
        return self._int_option("windowsize")

    @property
    def _number(self) -> int | None:
        """Return the 2 bytes after the opcode as a number, if present."""
        if len(self.body) < 2:
            return None
        return int.from_bytes(self.body[:2], "big")

    @property
    def block(self) -> int | None:
        """Return a DATA's or ACK's block number.

        Blocks count from 1 (RFC 1350 §5). The number is 16 bits and
        RFC 1350 does not say what follows block 65,535: implementations
        that go on wrap it, some to 0 and some to 1, so block 0 can
        appear mid-transfer. An ACK of block 0 answers a WRQ
        (RFC 1350 §4), or an OACK that answered an RRQ (RFC 2347; after
        a WRQ the client answers an OACK with DATA block 1). ``None``
        for another opcode.
        """
        return self._number if self.opcode in (_DATA, _ACK) else None

    @property
    def data(self) -> bytes | None:
        """Return a DATA's data: up to 512 bytes, or the negotiated
        ``blksize``.

        It runs to the end of the buffer decode was given, so bytes
        after the datagram, such as Ethernet padding, are part of it
        (see the module docstring). ``None`` for another opcode.
        """
        if self.opcode != _DATA or len(self.body) < 2:
            return None
        return self.body[2:]

    @property
    def error_code(self) -> int | None:
        """Return an ERROR's error code (see :attr:`error_name`).

        ``None`` for another opcode.
        """
        return self._number if self.opcode == _ERROR else None

    @property
    def error_name(self) -> str | None:
        """Name an ERROR's error code, e.g. ``"File not found"``.

        Falls back to ``"unknown (n)"`` for a code not named here.
        ``None`` for another opcode.
        """
        code = self.error_code
        if code is None:
            return None
        return _ERROR_NAMES.get(code, f"unknown ({code})")

    @property
    def error_message(self) -> str | None:
        """Return an ERROR's message, for a human, without its zero byte.

        ``None`` for another opcode, or a body whose message has no zero
        byte after it (which only construction can give).
        """
        if self.opcode != _ERROR or len(self.body) < 2:
            return None
        end = self.body.find(_NUL, 2)
        return None if end < 0 else _text(self.body[2:end])
