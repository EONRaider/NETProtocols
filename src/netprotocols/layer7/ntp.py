"""NTP — the Network Time Protocol, versions 1 to 4 (RFC 5905).

NTP (RFC 5905 for version 4, RFC 1305 for version 3) synchronizes
clocks over UDP port 123. Every message but a control message (modes 6
and 7, below) opens with the same 48-byte header (RFC 5905 §7.3,
Figure 8)::

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |LI | VN  |Mode |    Stratum     |     Poll      |  Precision   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         Root Delay                            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         Root Dispersion                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          Reference ID                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   +                     Reference Timestamp (64)                  +
   +                      Origin Timestamp (64)                    +
   +                      Receive Timestamp (64)                   +
   +                      Transmit Timestamp (64)                  +
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   .                                                               .
   .                    Extension Field 1 (variable)               .
   .                    Extension Field 2 (variable)               .
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          Key Identifier                       |
   |                            dgst (128)                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Every header field is kept as its raw wire value, so nothing is lost
in decoding and ``bytes()`` writes it back as it was: Poll and
Precision as the signed log2 seconds they are, Root Delay and Root
Dispersion as the 32 bits of a 16.16 fixed-point number, the Reference
ID as a 32-bit integer and each timestamp as the 64-bit NTP timestamp
format (32.32 fixed point, seconds since 1900, §6). Properties convert
alongside: :attr:`NTP.root_delay_seconds`, :attr:`NTP.poll_seconds`,
:attr:`NTP.reference_id_str`, and :attr:`NTP.transmit_time` and the
other three ``*_time`` properties, which give a
:class:`~datetime.datetime` in UTC.

The versions disagree on the sign of Root Delay. RFC 5905 gives NTPv4
both delay and dispersion in its NTP short format, whose seconds are
unsigned (§6), but RFC 1305 for NTPv3, and RFC 2030 for SNTP, define
Root Delay as a *signed* fixed-point number, which "can take on both
positive and negative values" (RFC 2030 §4). RFC 5905 obsoletes RFC
1305 and governs NTPv4 alone, so :attr:`NTP.root_delay_seconds` reads
Root Delay signed below version 4 and unsigned from it: ``0xffff0000``
is -1.0 s in an NTPv3 message and 65535.0 s in an NTPv4 one. Root
Dispersion is never negative in NTPv2-4, and
:attr:`NTP.root_dispersion_seconds` reads it unsigned. Both
``*_seconds`` conversions assume NTPv2-4's meanings of these two words
and do not apply to NTPv1, whose words are other fields (see below).

Timestamps
----------

An NTP timestamp counts seconds from 1900-01-01 00:00:00 UTC in 32
bits, so it wraps every 136 years, first on 2036-02-07 at 06:28:16 UTC
(RFC 5905 §6's era 1 starts there). The era is not on the wire, so the
conversions follow RFC 4330 §3: a timestamp whose most significant bit
is set is in era 0 (1968-2036), and one whose bit is clear is in era 1
(2036-2104). Zero is not a time: RFC 5905 §6 reserves it for "unknown
or unsynchronized", and every conversion answers ``None`` for it.
:func:`ntp_to_datetime` truncates the 32-bit fraction to the
microsecond a :class:`~datetime.datetime` holds; :func:`ntp_to_unix`
keeps it as a float.

A conversion is only as meaningful as the value: chrony's client fills
its request's Transmit Timestamp with random bits, which the server
returns as the Origin Timestamp, so that it can match the answer
without telling the server its clock.

After the header
----------------

NTP has no length field: what follows the 48 bytes runs to the end of
the UDP datagram, whose length ends the buffer in a
:func:`~netprotocols.decode_frame` walk. So, like RIP, an NTP message
keeps the whole buffer after
its header as :attr:`NTP.body`, verbatim, ``bytes(NTP.decode(x)) == x``
holds for every buffer decode accepts, and the accessors split the body
without raising:

- :attr:`NTP.extension_fields`, NTPv4 only (RFC 7822): each a 16-bit
  Field Type, a 16-bit Length that counts the 4-byte header and is a
  multiple of 4 and at least 16 (§3), and its value. Network Time
  Security (RFC 8915) is carried this way: a Unique Identifier, NTS
  Cookies and an NTS Authenticator whose ciphertext holds any further
  fields, which are not decrypted.
- :attr:`NTP.mac`, the Message Authentication Code: a 32-bit Key
  Identifier and a digest (RFC 5905 §7.3): 16 bytes for MD5 or for
  AES-128-CMAC (RFC 8573), 20 for SHA-1, as chrony and ntpsec send
  them, or none at all, the crypto-NAK, "a MAC consisting of four
  octets of zeros" with which a server answers a failed authentication
  (RFC 5905 §9.2). NTPv4 tells a MAC from an extension field by
  length alone, which is why RFC 7822 §3 sets a minimum length for the
  last extension field of a message without a MAC: the walk stops when
  what is left is exactly 4, 20 or 24 bytes, and reads that as the
  MAC. NTPv1-3 have no extension fields, and NTPv3's 12-byte DES
  authenticator (RFC 1305 §C) is read as a MAC too. No digest
  is verified: that needs the key.
- :attr:`NTP.remainder`: anything else, which neither walks as
  extension fields nor has a MAC's length.

The rule has the blind spot RIP's has, where no UDP length bounds the
buffer: decoded on its own, a plain 48-byte message followed by a
captured 4-byte Ethernet FCS gives a body of 4 bytes, which reads as a
crypto-NAK whose Key Identifier is the FCS. In a walk the FCS is the
packet's :attr:`~netprotocols.Packet.trailer`. Ethernet's zero padding
never follows NTP: the 48-byte header, behind IPv4's 20 and UDP's 8,
already fills Ethernet's 46-byte minimum payload.

Decoding a guess
----------------

NTP is reached through ``udp.port``, which is best-effort (see
:mod:`netprotocols.registry`), and any 48 bytes would make a header.
:meth:`NTP.decode` therefore rejects the first-byte values that are not
an NTP time message: a version outside 1-4 (the versions RFC 5905 and
its predecessors, RFC 1059, RFC 1119 and RFC 1305, define), and modes 6
and 7. Mode 0, reserved, decodes. Of the 256 first bytes 96 pass (4
Leap Indicators, 4 versions, 6 modes). The first byte is checked before
the length, so a rejected version or mode is reported as such
(``InvalidFieldError``, ``offset`` 0) however short the message, and
``TruncatedHeaderError`` is left for an empty buffer and for a short
one whose first byte passes. Nothing else is checked: a stratum RFC
5905 reserves (17-255) and a Kiss-o'-Death (stratum 0,
:attr:`NTP.kiss_code`) decode.

NTPv1 (RFC 1059) shares the header only by position: it has no Mode
field, so those three bits are zero and every NTPv1 message decodes
with mode 0, ``"reserved"``, and its second and third words are a
Synchronizing Distance and an Estimated Drift Rate, which
:attr:`NTP.root_delay` and :attr:`NTP.root_dispersion` hold, raw,
under NTPv2-4's names.

Construction checks only that each field fits its width, so a header
with a version or mode decode rejects builds, and
``NTP.decode(bytes(message))`` raises for it, which ARCHITECTURE.md's
round-trip guarantee allows: it covers canonical headers, which that
one is not.

Control messages
----------------

Modes 6 and 7 carry control messages: RFC 9327's mode 6, which
``ntpq`` speaks, and ntpd's private mode 7, which ``ntpdc`` speaks.
Their headers are not the time message's. UDP port 123 names
:class:`NTP`, and a walk hands it the first two bytes of the datagram
before choosing a header (``NTP._for_payload``): a mode 6 first byte
selects :class:`NTPControl`, and any other :class:`NTP`, which rejects
mode 7 with ``InvalidFieldError``, ``field`` ``"mode"``, whatever its
length. A strict ``decode_frame`` therefore raises on ``ntpdc`` traffic
to or from port 123; ``decode_frame(frame, lax=True)`` keeps Ethernet,
IP and UDP and reports the rejection as ``stopped_by``. Called
directly, :meth:`NTP.decode` rejects mode 6 too, with a message that
names :class:`NTPControl`, and :meth:`NTPControl.decode` rejects every
mode but 6. The choice holds wherever :class:`NTP` is registered, a
port named in ``decode_as`` included.

A mode 6 message (RFC 9327 §2, Figure 1) is a 12-byte header, then
``Count`` bytes of data, then padding and, optionally, a MAC::

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |LI |  VN |Mode |R|E|M| opcode  |       Sequence Number         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |            Status             |       Association ID          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |            Offset             |            Count              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   /                    Data (up to 468 bytes)                     /
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Padding (optional)                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   /              Authenticator (optional)                         /
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

:meth:`NTPControl.decode` judges the version (1-4) and the mode (6)
before the length, then needs the 12-byte header, then a Count of at
most 468, the most data RFC 9327 allows, then the Count's bytes of
data, whole: a Count past the end of the buffer raises
``TruncatedHeaderError`` with ``field`` ``"data"`` and reads nothing
past the header. In a walk the buffer ends at UDP's Length, so a Count
past the datagram is refused rather than read into Ethernet padding or
an FCS.

RFC 9327 pads the data to a multiple of 4 bytes and puts the
authenticator, the MAC of RFC 1305 Appendix C, a 4-byte Key ID and a
digest, after the padding, but does not say where it starts when the
data's end is a multiple of 4 and not of 8. :meth:`NTPControl.decode`
looks for it where ntpd and ntpsec write and read it: after the data
padded to a multiple of 8 bytes, which both require of an
authenticated request and send in an authenticated response; and, in
an error response (R and E both set), after the data padded to a
multiple of 4, since both write the MAC of an error response right
after its 12-byte header. A MAC is found when exactly 20 or 24 bytes
are left from there, a Key ID and a 16-byte (MD5, AES-128-CMAC) or
20-byte (SHA-1) digest, and is kept as an :class:`NTPMAC`, with the
bytes before it as :attr:`NTPControl.padding`. Otherwise
:attr:`NTPControl.padding` is the bytes up to the next multiple of 4,
or to the end of a shorter message, and :attr:`NTPControl.remainder`
holds anything after that. So a MAC that starts on a 4-byte but not an
8-byte boundary of a message that is not an error response is not
recognised: a 24-byte one reads as 4 bytes of padding and a 20-byte
MAC made of its last 20 bytes, and a 20-byte one as remainder. The
padding is not required to be zero, since ntpsec's responses can carry
other bytes there. No digest is verified: that needs the key.
``bytes(NTPControl.decode(x)) == x`` for every buffer decode accepts.

Of the 256 first bytes 16 more reach :class:`NTPControl` (4 Leap
Indicators, 4 versions, mode 6), and those pass when the Count fits:
a random 300-byte datagram on port 123 is rejected 62.5% of the time,
less 16/256 x 289/65,536 for a control message that decodes, about
62.47%, and more often when it is shorter than 48 bytes.

The data stays raw. Most commands and responses carry RFC 9327 §4's
comma-separated ``name=value`` text, which :attr:`NTPControl.variables`
splits without raising; a read status response carries binary pairs
of Association ID and peer status word, and a fragment of a longer
response (the M bit set, or a nonzero Offset) holds a slice of the
whole. The Status is kept raw as well, because what it holds depends on
the message: a system status word in a response to read status, read
variables or write variables, or in a trap response, for association
0, a peer status word in such a response for another association, a
clock status word in a response to read or write clock variables, an
Error Status Word in an error response, and zero in a command
(RFC 9327 §3 and §4). :attr:`NTPControl.system_status` splits it as a
system status word, as an :class:`NTPSystemStatus`, only in a response
to opcode 1, 2, 3 or 7 for association 0 that is not an error response,
and :attr:`NTPControl.error_code` reads an error response's code.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from struct import Struct
from typing import ClassVar, Self

from netprotocols._base import Protocol, bytes_to_ipv4, hex_str
from netprotocols.utils.exceptions import (
    InvalidFieldError,
    TruncatedHeaderError,
)

__all__ = [
    "NTP",
    "NTPMAC",
    "NTPControl",
    "NTPExtensionField",
    "NTPSystemStatus",
    "ntp_to_datetime",
    "ntp_to_unix",
]

#: Seconds from the NTP prime epoch, 1900-01-01, to the Unix epoch,
#: 1970-01-01 (RFC 5905 §6, Figure 4).
_NTP_TO_UNIX = 2_208_988_800

#: The length of one era, 2**32 seconds (RFC 5905 §6).
_ERA = 1 << 32

_UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)

#: An extension field's 4-byte header: Field Type, then Length.
_FIELD_HEADER = Struct("!HH")

#: The shortest extension field RFC 7822 §3 allows, its header included.
_MIN_FIELD_LEN = 16

#: The lengths of an NTPv4 MAC: a crypto-NAK (the Key Identifier
#: alone), and a Key Identifier with a 16-byte digest (MD5 or
#: AES-128-CMAC, RFC 8573) or a 20-byte one (SHA-1).
_MAC_LENGTHS_V4 = frozenset({4, 20, 24})

#: NTPv1-3 add RFC 1305 §C's 12-byte DES authenticator.
_MAC_LENGTHS_V3 = _MAC_LENGTHS_V4 | {12}

#: Leap Indicator meanings (RFC 5905 §7.3, Figure 9).
_LEAP_NAMES: dict[int, str] = {
    0: "no warning",
    1: "last minute of the day has 61 seconds",
    2: "last minute of the day has 59 seconds",
    3: "unknown (clock unsynchronized)",
}

#: Association modes (RFC 5905 §7.3, Figure 10).
_MODE_NAMES: dict[int, str] = {
    0: "reserved",
    1: "symmetric active",
    2: "symmetric passive",
    3: "client",
    4: "server",
    5: "broadcast",
    6: "NTP control message",
    7: "reserved for private use",
}

#: The mode of an NTP control message (RFC 9327 §2).
_MODE_CONTROL = 6

#: The most data octets a control message carries (RFC 9327 §2).
_MAX_CONTROL_DATA = 468

#: The lengths of a control message's MAC: a Key ID and a 16-byte
#: digest (MD5 or AES-128-CMAC) or a 20-byte one (SHA-1).
_CONTROL_MAC_LENGTHS = frozenset({20, 24})

#: Control message Operation Codes (RFC 9327 §2, Table 1); 0 and 13-30
#: are reserved.
_OPCODE_NAMES: dict[int, str] = {
    1: "read status",
    2: "read variables",
    3: "write variables",
    4: "read clock variables",
    5: "write clock variables",
    6: "set trap address/port",
    7: "trap response",
    8: "runtime configuration",
    9: "export configuration to file",
    10: "retrieve remote address stats",
    11: "retrieve ordered list",
    12: "request client-specific nonce",
    31: "unset trap address/port",
}

#: The opcodes whose response to association 0 carries a system status
#: word (RFC 9327 §3.1 and §4): read status, read variables, write
#: variables and trap response.
_SYSTEM_STATUS_OPCODES = frozenset({1, 2, 3, 7})

#: Error Status Word codes (RFC 9327 §3.4, Table 9); 8-255 are
#: reserved.
_ERROR_NAMES: dict[int, str] = {
    0: "unspecified",
    1: "authentication failure",
    2: "invalid message length or format",
    3: "invalid opcode",
    4: "unknown Association ID",
    5: "unknown variable name",
    6: "invalid variable value",
    7: "administratively prohibited",
}

#: System status word Clock Source values (RFC 9327 §3.1, Table 3);
#: 10-63 are reserved.
_CLOCK_SOURCE_NAMES: dict[int, str] = {
    0: "unspecified or unknown",
    1: "calibrated atomic clock",
    2: "VLF or LF radio",
    3: "HF radio",
    4: "UHF satellite",
    5: "local net",
    6: "UDP/NTP",
    7: "UDP/TIME",
    8: "eyeball-and-wristwatch",
    9: "telephone modem",
}

#: System Event Codes (RFC 9327 §3.1, Table 4).
_SYSTEM_EVENT_NAMES: dict[int, str] = {
    0: "unspecified",
    1: "frequency correction (drift) file not available",
    2: "frequency correction started (frequency stepped)",
    3: "spike detected and ignored, starting stepout timer",
    4: "frequency training started",
    5: "clock synchronized",
    6: "system restart",
    7: "panic stop (required step greater than panic threshold)",
    8: "no system peer",
    9: "leap second insertion/deletion armed for the current month",
    10: "leap second disarmed",
    11: "leap second inserted or deleted",
    12: "clock stepped (stepout timer expired)",
    13: "kernel loop discipline status changed",
    14: "leapseconds table loaded from file",
    15: "leapseconds table outdated, updated file needed",
}

#: Extension Field Types: IANA's "NTP Extension Field Types" as RFC
#: 9748 left it, the entries RFC 8915 (NTS) and RFC 7821 (UDP Checksum
#: Complement) added. 0x0204, which Autokey shares, is named for NTS;
#: the other Autokey types (RFC 5906), 0x0000 (Crypto-NAK) and the
#: historic reservations decode unnamed.
_FIELD_TYPE_NAMES: dict[int, str] = {
    0x0104: "Unique Identifier",
    0x0204: "NTS Cookie",
    0x0304: "NTS Cookie Placeholder",
    0x0404: "NTS Authenticator and Encrypted Extension Fields",
    0x2005: "UDP Checksum Complement",
}

#: The Field Types RFC 9748 reserves for experimentation and
#: development, which IANA cannot assign: 0xF000-0xFFFF. Wireshark's
#: packet-ntp.c, which tracks the IANA registry, names the range
#: "Reserved for Private or Experimental Use".
_EXPERIMENTAL_FIELD_TYPES = range(0xF000, 0x10000)


def _check_range(
    owner: type, name: str, value: int, low: int, high: int
) -> None:
    """Raise :class:`InvalidFieldError` unless ``low <= value <= high``."""
    if not low <= value <= high:
        raise InvalidFieldError(
            f"{owner.__name__} {name} must be within {low}-{high}, got {value}",
            protocol=owner,
            field=name,
            expected=f"{low}-{high}",
            actual=value,
        )


def _check_version(owner: type, flags: int) -> None:
    """Raise :class:`InvalidFieldError` unless ``flags`` has version 1-4.

    :param owner: The class named as ``protocol`` in a raised error.
    :param flags: The message's first byte.
    :raises InvalidFieldError: if the version is outside 1-4.
    """
    version = (flags >> 3) & 0x07
    if not 1 <= version <= 4:
        raise InvalidFieldError(
            f"NTP version must be 1-4, got {version}",
            protocol=owner,
            field="version",
            offset=0,
            expected="1-4",
            actual=version,
        )


def _check_first_byte(owner: type, flags: int) -> None:
    """Raise :class:`InvalidFieldError` unless ``flags`` opens a time message.

    The version must be 1-4, then the mode must not be 6 or 7. The
    check is decode-only, like RIP's version check: construction accepts
    any version and mode.

    :param owner: The class named as ``protocol`` in a raised error.
    :param flags: The message's first byte.
    :raises InvalidFieldError: if the version is outside 1-4, or else
        the mode is 6 or 7.
    """
    _check_version(owner, flags)
    mode = flags & 0x07
    if mode == _MODE_CONTROL:
        raise InvalidFieldError(
            "NTP mode 6 is a control message: decode it with NTPControl",
            protocol=owner,
            field="mode",
            offset=0,
            expected="0-5",
            actual=mode,
        )
    if mode == 7:
        raise InvalidFieldError(
            "NTP mode 7 is a private control message, not decoded",
            protocol=owner,
            field="mode",
            offset=0,
            expected="0-5",
            actual=mode,
        )


def ntp_to_unix(timestamp: int) -> float | None:
    """Convert a 64-bit NTP timestamp to seconds since the Unix epoch.

    The era follows RFC 4330 §3 (see the module docstring): a timestamp
    whose top bit is clear is read as in era 1, from 2036-02-07.
    ``None`` for 0, which RFC 5905 §6 reserves for an unknown time.
    """
    if timestamp == 0:
        return None
    seconds, fraction = divmod(timestamp, _ERA)
    if not seconds >> 31:
        seconds += _ERA
    return seconds - _NTP_TO_UNIX + fraction / _ERA


def ntp_to_datetime(timestamp: int) -> datetime | None:
    """Convert a 64-bit NTP timestamp to an aware UTC datetime.

    The fraction is truncated to whole microseconds; the era follows
    RFC 4330 §3, as :func:`ntp_to_unix` does. ``None`` for 0.
    """
    if timestamp == 0:
        return None
    seconds, fraction = divmod(timestamp, _ERA)
    if not seconds >> 31:
        seconds += _ERA
    return _UNIX_EPOCH + timedelta(
        seconds=seconds - _NTP_TO_UNIX,
        microseconds=fraction * 1_000_000 >> 32,
    )


@dataclass(frozen=True, slots=True)
class NTPExtensionField:
    """One NTPv4 extension field (RFC 7822 §3).

    :param type: The 16-bit Field Type (see :attr:`type_name`).
    :param value: Everything after the 4-byte header that the Length
        covers, padding included, kept raw.
    :raises InvalidFieldError: if ``type`` does not fit 16 bits, or the
        field would be longer than its 16-bit Length can say.

    ``bytes(field)`` writes the header, with a Length of
    ``4 + len(value)``, and the value. Construction does not hold the
    value to RFC 7822's multiple of 4 or minimum of 16 bytes, which
    only :attr:`NTP.extension_fields` applies, so that a test can build
    the fields a decoder must refuse.
    """

    type: int
    value: bytes = b""

    def __post_init__(self) -> None:
        """Check the type's width and the field's length."""
        _check_range(type(self), "type", self.type, 0, 0xFFFF)
        _check_range(
            type(self),
            "value",
            len(self.value),
            0,
            0xFFFF - _FIELD_HEADER.size,
        )

    def __bytes__(self) -> bytes:
        """Serialize the field: Field Type, Length, then the value."""
        return (
            _FIELD_HEADER.pack(self.type, _FIELD_HEADER.size + len(self.value))
            + self.value
        )

    @property
    def type_name(self) -> str:
        """Name the Field Type, e.g. ``"NTS Cookie"``.

        A type in 0xF000-0xFFFF, the range RFC 9748 reserves for
        Private or Experimental Use, says so, such as chrony's
        ``"Private or Experimental Use (0xf323)"``; any other type not
        named here falls back to ``"unknown (0x0002)"``, in hex as the
        registry writes types (degrades, never raises).
        """
        name = _FIELD_TYPE_NAMES.get(self.type)
        if name is not None:
            return name
        hex_type = hex_str(self.type, 6)
        if self.type in _EXPERIMENTAL_FIELD_TYPES:
            return f"Private or Experimental Use ({hex_type})"
        return f"unknown ({hex_type})"


@dataclass(frozen=True, slots=True)
class NTPMAC:
    """An NTP Message Authentication Code (RFC 5905 §7.3).

    :param key_id: The 32-bit Key Identifier: which symmetric key, and
        so which algorithm, made the digest.
    :param digest: The message digest, raw: 16 bytes for MD5 or
        AES-128-CMAC (RFC 8573), 20 for SHA-1, or none in a crypto-NAK.
        It is not verified.
    :raises InvalidFieldError: if ``key_id`` does not fit 32 bits.
    """

    key_id: int
    digest: bytes = b""

    def __post_init__(self) -> None:
        """Check the Key Identifier's width."""
        _check_range(type(self), "key_id", self.key_id, 0, 0xFFFFFFFF)

    def __bytes__(self) -> bytes:
        """Serialize the MAC: the Key Identifier, then the digest."""
        return self.key_id.to_bytes(4, "big") + self.digest

    @property
    def is_crypto_nak(self) -> bool:
        """Whether this is a crypto-NAK: Key Identifier 0, no digest."""
        return self.key_id == 0 and not self.digest


def _field_length(body: bytes, offset: int) -> int | None:
    """Return the Length of an extension field at ``offset`` in ``body``.

    ``None`` unless RFC 7822 §3 allows it there: at least 16, a
    multiple of 4, and within the body.
    """
    if len(body) - offset < _FIELD_HEADER.size:
        return None
    _, length = _FIELD_HEADER.unpack_from(body, offset)
    if length < _MIN_FIELD_LEN or length % 4 or offset + length > len(body):
        return None
    return int(length)


def _split_body(
    body: bytes, version: int
) -> tuple[tuple[NTPExtensionField, ...], NTPMAC | None, int]:
    """Split ``body`` into extension fields and a MAC.

    Returns the fields, the MAC or ``None``, and where in ``body`` the
    two end: the remainder starts there.
    """
    fields: list[NTPExtensionField] = []
    offset = 0
    mac_lengths = _MAC_LENGTHS_V3
    if version == 4:
        mac_lengths = _MAC_LENGTHS_V4
        while (left := len(body) - offset) and left not in mac_lengths:
            length = _field_length(body, offset)
            if length is None:
                break
            field_type = int.from_bytes(body[offset : offset + 2], "big")
            value = body[offset + _FIELD_HEADER.size : offset + length]
            fields.append(NTPExtensionField(field_type, value))
            offset += length
    if len(body) - offset not in mac_lengths:
        return tuple(fields), None, offset
    key_id = int.from_bytes(body[offset : offset + 4], "big")
    return tuple(fields), NTPMAC(key_id, body[offset + 4 :]), len(body)


@dataclass(frozen=True, slots=True)
class NTP(Protocol):
    """An NTP time message: the header (RFC 5905 §7.3) and what follows.

    Construction accepts any value that fits each field; :meth:`decode`
    is stricter and rejects a version outside 1-4 and modes 6 and 7
    (see the module docstring).

    :param leap: Leap Indicator, 2 bits (see :attr:`leap_name`); ``3``
        means the sender's clock is unsynchronized.
    :param version: Version Number, 3 bits: ``4`` (RFC 5905) or ``3``
        (RFC 1305), or ``1``-``2`` from older senders.
    :param mode: Mode, 3 bits: ``3`` client, ``4`` server, ``1``/``2``
        symmetric active/passive, ``5`` broadcast, ``0`` in every NTPv1
        message, which has no Mode field (see
        :attr:`mode_name`).
    :param stratum: ``1`` for a primary server, ``2``-``15`` for a
        secondary one, ``16`` unsynchronized, ``0`` unspecified or, in a
        Kiss-o'-Death, with a kiss code in the Reference ID (see
        :attr:`stratum_name` and :attr:`kiss_code`).
    :param poll: The maximum interval between messages, in signed log2
        seconds (:attr:`poll_seconds`).
    :param precision: The sender's clock precision, in signed log2
        seconds (:attr:`precision_seconds`).
    :param root_delay: Round-trip delay to the reference clock, the
        raw 32 bits of a 16.16 fixed-point number, which is signed
        below version 4 (:attr:`root_delay_seconds`).
    :param root_dispersion: Dispersion to the reference clock, raw NTP
        short format, unsigned 16.16 (:attr:`root_dispersion_seconds`).
    :param reference_id: Reference ID, raw: a kiss code, a reference
        clock's ASCII name or an IPv4 address, by stratum (see
        :attr:`reference_id_str`).
    :param reference_timestamp: When the clock was last set, raw NTP
        timestamp format (:attr:`reference_time`).
    :param origin_timestamp: The Transmit Timestamp of the message this
        one answers (:attr:`origin_time`).
    :param receive_timestamp: When the message this one answers
        arrived (:attr:`receive_time`).
    :param transmit_timestamp: When this message left
        (:attr:`transmit_time`).
    :param body: Everything after the 48-byte header, kept raw:
        extension fields, a MAC, and any remainder, read by
        :attr:`extension_fields`, :attr:`mac` and :attr:`remainder`.
    """

    leap: int
    version: int
    mode: int
    stratum: int = 0
    poll: int = 0
    precision: int = 0
    root_delay: int = 0
    root_dispersion: int = 0
    reference_id: int = 0
    reference_timestamp: int = 0
    origin_timestamp: int = 0
    receive_timestamp: int = 0
    transmit_timestamp: int = 0
    body: bytes = b""

    _struct: ClassVar[Struct] = Struct("!BBbbIIIQQQQ")

    def __post_init__(self) -> None:
        """Check each header field's width."""
        owner = type(self)
        _check_range(owner, "leap", self.leap, 0, 3)
        _check_range(owner, "version", self.version, 0, 7)
        _check_range(owner, "mode", self.mode, 0, 7)
        _check_range(owner, "stratum", self.stratum, 0, 0xFF)
        _check_range(owner, "poll", self.poll, -128, 127)
        _check_range(owner, "precision", self.precision, -128, 127)
        for name in ("root_delay", "root_dispersion", "reference_id"):
            _check_range(owner, name, getattr(self, name), 0, 0xFFFFFFFF)
        for name in (
            "reference_timestamp",
            "origin_timestamp",
            "receive_timestamp",
            "transmit_timestamp",
        ):
            _check_range(owner, name, getattr(self, name), 0, _ERA * _ERA - 1)

    @classmethod
    def decode(cls, data: bytes | memoryview) -> Self:
        """Decode the header and keep the rest of ``data`` as the body.

        The first byte is judged before the length (see "Decoding a
        guess" and "Control messages" in the module docstring).

        :param data: The buffer, starting at the LI/VN/Mode byte.
        :raises InvalidFieldError: if the version is outside 1-4 (``field``
            ``"version"``), or else the mode is 6 or 7, a control
            message (``field`` ``"mode"``), at any length; ``offset``
            ``0`` for both.
        :raises TruncatedHeaderError: if ``data`` is empty, or its first
            byte passes and it is shorter than 48 bytes.
        """
        if data:
            _check_first_byte(cls, data[0])
        (
            flags,
            stratum,
            poll,
            precision,
            root_delay,
            root_dispersion,
            reference_id,
            reference_timestamp,
            origin_timestamp,
            receive_timestamp,
            transmit_timestamp,
        ) = cls._unpack_fixed(data)
        return cls(
            leap=flags >> 6,
            version=(flags >> 3) & 0x07,
            mode=flags & 0x07,
            stratum=stratum,
            poll=poll,
            precision=precision,
            root_delay=root_delay,
            root_dispersion=root_dispersion,
            reference_id=reference_id,
            reference_timestamp=reference_timestamp,
            origin_timestamp=origin_timestamp,
            receive_timestamp=receive_timestamp,
            transmit_timestamp=transmit_timestamp,
            body=bytes(data[cls._struct.size :]),
        )

    def __bytes__(self) -> bytes:
        """Serialize the header and the body, verbatim."""
        return (
            self._struct.pack(
                (self.leap << 6) | (self.version << 3) | self.mode,
                self.stratum,
                self.poll,
                self.precision,
                self.root_delay,
                self.root_dispersion,
                self.reference_id,
                self.reference_timestamp,
                self.origin_timestamp,
                self.receive_timestamp,
                self.transmit_timestamp,
            )
            + self.body
        )

    @property
    def header_len(self) -> int:
        """The whole message: the 48-byte header and the whole body.

        The body is the rest of the datagram: NTP is terminal.
        """
        return self._struct.size + len(self.body)

    @classmethod
    def _for_payload(cls, lead: int) -> type[Protocol]:
        """Return :class:`NTPControl` for a mode 6 first byte, else ``cls``.

        UDP port 123 carries both formats, so a walk reads the mode in
        the first byte of ``lead`` before it chooses a header (see
        "Control messages" in the module docstring).

        :param lead: The first two bytes of the UDP payload, as a
            big-endian 16-bit integer.
        """
        return NTPControl if lead >> 8 & 0x07 == _MODE_CONTROL else cls

    @property
    def leap_name(self) -> str:
        """Describe the Leap Indicator, e.g. ``"no warning"``.

        Every value construction accepts (0-3) has a name, so this never
        raises.
        """
        return _LEAP_NAMES[self.leap]

    @property
    def mode_name(self) -> str:
        """Name the mode, e.g. ``"client"``.

        Every value construction accepts (0-7) has a name, so this never
        raises.
        """
        return _MODE_NAMES[self.mode]

    @property
    def stratum_name(self) -> str:
        """Describe the stratum (RFC 5905 §7.3, Figure 11).

        ``"unspecified or invalid"`` (0), ``"primary server"`` (1),
        ``"secondary server"`` (2-15), ``"unsynchronized"`` (16) or
        ``"reserved"`` (17-255); every stratum has a description, so
        this never raises.
        """
        stratum = self.stratum
        if stratum == 0:
            return "unspecified or invalid"
        if stratum == 1:
            return "primary server"
        if stratum <= 15:
            return "secondary server"
        return "unsynchronized" if stratum == 16 else "reserved"

    @property
    def poll_seconds(self) -> float:
        """Return the poll interval in seconds, ``2 ** poll``."""
        return 2.0**self.poll

    @property
    def precision_seconds(self) -> float:
        """Return the precision in seconds, ``2 ** precision``."""
        return 2.0**self.precision

    @property
    def root_delay_seconds(self) -> float:
        """Return the Root Delay in seconds, 16.16 fixed point.

        Signed below version 4, as RFC 1305 and RFC 2030 define it, so
        ``0xffff0000`` is -1.0; unsigned from version 4, RFC 5905's NTP
        short format (§6), so the same bits are 65535.0. Meaningless
        for NTPv1, whose second word is a Synchronizing Distance. See
        the module docstring. :attr:`root_delay` stays the raw 32 bits.
        """
        delay = self.root_delay
        if self.version < 4 and delay >> 31:
            delay -= 1 << 32
        return delay / 0x10000

    @property
    def root_dispersion_seconds(self) -> float:
        """Return the Root Dispersion in seconds, unsigned 16.16.

        Unsigned: no NTPv2-4 or SNTP specification lets it go negative.
        Meaningless for NTPv1, whose third word is an Estimated Drift
        Rate (see the module docstring).
        """
        return self.root_dispersion / 0x10000

    @property
    def kiss_code(self) -> str | None:
        """Return the kiss code of a stratum 0 message (RFC 5905 §7.4).

        That is the Reference ID as ASCII, NUL padding stripped, such as
        ``"RATE"`` or ``"DENY"``. ``None`` at any other stratum, and
        when the Reference ID is zero or not printable ASCII, as in a
        client's request, which leaves it zero.
        """
        if self.stratum != 0:
            return None
        return _ascii_id(self.reference_id)

    @property
    def reference_id_str(self) -> str:
        """Render the Reference ID as its stratum gives it (§7.3).

        At stratum 0 and 1, ASCII: a kiss code, or a reference clock's
        name such as ``"GPS"``; ``""`` for zero, and hex, such as
        ``"0x7f7f0101"``, when not printable. From stratum 2, a dotted
        IPv4 address: the server's own, or, for an IPv6 one, the first
        four bytes of the MD5 hash of the address, shown the same way.
        """
        reference_id = self.reference_id
        if self.stratum >= 2:
            return bytes_to_ipv4(reference_id.to_bytes(4, "big"))
        if reference_id == 0:
            return ""
        text = _ascii_id(reference_id)
        return text if text is not None else hex_str(reference_id, 10)

    @property
    def reference_time(self) -> datetime | None:
        """Return the Reference Timestamp as a UTC datetime, or ``None``.

        See :func:`ntp_to_datetime`.
        """
        return ntp_to_datetime(self.reference_timestamp)

    @property
    def origin_time(self) -> datetime | None:
        """Return the Origin Timestamp as a UTC datetime, or ``None``."""
        return ntp_to_datetime(self.origin_timestamp)

    @property
    def receive_time(self) -> datetime | None:
        """Return the Receive Timestamp as a UTC datetime, or ``None``."""
        return ntp_to_datetime(self.receive_timestamp)

    @property
    def transmit_time(self) -> datetime | None:
        """Return the Transmit Timestamp as a UTC datetime, or ``None``."""
        return ntp_to_datetime(self.transmit_timestamp)

    @property
    def extension_fields(self) -> tuple[NTPExtensionField, ...]:
        """Parse the NTPv4 extension fields (RFC 7822), in wire order.

        The walk stops at what is left when it has a MAC's length, at a
        Length RFC 7822 §3 does not allow, or at the end of the body.
        Always empty below version 4. Never raises.
        """
        return _split_body(self.body, self.version)[0]

    @property
    def mac(self) -> NTPMAC | None:
        """Return the MAC after the extension fields, if there is one.

        ``None`` unless what is left has a MAC's length: 4 bytes (a
        crypto-NAK), 20 (MD5 or AES-128-CMAC) or 24 (SHA-1), and below
        version 4 also 12 (DES). A 4-byte Ethernet FCS after a plain
        message reads as a crypto-NAK (see the module docstring). Never
        raises.
        """
        return _split_body(self.body, self.version)[1]

    @property
    def remainder(self) -> bytes:
        """Return what follows the extension fields, short of a MAC.

        Empty when the body is extension fields and a MAC, or nothing.
        """
        return self.body[_split_body(self.body, self.version)[2] :]


@dataclass(frozen=True, slots=True)
class NTPSystemStatus:
    """A system status word, split (RFC 9327 §3.1).

    :param leap: Leap Indicator, 2 bits (see :attr:`leap_name`).
    :param clock_source: Clock Source, 6 bits: what the server
        synchronizes to (see :attr:`clock_source_name`).
    :param event_count: System Event Counter, 4 bits: events since the
        System Event Code last changed, at most 15.
    :param event_code: System Event Code, 4 bits: the latest system
        event (see :attr:`event_name`).
    :raises InvalidFieldError: if a field does not fit its width.
    """

    leap: int
    clock_source: int
    event_count: int
    event_code: int

    def __post_init__(self) -> None:
        """Check each field's width."""
        owner = type(self)
        _check_range(owner, "leap", self.leap, 0, 3)
        _check_range(owner, "clock_source", self.clock_source, 0, 0x3F)
        _check_range(owner, "event_count", self.event_count, 0, 0x0F)
        _check_range(owner, "event_code", self.event_code, 0, 0x0F)

    @classmethod
    def from_word(cls, word: int) -> NTPSystemStatus:
        """Split a 16-bit status word into the four fields.

        :param word: The Status field of a control message.
        """
        return cls(
            leap=(word >> 14) & 0x03,
            clock_source=(word >> 8) & 0x3F,
            event_count=(word >> 4) & 0x0F,
            event_code=word & 0x0F,
        )

    @property
    def leap_name(self) -> str:
        """Describe the Leap Indicator, as :attr:`NTP.leap_name` does."""
        return _LEAP_NAMES[self.leap]

    @property
    def clock_source_name(self) -> str:
        """Name the Clock Source, e.g. ``"UDP/NTP"``.

        ``"reserved (n)"`` for 10-63, which RFC 9327 reserves.
        """
        name = _CLOCK_SOURCE_NAMES.get(self.clock_source)
        return name if name is not None else f"reserved ({self.clock_source})"

    @property
    def event_name(self) -> str:
        """Name the System Event Code, e.g. ``"system restart"``.

        Every 4-bit code has a name, so this never raises.
        """
        return _SYSTEM_EVENT_NAMES[self.event_code]


@dataclass(frozen=True, slots=True)
class NTPControl(Protocol):
    """An NTP control message, mode 6 (RFC 9327 §2).

    The 12-byte header, then ``Count`` bytes of data, padding, and an
    optional MAC. The data stays raw; :attr:`variables` splits the
    ``name=value`` text most commands carry. Construction accepts any
    value that fits each field; :meth:`decode` rejects a version outside
    1-4 and any mode but 6, and a Count above 468 or past the buffer
    (see "Control messages" in the module docstring).

    :param leap: Leap Indicator, 2 bits. RFC 9327 §2 sets it to zero
        and puts the server's in the system status word (see
        :attr:`system_status`), but ntpsec's ``ntpq`` sends ``3`` and
        its ``ntpd`` answers with its own Leap Indicator here too.
    :param version: Version Number, 3 bits: ``2`` from ``ntpq``, which
        a response repeats.
    :param response: The R bit: set in a response, clear in a command.
    :param error: The E bit: set in an error response, whose Status is
        an Error Status Word (see :attr:`error_code`).
    :param more: The M bit: set in every fragment of a response but the
        last.
    :param opcode: Operation Code, 5 bits (see :attr:`opcode_name`).
    :param sequence: Sequence Number, which a response repeats from its
        command, in every fragment.
    :param status: Status, the 16-bit status word, raw: a system, peer,
        clock or error status word by opcode, Association ID and E bit,
        zero in a command (see :attr:`system_status` and
        :attr:`error_code`).
    :param association_id: Association ID: ``0`` for the system,
        otherwise a peer association.
    :param offset: Offset, in octets, of the first data octet within
        the whole response; ``0`` in a command and a first fragment.
    :param data: The data, raw, whose length is the Count field.
    :param padding: The bytes between the data and the MAC, or, without
        a MAC, up to the next multiple of 4 bytes, raw; RFC 9327 has
        them zero, but ntpsec's responses can carry other bytes there.
    :param mac: The Message Authentication Code, or ``None``.
    :param remainder: Anything after the padding of a message without a
        MAC, raw.
    :raises InvalidFieldError: if a field does not fit its width, or the
        data is longer than its 16-bit Count can say.
    """

    leap: int = 0
    version: int = 2
    response: bool = False
    error: bool = False
    more: bool = False
    opcode: int = 0
    sequence: int = 0
    status: int = 0
    association_id: int = 0
    offset: int = 0
    data: bytes = b""
    padding: bytes = b""
    mac: NTPMAC | None = None
    remainder: bytes = b""

    _struct: ClassVar[Struct] = Struct("!BBHHHHH")

    def __post_init__(self) -> None:
        """Check each header field's width and the data's length."""
        owner = type(self)
        _check_range(owner, "leap", self.leap, 0, 3)
        _check_range(owner, "version", self.version, 0, 7)
        _check_range(owner, "opcode", self.opcode, 0, 0x1F)
        for name in ("sequence", "status", "association_id", "offset"):
            _check_range(owner, name, getattr(self, name), 0, 0xFFFF)
        _check_range(owner, "data", len(self.data), 0, 0xFFFF)

    @classmethod
    def decode(cls, data: bytes | memoryview) -> Self:
        """Decode a whole control message: header, data, padding and MAC.

        The first byte is judged before the length, then the Count
        before the data it counts. Where the MAC starts, and so whether
        there is one, is set out under "Control messages" in the module
        docstring.

        :param data: The buffer, starting at the LI/VN/Mode byte.
        :raises InvalidFieldError: if the version is outside 1-4
            (``field`` ``"version"``), or else the mode is not 6
            (``field`` ``"mode"``), both at ``offset`` 0 and at any
            length; or if the Count is above 468 (``field``
            ``"count"``, ``offset`` 10).
        :raises TruncatedHeaderError: if ``data`` is empty, or its first
            byte passes and it is shorter than the 12-byte header, or
            the Count runs past it (``field`` ``"data"``, ``offset``
            12).
        """
        if data:
            _check_version(cls, data[0])
            mode = data[0] & 0x07
            if mode != _MODE_CONTROL:
                raise InvalidFieldError(
                    f"NTPControl mode must be 6, got {mode}",
                    protocol=cls,
                    field="mode",
                    offset=0,
                    expected=_MODE_CONTROL,
                    actual=mode,
                )
        (
            flags,
            bits,
            sequence,
            status,
            association_id,
            offset,
            count,
        ) = cls._unpack_fixed(data)
        if count > _MAX_CONTROL_DATA:
            raise InvalidFieldError(
                f"NTPControl count must be at most {_MAX_CONTROL_DATA}, "
                f"got {count}",
                protocol=cls,
                field="count",
                offset=10,
                expected=f"0-{_MAX_CONTROL_DATA}",
                actual=count,
            )
        end = cls._struct.size + count
        if end > len(data):
            raise TruncatedHeaderError(
                f"NTPControl count {count} needs {end} bytes, buffer "
                f"holds {len(data)}",
                protocol=cls,
                field="data",
                offset=cls._struct.size,
                expected=end,
                actual=len(data),
            )
        response, error = bool(bits & 0x80), bool(bits & 0x40)
        padding, mac, remainder = _split_control_tail(
            bytes(data), end, response and error
        )
        return cls(
            leap=flags >> 6,
            version=(flags >> 3) & 0x07,
            response=response,
            error=error,
            more=bool(bits & 0x20),
            opcode=bits & 0x1F,
            sequence=sequence,
            status=status,
            association_id=association_id,
            offset=offset,
            data=bytes(data[cls._struct.size : end]),
            padding=padding,
            mac=mac,
            remainder=remainder,
        )

    def __bytes__(self) -> bytes:
        """Serialize the header, then the data, padding, MAC and remainder.

        The mode is written as 6 and the Count as the data's length.
        """
        bits = (
            (self.response << 7)
            | (self.error << 6)
            | (self.more << 5)
            | self.opcode
        )
        return (
            self._struct.pack(
                (self.leap << 6) | (self.version << 3) | _MODE_CONTROL,
                bits,
                self.sequence,
                self.status,
                self.association_id,
                self.offset,
                len(self.data),
            )
            + self.data
            + self.padding
            + (bytes(self.mac) if self.mac is not None else b"")
            + self.remainder
        )

    @property
    def header_len(self) -> int:
        """The whole message, as ``bytes()`` writes it.

        A control message ends the datagram: NTPControl is terminal.
        """
        mac = len(bytes(self.mac)) if self.mac is not None else 0
        return (
            self._struct.size
            + len(self.data)
            + len(self.padding)
            + mac
            + len(self.remainder)
        )

    @property
    def mode(self) -> int:
        """The mode, always ``6``."""
        return _MODE_CONTROL

    @property
    def count(self) -> int:
        """The Count field: the data's length in bytes."""
        return len(self.data)

    @property
    def leap_name(self) -> str:
        """Describe the Leap Indicator, as :attr:`NTP.leap_name` does."""
        return _LEAP_NAMES[self.leap]

    @property
    def opcode_name(self) -> str:
        """Name the Operation Code, e.g. ``"read variables"``.

        ``"reserved (n)"`` for 0 and 13-30, which RFC 9327 reserves;
        every 5-bit opcode has a name, so this never raises.
        """
        name = _OPCODE_NAMES.get(self.opcode)
        return name if name is not None else f"reserved ({self.opcode})"

    @property
    def system_status(self) -> NTPSystemStatus | None:
        """Split the Status as a system status word, where it is one.

        A system status word is the Status of a response that is not an
        error response, to association 0, for opcode 1 (read status), 2
        (read variables), 3 (write variables) or 7 (trap response)
        (RFC 9327 §3.1 and §4); ``None`` for any other message, a runtime
        configuration response included.
        """
        if (
            not self.response
            or self.error
            or self.association_id != 0
            or self.opcode not in _SYSTEM_STATUS_OPCODES
        ):
            return None
        return NTPSystemStatus.from_word(self.status)

    @property
    def error_code(self) -> int | None:
        """Return the error code of an error response (RFC 9327 §3.4).

        The Status's first byte, when the R and E bits are both set;
        ``None`` otherwise.
        """
        if not (self.response and self.error):
            return None
        return self.status >> 8

    @property
    def error_name(self) -> str | None:
        """Name the error code, e.g. ``"unknown variable name"``.

        ``"reserved (n)"`` for 8-255; ``None`` unless this is an error
        response.
        """
        code = self.error_code
        if code is None:
            return None
        name = _ERROR_NAMES.get(code)
        return name if name is not None else f"reserved ({code})"

    @property
    def variables(self) -> tuple[tuple[str, str | None], ...]:
        """Split the data as ``name=value`` text (RFC 9327 §4).

        Items are separated by commas outside double quotes, and each is
        stripped of surrounding white space, the trailing CR LF
        included; empty items are skipped. An item splits at its first
        ``=`` into a name and a value, each stripped, the value's quotes
        kept, and an item without one is a name with the value ``None``,
        as in a command naming the variables it reads; an unclosed quote
        runs to the end of the data. Bytes that are
        not ASCII read as U+FFFD. Only this message's data is split: a
        fragment of a longer response can begin or end inside an item.
        Binary data, such as a read status response's association list,
        splits into whatever its bytes spell. Never raises.
        """
        text = self.data.decode("ascii", "replace")
        pieces: list[str] = []
        start, quoted = 0, False
        for index, char in enumerate(text):
            if char == '"':
                quoted = not quoted
            elif char == "," and not quoted:
                pieces.append(text[start:index])
                start = index + 1
        pieces.append(text[start:])
        items: list[tuple[str, str | None]] = []
        for piece in pieces:
            item = piece.strip()
            if item:
                name, equals, value = item.partition("=")
                items.append((name.strip(), value.strip() if equals else None))
        return tuple(items)


def _split_control_tail(
    data: bytes, end: int, error_response: bool
) -> tuple[bytes, NTPMAC | None, bytes]:
    """Split what follows a control message's data.

    Returns the padding, the MAC or ``None``, and the remainder (see
    "Control messages" in the module docstring).

    :param data: The whole message.
    :param end: Where the data ends: 12 plus the Count.
    :param error_response: Whether the R and E bits are both set.
    """
    aligned = (end + 3) & ~3
    start = aligned if error_response else (end + 7) & ~7
    if len(data) - start in _CONTROL_MAC_LENGTHS:
        key_id = int.from_bytes(data[start : start + 4], "big")
        return data[end:start], NTPMAC(key_id, data[start + 4 :]), b""
    return data[end:aligned], None, data[aligned:]


def _ascii_id(reference_id: int) -> str | None:
    """Return a Reference ID as ASCII, its NUL padding stripped.

    ``None`` when nothing is left or a byte is not printable ASCII.
    """
    text = reference_id.to_bytes(4, "big").rstrip(b"\x00")
    if not text or not all(0x20 <= byte < 0x7F for byte in text):
        return None
    return text.decode("ascii")
