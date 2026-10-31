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
without telling the server its clock (the corpus holds such requests).

After the header
----------------

NTP has no length field: what follows the 48 bytes runs to the end of
the UDP datagram, and the chain walk does not trim a frame to UDP's
length (#235). So, like RIP, an NTP message keeps the whole buffer after
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
  authenticator (RFC 1305 Appendix C) is read as a MAC too. No digest
  is verified: that needs the key.
- :attr:`NTP.remainder`: anything else, which neither walks as
  extension fields nor has a MAC's length.

The rule has the blind spot RIP's has. A capture that keeps a 4-byte
Ethernet FCS after a plain 48-byte message gives a body of 4 bytes,
which reads as a crypto-NAK whose Key Identifier is the FCS; only the
UDP length could tell them apart. Ethernet's zero padding never
reaches NTP: the 48-byte header, behind IPv4's 20 and UDP's 8, already
fills Ethernet's 46-byte minimum payload.

Decoding a guess
----------------

NTP is reached through ``udp.port``, which is best-effort (see
:mod:`netprotocols.registry`), and any 48 bytes would make a header.
:meth:`NTP.decode` therefore rejects the first-byte values that are not
an NTP time message: a version outside 1-4 (the versions RFC 5905 and
its predecessors, RFC 1059, RFC 1119 and RFC 1305, define), and modes 6
and 7. Mode 0, reserved, decodes. Of the 256 first bytes 96 pass (4
Leap Indicators, 4 versions, 6 modes), so a random datagram on port
123 is rejected 62.5% of the time, and more often when it is shorter
than 48 bytes. The first byte is checked before the length, so a
rejected version or mode is reported as such (``InvalidFieldError``,
``offset`` 0) however short the message, and ``TruncatedHeaderError``
is left for an empty buffer and for a short one whose first byte
passes. Nothing else is checked: a stratum RFC 5905 reserves (17-255) and a
Kiss-o'-Death (stratum 0, :attr:`NTP.kiss_code`) decode.

NTPv1 (RFC 1059) shares the header only by position: it has no Mode
field, so those three bits are zero and every NTPv1 message decodes
with mode 0, ``"reserved"``, and its second and third words are a
Synchronizing Distance and an Estimated Drift Rate, which
:attr:`NTP.root_delay` and :attr:`NTP.root_dispersion` hold, raw,
under NTPv2-4's names.

Control messages are not decoded
--------------------------------

Modes 6 and 7 carry control messages: RFC 9327's mode 6, which
``ntpq`` speaks, and ntpd's private mode 7, which ``ntpdc`` speaks.
Their headers are not this one (a mode 6 header is 12 bytes, and a
read-variables request may be nothing more), and reading one as a time
message would give fields that mean nothing, so :meth:`NTP.decode`
raises ``InvalidFieldError`` with ``field`` ``"mode"`` for every one,
whatever its length. A strict ``decode_frame`` therefore raises on
``ntpq`` and ``ntpdc`` traffic to or from port 123. Walk it with
``decode_frame(frame, lax=True)``, which keeps Ethernet, IP and UDP and
reports the rejection as ``stopped_by``, the UDP payload left
undecoded. A typed way to take port 123 out of dispatch for one walk,
and decoding mode 6, are planned follow-ups.

Construction checks only that each field fits its width, so a header
with a version or mode decode rejects builds, and
``NTP.decode(bytes(message))`` raises for it, which ARCHITECTURE.md's
round-trip guarantee allows: it covers canonical headers, which that
one is not.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from struct import Struct
from typing import ClassVar, Self

from netprotocols._base import Protocol, bytes_to_ipv4, hex_str
from netprotocols.utils.exceptions import InvalidFieldError

__all__ = [
    "NTP",
    "NTPMAC",
    "NTPExtensionField",
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

#: NTPv1-3 add RFC 1305 Appendix C's 12-byte DES authenticator.
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

#: The control-message modes :meth:`NTP.decode` rejects (RFC 9327 for
#: mode 6; mode 7 is ntpd's private format).
_CONTROL_MODES = frozenset({6, 7})

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


def _check_first_byte(owner: type, flags: int) -> None:
    """Raise :class:`InvalidFieldError` unless ``flags`` opens a time message.

    The version must be 1-4, then the mode must not be 6 or 7. Checked
    at decode and not in ``__post_init__``, as RIP's version is: a
    message that fails either is most likely not NTP, or not a time
    message.
    """
    version, mode = (flags >> 3) & 0x07, flags & 0x07
    if not 1 <= version <= 4:
        raise InvalidFieldError(
            f"NTP version must be 1-4, got {version}",
            protocol=owner,
            field="version",
            offset=0,
            expected="1-4",
            actual=version,
        )
    if mode in _CONTROL_MODES:
        raise InvalidFieldError(
            f"NTP mode {mode} is a control message, not decoded",
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
    :raises InvalidFieldError: ``type`` does not fit 16 bits, or the
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
        registry writes types.
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
    :raises InvalidFieldError: ``key_id`` does not fit 32 bits.
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

        The first byte is judged before the length (see "Control
        messages are not decoded" in the module docstring).

        :raises InvalidFieldError: the version is outside 1-4 (``field``
            ``"version"``), or else the mode is 6 or 7, a control
            message (``field`` ``"mode"``), at any length; ``offset``
            ``0`` for both.
        :raises TruncatedHeaderError: ``data`` is empty, or its first
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
        """Return the header's 48 bytes plus the whole body.

        The body is the rest of the datagram: NTP is terminal.
        """
        return self._struct.size + len(self.body)

    @property
    def leap_name(self) -> str:
        """Describe the Leap Indicator, e.g. ``"no warning"``."""
        return _LEAP_NAMES[self.leap]

    @property
    def mode_name(self) -> str:
        """Name the mode, e.g. ``"client"``."""
        return _MODE_NAMES[self.mode]

    @property
    def stratum_name(self) -> str:
        """Describe the stratum (RFC 5905 §7.3, Figure 11).

        ``"unspecified or invalid"`` (0), ``"primary server"`` (1),
        ``"secondary server"`` (2-15), ``"unsynchronized"`` (16) or
        ``"reserved"`` (17-255).
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


def _ascii_id(reference_id: int) -> str | None:
    """Return a Reference ID as ASCII, its NUL padding stripped.

    ``None`` when nothing is left or a byte is not printable ASCII.
    """
    text = reference_id.to_bytes(4, "big").rstrip(b"\x00")
    if not text or not all(0x20 <= byte < 0x7F for byte in text):
        return None
    return text.decode("ascii")
