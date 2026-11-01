"""TLS records (RFC 8446 §5.1, RFC 5246 §6.2), and the ClientHello's SNI.

TLS runs over TCP, HTTPS on port 443 among many others, and everything
it sends is a sequence of records. Each starts with a 5-byte header
(RFC 8446 §5.1, which keeps RFC 5246 §6.2.1's layout)::

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  ContentType  |     legacy_record_version     |    length     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |    length     |    fragment (length bytes) ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

followed by ``length`` bytes of fragment. The ContentType is one of
``change_cipher_spec`` (20), ``alert`` (21), ``handshake`` (22),
``application_data`` (23) and ``heartbeat`` (24, RFC 6520). The version
is SSL 3.0's ``0x0300`` through TLS 1.3's ``0x0304`` in form, though in
practice ``0x0301`` (a ClientHello's, for compatibility) or ``0x0303``:
RFC 8446 freezes it at TLS 1.2's value and negotiates the real version
in the ``supported_versions`` extension. One :class:`TLS` instance is
one record: the header decoded into :attr:`TLS.content_type`,
:attr:`TLS.legacy_version` and :attr:`TLS.length`, and the fragment
kept as raw ``bytes``, so ``bytes(TLS.decode(x)) == x[:header_len]``
holds by construction. Nothing is decrypted: under TLS 1.3 everything
after the ServerHello is ``application_data`` on the wire, and under
TLS 1.2 everything after ChangeCipherSpec is encrypted under its own
content type.

Validation
----------
TLS is reached through ``tcp.port``, which is a guess (see
:mod:`netprotocols.registry`), so :meth:`TLS.decode` rejects what no
record carries, each byte as soon as the buffer holds it and before the
length is held against the buffer, as :mod:`netprotocols.layer7.hsrp`
does: a ContentType outside 20-24 (``field`` ``"content_type"``,
``offset`` 0), a version whose first byte is not 3 (``"legacy_version"``,
1) or whose second is above 4 (``"legacy_version"``, 2), and a length
above 2**14 + 2048 (``"length"``, 3), RFC 5246 §6.2.3's bound on an
encrypted TLSCiphertext and the loosest any version sets (RFC 8446
§5.2 allows 2**14 + 256). Each raises
:class:`~netprotocols.InvalidFieldError`, so a payload that is not TLS
is reported as that however short it is; only then does a record the
buffer cuts short, or a buffer shorter than the 5-byte header whose
bytes all pass (an empty one among them), raise
:class:`~netprotocols.TruncatedHeaderError`.

Random bytes pass the first three checks 25 times in 2**24 (5 types, 1
major and 5 minor version bytes), about once in 671,000, and then the
length has to fit the buffer. Measured as ARCHITECTURE.md's *Port-based
dispatch is best-effort* describes (``random.Random`` seeds 0-2, each
10,000 random 300-byte TCP payloads to port 443 and 10,000 of uniformly
random length 0-600, the latter walked unpadded and padded: 90,000
walks), every walk ended with ``stopped_by`` set and none decoded a TLS
layer: about 0.13 of them are expected to pass the first three checks
(90,000 x 25 / 2**24) and about 0.0006 to hold a whole record as well.
With the first three bytes forced to a valid header (a ContentType of
20-24, ``0x03`` and 0-4), :meth:`TLS.decode` accepted 449 of 100,000
random 300-byte payloads (``random.Random(0)``), near the 452 expected:
a length of 0-295 is 296 of the 65,536 values. The fragment is not
judged: a zero-length Handshake record, which RFC 8446 §5.1 forbids,
decodes, and so does Heartbeat.

The guard is what turns away an SSL 2.0-compatible ClientHello, whose
first byte has its top bit set (RFC 5246 Appendix E.2), at
``content_type``: such hellos are not decoded.

Records and segments
--------------------
TCP delivers TLS as a byte stream, cut wherever it likes, and records
are its only framing, as BGP's messages are (see
:mod:`netprotocols.layer7.bgp`). Within one segment the decoder does
what it can without reassembly:

- A segment holding *N* complete records decodes as *N* :class:`TLS`
  layers. :meth:`TLS.decode` notes whether the bytes after its record
  begin like another record: whether as much of the next 3 bytes as the
  buffer holds passes the guard above, a ContentType of 20-24, then
  ``0x03``, then a byte of 0-4. :meth:`TLS.next_protocol` answers
  :class:`TLS` when they do and ``None`` otherwise; it is given no bytes,
  so the answer is recorded on the instance, outside the comparison and
  hash, and two equal records compare equal wherever they were found.
  A server's TLS 1.3 flight (ServerHello, ChangeCipherSpec and four
  encrypted records) is one segment of six records in the corpus.
- A segment whose last record is cut by the segment boundary decodes
  the complete ones and then raises
  :class:`~netprotocols.TruncatedHeaderError` at the cut one, since its
  first bytes passed the predicate. With ``lax=True`` the walk keeps the
  complete records and reports the error on ``packet.stopped_by``.
- A segment that begins inside a record, the rest of one an earlier
  segment cut, almost always fails the guard
  (:class:`~netprotocols.InvalidFieldError`), and in lax mode stops the
  walk after TCP.
- A segment with no payload at all (the handshake, a bare ACK, a FIN)
  raises :class:`~netprotocols.TruncatedHeaderError` at the empty
  buffer, as it does on BGP's port 179: dispatch happens before anyone
  looks at the payload.

A ClientHello larger than one segment is the case that matters most. A
post-quantum key share makes one: Chromium's X25519MLKEM768 share is
1,216 bytes, and its ClientHello in ``tests/fixtures/tls/tls_session.pcap``
is a 1,738-byte record that TCP carries in a 1,448-byte segment and a
290-byte one. A strict walk of the first raises
:class:`~netprotocols.TruncatedHeaderError` (the lax one keeps TCP and
stops), and of the second :class:`~netprotocols.InvalidFieldError`.
There is no lenient mode that reads a partial hello: to get the SNI of
such a client, reassemble the client's byte stream and call
:meth:`TLS.decode` on it, as ``tests/test_tls.py`` does with
``scripts/extract_http_streams.py``.

Each record being a layer, a segment of many is a deep chain: Ethernet,
IPv4 and TCP are three layers, and the walk's default ``max_depth`` of
:data:`~netprotocols.MAX_DEPTH` (32) leaves room for 29 records. A
record can be a bare 5-byte header (a zero-length application_data
fragment, which RFC 8446 §5.1 allows), so a 1,448-byte segment can hold
289 of them, and a capture taken with GRO or TSO on holds segments of
up to 64 KB. Past the limit a strict walk raises
:class:`~netprotocols.MaxDepthExceededError` on valid traffic and a lax
one stops with ``packet.stopped_by`` set; a larger ``max_depth``, or a
second walk ``decode_frame(frame[packet.consumed:], start=TLS)``, decodes
the rest, as for BGP. The corpus's busiest segment carries 6.

The handshake and the ClientHello
---------------------------------
Accessors parse the fragment on demand, never in :meth:`TLS.decode`,
and never re-encode it. A Handshake record's fragment begins with a
handshake message's header, a 1-byte HandshakeType and a 3-byte length
(RFC 8446 §4), so :attr:`TLS.handshake_type` is the fragment's first
byte, for any non-empty Handshake record, and ``None`` otherwise. That
byte is a HandshakeType only where the record is in the clear: under
TLS 1.2 the Finished after ChangeCipherSpec is encrypted, and its
record, still ``handshake`` on the wire, starts with ciphertext, which
the record layer gives no way to tell apart.

:attr:`TLS.client_hello` parses the first handshake message of a
Handshake record whose type is ``client_hello`` (1) into a
:class:`TLSClientHello`: ``legacy_version``, the 32-byte ``random``,
``legacy_session_id`` (at most 32 bytes), ``cipher_suites`` and
``legacy_compression_methods`` (both raw), and the extensions, each a
:class:`TLSExtension` with its data raw. A ClientHello may end after its
compression methods with no extensions block at all (RFC 5246 §7.4.1.2),
which :attr:`TLSClientHello.extensions` reports as ``None``, apart from
an empty block, ``()``. Errors follow one rule:
:class:`~netprotocols.TruncatedHeaderError` when the record holds less
than the handshake message's own length says, which is how a
ClientHello fragmented across records, or cut by a capture, looks;
:class:`~netprotocols.InvalidFieldError` when a length inside the
message runs past what contains it (the session ID, the cipher suites,
the compression methods, the extensions block or one extension), when
the session ID is longer than 32 bytes, or when bytes follow the
extensions block inside the message. Both name ``field`` ``"fragment"``
and give an ``offset`` relative to :attr:`TLS.fragment`, as every
accessor error on a raw attribute does (ARCHITECTURE.md's *The decode
contract*): where the length, extension header or name at fault starts
(for a message too short for its version and Random, where those
start; for bytes after the extensions block, where those start), inside
the server_name extension as anywhere else. Nothing else ever escapes.

:attr:`TLS.server_name` reads the ``server_name`` extension (0, RFC 6066
§3): a 2-byte ServerNameList length, then entries of a 1-byte NameType
and a 2-byte length-prefixed name. It returns the first ``host_name``
(NameType 0), the only type defined, decoded as ASCII, which RFC 6066
requires (an internationalized name travels as its A-labels); every
byte below 0x80 is accepted as it is, a trailing dot or an IP literal
(which RFC 6066 forbids) included. A byte of 0x80 or more, an empty
name, an empty list, or a length that runs past the list or the
extension raises :class:`~netprotocols.InvalidFieldError`, as above. An
entry of another NameType, which no RFC defines, is assumed to be
length-prefixed like ``host_name`` and is skipped. ``None`` when the
record is not a ClientHello, when the ClientHello carries no
``server_name`` extension, as ``openssl s_client -noservername`` sends,
or when its list holds no ``host_name``.
Under Encrypted Client Hello (RFC 9849's ``encrypted_client_hello``,
type 65037) the name read here is the outer ClientHello's, the
client-facing server's public name, not the one the inner, encrypted
ClientHello asks for.

Ports
-----
Only TCP port 443 is registered. TLS from its first byte also runs on
853 (DNS over TLS, RFC 7858), 465 (SMTP submission, RFC 8314), 993
(IMAP) and 995 (POP3), and HTTPS often on 8443; a walk names them with
``decode_as={"tcp.port": {853: TLS}}`` and the like. A protocol that
starts in the clear and upgrades (STARTTLS on 25, 587 or 143) is not
TLS on the port at all.

Out of scope
------------
No cryptography and no handshake beyond the ClientHello's fields:
nothing is decrypted, verified or derived. The ServerHello,
Certificate and key exchange messages, and every extension but
``server_name``, are kept raw. Only the first handshake message of a
record is looked at: a handshake message fragmented across records, or
several coalesced into one, is not reassembled or split. SSL 2.0-
compatible hellos are rejected by the guard. DTLS, which has its own
record header, and QUIC, which carries TLS's handshake in its own
frames on UDP port 443, are not decoded, and no ``udp.port`` 443 entry
exists.
"""

from __future__ import annotations

import builtins
from collections.abc import Iterator
from dataclasses import dataclass, field
from struct import Struct
from typing import ClassVar, NoReturn, Self

from netprotocols._base import Protocol
from netprotocols.registry import Registry
from netprotocols.utils.exceptions import (
    InvalidFieldError,
    TruncatedHeaderError,
)

__all__ = ["TLS", "TLSClientHello", "TLSExtension"]

#: The record header's length (RFC 8446 §5.1).
_HEADER_LEN = 5

#: The largest record length any version allows: RFC 5246 §6.2.3's
#: TLSCiphertext, 2**14 + 2048 (RFC 8446 §5.2 caps TLS 1.3's at
#: 2**14 + 256).
_MAX_LENGTH = 2**14 + 2048

#: ContentType values (RFC 8446 §5.1; heartbeat, RFC 6520), named as
#: IANA's "TLS ContentType" registry names them (fetched 2026-11-01).
#: Its 25-27 are DTLS's or connection-ID records, which the guard
#: rejects.
_CHANGE_CIPHER_SPEC, _ALERT, _HANDSHAKE = 20, 21, 22
_APPLICATION_DATA, _HEARTBEAT = 23, 24
_CONTENT_TYPE_NAMES: dict[int, str] = {
    _CHANGE_CIPHER_SPEC: "change_cipher_spec",
    _ALERT: "alert",
    _HANDSHAKE: "handshake",
    _APPLICATION_DATA: "application_data",
    _HEARTBEAT: "heartbeat",
}

#: The version names a record or ClientHello can carry: SSL 3.0 (RFC
#: 6101) and TLS 1.0-1.3 (RFCs 2246, 4346, 5246, 8446).
_VERSION_NAMES: dict[int, str] = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

#: HandshakeType values, named as IANA's "TLS HandshakeType" registry
#: names them (fetched 2026-11-01), except that the types it marks
#: ``_RESERVED`` because TLS 1.3 retired them keep their TLS 1.2 names,
#: since TLS 1.2 still sends them.
_CLIENT_HELLO = 1
_HANDSHAKE_TYPE_NAMES: dict[int, str] = {
    0: "hello_request",
    _CLIENT_HELLO: "client_hello",
    2: "server_hello",
    3: "hello_verify_request",
    4: "new_session_ticket",
    5: "end_of_early_data",
    6: "hello_retry_request",
    8: "encrypted_extensions",
    9: "request_connection_id",
    10: "new_connection_id",
    11: "certificate",
    12: "server_key_exchange",
    13: "certificate_request",
    14: "server_hello_done",
    15: "certificate_verify",
    16: "client_key_exchange",
    17: "client_certificate_request",
    20: "finished",
    21: "certificate_url",
    22: "certificate_status",
    23: "supplemental_data",
    24: "key_update",
    25: "compressed_certificate",
    26: "ekt_key",
    254: "message_hash",
}

#: ExtensionType values a ClientHello commonly carries, named as IANA's
#: "TLS ExtensionType Values" registry names them (fetched 2026-11-01).
#: The sixteen GREASE values of RFC 8701 are named by
#: :attr:`TLSExtension.type_name` without a table.
_SERVER_NAME = 0
_EXTENSION_NAMES: dict[int, str] = {
    _SERVER_NAME: "server_name",
    1: "max_fragment_length",
    5: "status_request",
    10: "supported_groups",
    11: "ec_point_formats",
    13: "signature_algorithms",
    14: "use_srtp",
    15: "heartbeat",
    16: "application_layer_protocol_negotiation",
    18: "signed_certificate_timestamp",
    19: "client_certificate_type",
    20: "server_certificate_type",
    21: "padding",
    22: "encrypt_then_mac",
    23: "extended_main_secret",
    27: "compress_certificate",
    28: "record_size_limit",
    34: "delegated_credential",
    35: "session_ticket",
    41: "pre_shared_key",
    42: "early_data",
    43: "supported_versions",
    44: "cookie",
    45: "psk_key_exchange_modes",
    47: "certificate_authorities",
    48: "oid_filters",
    49: "post_handshake_auth",
    50: "signature_algorithms_cert",
    51: "key_share",
    57: "quic_transport_parameters",
    64768: "ech_outer_extensions",
    65037: "encrypted_client_hello",
    65281: "renegotiation_info",
}

#: server_name's NameType for a DNS host name, the only one defined
#: (RFC 6066 §3).
_HOST_NAME = 0

#: The ClientHello's longest legacy_session_id (RFC 8446 §4.1.2).
_MAX_SESSION_ID = 32

_U16 = Struct("!H")


def _grease(value: int) -> bool:
    """Whether ``value`` is one of RFC 8701's GREASE values, 0x?A?A."""
    return value & 0x0F0F == 0x0A0A and value >> 8 == value & 0xFF


def _version_name(version: int) -> str:
    return _VERSION_NAMES.get(version, f"unknown ({version:#06x})")


@dataclass(frozen=True, slots=True)
class TLSExtension:
    """One extension of a ClientHello (RFC 8446 §4.2).

    :param type: ExtensionType, e.g. ``0`` server_name, ``43``
        supported_versions, ``51`` key_share (see :attr:`type_name`).
    :param data: extension_data, kept raw: only ``server_name``'s is
        read, by :attr:`TLS.server_name`.

    ``bytes(extension)`` is the on-wire form: the type, a 2-byte
    length and the data.
    """

    type: int
    data: bytes = b""

    def __post_init__(self) -> None:
        """Check the type fits 2 bytes and the data a 2-byte length.

        :raises InvalidFieldError: either does not.
        """
        if not 0 <= self.type <= 0xFFFF:
            raise InvalidFieldError(
                f"TLS extension type must be within 0-65535, got {self.type}",
                protocol=type(self),
                field="type",
                expected="0-65535",
                actual=self.type,
            )
        if len(self.data) > 0xFFFF:
            raise InvalidFieldError(
                f"TLS extension data of {len(self.data)} bytes exceeds "
                f"the 65535 its length can say",
                protocol=type(self),
                field="data",
                expected="<=65535 bytes",
                actual=len(self.data),
            )

    def __bytes__(self) -> bytes:
        """Serialize to the on-wire type, length and data."""
        return _U16.pack(self.type) + _U16.pack(len(self.data)) + self.data

    @property
    def type_name(self) -> str:
        """Display name of the type, e.g. ``"server_name"``.

        ``"GREASE"`` for one of RFC 8701's sixteen reserved values,
        which a client sends to keep servers tolerant of unknown ones,
        and ``"unknown (n)"`` for a type not named here.
        """
        if _grease(self.type):
            return "GREASE"
        return _EXTENSION_NAMES.get(self.type, f"unknown ({self.type})")


@dataclass(frozen=True, slots=True)
class TLSClientHello:
    """A ClientHello's fields (RFC 8446 §4.1.2, RFC 5246 §7.4.1.2).

    Built by :attr:`TLS.client_hello` from a record's fragment, never
    on decode; a value, not a layer.

    :param legacy_version: The version field, ``0x0303`` (TLS 1.2) in
        every TLS 1.3 ClientHello, which offers its versions in the
        ``supported_versions`` extension instead (see
        :attr:`legacy_version_name`).
    :param random: The 32-byte Random.
    :param legacy_session_id: The session ID, 0-32 bytes.
    :param cipher_suites: The cipher suite list, raw: two bytes a
        suite, in the client's order of preference.
    :param legacy_compression_methods: The compression method list,
        raw: one byte a method, ``b"\\x00"`` (null) in practice.
    :param extensions: The extensions in wire order; ``None`` when the
        ClientHello ends after its compression methods with no
        extensions block (RFC 5246 §7.4.1.2), ``()`` for an empty one.

    ``bytes(hello)`` is the ClientHello's body, the handshake message
    without its 4-byte header.
    """

    legacy_version: int
    random: bytes
    legacy_session_id: bytes = b""
    cipher_suites: bytes = b""
    legacy_compression_methods: bytes = b"\x00"
    extensions: tuple[TLSExtension, ...] | None = ()

    def __post_init__(self) -> None:
        """Check each field fits the length the wire gives it.

        :raises InvalidFieldError: one does not.
        """
        limits = (
            ("legacy_session_id", len(self.legacy_session_id), _MAX_SESSION_ID),
            ("cipher_suites", len(self.cipher_suites), 0xFFFF),
            (
                "legacy_compression_methods",
                len(self.legacy_compression_methods),
                0xFF,
            ),
        )
        if not 0 <= self.legacy_version <= 0xFFFF:
            raise InvalidFieldError(
                f"TLS ClientHello legacy_version must be within 0-65535, "
                f"got {self.legacy_version}",
                protocol=type(self),
                field="legacy_version",
                expected="0-65535",
                actual=self.legacy_version,
            )
        if len(self.random) != 32:
            raise InvalidFieldError(
                f"TLS ClientHello random must be 32 bytes, "
                f"got {len(self.random)}",
                protocol=type(self),
                field="random",
                expected=32,
                actual=len(self.random),
            )
        for name, size, limit in limits:
            if size > limit:
                raise InvalidFieldError(
                    f"TLS ClientHello {name} of {size} bytes exceeds {limit}",
                    protocol=type(self),
                    field=name,
                    expected=f"<={limit} bytes",
                    actual=size,
                )
        if (
            self.extensions is not None
            and sum(4 + len(ext.data) for ext in self.extensions) > 0xFFFF
        ):
            raise InvalidFieldError(
                "TLS ClientHello extensions exceed the 65535 bytes their "
                "length can say",
                protocol=type(self),
                field="extensions",
                expected="<=65535 bytes",
            )

    def __bytes__(self) -> bytes:
        """Serialize the ClientHello body, without the handshake header."""
        body = (
            _U16.pack(self.legacy_version)
            + self.random
            + bytes([len(self.legacy_session_id)])
            + self.legacy_session_id
            + _U16.pack(len(self.cipher_suites))
            + self.cipher_suites
            + bytes([len(self.legacy_compression_methods)])
            + self.legacy_compression_methods
        )
        if self.extensions is None:
            return body
        block = b"".join(bytes(ext) for ext in self.extensions)
        return body + _U16.pack(len(block)) + block

    @property
    def legacy_version_name(self) -> str:
        """Display name of :attr:`legacy_version`, e.g. ``"TLS 1.2"``.

        ``"unknown (0x....)"`` for a value no version used.
        """
        return _version_name(self.legacy_version)


def _malformed(message: str, offset: int) -> InvalidFieldError:
    """Build an error in a :class:`TLS` fragment, positioned within it."""
    return InvalidFieldError(
        message, protocol=TLS, field="fragment", offset=offset
    )


def _prefixed(
    data: bytes, at: int, width: int, end: int, what: str
) -> tuple[int, int]:
    """Locate a ``width``-byte length-prefixed element at ``at``.

    :returns: ``(start, stop)`` of its contents.
    :raises InvalidFieldError: its length, or its contents, runs past
        ``end`` (offsets as in ``data``).
    """
    if at + width > end:
        raise _malformed(f"TLS {what} length runs past its message", at)
    start = at + width
    stop = start + int.from_bytes(data[at:start], "big")
    if stop > end:
        raise _malformed(f"TLS {what} runs past its message", at)
    return start, stop


def _walk_extensions(
    data: bytes, at: int, end: int
) -> Iterator[tuple[int, TLSExtension]]:
    """Yield ``(offset, extension)`` for each extension in ``data[at:end]``.

    :raises InvalidFieldError: an extension's header or data runs past
        ``end``.
    """
    while at < end:
        if at + 4 > end:
            raise _malformed("TLS extension header runs past the block", at)
        start, stop = _prefixed(data, at + 2, 2, end, "extension")
        yield (
            at,
            TLSExtension(
                type=int.from_bytes(data[at : at + 2], "big"),
                data=data[start:stop],
            ),
        )
        at = stop


def _parse_client_hello(
    fragment: bytes,
) -> tuple[TLSClientHello, tuple[int, ...]]:
    """Parse the ClientHello at the start of a Handshake fragment.

    :returns: The ClientHello, and where in ``fragment`` each of its
        extensions starts.
    :raises TruncatedHeaderError: ``fragment`` holds less than the
        handshake message's length says.
    :raises InvalidFieldError: a length inside the message runs past
        what contains it, the session ID exceeds 32 bytes, or bytes
        follow the extensions block.
    """
    length = (
        int.from_bytes(fragment[1:4], "big") if len(fragment) >= 4 else None
    )
    if length is None or 4 + length > len(fragment):
        raise TruncatedHeaderError(
            "TLS ClientHello runs past its record"
            + ("" if length is None else f" ({length} bytes)"),
            protocol=TLS,
            field="fragment",
            offset=1,
            expected=None if length is None else 4 + length,
            actual=len(fragment),
        )
    end = 4 + length
    if end < 4 + 2 + 32:
        raise _malformed("TLS ClientHello ends inside its random", 4)
    at = 4 + 2 + 32
    sid_start, sid_stop = _prefixed(fragment, at, 1, end, "legacy_session_id")
    if sid_stop - sid_start > _MAX_SESSION_ID:
        raise _malformed(
            f"TLS legacy_session_id of {sid_stop - sid_start} bytes "
            f"exceeds {_MAX_SESSION_ID}",
            at,
        )
    cs_start, cs_stop = _prefixed(fragment, sid_stop, 2, end, "cipher_suites")
    cm_start, cm_stop = _prefixed(
        fragment, cs_stop, 1, end, "legacy_compression_methods"
    )
    extensions: tuple[TLSExtension, ...] | None = None
    offsets: tuple[int, ...] = ()
    if cm_stop < end:
        block_start, block_stop = _prefixed(
            fragment, cm_stop, 2, end, "extensions block"
        )
        if block_stop != end:
            raise _malformed(
                "TLS ClientHello holds bytes after its extensions", block_stop
            )
        walked = tuple(_walk_extensions(fragment, block_start, block_stop))
        offsets = tuple(offset for offset, _ in walked)
        extensions = tuple(extension for _, extension in walked)
    hello = TLSClientHello(
        legacy_version=int.from_bytes(fragment[4:6], "big"),
        random=fragment[6:38],
        legacy_session_id=fragment[sid_start:sid_stop],
        cipher_suites=fragment[cs_start:cs_stop],
        legacy_compression_methods=fragment[cm_start:cm_stop],
        extensions=extensions,
    )
    return hello, offsets


def _host_name(fragment: bytes, begin: int, end: int) -> str | None:
    """Read the first host_name of the server_name extension whose data
    is ``fragment[begin:end]``.

    Every position is the fragment's, so every offset raised is one in
    :attr:`TLS.fragment`, as the accessors promise.

    ``None`` when the list holds names of other types only.

    :raises InvalidFieldError: the list is empty or malformed, or the
        host_name is empty or not ASCII.
    """
    list_start, list_stop = _prefixed(
        fragment, begin, 2, end, "server_name list"
    )
    if list_stop != end or list_start == list_stop:
        raise _malformed(
            "TLS server_name list does not fill its extension, or is empty",
            begin,
        )
    at = list_start
    while at < list_stop:
        name_type = fragment[at]
        start, stop = _prefixed(fragment, at + 1, 2, list_stop, "server name")
        if name_type == _HOST_NAME:
            if start == stop:
                raise _malformed("TLS host_name is empty", at + 1)
            try:
                return fragment[start:stop].decode("ascii")
            except UnicodeDecodeError:
                raise _malformed(
                    "TLS host_name is not ASCII (RFC 6066 §3)", start
                ) from None
        at = stop
    return None


def _reject(
    owner: type,
    field: str,
    offset: int,
    expected: str,
    actual: int,
    message: str,
) -> NoReturn:
    """Raise the decode-time :class:`InvalidFieldError` for ``field``.

    ``expected`` is what ``offset`` may hold and ``actual`` what it
    does, in the terms ``message`` uses, as HSRP's and NTP's guard
    errors set them.
    """
    raise InvalidFieldError(
        message,
        protocol=owner,
        field=field,
        offset=offset,
        expected=expected,
        actual=actual,
    )


@dataclass(frozen=True, slots=True)
class TLS(Protocol):
    """One TLS record (RFC 9846 §5.1, RFC 5246 §6.2.1).

    Construction checks that each header field fits and that
    :attr:`length` agrees with :attr:`fragment`; it does not check the
    ContentType, the version or the length's bound, so a test of
    another stack can build a record :meth:`decode` would reject.

    :param content_type: ContentType: :attr:`CHANGE_CIPHER_SPEC` (20),
        :attr:`ALERT` (21), :attr:`HANDSHAKE` (22),
        :attr:`APPLICATION_DATA` (23) or :attr:`HEARTBEAT` (24) (see
        :attr:`content_type_name`).
    :param legacy_version: legacy_record_version, ``0x0301`` or
        ``0x0303`` in practice (see :attr:`legacy_version_name`).
    :param length: The fragment's length in bytes.
    :param fragment: The record's contents, kept raw and parsed on
        demand by :attr:`handshake_type`, :attr:`client_hello` and
        :attr:`server_name`; encrypted for most records.
    """

    content_type: int
    legacy_version: int
    length: int
    fragment: bytes = b""
    #: Whether the bytes after this record, in the buffer it was decoded
    #: from, begin like another record; decode context, not a wire
    #: field, so it is neither compared nor hashed (see the module
    #: docstring's *Records and segments*).
    _followed: bool = field(
        default=False, init=False, repr=False, compare=False
    )

    CHANGE_CIPHER_SPEC: ClassVar[int] = _CHANGE_CIPHER_SPEC
    ALERT: ClassVar[int] = _ALERT
    HANDSHAKE: ClassVar[int] = _HANDSHAKE
    APPLICATION_DATA: ClassVar[int] = _APPLICATION_DATA
    HEARTBEAT: ClassVar[int] = _HEARTBEAT
    MAX_LENGTH: ClassVar[int] = _MAX_LENGTH

    _struct: ClassVar[Struct] = Struct("!BHH")

    def __post_init__(self) -> None:
        """Check each header field fits and the length matches.

        :raises InvalidFieldError: a field does not.
        """
        if not 0 <= self.content_type <= 0xFF:
            raise InvalidFieldError(
                f"TLS content_type must be within 0-255, "
                f"got {self.content_type}",
                protocol=type(self),
                field="content_type",
                expected="0-255",
                actual=self.content_type,
            )
        if not 0 <= self.legacy_version <= 0xFFFF:
            raise InvalidFieldError(
                f"TLS legacy_version must be within 0-65535, "
                f"got {self.legacy_version}",
                protocol=type(self),
                field="legacy_version",
                expected="0-65535",
                actual=self.legacy_version,
            )
        if not 0 <= self.length <= 0xFFFF:
            raise InvalidFieldError(
                f"TLS length must be within 0-65535, got {self.length}",
                protocol=type(self),
                field="length",
                expected="0-65535",
                actual=self.length,
            )
        if self.length != len(self.fragment):
            raise InvalidFieldError(
                f"TLS length {self.length} disagrees with a "
                f"{len(self.fragment)}-byte fragment",
                protocol=type(self),
                field="length",
                expected=len(self.fragment),
                actual=self.length,
            )

    @classmethod
    def decode(cls, data: bytes | memoryview) -> Self:
        """Decode the record at the start of ``data``.

        The ContentType and the two version bytes are judged as soon as
        each is in the buffer, then the length's bound, and only then
        the length against the buffer (see the module docstring's
        *Validation*).

        :raises InvalidFieldError: the ContentType is not 20-24
            (``field`` ``"content_type"``, ``offset`` 0), else the
            version's first byte is not 3 (``"legacy_version"``, 1) or
            its second above 4 (``"legacy_version"``, 2), else the
            length exceeds 2**14 + 2048 (``"length"``, 3); the first
            three at any buffer length, the length once both its bytes
            are present. ``actual`` is the value judged: the byte, the
            version (``0x0305`` and up) or the length.
        :raises TruncatedHeaderError: ``data`` is shorter than the
            5-byte header and every byte of the first three it holds
            passes, or shorter than the record's length says (``field``
            ``"length"``).
        """
        size = len(data)
        if size > 0 and data[0] not in _CONTENT_TYPE_NAMES:
            _reject(
                cls,
                "content_type",
                0,
                "20-24",
                data[0],
                f"TLS content_type must be 20-24, got {data[0]}",
            )
        if size > 1 and data[1] != 3:
            _reject(
                cls,
                "legacy_version",
                1,
                "0x03",
                data[1],
                f"TLS legacy_version must start 0x03, got {data[1]:#04x}",
            )
        if size > 2 and data[2] > 4:
            _reject(
                cls,
                "legacy_version",
                2,
                "0x0300-0x0304",
                0x0300 | data[2],
                f"TLS legacy_version must be 0x0300-0x0304, "
                f"got 0x03{data[2]:02x}",
            )
        content_type, version, length = cls._unpack_fixed(data)
        if length > _MAX_LENGTH:
            _reject(
                cls,
                "length",
                3,
                f"<={_MAX_LENGTH}",
                length,
                f"TLS record length {length} exceeds {_MAX_LENGTH}",
            )
        end = _HEADER_LEN + length
        if end > size:
            raise TruncatedHeaderError(
                f"TLS record of {end} bytes, buffer holds {size}",
                protocol=cls,
                field="length",
                offset=3,
                expected=end,
                actual=size,
            )
        record = cls(
            content_type=content_type,
            legacy_version=version,
            length=length,
            fragment=bytes(data[_HEADER_LEN:end]),
        )
        if _begins_record(bytes(data[end : end + 3])):
            object.__setattr__(record, "_followed", True)
        return record

    def __bytes__(self) -> bytes:
        """Serialize the header and the raw fragment."""
        return (
            self._struct.pack(
                self.content_type, self.legacy_version, self.length
            )
            + self.fragment
        )

    @property
    def header_len(self) -> int:
        """The whole record: the 5-byte header and the fragment."""
        return _HEADER_LEN + len(self.fragment)

    def next_protocol(
        self, registry: Registry | None = None
    ) -> builtins.type[Protocol] | None:
        """Name the next record in the same buffer, if one begins there.

        :class:`TLS` when, at decode, the bytes after this record began
        like a record header, as much of its first 3 bytes as the
        buffer held passing :meth:`decode`'s checks; ``None``
        otherwise, and for a record built rather than decoded. The
        answer is always this class, so ``registry`` has nothing to
        select.
        """
        return TLS if self._followed else None

    @property
    def content_type_name(self) -> str:
        """Display name of the ContentType, e.g. ``"handshake"``.

        ``"unknown (n)"`` for a value only construction can give.
        """
        return _CONTENT_TYPE_NAMES.get(
            self.content_type, f"unknown ({self.content_type})"
        )

    @property
    def legacy_version_name(self) -> str:
        """Display name of the record's version, e.g. ``"TLS 1.0"``.

        The version a record says is not the one negotiated: TLS 1.3
        records say TLS 1.2, and a first ClientHello often TLS 1.0.
        ``"unknown (0x....)"`` for a value no version used.
        """
        return _version_name(self.legacy_version)

    @property
    def handshake_type(self) -> int | None:
        """The first byte of a Handshake record's fragment.

        That is its first handshake message's HandshakeType, e.g. ``1``
        for a ClientHello, where the record is in the clear; under TLS
        1.2 the Finished after ChangeCipherSpec is encrypted, and this
        is its first byte of ciphertext (see the module docstring).
        ``None`` for another content type or an empty fragment.
        """
        if self.content_type != _HANDSHAKE or not self.fragment:
            return None
        return self.fragment[0]

    @property
    def handshake_type_name(self) -> str | None:
        """Display name of :attr:`handshake_type`, e.g. ``"client_hello"``.

        ``"unknown (n)"`` for a value no registry assigns, an encrypted
        Finished's first byte among them; ``None`` when
        :attr:`handshake_type` is.
        """
        kind = self.handshake_type
        if kind is None:
            return None
        return _HANDSHAKE_TYPE_NAMES.get(kind, f"unknown ({kind})")

    @property
    def client_hello(self) -> TLSClientHello | None:
        """The ClientHello this record begins with, parsed on demand.

        ``None`` unless the record is Handshake and its first message a
        ClientHello (:attr:`handshake_type` 1).

        :raises TruncatedHeaderError: the record holds less than the
            ClientHello's length says (``field`` ``"fragment"``).
        :raises InvalidFieldError: a length inside it runs past what
            contains it, the session ID exceeds 32 bytes, or bytes
            follow its extensions (``field`` ``"fragment"``, ``offset``
            within :attr:`fragment`).
        """
        if self.handshake_type != _CLIENT_HELLO:
            return None
        return _parse_client_hello(self.fragment)[0]

    @property
    def server_name(self) -> str | None:
        """The ClientHello's SNI host name (RFC 6066 §3).

        For example ``"example.com"``.

        The first ``host_name`` of the ``server_name`` extension,
        decoded as ASCII. ``None`` when the record is not a ClientHello,
        the ClientHello has no ``server_name`` extension, or its list
        names no ``host_name``. Under
        Encrypted Client Hello this is the outer ClientHello's name,
        the client-facing server's (see the module docstring).

        :raises TruncatedHeaderError: as :attr:`client_hello`.
        :raises InvalidFieldError: as :attr:`client_hello`, or the
            extension is malformed, empty, or holds a non-ASCII byte
            (``field`` ``"fragment"``, ``offset`` within
            :attr:`fragment`).
        """
        if self.handshake_type != _CLIENT_HELLO:
            return None
        hello, offsets = _parse_client_hello(self.fragment)
        extensions = hello.extensions or ()
        for offset, extension in zip(offsets, extensions, strict=True):
            if extension.type == _SERVER_NAME:
                begin = offset + 4
                return _host_name(
                    self.fragment, begin, begin + len(extension.data)
                )
        return None


def _begins_record(rest: bytes) -> bool:
    """Whether ``rest``, up to 3 bytes, begins like a record header.

    Every byte present must pass :meth:`TLS.decode`'s checks: a
    ContentType of 20-24, then ``0x03``, then 0-4. Empty bytes do not.
    """
    if not rest or rest[0] not in _CONTENT_TYPE_NAMES:
        return False
    return (len(rest) < 2 or rest[1] == 3) and (len(rest) < 3 or rest[2] <= 4)
