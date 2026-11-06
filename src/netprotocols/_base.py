"""The Protocol base class and the decode contract shared by all headers.

Decode contract
---------------
``decode(data)`` receives the *entire remaining buffer* — everything from
the start of this protocol's header to the end of the captured frame,
or to the end the enclosing headers' declared lengths give, whichever
comes first — and must:

1. Parse the fixed portion with the class-level ``struct.Struct``,
   raising :class:`TruncatedHeaderError` if the buffer is too short.
   The enclosing lengths that shorten the buffer are an 802.3 Length
   after an Ethernet or VLAN header, an IPv4 Total Length, an IPv6
   Payload Length and a UDP Length: the chain walk ends every later
   layer's buffer where the tightest of them puts the end of the
   payload, never past the end of the frame (see "Payload extent"
   below).
2. For variable-length headers (IPv4, TCP), validate the declared
   length, raising
   :class:`~netprotocols.utils.exceptions.InvalidFieldError` for
   nonsense values and
   :class:`~netprotocols.utils.exceptions.TruncatedHeaderError` when
   the declared length exceeds the buffer, and materialize the options
   as ``bytes``.
3. Tolerate trailing bytes: whatever follows the header is the next
   layer's problem, reachable via ``instance.header_len``. In a chain
   walk, the bytes past the tightest declared end reach no decoder and
   are the packet's :attr:`~netprotocols.Packet.trailer`.

``memoryview`` input is accepted and used as a decode-time transient
only; no view is ever stored on an instance.

Decode-path construction
------------------------
Constructing a header from field values validates them: an address that
is not a valid MAC or IPv4 string raises, and that strictness is part
of the public contract. ``decode()`` generates those strings itself,
from raw bytes, via ``bytes_to_mac()`` / ``bytes_to_ipv4()``, so they
are valid by construction.

The three headers that carry addresses (``Ethernet``, ``ARP``,
``IPv4``) build their decoded instance directly, with
``object.__new__`` plus ``object.__setattr__`` per field, skipping
``__init__`` and ``__post_init__``. Every public constructor still
validates, and every ``__post_init__`` check skipped this way holds for
what ``decode()`` produces (documented at each site).

``HTTP`` takes the same path: its ``__post_init__`` re-parses
``head + raw_body`` to check that the two are one complete, exactly
framed message, which ``decode()`` has established by parsing the
buffer they were cut from.

Text-framed protocols
---------------------
``HTTP`` has no fixed portion: ``decode()`` scans for the empty line
ending the head and for the end the head's framing gives the body, and
``header_len`` covers the whole message rather than a ``_struct``
size, so it must be overridden (step 1 above is a scan, not an
unpack).

Protocols without a length field
--------------------------------
``ICMPv4``, ``ICMPv6``, ``IGMP`` and ``SCTP`` carry no length of their
own: each is the whole IP payload, and in a chain walk the IP header's
declared length ends their buffer, so Ethernet's padding and a captured
FCS are the packet's trailer. Decoded on their own, or under an IP
length of zero, which bounds nothing, the first three keep the whole
buffer, so trailing bytes land in their ``body``. ``SCTP``'s CRC32c
changes with appended bytes, so its ``decode()`` walks the chunk
headers to find where the packet ends and leaves a run of zero bytes
where the next chunk would start undecoded: step 3 holds for those
zeros, while any other trailing bytes become part of the packet. Like
the other three, it never raises past its fixed portion: a remainder
the walk cannot parse (a cut chunk, a nonzero trailer) stays in
``chunks`` verbatim, for the ``parsed_chunks`` accessor to report. See
:mod:`netprotocols.layer4.sctp`.

``PIM`` has no length either, and bounds a message by its own
structure: its counts and encoded addresses, or, for a Hello, a walk of
its options that leaves a zero tail where the next option would start.
Past its 4-byte header it never raises: a body its parser cannot read
is kept whole. See :mod:`netprotocols.layer3.pim`.

``RIP`` is the port-dispatched case: its entries fill the UDP datagram,
whose length ends its buffer in a walk. It keeps the whole buffer after
its 4-byte header, like ICMPv4 and IGMP, and its accessors report a
remainder shorter than an entry (a cut entry, or trailing bytes when it
is decoded on its own) instead of raising. See
:mod:`netprotocols.layer7.rip`. ``NTP`` is the same case after its
48-byte header: its extension fields and MAC run to the end of the
datagram, so it keeps the rest of the buffer, and its accessors report
what is neither as a remainder. See :mod:`netprotocols.layer7.ntp`.

``TFTP`` is port-dispatched too, but bounds most of its messages by
their structure: an ACK's 4 bytes, an ERROR's terminated message, a
request's or an OACK's last whole option pair; step 3 holds after them.
Its strings are zero-terminated, so a missing terminator is its
truncation case, as a lying length is in step 2. A DATA message's data
has no terminator and runs to the end of the buffer. See
:mod:`netprotocols.layer7.tftp`.

``VRRP`` has no length field either, but its version and address count
give its exact length, so step 3 holds as for a header with one: the
padding is left undecoded. See :mod:`netprotocols.layer3.vrrp`.
``STP`` is the same case at layer 2: its BPDU Type gives its exact
length, so the octets after the BPDU are left undecoded. See
:mod:`netprotocols.layer2.stp`.

``LLDP`` has no length for the whole LLDPDU, but each TLV has one and
the End of LLDPDU TLV ends the walk, so step 3 holds after it; a TLV
running past the buffer raises :class:`TruncatedHeaderError`, as in
step 2. An LLDPDU without an End TLV (optional since 802.1AB-2016, as
Wireshark's dissector notes) runs to the end of the buffer. See
:mod:`netprotocols.layer2.lldp`.

``MPLS`` has none either, but its label stack ends at the entry with the
Bottom of Stack bit set, so step 3 holds as for a header with one: the
labelled packet, and any padding after it, is the next layer's. See
:mod:`netprotocols.layer2.mpls`.

``CDP`` has no length either; in a walk the 802.3 Length before it
ends its buffer (see "Payload extent"). Its ``decode()`` walks TLVs to
the end of that buffer and leaves only a run of zero bytes where the
next TLV would start undecoded, so step 3 holds for those zeros alone:
unlike SCTP's, it raises for any other bytes no TLV fits. See
:mod:`netprotocols.layer2.cdp`.

Payload extent
--------------
A header whose class sets ``_BOUNDS_PAYLOAD`` answers
``_payload_extent()`` with how many bytes after it belong to its
payload, or ``None`` for no bound, and
:func:`~netprotocols.decode_frame` ends the buffers it hands every later
layer there, so zero padding and an FCS after a short payload reach no
decoder and are the packet's :attr:`~netprotocols.Packet.trailer`. The
classes and their extents:

- ``Ethernet`` and ``VLAN``: an 802.3 Length; ``None`` for an EtherType.
- ``IPv4``: ``total_length - ihl * 4``; ``None`` for a Total Length of
  0.
- ``IPv6``: ``payload_length``, extension headers included; ``None``
  for 0.
- ``UDP``: ``length - 8``; ``None`` for 0.

A bound past the end of the frame bounds nothing, so a frame cut by a
snap length decodes as it would unbounded, and the tightest bound wins,
so a looser one, such as a first fragment's UDP Length, never widens
it. A length shorter than its own header cannot bound anything:
``_payload_extent()`` raises
:class:`~netprotocols.utils.exceptions.InvalidFieldError` for an IPv4
Total Length below ``ihl * 4`` and a UDP Length of 1 to 7, and the walk
sets its ``frame_offset`` to the start of that header. A positive length too
short for what follows is the next decoder's
:class:`TruncatedHeaderError`. ``decode()`` reads none of these
extents, so a header decoded on its own is never judged by them. Both
names are private.

Decode context in ``next_protocol``
-----------------------------------
Six headers answer ``next_protocol()`` from what ``decode()`` saw
rather than from a wire field alone, because no field says what follows
them. ``BGP`` names the next message beside it rather than a class for
its payload: whether the bytes after the message begin another one in
the same TCP segment. ``STUN`` does the same over TCP, where its
messages follow one another with no framing but their own length, and
``TLS`` does for its records.
``MPLS`` names its payload by convention: by its
bottom label where RFC 3032 reserves that label for one, and otherwise
by the first nibble after the stack, read as an IP version. ``LLC``
gates DSAP 0x42 on the payload's first two octets: a Protocol
Identifier other than STP's 0x0000, such as GARP's, ends the walk.
``UDP`` keeps the first byte of its payload and hands it to the class
its port names, through that class's ``_for_payload()``, which may
answer another class: ``NTP`` answers ``NTPControl`` for a mode 6
first byte, so UDP port 123 reads the mode before choosing a header.
Each ``decode()`` records what only the bytes could tell it on the
instance, in a ``compare=False`` field outside its comparison and
hash, so two equal headers compare equal wherever they were found,
and can still chain differently. Steps 1-3 above hold for all six
unchanged. See :mod:`netprotocols.layer7.bgp`,
:mod:`netprotocols.layer7.stun`, :mod:`netprotocols.layer7.tls`,
:mod:`netprotocols.layer2.mpls`, :mod:`netprotocols.layer2.llc` and
:mod:`netprotocols.layer7.ntp`.
"""

from __future__ import annotations

import socket
from abc import ABC, abstractmethod
from ipaddress import AddressValueError, IPv6Address
from struct import Struct
from struct import error as StructError
from typing import TYPE_CHECKING, Any, ClassVar, Self

from netprotocols.utils.exceptions import TruncatedHeaderError

if TYPE_CHECKING:
    from netprotocols.registry import Registry

__all__ = [
    "Protocol",
    "bytes_to_ipv4",
    "bytes_to_ipv6",
    "bytes_to_mac",
    "hex_str",
    "ipv4_to_bytes",
    "ipv6_to_bytes",
    "mac_to_bytes",
]


def mac_to_bytes(mac: str) -> bytes:
    """Pack ``"00:c0:ca:a8:19:74"`` (``:`` or ``-`` separated) into 6 bytes."""
    return bytes.fromhex(mac.replace(":", "").replace("-", ""))


def bytes_to_mac(data: bytes) -> str:
    """Render 6 raw bytes as a colon-separated lowercase MAC address."""
    # bytes.hex(sep) formats the address in one C call. memoryview.hex
    # takes a separator too, so this also accepts a decode-time view.
    return data.hex(":")


def ipv4_to_bytes(addr: str) -> bytes:
    """Pack a dotted-decimal IPv4 address string into 4 bytes."""
    return socket.inet_pton(socket.AF_INET, addr)


def bytes_to_ipv4(data: bytes) -> str:
    """Render 4 raw bytes as a dotted-decimal IPv4 address string."""
    return socket.inet_ntop(socket.AF_INET, data)


def ipv6_to_bytes(addr: str) -> bytes:
    """Pack an IPv6 address string into 16 bytes.

    Uses :mod:`ipaddress`, which is pure Python, and not
    ``socket.inet_pton``, which needs a C library with ``AF_INET6``
    support. Pyodide's WebAssembly build of CPython has none
    (``OSError: can't use AF_INET6, IPv6 is disabled``; see
    ``docs/CLAIMS.md`` 3.1), and this function works there.

    :param addr: The address, in any form :mod:`ipaddress` accepts.
    :raises OSError: if ``addr`` is not a valid IPv6 address, with the
        message ``inet_pton`` gives.
    """
    try:
        return IPv6Address(addr).packed
    except AddressValueError as e:
        raise OSError("illegal IP address string passed to inet_pton") from e


_IPV6_WORDS = Struct("!8H")


def bytes_to_ipv6(data: bytes) -> str:
    """Render 16 raw bytes as an RFC 5952 IPv6 address string.

    The output matches glibc's ``inet_ntop`` byte for byte, including
    its two dotted-quad forms, ``::a.b.c.d`` and ``::ffff:a.b.c.d``. It
    is the same on every supported Python version: it depends neither
    on ``socket`` (see :func:`ipv6_to_bytes`) nor on :class:`str` of an
    :class:`ipaddress.IPv6Address`, whose rendering of
    ``::ffff:a.b.c.d`` addresses differs between CPython versions.

    The eight words are formatted by one ``%``-format call, a single C
    call; the compressed forms slice its result.
    """
    words = _IPV6_WORDS.unpack(data)

    # Longest run of consecutive zero words, leftmost on a tie (RFC
    # 5952 §4.2.3); a single zero word is not compressed (§4.2.2).
    best_start = best_len = -1
    run_start = None
    for i, word in enumerate((*words, 1)):  # sentinel closes a trailing run
        if i < 8 and word == 0:
            run_start = i if run_start is None else run_start
            continue
        if run_start is not None:
            run_len = i - run_start
            if run_len > best_len:
                best_start, best_len = run_start, run_len
            run_start = None
    if best_len < 2:
        best_start = -1

    # The two legacy dotted-quad forms BSD/glibc's inet_ntop still
    # special-cases, both requiring the compressed run to start at
    # word 0: the deprecated "IPv4-compatible" address (a bare 6-word
    # run, ``::a.b.c.d``) and the still-current "IPv4-mapped" address
    # (a 5-word run whose next word is ``0xffff``, ``::ffff:a.b.c.d``).
    if best_start == 0 and (
        best_len == 6 or (best_len == 5 and words[5] == 0xFFFF)
    ):
        prefix = "::ffff:" if best_len == 5 else "::"
        octets = (
            words[6] >> 8,
            words[6] & 0xFF,
            words[7] >> 8,
            words[7] & 0xFF,
        )
        return prefix + ".".join(str(octet) for octet in octets)

    # One %-format call formats the whole tuple in a single C call.
    hexed = "%x:%x:%x:%x:%x:%x:%x:%x" % words  # noqa: UP031
    if best_start == -1:
        return hexed

    parts = hexed.split(":")
    head = ":".join(parts[:best_start])
    tail = ":".join(parts[best_start + best_len :])
    return f"{head}::{tail}"


def hex_str(value: int, width: int) -> str:
    """Render ``value`` as a hexadecimal string zero-padded to ``width``.

    ``width`` counts every character, the ``0x`` prefix included:
    ``hex_str(0x1c2a, 6) == "0x1c2a"``.
    """
    return f"{value:#0{width}x}"


class Protocol(ABC):
    """Abstract base for all protocol headers.

    Concrete protocols are frozen, slotted dataclasses whose fields
    mirror the on-wire header. Each class declares the layout of its
    fixed portion as a ``struct.Struct`` (compiled once, at class
    definition time) and implements the decode contract described in
    this module's docstring.
    """

    __slots__ = ()

    #: Layout of the fixed portion of the header, network byte order.
    _struct: ClassVar[Struct]

    #: Whether :meth:`_payload_extent` can bound this header's payload.
    #: A class attribute, so the chain walk tests it per layer without a
    #: call (see "Payload extent" in this module's docstring).
    _BOUNDS_PAYLOAD: ClassVar[bool] = False

    @classmethod
    def _unpack_fixed(cls, data: bytes | memoryview) -> tuple[Any, ...]:
        """Unpack the fixed portion of the header from ``data``.

        :param data: The buffer, starting at this header.
        :raises TruncatedHeaderError: if ``data`` is shorter than the
            fixed portion.
        """
        try:
            return cls._struct.unpack_from(data)
        except StructError as e:
            raise TruncatedHeaderError(
                f"{cls.__name__} header needs {cls._struct.size} bytes, "
                f"buffer holds {len(data)}",
                protocol=cls,
                offset=0,
                expected=cls._struct.size,
                actual=len(data),
            ) from e

    @classmethod
    @abstractmethod
    def decode(cls, data: bytes | memoryview) -> Self:
        """Decode the header at the start of ``data`` (see decode contract)."""

    @abstractmethod
    def __bytes__(self) -> bytes:
        """Serialize this header back to its exact on-wire form."""

    @property
    def header_len(self) -> int:
        """The header's length in bytes: the fixed struct's size.

        Fixed-size protocols inherit this default; variable-length
        headers (IPv4, TCP) override it to account for options.
        """
        return self._struct.size

    def _payload_extent(self) -> int | None:
        """Return how many bytes after this header its payload occupies.

        The count comes from a length field the header carries; ``None``
        if it carries none, or one whose value bounds nothing. Read by
        the chain walk only for a class that sets ``_BOUNDS_PAYLOAD``
        (see "Payload extent" in this module's docstring).
        """
        return None

    def next_protocol(
        self, registry: Registry | None = None
    ) -> type[Protocol] | None:
        """Return the class for this header's payload, if known.

        ``None`` means the chain ends here: the protocol never
        encapsulates another (ARP, UDP), the encapsulated protocol is
        not implemented by this library, or nothing in the clear names
        it (ESP, whose payload's protocol is in its protected trailer).

        ``registry`` selects the dispatch tables to resolve against.
        Omitting it reads the process-wide default directly, in a single
        dict lookup. :func:`~netprotocols.decode_frame` passes an
        explicit registry when a caller asked for one, so a per-call
        decoder override leaves global state untouched.
        """
        return None

    @classmethod
    def _for_payload(cls, lead: int) -> type[Protocol]:
        """Return the class that decodes a payload opening with ``lead``.

        A port table names one class for a port, and
        :meth:`~netprotocols.UDP.next_protocol` hands that class the
        first byte of the datagram's payload, so that a port carrying
        two message formats can pick between them before either is
        decoded (see "Decode context in next_protocol" above). This
        answers ``cls`` itself; :class:`~netprotocols.NTP` overrides
        it.

        :param lead: The first byte of the payload.
        """
        return cls
