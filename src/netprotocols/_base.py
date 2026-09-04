"""The Protocol base class and the decode contract shared by all headers.

Decode contract
---------------
``decode(data)`` receives the *entire remaining buffer* — everything from
the start of this protocol's header to the end of the captured frame —
and must:

1. Parse the fixed portion with the class-level ``struct.Struct``,
   raising :class:`TruncatedHeaderError` if the buffer is too short.
2. For variable-length headers (IPv4, TCP), validate the declared
   length (raising :class:`InvalidFieldError` for nonsense values and
   :class:`TruncatedHeaderError` when the declared length exceeds the
   buffer) and materialize the options as ``bytes``.
3. Tolerate trailing bytes: whatever follows the header is the next
   layer's problem, reachable via ``instance.header_len``.

``memoryview`` input is accepted and used as a decode-time transient
only; no view is ever stored on an instance.

Decode-path construction
------------------------
Constructing a header from field values validates them: an address that
is not a valid MAC or IPv4 string raises, and that strictness is part
of the public contract. It is pure overhead on the decode path, though,
because ``decode()`` *generates* those strings itself, from raw bytes,
via ``bytes_to_mac()`` / ``bytes_to_ipv4()`` — a regex can only confirm
what the conversion already guarantees.

The three headers that carry addresses (``Ethernet``, ``ARP``,
``IPv4``) therefore build their decoded instance directly, with
``object.__new__`` plus ``object.__setattr__`` per field, skipping
``__init__`` and ``__post_init__``. This is an internal shortcut on a
path whose inputs are known-good, not a relaxation of the contract:
every public constructor still validates, and any ``__post_init__``
check bypassed this way is one ``decode()`` has already established
itself (documented at each site).
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
    "ipv4_to_bytes",
    "ipv6_to_bytes",
    "mac_to_bytes",
]


def mac_to_bytes(mac: str) -> bytes:
    """Pack ``"00:c0:ca:a8:19:74"`` (``:`` or ``-`` separated) into 6 bytes."""
    return bytes.fromhex(mac.replace(":", "").replace("-", ""))


def bytes_to_mac(data: bytes) -> str:
    """Render 6 raw bytes as a colon-separated lowercase MAC address."""
    # bytes.hex(sep) does this in one C call; the generator-plus-format
    # equivalent it replaces ran seven generator steps and six format()
    # calls per address, twice per Ethernet frame. memoryview.hex takes
    # a separator too, so this still accepts a decode-time view.
    return data.hex(":")


def ipv4_to_bytes(addr: str) -> bytes:
    """Pack a dotted-decimal IPv4 address string into 4 bytes."""
    return socket.inet_pton(socket.AF_INET, addr)


def bytes_to_ipv4(data: bytes) -> str:
    """Render 4 raw bytes as a dotted-decimal IPv4 address string."""
    return socket.inet_ntop(socket.AF_INET, data)


def ipv6_to_bytes(addr: str) -> bytes:
    """Pack an IPv6 address string into 16 bytes.

    Deliberately :mod:`ipaddress`, not ``socket.inet_pton`` — the
    latter needs the platform's C library to support ``AF_INET6``
    sockets, which Pyodide's WebAssembly build of CPython does not
    (``OSError: can't use AF_INET6, IPv6 is disabled``; see
    ``docs/CLAIMS.md`` 3.1). :mod:`ipaddress` is pure Python and has
    no such dependency, so this keeps IPv6 decoding working under
    Pyodide, not just the modules that never happened to be built on
    ``AF_INET6``. The exception is translated to match what
    ``inet_pton`` used to raise, so this stays a pure implementation
    swap and not a public contract change.
    """
    try:
        return IPv6Address(addr).packed
    except AddressValueError as e:
        raise OSError("illegal IP address string passed to inet_pton") from e


_IPV6_WORDS = Struct("!8H")


def bytes_to_ipv6(data: bytes) -> str:
    """Render 16 raw bytes as an RFC 5952 IPv6 address string, matching
    glibc's ``inet_ntop`` byte-for-byte (verified by differential
    testing against it across 500,000+ random addresses plus an
    exhaustive sweep of both dotted-quad special cases below — see
    the PR that introduced this function for the harness).

    Not :func:`str` on an :class:`ipaddress.IPv6Address`: that class's
    formatting is not the fixed point it looks like — CPython 3.12
    changed it to stop rendering ``::ffff:a.b.c.d``-form addresses in
    dotted-quad, while 3.11 (and glibc, and this project's own
    supported 3.12/3.13/3.14 matrix's *history* of output) all agree
    it should. Reimplementing the compression here, once, keeps the
    string form stable across Python versions instead of inheriting
    whatever :mod:`ipaddress` decides this release. See
    :func:`ipv6_to_bytes` for why sidestepping ``socket`` entirely
    also matters — Pyodide's CPython build has ``AF_INET6`` disabled.

    The eight words are rendered with one ``%``-format call rather
    than a per-word f-string through a generator: profiling the
    decode corpus (see the PR that made this change) showed the
    generator/join form costing ~18% of total decode time, almost
    entirely interpreter overhead of formatting one word at a time
    rather than the algorithm itself. ``%`` formats all eight in a
    single C call; the compressed forms then slice the pre-split
    result instead of re-formatting a subset of the words.
    """
    words = _IPV6_WORDS.unpack(data)

    # Longest run of consecutive zero words, leftmost on a tie (RFC
    # 5952 4.2.3); single zero words are not worth compressing (4.2.2).
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

    # %-formatting the whole tuple in one call, not f-string
    # specifiers: measured faster here specifically (a single
    # all-in-one f-string interpolating all eight words ran ~2.6x
    # slower, str.format() ~1.7x slower — both still pay per-value
    # interpreter overhead that % 's one-shot tuple formatting does
    # not), so this one line keeps %, everywhere else in the codebase
    # still prefers f-strings.
    hexed = "%x:%x:%x:%x:%x:%x:%x:%x" % words  # noqa: UP031
    if best_start == -1:
        return hexed

    parts = hexed.split(":")
    head = ":".join(parts[:best_start])
    tail = ":".join(parts[best_start + best_len :])
    return f"{head}::{tail}"


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

    @classmethod
    def _unpack_fixed(cls, data: bytes | memoryview) -> tuple[Any, ...]:
        """Unpack the fixed portion of the header from ``data``.

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
        """Length of this header in bytes.

        Fixed-size protocols inherit this default; variable-length
        headers (IPv4, TCP) override it to account for options.
        """
        return self._struct.size

    def next_protocol(
        self, registry: Registry | None = None
    ) -> type[Protocol] | None:
        """The class that decodes this header's payload, if known.

        ``None`` means the chain ends here: either the protocol never
        encapsulates another (ARP, UDP), or the encapsulated protocol
        is not implemented by this library.

        ``registry`` selects the dispatch tables to resolve against.
        Omitting it — the overwhelmingly common case — reads the
        process-wide default directly, which is why this stays a single
        dict lookup. :func:`~netprotocols.decode_frame` passes an
        explicit registry when a caller asked for one, so a per-call
        decoder override never has to mutate global state.
        """
        return None
