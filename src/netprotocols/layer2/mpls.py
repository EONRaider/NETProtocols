"""MPLS label stack (RFC 3032 §2.1), carried under EtherType 0x8847 or 0x8848.

An MPLS packet is a stack of 4-byte label stack entries between the
data link header and the packet it labels::

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                Label                  | TC  |S|       TTL     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

The 20-bit Label, the 3-bit Traffic Class (RFC 3032's "Exp" field,
renamed by RFC 5462), the Bottom of Stack bit S, set on the last entry
only, and an 8-bit TTL. One :class:`MPLS` layer holds the whole stack,
top entry first, as :attr:`MPLS.labels`, a tuple of :class:`MPLSLabel`.
:meth:`MPLS.decode` reads entries until the first one with S set, so
the stack bounds itself and ``bytes(MPLS.decode(x)) == x[:header_len]``.
MPLS has no length field and no checksum: what follows the stack is the
labelled packet, to the end of the buffer. Ethernet zero padding or an
FCS after it reaches that packet, and an IPv4 or IPv6 header bounds
itself by its own length fields, as it does directly after Ethernet.

EtherTypes
----------
Both EtherTypes RFC 3032 §5 assigned dispatch here, under the names
IANA's EtherType registry gives them (``ieee-802-numbers``, last updated
2024-11-03, fetched 2026-10-25): 0x8847, "MPLS"
(:attr:`~netprotocols.EtherType.MPLS`), and 0x8848, "MPLS with
upstream-assigned label"
(:attr:`~netprotocols.EtherType.MPLS_UPSTREAM_ASSIGNED`). RFC 3032
called 0x8848 the multicast codepoint; RFC 5332 §4 reassigned it to a
multicast frame whose top label is upstream-assigned, and 0x8847 to
every other MPLS frame, multicast included. The label stack is the same
under both. GRE dispatches its Protocol Type through the same
``ethertype`` table, so MPLS in GRE (RFC 4023, RFC 5332 §6) reaches
:class:`MPLS` too.

What the stack carries
----------------------
Nothing in the stack names the labelled packet's protocol: RFC 3032 §2.2
leaves that to the label the egress router popped, a binding no capture
shows. :meth:`MPLS.next_protocol` therefore works by convention, in this
order:

1. The bottom entry's label, where RFC 3032 reserves it for a purpose:
   0, IPv4 Explicit NULL, names IPv4 and 2, IPv6 Explicit NULL, names
   IPv6 (RFC 3032 §2.1; RFC 4182 lets them appear higher in the stack
   too, where they do not name the payload); 13, the Generic Associated
   Channel Label, is followed by an Associated Channel Header (RFC 5586
   §4.2) and 14, the OAM Alert Label, by an OAM message (RFC 3429), and
   neither is IP, so the walk stops. The label settles it: a bottom
   label of 0 dispatches to IPv4 whatever the next byte holds.
2. Otherwise the first nibble after the stack, where an IP header keeps
   its version: 4 is IPv4 and 6 is IPv6, which is what deployed routers
   look at to load-balance IP over MPLS (RFC 4928 §2). Anything else
   stops the walk. That includes what RFC 4385 §2 and RFC 4928 §3 make
   a pseudowire send so as not to look like IP: first nibble 0 is a
   pseudowire control word (RFC 4385 §3), and 1 an Associated Channel
   Header (RFC 4385 §5, RFC 5586 §2), so a control word ends the walk
   after the MPLS layer.

The answer is a class from the ``ethertype`` table, looked up at IPv4's
EtherType, 0x0800, or IPv6's, 0x86DD, so a ``registry`` or ``decode_as``
the caller passes reaches the labelled packet as it reaches a payload
after Ethernet. :attr:`MPLS.payload_ethertype` says which EtherType the
convention chose.

``next_protocol`` is handed no bytes, so :meth:`MPLS.decode` reads the
nibble and records what it implies on the instance, in a field outside
its comparison and hash, as :class:`~netprotocols.BGP` records whether
another message follows: two equal stacks compare equal wherever they
were found, and can chain differently. An :class:`MPLS` built rather
than decoded has seen no payload, so it answers from its bottom label
alone: IPv4 or IPv6 for an Explicit NULL, ``None`` for anything else.

The convention is a guess, and it can be wrong. An Ethernet
pseudowire sent without a control word, which RFC 4448 §4.6 makes
optional, starts with the carried frame's destination MAC address, and
one whose first nibble is 4 or 6 decodes as an IPv4 or IPv6 header:
RFC 4928 is about exactly that misreading, and the control word of
RFC 4385 is its cure. Such a walk decodes
garbage or stops with an error past the MPLS layer. Where the payload
is known, walk it explicitly instead, for example
``decode_frame(frame[offset:], start=Ethernet)`` from the end of the
stack.

The Entropy Label Indicator (label 7, RFC 6790) needs no rule of its
own. It is never the bottom entry (RFC 6790 §4.1: a receiver discards a
packet whose ELI has S set): the entry after it is the entropy label,
whose value RFC 6790 §3 keeps out of 0-15, so an entropy label at the
bottom of the stack is never one of the labels in step 1, and the
nibble decides.

Bounds
------
A stack ends at its first entry with S set. One whose S bit never comes
— a frame cut by a snap length, or a hostile one of thousands of
entries — raises :class:`~netprotocols.TruncatedHeaderError` with
``field="labels"`` and the ``offset`` where the missing entry would
start. Decoding reads each entry once, in place, so it costs time
linear in the stack's length, and the whole stack is one layer however
deep it is, so it does not count against ``decode_frame``'s
``max_depth``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from struct import Struct
from typing import ClassVar, Self

from netprotocols._base import Protocol
from netprotocols._enums import EtherType
from netprotocols.layer2.ethernet import _ethertype_class
from netprotocols.registry import Registry
from netprotocols.utils.exceptions import (
    InvalidFieldError,
    TruncatedHeaderError,
)

__all__ = ["MPLS", "MPLSLabel"]

#: One label stack entry, as a 32-bit word.
_ENTRY = Struct("!I")
_ENTRY_LEN = _ENTRY.size

#: The Base Special-Purpose MPLS Label Values, named as IANA's
#: "Special-Purpose Multiprotocol Label Switching (MPLS) Label Values"
#: registry assigns them (https://www.iana.org/assignments/
#: mpls-label-values, last updated 2026-06-30, fetched 2026-10-25).
#: Values 5-6 and 8-12 are unassigned and left unnamed.
_SPECIAL_PURPOSE_NAMES: dict[int, str] = {
    0: "IPv4 Explicit NULL Label",  # RFC 3032
    1: "Router Alert Label",  # RFC 3032
    2: "IPv6 Explicit NULL Label",  # RFC 3032
    3: "Implicit NULL Label",  # RFC 3032
    4: "MPLS Network Actions",  # RFC 9994
    7: "Entropy Label Indicator (ELI)",  # RFC 6790
    13: "Generic Associated Channel Label",  # RFC 5586
    14: "OAM Alert Label",  # RFC 3429
    15: "Extension Label (XL)",  # RFC 7274, RFC 9017
}

#: Labels 0-15 are special-purpose (RFC 3032 §2.1, RFC 7274 §2).
_SPECIAL_PURPOSE_LIMIT = 16

#: Bottom labels that settle what follows the stack (see the module
#: docstring): an EtherType to dispatch through, or ``None`` to stop.
_BOTTOM_LABEL_PAYLOADS: dict[int, int | None] = {
    0: EtherType.IPV4,  # IPv4 Explicit NULL
    2: EtherType.IPV6,  # IPv6 Explicit NULL
    13: None,  # GAL: an Associated Channel Header follows (RFC 5586)
    14: None,  # OAM Alert: an OAM message follows (RFC 3429)
}

#: The first nibble after the stack, read as an IP version (RFC 4928).
_FIRST_NIBBLE_PAYLOADS: dict[int, int] = {
    4: EtherType.IPV4,
    6: EtherType.IPV6,
}


def _check_width(name: str, value: int, bits: int) -> None:
    """Raise :class:`InvalidFieldError` unless ``value`` fits ``bits``."""
    top = (1 << bits) - 1
    if not 0 <= value <= top:
        raise InvalidFieldError(
            f"MPLS label stack entry {name} must be within 0-{top}, "
            f"got {value}",
            protocol=MPLSLabel,
            field=name,
            expected=f"0-{top}",
            actual=value,
        )


@dataclass(frozen=True, slots=True)
class MPLSLabel:
    """One MPLS label stack entry (RFC 3032 §2.1).

    :param label: The 20-bit label value; ``0``-``15`` are
        special-purpose (see :attr:`label_name`).
    :param traffic_class: The 3-bit Traffic Class (RFC 5462; RFC 3032's
        "Exp" field).
    :param bottom_of_stack: The S bit, ``1`` on the last entry of a
        stack and ``0`` on every other.
    :param ttl: Time to Live (RFC 3032 §2.4).
    :raises InvalidFieldError: a field does not fit its width.

    ``bytes(entry)`` is the 4-byte on-wire entry.
    """

    label: int
    traffic_class: int
    bottom_of_stack: int
    ttl: int

    def __post_init__(self) -> None:
        """Check each field fits its width."""
        _check_width("label", self.label, 20)
        _check_width("traffic_class", self.traffic_class, 3)
        _check_width("bottom_of_stack", self.bottom_of_stack, 1)
        _check_width("ttl", self.ttl, 8)

    @classmethod
    def from_word(cls, word: int) -> Self:
        """Split a 32-bit label stack entry into its fields.

        :param word: The entry as an unsigned 32-bit integer.
        """
        return cls(
            label=word >> 12,
            traffic_class=(word >> 9) & 0b111,
            bottom_of_stack=(word >> 8) & 1,
            ttl=word & 0xFF,
        )

    @property
    def word(self) -> int:
        """The entry packed back into its 32-bit word."""
        return (
            (self.label << 12)
            | (self.traffic_class << 9)
            | (self.bottom_of_stack << 8)
            | self.ttl
        )

    def __bytes__(self) -> bytes:
        """Serialize the 4-byte entry."""
        return _ENTRY.pack(self.word)

    @property
    def is_special_purpose(self) -> bool:
        """Whether the label is one of the reserved values ``0``-``15``."""
        return self.label < _SPECIAL_PURPOSE_LIMIT

    @property
    def label_name(self) -> str | None:
        """Name a special-purpose label as IANA does.

        For example ``"IPv4 Explicit NULL Label"`` for label 0;
        ``None`` for an ordinary label and for the unassigned values 5-6
        and 8-12.
        """
        return _SPECIAL_PURPOSE_NAMES.get(self.label)


@dataclass(frozen=True, slots=True)
class MPLS(Protocol):
    """An MPLS label stack: every entry down to the bottom of stack.

    Construction checks that the stack holds at least one entry and
    that the S bit is set on its last entry and on no other, which is
    what :meth:`decode` produces, so ``MPLS.decode(bytes(stack)) ==
    stack`` for every stack that can be built.

    :param labels: The label stack entries, top of the stack first; any
        iterable of them, kept as a tuple.
    :raises InvalidFieldError: the stack is empty or its S bits are not
        set on the last entry alone (``field`` ``"labels"``).
    """

    labels: tuple[MPLSLabel, ...]
    #: The EtherType the first nibble after the stack implied when it
    #: was decoded, or ``None``; decode context, not a wire field, so it
    #: is neither compared nor hashed (see the module docstring's *What
    #: the stack carries*).
    _nibble_ethertype: int | None = field(
        default=None, init=False, repr=False, compare=False
    )

    _struct: ClassVar[Struct] = _ENTRY

    def __post_init__(self) -> None:
        """Check the stack is non-empty and ends, alone, at its S bit.

        :raises InvalidFieldError: it is empty, or an S bit is misplaced.
        """
        # Any iterable of entries is accepted and kept as a tuple, so a
        # stack built from a list still compares equal to its decode and
        # stays hashable.
        object.__setattr__(self, "labels", tuple(self.labels))
        if not self.labels:
            raise InvalidFieldError(
                "MPLS label stack must hold at least one entry",
                protocol=type(self),
                field="labels",
                expected="at least 1 entry",
                actual=0,
            )
        last = len(self.labels) - 1
        flags = [entry.bottom_of_stack for entry in self.labels]
        if flags != [0] * last + [1]:
            raise InvalidFieldError(
                "MPLS bottom of stack bit must be set on the last entry "
                f"alone, got {flags}",
                protocol=type(self),
                field="labels",
                expected=f"S set on entry {last} only",
                actual=flags,
            )

    @classmethod
    def decode(cls, data: bytes | memoryview) -> Self:
        """Decode the label stack at the start of ``data``.

        Entries are read until the first with the S bit set; the byte
        after it, if any, is where the labelled packet starts (see the
        module docstring's *What the stack carries*).

        :raises TruncatedHeaderError: ``data`` ends before an entry with
            the S bit set (``field`` ``"labels"``, ``offset`` where the
            missing entry would start).
        """
        entries: list[MPLSLabel] = []
        offset = 0
        size = len(data)
        while True:
            if offset + _ENTRY_LEN > size:
                raise TruncatedHeaderError(
                    f"MPLS label stack ends without a bottom of stack "
                    f"entry: {len(entries)} entries, then "
                    f"{size - offset} bytes",
                    protocol=cls,
                    field="labels",
                    offset=offset,
                    expected=offset + _ENTRY_LEN,
                    actual=size,
                )
            (word,) = _ENTRY.unpack_from(data, offset)
            entries.append(MPLSLabel.from_word(word))
            offset += _ENTRY_LEN
            if word & 0x100:
                break
        stack = cls(labels=tuple(entries))
        if offset < size:
            object.__setattr__(
                stack,
                "_nibble_ethertype",
                _FIRST_NIBBLE_PAYLOADS.get(data[offset] >> 4),
            )
        return stack

    def __bytes__(self) -> bytes:
        """Serialize every entry, top of the stack first."""
        return b"".join(bytes(entry) for entry in self.labels)

    @property
    def header_len(self) -> int:
        """The whole stack: 4 bytes an entry."""
        return _ENTRY_LEN * len(self.labels)

    @property
    def bottom(self) -> MPLSLabel:
        """The bottom of stack entry, the one with the S bit set."""
        return self.labels[-1]

    @property
    def payload_ethertype(self) -> EtherType | None:
        """Name the EtherType the convention picks for the payload.

        :attr:`~netprotocols.EtherType.IPV4`,
        :attr:`~netprotocols.EtherType.IPV6`, or ``None`` when the walk
        stops here (see the module docstring's *What the stack
        carries*).
        """
        ethertype = _BOTTOM_LABEL_PAYLOADS.get(
            self.labels[-1].label, self._nibble_ethertype
        )
        return None if ethertype is None else EtherType(ethertype)

    def next_protocol(
        self, registry: Registry | None = None
    ) -> type[Protocol] | None:
        """Name the class for the labelled packet, by convention.

        The class the ``ethertype`` table holds at
        :attr:`payload_ethertype`, so ``registry`` selects it as it does
        after Ethernet; ``None`` when that is ``None``.
        """
        ethertype = self.payload_ethertype
        if ethertype is None:
            return None
        return _ethertype_class(ethertype, registry)
