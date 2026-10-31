"""Shared kind/length/value option-TLV walker.

TCP options (RFC 9293 §3.2), IPv4 options (RFC 791 §3.1), and the two
IPv6 TLV extension headers (RFC 8200 §4.2) all walk the same shape of
blob: a sequence of kind (or type) bytes, most of them followed by a
length byte and that many bytes of data. Three real differences
separate them — TCP/IPv4 stop the walk early on an EOL byte and reject
a length below 2, while IPv6 has neither a terminator nor a length
floor; and TCP/IPv4's length byte counts itself and the kind byte,
while IPv6's counts only the trailing data — so this module holds the
one walker parameterized over those differences, and each call site
differs only in how it wraps a ``(kind, data)`` pair into its own
dataclass.

PIM Hello options (RFC 7761 §4.9.2) are the same shape with wider
fields: a 2-byte type and a 2-byte length counting only the value, with
no lone-byte kinds, no terminator and no length floor. ``width`` covers
that, and every byte-wide caller keeps the default of ``1``.

STUN attributes (RFC 8489 §14, RFC 5389 §15) are PIM's shape again, but
each value is padded to a multiple of 4 bytes and the padding is not
counted in its length. ``align`` covers that, and every other caller
keeps the default of ``1``, which pads nothing.
"""

from __future__ import annotations

from collections.abc import Iterator

from netprotocols.utils.exceptions import InvalidFieldError

__all__ = ["walk_kind_length_value"]


def walk_kind_length_value(
    raw: bytes,
    *,
    lone_byte_kinds: frozenset[int],
    terminator_kind: int | None,
    min_option_length: int | None,
    length_includes_header: bool,
    protocol: type,
    field: str = "options",
    width: int = 1,
    align: int = 1,
) -> Iterator[tuple[int, bytes]]:
    """Walk a TLV-encoded options blob, yielding ``(kind, data)`` pairs
    in wire order.

    :param raw: The options bytes to walk.
    :param lone_byte_kinds: Kind values that are a single byte with no
        length or data (e.g. TCP/IPv4 EOL ``0``, NOP ``1``; IPv6 Pad1
        ``0``) — yielded with ``data`` set to ``b""``.
    :param terminator_kind: If set and this lone-byte kind is seen, the
        walk stops right there without an error even if bytes remain
        (TCP/IPv4's EOL, ``0``); ``None`` for IPv6, which has no
        terminator per RFC 8200 — Pad1 does not stop the walk.
    :param min_option_length: If set, a length byte smaller than this
        raises (TCP/IPv4 require ``>=2``); ``None`` for IPv6, which has
        no such floor.
    :param length_includes_header: ``True`` for TCP/IPv4, where the
        length byte counts the kind and length bytes themselves, so
        the data slice is ``raw[cursor + 2 : cursor + length]`` and the
        cursor advances by ``length``. ``False`` for IPv6, where the
        length byte counts only the trailing data, so the data slice
        is ``raw[cursor + 2 : cursor + 2 + length]`` and the cursor
        advances by ``2 + length``.
    :param protocol: The class to attach to a raised
        :class:`~netprotocols.utils.exceptions.InvalidFieldError`
        (also named in its message text via ``protocol.__name__``).
    :param field: The field name to attach to a raised error; every
        current caller parses an attribute named ``options``.
    :param width: How many bytes the kind and the length each take, read
        big-endian: ``1`` for TCP, IPv4 and IPv6, ``2`` for PIM Hello
        options. Every offset above that says ``2`` is ``2 * width``:
        the header the length does or does not count, the data's start,
        and the structural floor when the length counts the header.
    :param align: The boundary, counted from the start of ``raw``, that
        each option's end is padded to before the next one starts:
        ``4`` for STUN attributes, ``1`` (no padding) for every other
        caller. The padding is skipped, never yielded or inspected, and
        padding that ``raw`` ends before completing ends the walk
        without an error. A lone-byte kind is not padded.

    :raises InvalidFieldError: if a kind byte has no following length
        byte, if a length is below ``min_option_length``, or if a
        length would run past ``raw`` — bounded, so the walk never
        hangs or over-reads regardless of what ``raw`` contains.
    """
    header = 2 * width
    effective_min, skip, overrun = _layout(
        min_option_length, length_includes_header, header, protocol.__name__
    )
    cursor = 0
    while cursor < len(raw):
        # int.from_bytes reads big-endian unless told otherwise (Python
        # 3.11+), which is network byte order.
        kind = int.from_bytes(raw[cursor : cursor + width])
        if kind in lone_byte_kinds:
            yield kind, b""
            if terminator_kind is not None and kind == terminator_kind:
                return
            cursor += width
            continue
        if cursor + header > len(raw):
            raise InvalidFieldError(
                f"{protocol.__name__} option missing its length "
                f"{'byte' if width == 1 else 'field'}",
                protocol=protocol,
                field=field,
                offset=cursor,
            )
        length = int.from_bytes(raw[cursor + width : cursor + header])
        if effective_min is not None and length < effective_min:
            raise InvalidFieldError(
                f"{protocol.__name__} option length must be at least "
                f"{effective_min}, got {length}",
                protocol=protocol,
                field=field,
                offset=cursor,
                expected=f">={effective_min}",
                actual=length,
            )
        end = cursor + skip + length
        if end > len(raw):
            raise InvalidFieldError(
                overrun, protocol=protocol, field=field, offset=cursor
            )
        yield kind, raw[cursor + header : end]
        cursor = end + -end % align


def _layout(
    min_option_length: int | None,
    length_includes_header: bool,
    header: int,
    name: str,
) -> tuple[int | None, int, str]:
    """Derive the walk's per-call constants from its parameters.

    These are the length floor, how many bytes past ``cursor + length``
    an option ends, and the message for a length that runs past the
    buffer, all fixed for one call of :func:`walk_kind_length_value`.

    When the length counts the kind and length fields themselves, it can
    never validly be below their size, ``header`` -- that floor is
    structural, not a per-caller policy, so it applies even if a caller
    passes a lower (or no) ``min_option_length``. Below it, ``end =
    cursor + length`` would not advance past ``cursor``, hanging the walk
    forever on a length of 0.
    """
    if length_includes_header:
        floor = (
            header
            if min_option_length is None
            else max(header, min_option_length)
        )
        return floor, 0, f"{name} option value runs past the options bytes"
    return min_option_length, header, f"{name} option data runs past the header"
