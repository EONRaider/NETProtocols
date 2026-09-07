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

    :raises InvalidFieldError: if a kind byte has no following length
        byte, if a length is below ``min_option_length``, or if a
        length would run past ``raw`` — bounded, so the walk never
        hangs or over-reads regardless of what ``raw`` contains.
    """
    cursor = 0
    while cursor < len(raw):
        kind = raw[cursor]
        if kind in lone_byte_kinds:
            yield kind, b""
            if terminator_kind is not None and kind == terminator_kind:
                return
            cursor += 1
            continue
        if cursor + 1 >= len(raw):
            raise InvalidFieldError(
                f"{protocol.__name__} option missing its length byte",
                protocol=protocol,
                field=field,
                offset=cursor,
            )
        length = raw[cursor + 1]
        if min_option_length is not None and length < min_option_length:
            raise InvalidFieldError(
                f"{protocol.__name__} option length must be at least "
                f"{min_option_length}, got {length}",
                protocol=protocol,
                field=field,
                offset=cursor,
                expected=f">={min_option_length}",
                actual=length,
            )
        if length_includes_header:
            end = cursor + length
            if end > len(raw):
                raise InvalidFieldError(
                    f"{protocol.__name__} option value runs past the "
                    f"options bytes",
                    protocol=protocol,
                    field=field,
                    offset=cursor,
                )
        else:
            end = cursor + 2 + length
            if end > len(raw):
                raise InvalidFieldError(
                    f"{protocol.__name__} option data runs past the header",
                    protocol=protocol,
                    field=field,
                    offset=cursor,
                )
        yield kind, raw[cursor + 2 : end]
        cursor = end
