"""HTTP/1.1 message grammar (RFC 9112 framing, RFC 9110 fields).

This module holds the byte-level grammar the HTTP codec is built on:
it finds where one message ends within a buffer and reports every way
the message departs from the RFCs, without choosing silently between
readings that real implementations disagree on. It decodes a single,
already-reassembled buffer; TCP stream reassembly is the caller's.

Three rules shape it:

- **Raise only when the message itself cannot be represented**: the
  first line is not HTTP/1.x, a hard size limit is exceeded, the
  decode context is misused, the body's boundary is lost partway
  through, or (with ``closed=True``) the input ends before the framing
  says it should. Everything else decodes, using the resolution
  RFC 9112/9110 define or a documented reading, and records an
  :class:`HTTPAnomaly`. A passive decoder that raised on a smuggling
  attempt would hide exactly what a security tool exists to show.
- **Bytes, never text.** Grammar is matched on ``bytes``; optional
  whitespace means SP and HTAB only (``.strip(b" \\t")`` — a bare
  ``strip()`` would also eat VT, FF and, on ``str``, NEL and NBSP);
  case folding is ASCII; ``int()`` only ever sees validated, capped
  digits (it would otherwise accept ``+5``, ``5_0`` and non-ASCII
  digits).
- **Every rule lives in an undecorated module-level function**, so
  mutation testing reaches it (mutmut never mutates a decorated
  function).

Byte offsets in anomalies and in raised errors are relative to the
start of the message, i.e. to the buffer passed in.
"""

from __future__ import annotations

import enum
from typing import NamedTuple, NoReturn

from netprotocols.utils.exceptions import (
    InvalidFieldError,
    TruncatedHeaderError,
)

__all__ = [
    "MAX_HEAD_BYTES",
    "HTTPAnomaly",
    "HTTPAnomalyKind",
    "HTTPDisposition",
    "HTTPFraming",
]

#: Upper bound on the head (start line through the empty line), on the
#: trailer section, on each chunk line, and on the total chunk-extension
#: bytes of one body. Exceeding it is a hard failure.
MAX_HEAD_BYTES = 64 * 1024
_MAX_CONTENT_LENGTH_DIGITS = 18
_MAX_CHUNK_SIZE_DIGITS = 16

# RFC 9110 §5.6.2 / RFC 5234 core rules. Module constants are outside
# mutmut's reach, so tests/test_http.py pins each against the ABNF over
# all 256 byte values.
_DIGIT = frozenset(b"0123456789")
_HEXDIG = _DIGIT | frozenset(b"abcdefABCDEF")
_ALPHA = frozenset(range(0x41, 0x5B)) | frozenset(range(0x61, 0x7B))
_TCHAR = _ALPHA | _DIGIT | frozenset(b"!#$%&'*+-.^_`|~")
_VCHAR = frozenset(range(0x21, 0x7F))
_OBS_TEXT = frozenset(range(0x80, 0x100))
_OWS = b" \t"
_OWS_SET = frozenset(_OWS)
#: Separators RFC 9112 §3 and §4 let a recipient accept in a start line.
_START_LINE_WS = frozenset(b" \t\x0b\x0c\r")
_QDTEXT = (
    frozenset(b"\t !")
    | frozenset(range(0x23, 0x5C))
    | frozenset(range(0x5D, 0x7F))
    | _OBS_TEXT
)
_QUOTED_PAIR = frozenset(b"\t ") | _VCHAR | _OBS_TEXT

_FRAMING_FIELDS = (b"content-length", b"transfer-encoding")
_ROUTING_FIELDS = (*_FRAMING_FIELDS, b"host")


class HTTPAnomalyKind(enum.Enum):
    """A way an HTTP/1.1 message departs from RFC 9112/9110 that the
    codec resolved rather than rejected."""

    #: Empty line(s) before the start line (§2.2), kept in the head.
    LEADING_EMPTY_LINE = "leading_empty_line"
    #: A head or trailer line ended in a lone LF (§2.2).
    BARE_LF = "bare_lf"
    #: A start-line separator other than a single SP (§3, §4).
    START_LINE_WHITESPACE = "start_line_whitespace"
    #: A status line with no SP after the status code.
    STATUS_LINE_NO_REASON_SP = "status_line_no_reason_sp"
    #: A status code outside 100-599 (RFC 9110 §15).
    STATUS_CODE_OUT_OF_RANGE = "status_code_out_of_range"
    #: A request-target holding whitespace or a non-VCHAR byte (§3.2).
    REQUEST_TARGET_INVALID_OCTET = "request_target_invalid_octet"
    #: A target form the method doesn't use (§3.2.3, §3.2.4).
    REQUEST_TARGET_FORM = "request_target_form"
    #: A whitespace-preceded line before the first field (§2.2),
    #: consumed and ignored.
    WHITESPACE_PRECEDED_LINE = "whitespace_preceded_line"
    #: Whitespace between a field name and its colon (§5.1).
    WHITESPACE_BEFORE_COLON = "whitespace_before_colon"
    #: An obs-fold continuation line, unfolded to SP (§5.2).
    OBS_FOLD = "obs_fold"
    #: CR or NUL in a field value, replaced with SP (RFC 9110 §5.5).
    CTL_IN_FIELD_VALUE = "ctl_in_field_value"
    #: A field name that is not a token; excluded from every lookup.
    INVALID_FIELD_NAME = "invalid_field_name"
    #: A field line with no colon; excluded from every lookup.
    FIELD_LINE_NO_COLON = "field_line_no_colon"
    #: An empty list element, ignored (RFC 9110 §5.6.1.2).
    LIST_EMPTY_ELEMENT = "list_empty_element"
    #: Leading zeros on a Content-Length or chunk-size.
    NUMBER_LEADING_ZEROS = "number_leading_zeros"
    #: Connection naming a framing or routing field (RFC 9110 §7.6.1).
    CONNECTION_LISTS_FRAMING_FIELD = "connection_lists_framing_field"
    #: Both Content-Length and Transfer-Encoding; TE wins (§6.3 rule 3).
    CL_AND_TE = "cl_and_te"
    #: Content-Length repeated with one value (§6.3 rule 5).
    CONTENT_LENGTH_REPEATED = "content_length_repeated"
    #: A malformed Content-Length that Transfer-Encoding overrode.
    INVALID_CONTENT_LENGTH = "invalid_content_length"
    #: A Content-Length that cannot frame the message (§6.3 rule 5).
    CONTENT_LENGTH_UNRECOVERABLE = "content_length_unrecoverable"
    #: A transfer coding with parameters; not recognized as chunked.
    TE_PARAMETERS = "te_parameters"
    #: A transfer coding holding a non-token byte; unrecognized.
    TE_INVALID_OCTET = "te_invalid_octet"
    #: chunked applied more than once (§6.1).
    TE_CHUNKED_REPEATED = "te_chunked_repeated"
    #: Transfer-Encoding in an HTTP/1.0 message (§6.1).
    TE_IN_HTTP10 = "te_in_http10"
    #: A request whose final coding isn't chunked (§6.3 rule 4).
    REQUEST_FRAMING_UNDETERMINABLE = "request_framing_undeterminable"
    #: A response whose final coding isn't chunked, read until close.
    RESPONSE_TE_NOT_CHUNKED = "response_te_not_chunked"
    #: A framing or routing field where it has no effect: on a 1xx/204
    #: or 2xx-to-CONNECT response, or in a trailer section.
    FRAMING_FIELD_MISPLACED = "framing_field_misplaced"
    #: A chunk carrying an extension (§7.1.1).
    CHUNK_EXTENSION = "chunk_extension"
    #: A chunk extension that doesn't match the chunk-ext grammar.
    CHUNK_EXTENSION_INVALID = "chunk_extension_invalid"
    #: A lone LF inside a chunk line, read through to the next CRLF.
    CHUNK_LINE_BARE_LF = "chunk_line_bare_lf"
    #: Whitespace after a chunk-size with no extension following it.
    CHUNK_SIZE_TRAILING_WHITESPACE = "chunk_size_trailing_whitespace"


class HTTPFraming(enum.Enum):
    """How a message's body length is determined (RFC 9112 §6.3)."""

    NONE = "none"
    CONTENT_LENGTH = "content_length"
    CHUNKED = "chunked"
    UNTIL_CLOSE = "until_close"
    #: The head cannot determine the body length (§6.3 rules 4-5).
    INVALID = "invalid"


class HTTPDisposition(enum.Enum):
    """What the connection carries after this message."""

    CONTINUE = "continue"
    CLOSE = "close"
    #: Not HTTP any more: a 101 upgrade or an established CONNECT tunnel.
    TUNNEL = "tunnel"


class HTTPAnomaly(NamedTuple):
    """One kind of anomaly, aggregated: where it first occurred and how
    many times, so a body of a million odd chunks yields one record."""

    kind: HTTPAnomalyKind
    field: str | None
    offset: int
    occurrences: int


_Found = dict[tuple[HTTPAnomalyKind, str | None], list[int]]


class _Line(NamedTuple):
    offset: int
    content: bytes


class _StartLine(NamedTuple):
    is_response: bool
    version: tuple[int, int]
    method: bytes = b""
    target: bytes = b""
    status: int = 0
    reason: bytes = b""


class _Field(NamedTuple):
    name: bytes
    value: bytes
    offset: int
    #: False for a name that isn't a token or a line without a colon:
    #: kept for display, excluded from every semantic lookup.
    is_token: bool


class _Framing(NamedTuple):
    kind: HTTPFraming
    length: int | None = None


class _Message(NamedTuple):
    head_len: int
    end: int
    start: _StartLine
    fields: tuple[_Field, ...]
    request_method: bytes | None
    framing: _Framing
    disposition: HTTPDisposition
    content_spans: tuple[tuple[int, int], ...]
    trailers: tuple[_Field, ...]
    anomalies: tuple[HTTPAnomaly, ...]


def _flag(
    found: _Found, kind: HTTPAnomalyKind, field: str | None, offset: int
) -> None:
    entry = found.get((kind, field))
    if entry is None:
        found[(kind, field)] = [offset, 1]
    else:
        entry[1] += 1


def _flagged(found: _Found, kind: HTTPAnomalyKind) -> bool:
    return any(key[0] is kind for key in found)


def _collect(found: _Found) -> tuple[HTTPAnomaly, ...]:
    return tuple(
        sorted(
            (
                HTTPAnomaly(kind, field, entry[0], entry[1])
                for (kind, field), entry in found.items()
            ),
            key=lambda anomaly: (anomaly.offset, anomaly.kind.value),
        )
    )


def _label(name: bytes) -> str:
    return name.lower().decode("latin-1")


def _incomplete(
    message: str,
    *,
    field: str,
    offset: int,
    expected: int | None,
    actual: int,
    closed: bool,
    protocol: type[object],
) -> NoReturn:
    """More input is needed -- unless the caller says the connection
    has closed, in which case the message is incomplete for good (RFC
    9112 §6.3 rule 6, §8)."""
    if closed:
        raise InvalidFieldError(
            f"{message} at connection close",
            protocol=protocol,
            field=field,
            offset=offset,
            expected=expected,
            actual=actual,
        )
    raise TruncatedHeaderError(
        message,
        protocol=protocol,
        field=field,
        offset=offset,
        expected=expected,
        actual=actual,
    )


def _read_line(
    data: bytes, cursor: int, bound: int
) -> tuple[bytes, int, bool] | None:
    """The line at ``cursor`` as ``(content, end, bare_lf)``, or ``None``
    when no LF occurs before ``bound``."""
    lf = data.find(b"\n", cursor, bound)
    if lf == -1:
        return None
    if lf > cursor and data[lf - 1] == 0x0D:
        return data[cursor : lf - 1], lf + 1, False
    return data[cursor:lf], lf + 1, True


def _check_first_line_prefix(
    content: bytes, offset: int, protocol: type[object]
) -> None:
    """Fail fast on input that cannot begin an HTTP/1.x message: its
    first word must be token characters (and ``/``, for ``HTTP/``)."""
    word_end = len(content)
    for index, byte in enumerate(content):
        if byte in _START_LINE_WS:
            word_end = index
            break
    word = content[:word_end]
    if not content:
        return
    if not word or any(b not in _TCHAR and b != 0x2F for b in word):
        raise InvalidFieldError(
            "input does not begin an HTTP/1.x start line",
            protocol=protocol,
            field="start_line",
            offset=offset,
        )


def _scan_head(
    data: bytes, closed: bool, found: _Found, protocol: type[object]
) -> tuple[int, _StartLine, list[_Line]]:
    """Find the end of the head; return its length, the parsed start
    line and the remaining head lines."""
    cursor = 0
    start: _StartLine | None = None
    lines: list[_Line] = []
    while True:
        line = _read_line(data, cursor, MAX_HEAD_BYTES)
        if line is None:
            if start is None:
                _check_first_line_prefix(
                    data[cursor:MAX_HEAD_BYTES], cursor, protocol
                )
            if len(data) < MAX_HEAD_BYTES:
                _incomplete(
                    "HTTP head is incomplete",
                    field="head",
                    offset=cursor,
                    expected=None,
                    actual=len(data),
                    closed=closed,
                    protocol=protocol,
                )
            raise InvalidFieldError(
                f"HTTP head exceeds {MAX_HEAD_BYTES} bytes",
                protocol=protocol,
                field="head",
                offset=0,
                expected=MAX_HEAD_BYTES,
            )
        content, end, bare_lf = line
        if bare_lf:
            _flag(found, HTTPAnomalyKind.BARE_LF, None, end - 1)
        if not content:
            if start is None:
                _flag(found, HTTPAnomalyKind.LEADING_EMPTY_LINE, None, cursor)
                cursor = end
                continue
            return end, start, lines
        if start is None:
            _check_first_line_prefix(content, cursor, protocol)
            start = _parse_start_line(content, cursor, found, protocol)
        else:
            lines.append(_Line(cursor, content))
        cursor = end


def _split_words(content: bytes) -> list[tuple[int, bytes]]:
    """Whitespace-delimited words of a start line, with their offsets."""
    words: list[tuple[int, bytes]] = []
    index = 0
    while index < len(content):
        while index < len(content) and content[index] in _START_LINE_WS:
            index += 1
        begin = index
        while index < len(content) and content[index] not in _START_LINE_WS:
            index += 1
        if index > begin:
            words.append((begin, content[begin:index]))
    return words


def _single_sp_separated(
    content: bytes, words: list[tuple[int, bytes]]
) -> bool:
    cursor = 0
    for index, (at, word) in enumerate(words):
        if content[cursor:at] != (b" " if index else b""):
            return False
        cursor = at + len(word)
    return cursor == len(content)


def _leading_ws(data: bytes) -> bytes:
    index = 0
    while index < len(data) and data[index] in _START_LINE_WS:
        index += 1
    return data[:index]


def _parse_version(
    word: bytes, offset: int, protocol: type[object]
) -> tuple[int, int]:
    """``HTTP-version = "HTTP/" DIGIT "." DIGIT`` (§2.3), major 1 only."""
    if (
        len(word) != 8
        or not word.startswith(b"HTTP/")
        or word[5] not in _DIGIT
        or word[6] != 0x2E
        or word[7] not in _DIGIT
    ):
        raise InvalidFieldError(
            f"malformed HTTP-version {word!r}",
            protocol=protocol,
            field="start_line",
            offset=offset,
            actual=word,
        )
    version = (word[5] - 0x30, word[7] - 0x30)
    if version[0] != 1:
        raise InvalidFieldError(
            f"HTTP/{version[0]}.{version[1]} is not HTTP/1.x",
            protocol=protocol,
            field="start_line",
            offset=offset,
            expected="HTTP/1.x",
            actual=word,
        )
    return version


def _parse_start_line(
    content: bytes, offset: int, found: _Found, protocol: type[object]
) -> _StartLine:
    if content.startswith(b"HTTP/"):
        return _parse_status_line(content, offset, found, protocol)
    return _parse_request_line(content, offset, found, protocol)


def _parse_request_line(
    content: bytes, offset: int, found: _Found, protocol: type[object]
) -> _StartLine:
    """``method SP request-target SP HTTP-version`` (§3): the first word
    is the method, the last the version, everything between the
    target."""
    words = _split_words(content)
    if len(words) < 3:
        raise InvalidFieldError(
            "request-line needs a method, a target and a version",
            protocol=protocol,
            field="start_line",
            offset=offset,
        )
    method = words[0][1]
    if any(b not in _TCHAR for b in method):
        raise InvalidFieldError(
            f"method {method!r} is not a token",
            protocol=protocol,
            field="start_line",
            offset=offset,
            actual=method,
        )
    version_at, version_word = words[-1]
    target_at = words[1][0]
    target = content[target_at : words[-2][0] + len(words[-2][1])]
    if method == b"PRI" and target == b"*" and version_word == b"HTTP/2.0":
        raise InvalidFieldError(
            "the HTTP/2 connection preface is not an HTTP/1.x message",
            protocol=protocol,
            field="start_line",
            offset=offset,
        )
    version = _parse_version(version_word, offset + version_at, protocol)
    if not _single_sp_separated(content, words):
        _flag(found, HTTPAnomalyKind.START_LINE_WHITESPACE, None, offset)
    if any(b not in _VCHAR for b in target):
        _flag(
            found,
            HTTPAnomalyKind.REQUEST_TARGET_INVALID_OCTET,
            None,
            offset + target_at,
        )
    _check_target_form(method, target, offset + target_at, found)
    return _StartLine(False, version, method=method, target=target)


def _check_target_form(
    method: bytes, target: bytes, offset: int, found: _Found
) -> None:
    """asterisk-form is for OPTIONS and authority-form for CONNECT only
    (§3.2.3, §3.2.4); CONNECT takes nothing else."""
    if target == b"*":
        fits = method == b"OPTIONS"
    elif target.startswith(b"/") or b"://" in target:
        fits = method != b"CONNECT"
    else:
        fits = method == b"CONNECT"
    if not fits:
        _flag(found, HTTPAnomalyKind.REQUEST_TARGET_FORM, None, offset)


def _parse_status_line(
    content: bytes, offset: int, found: _Found, protocol: type[object]
) -> _StartLine:
    """``HTTP-version SP 3DIGIT SP [reason-phrase]`` (§4)."""
    version = _parse_version(content[:8], offset, protocol)
    separator = _leading_ws(content[8:])
    code_at = 8 + len(separator)
    code = content[code_at : code_at + 3]
    after = content[code_at + 3 :]
    if (
        not separator
        or len(code) != 3
        or any(b not in _DIGIT for b in code)
        or (after and after[0] not in _START_LINE_WS)
    ):
        raise InvalidFieldError(
            "status-line needs a version, SP and a 3-digit status code",
            protocol=protocol,
            field="start_line",
            offset=offset,
        )
    unusual = separator != b" "
    reason = b""
    if not after:
        _flag(found, HTTPAnomalyKind.STATUS_LINE_NO_REASON_SP, None, offset)
    else:
        reason_separator = _leading_ws(after)
        unusual = unusual or reason_separator != b" "
        reason = after[len(reason_separator) :]
    if unusual:
        _flag(found, HTTPAnomalyKind.START_LINE_WHITESPACE, None, offset)
    status = int(code)
    if not 100 <= status <= 599:
        _flag(
            found,
            HTTPAnomalyKind.STATUS_CODE_OUT_OF_RANGE,
            None,
            offset + code_at,
        )
    return _StartLine(True, version, status=status, reason=reason)


def _clean_value(
    raw: bytes, offset: int, label: str | None, found: _Found
) -> bytes:
    """A field value with CR and NUL replaced by SP (RFC 9110 §5.5) and
    surrounding optional whitespace removed."""
    if b"\r" in raw or b"\x00" in raw:
        _flag(found, HTTPAnomalyKind.CTL_IN_FIELD_VALUE, label, offset)
        raw = raw.replace(b"\r", b" ").replace(b"\x00", b" ")
    return raw.strip(_OWS)


def _parse_field_lines(lines: list[_Line], found: _Found) -> list[_Field]:
    """Field lines of a head or trailer section, in order (§5)."""
    fields: list[_Field] = []
    name = b""
    parts: list[bytes] = []
    field_offset = 0
    is_token = False
    current = False
    for line in lines:
        content = line.content
        if content[0] in _OWS_SET:
            if not current:
                _flag(
                    found,
                    HTTPAnomalyKind.WHITESPACE_PRECEDED_LINE,
                    None,
                    line.offset,
                )
                continue
            label = _label(name) if is_token else None
            _flag(found, HTTPAnomalyKind.OBS_FOLD, label, line.offset)
            parts.append(_clean_value(content, line.offset, label, found))
            continue
        if current:
            fields.append(_Field(name, _join(parts), field_offset, is_token))
        current = True
        field_offset = line.offset
        colon = content.find(b":")
        if colon == -1:
            _flag(found, HTTPAnomalyKind.FIELD_LINE_NO_COLON, None, line.offset)
            name, parts, is_token = content, [], False
            continue
        name = content[:colon].rstrip(_OWS)
        is_token = bool(name) and all(b in _TCHAR for b in name)
        if not is_token:
            _flag(found, HTTPAnomalyKind.INVALID_FIELD_NAME, None, line.offset)
        elif len(name) != colon:
            _flag(
                found,
                HTTPAnomalyKind.WHITESPACE_BEFORE_COLON,
                _label(name),
                line.offset,
            )
        label = _label(name) if is_token else None
        parts = [_clean_value(content[colon + 1 :], line.offset, label, found)]
    if current:
        fields.append(_Field(name, _join(parts), field_offset, is_token))
    return fields


def _join(parts: list[bytes]) -> bytes:
    return b" ".join(part for part in parts if part)


def _values(fields: list[_Field], name: bytes) -> list[_Field]:
    """Every token-named field called ``name``, in order (lowercase
    ``name``; field names are ASCII case-insensitive)."""
    return [f for f in fields if f.is_token and f.name.lower() == name]


def _parse_list(
    fields: list[_Field], label: str, found: _Found
) -> list[tuple[int, bytes]]:
    """The combined ``#element`` list of ``fields`` (RFC 9110 §5.3,
    §5.6.1.2): empty elements are ignored, and flagged."""
    elements: list[tuple[int, bytes]] = []
    for f in fields:
        for part in f.value.split(b","):
            element = part.strip(_OWS)
            if element:
                elements.append((f.offset, element))
            else:
                _flag(
                    found, HTTPAnomalyKind.LIST_EMPTY_ELEMENT, label, f.offset
                )
    return elements


def _parse_transfer_encoding(
    fields: list[_Field], version: tuple[int, int], found: _Found
) -> tuple[bool, bool]:
    """``(present, final coding is chunked)`` for the combined
    Transfer-Encoding list (§6.1, §7)."""
    te_fields = _values(fields, b"transfer-encoding")
    if not te_fields:
        return False, False
    label = "transfer-encoding"
    if version == (1, 0):
        _flag(found, HTTPAnomalyKind.TE_IN_HTTP10, label, te_fields[0].offset)
    final_is_chunked = False
    chunked_count = 0
    for offset, coding in _parse_list(te_fields, label, found):
        if b";" in coding:
            _flag(found, HTTPAnomalyKind.TE_PARAMETERS, label, offset)
            recognized = False
        elif any(b not in _TCHAR for b in coding):
            _flag(found, HTTPAnomalyKind.TE_INVALID_OCTET, label, offset)
            recognized = False
        else:
            recognized = coding.lower() == b"chunked"
        chunked_count += recognized
        final_is_chunked = recognized
    if chunked_count > 1:
        _flag(
            found,
            HTTPAnomalyKind.TE_CHUNKED_REPEATED,
            label,
            te_fields[0].offset,
        )
    return True, final_is_chunked


def _parse_content_length(
    fields: list[_Field],
    te_present: bool,
    found: _Found,
    protocol: type[object],
) -> tuple[bool, int | None]:
    """``(present, value)``; ``value`` is ``None`` when Transfer-Encoding
    overrides it or it cannot frame the message (§6.3 rules 3 and 5)."""
    cl_fields = _values(fields, b"content-length")
    if not cl_fields:
        return False, None
    label = "content-length"
    elements = _parse_list(cl_fields, label, found)
    valid = bool(elements)
    values: set[bytes] = set()
    for offset, element in elements:
        if any(b not in _DIGIT for b in element):
            valid = False
            continue
        significant = element.lstrip(b"0") or b"0"
        if len(significant) != len(element):
            _flag(found, HTTPAnomalyKind.NUMBER_LEADING_ZEROS, label, offset)
        if len(significant) > _MAX_CONTENT_LENGTH_DIGITS and not te_present:
            raise InvalidFieldError(
                f"Content-Length exceeds {_MAX_CONTENT_LENGTH_DIGITS} digits",
                protocol=protocol,
                field=label,
                offset=offset,
                expected=_MAX_CONTENT_LENGTH_DIGITS,
                actual=len(significant),
            )
        values.add(significant)
    offset = cl_fields[0].offset
    valid = valid and len(values) == 1
    if te_present:
        _flag(found, HTTPAnomalyKind.CL_AND_TE, label, offset)
        if not valid:
            _flag(found, HTTPAnomalyKind.INVALID_CONTENT_LENGTH, label, offset)
        return True, None
    if not valid:
        _flag(
            found, HTTPAnomalyKind.CONTENT_LENGTH_UNRECOVERABLE, label, offset
        )
        return True, None
    if len(elements) > 1:
        _flag(found, HTTPAnomalyKind.CONTENT_LENGTH_REPEATED, label, offset)
    return True, int(values.pop())


def _flag_present(
    fields: list[_Field], names: tuple[bytes, ...], found: _Found
) -> None:
    for name in names:
        for f in _values(fields, name):
            _flag(
                found,
                HTTPAnomalyKind.FRAMING_FIELD_MISPLACED,
                _label(name),
                f.offset,
            )


def _frame_message(
    start: _StartLine,
    fields: list[_Field],
    request_method: bytes | None,
    found: _Found,
    protocol: type[object],
) -> _Framing:
    """The message body length, per RFC 9112 §6.3."""
    if start.is_response:
        empty = 100 <= start.status < 200 or start.status == 204
        tunnel = request_method == b"CONNECT" and 200 <= start.status < 300
        if empty or tunnel:
            _flag_present(fields, _FRAMING_FIELDS, found)
            return _Framing(HTTPFraming.NONE)
        if start.status == 304 or request_method == b"HEAD":
            return _Framing(HTTPFraming.NONE)
    te_present, chunked = _parse_transfer_encoding(fields, start.version, found)
    cl_present, length = _parse_content_length(
        fields, te_present, found, protocol
    )
    if te_present:
        if chunked:
            return _Framing(HTTPFraming.CHUNKED)
        if start.is_response:
            _flag(found, HTTPAnomalyKind.RESPONSE_TE_NOT_CHUNKED, None, 0)
            return _Framing(HTTPFraming.UNTIL_CLOSE)
        _flag(found, HTTPAnomalyKind.REQUEST_FRAMING_UNDETERMINABLE, None, 0)
        return _Framing(HTTPFraming.INVALID)
    if cl_present:
        if length is None:
            return _Framing(HTTPFraming.INVALID)
        return _Framing(HTTPFraming.CONTENT_LENGTH, length)
    if start.is_response:
        return _Framing(HTTPFraming.UNTIL_CLOSE)
    return _Framing(HTTPFraming.NONE)


def _skip(data: bytes, index: int, allowed: frozenset[int]) -> int:
    while index < len(data) and data[index] in allowed:
        index += 1
    return index


def _quoted_string_end(data: bytes, start: int) -> int:
    """Index just past the quoted-string opening at ``start``, or -1."""
    index = start + 1
    while index < len(data):
        byte = data[index]
        if byte == 0x22:
            return index + 1
        if byte == 0x5C:
            if index + 1 >= len(data) or data[index + 1] not in _QUOTED_PAIR:
                return -1
            index += 2
        elif byte in _QDTEXT:
            index += 1
        else:
            return -1
    return -1


def _valid_chunk_ext(ext: bytes) -> bool:
    """``*( BWS ";" BWS name [ BWS "=" BWS ( token / quoted-string ) ] )``
    (§7.1.1)."""
    index = 0
    while index < len(ext):
        index = _skip(ext, index, _OWS_SET)
        if index >= len(ext) or ext[index] != 0x3B:
            return False
        index = _skip(ext, index + 1, _OWS_SET)
        name_end = _skip(ext, index, _TCHAR)
        if name_end == index:
            return False
        index = _skip(ext, name_end, _OWS_SET)
        if index < len(ext) and ext[index] == 0x3D:
            index = _skip(ext, index + 1, _OWS_SET)
            if index < len(ext) and ext[index] == 0x22:
                index = _quoted_string_end(ext, index)
                if index == -1:
                    return False
            else:
                value_end = _skip(ext, index, _TCHAR)
                if value_end == index:
                    return False
                index = value_end
    return True


def _parse_chunk_line(
    line: bytes,
    offset: int,
    extension_bytes: int,
    found: _Found,
    protocol: type[object],
) -> tuple[int, int]:
    """``chunk-size [ chunk-ext ]``: return ``(size, extension bytes so
    far)``."""
    digits_end = _skip(line, 0, _HEXDIG)
    digits = line[:digits_end]
    rest = line[digits_end:]
    if not digits or (
        rest and b"\n" not in rest and rest.lstrip(_OWS)[:1] not in (b"", b";")
    ):
        raise InvalidFieldError(
            "chunk-size line is not 1*HEXDIG [ chunk-ext ]",
            protocol=protocol,
            field="chunk-size",
            offset=offset,
        )
    significant = digits.lstrip(b"0") or b"0"
    if len(significant) != len(digits):
        _flag(found, HTTPAnomalyKind.NUMBER_LEADING_ZEROS, "chunk-size", offset)
    if len(significant) > _MAX_CHUNK_SIZE_DIGITS:
        raise InvalidFieldError(
            f"chunk-size exceeds {_MAX_CHUNK_SIZE_DIGITS} hex digits",
            protocol=protocol,
            field="chunk-size",
            offset=offset,
            expected=_MAX_CHUNK_SIZE_DIGITS,
            actual=len(significant),
        )
    if rest and not rest.strip(_OWS):
        _flag(
            found, HTTPAnomalyKind.CHUNK_SIZE_TRAILING_WHITESPACE, None, offset
        )
    elif rest:
        extension_bytes += len(rest)
        if extension_bytes > MAX_HEAD_BYTES:
            raise InvalidFieldError(
                f"chunk extensions exceed {MAX_HEAD_BYTES} bytes",
                protocol=protocol,
                field="chunk-ext",
                offset=offset,
                expected=MAX_HEAD_BYTES,
            )
        _flag(found, HTTPAnomalyKind.CHUNK_EXTENSION, None, offset)
        if b"\n" in rest:
            _flag(found, HTTPAnomalyKind.CHUNK_LINE_BARE_LF, None, offset)
        if not _valid_chunk_ext(rest):
            _flag(found, HTTPAnomalyKind.CHUNK_EXTENSION_INVALID, None, offset)
    return int(significant, 16), extension_bytes


def _parse_chunked(
    data: bytes,
    start: int,
    closed: bool,
    found: _Found,
    protocol: type[object],
) -> tuple[int, list[tuple[int, int]], list[_Field]]:
    """A chunked body starting at ``start`` (§7.1): return its end, the
    spans of chunk data, and the trailer fields."""
    cursor = start
    spans: list[tuple[int, int]] = []
    extension_bytes = 0
    while True:
        line_end = data.find(b"\r\n", cursor, cursor + MAX_HEAD_BYTES)
        if line_end == -1:
            if len(data) - cursor < MAX_HEAD_BYTES:
                _incomplete(
                    "chunk-size line is incomplete",
                    field="chunk-size",
                    offset=cursor,
                    expected=None,
                    actual=len(data),
                    closed=closed,
                    protocol=protocol,
                )
            raise InvalidFieldError(
                f"chunk-size line exceeds {MAX_HEAD_BYTES} bytes",
                protocol=protocol,
                field="chunk-size",
                offset=cursor,
                expected=MAX_HEAD_BYTES,
            )
        size, extension_bytes = _parse_chunk_line(
            data[cursor:line_end], cursor, extension_bytes, found, protocol
        )
        cursor = line_end + 2
        if size == 0:
            break
        data_end = cursor + size
        if len(data) < data_end + 2:
            _incomplete(
                "chunk-data is incomplete",
                field="raw_body",
                offset=cursor,
                expected=data_end + 2,
                actual=len(data),
                closed=closed,
                protocol=protocol,
            )
        if data[data_end : data_end + 2] != b"\r\n":
            raise InvalidFieldError(
                "chunk-data is not followed by CRLF",
                protocol=protocol,
                field="raw_body",
                offset=data_end,
            )
        spans.append((cursor, data_end))
        cursor = data_end + 2
    end, trailers = _parse_trailers(data, cursor, closed, found, protocol)
    return end, spans, trailers


def _parse_trailers(
    data: bytes,
    start: int,
    closed: bool,
    found: _Found,
    protocol: type[object],
) -> tuple[int, list[_Field]]:
    """The trailer section and the final empty line (§7.1.2)."""
    cursor = start
    bound = start + MAX_HEAD_BYTES
    lines: list[_Line] = []
    while True:
        line = _read_line(data, cursor, bound)
        if line is None:
            if len(data) < bound:
                _incomplete(
                    "trailer section is incomplete",
                    field="raw_body",
                    offset=cursor,
                    expected=None,
                    actual=len(data),
                    closed=closed,
                    protocol=protocol,
                )
            raise InvalidFieldError(
                f"trailer section exceeds {MAX_HEAD_BYTES} bytes",
                protocol=protocol,
                field="raw_body",
                offset=start,
                expected=MAX_HEAD_BYTES,
            )
        content, end, bare_lf = line
        if bare_lf:
            _flag(found, HTTPAnomalyKind.BARE_LF, None, end - 1)
        if not content:
            fields = _parse_field_lines(lines, found)
            _flag_present(fields, _ROUTING_FIELDS, found)
            return end, fields
        lines.append(_Line(cursor, content))
        cursor = end


def _message_end(
    data: bytes,
    head_len: int,
    framing: _Framing,
    closed: bool,
    found: _Found,
    protocol: type[object],
) -> tuple[int, list[tuple[int, int]], list[_Field]]:
    """Where the message ends, with its content spans and trailers."""
    if framing.kind is HTTPFraming.CHUNKED:
        return _parse_chunked(data, head_len, closed, found, protocol)
    if framing.kind is HTTPFraming.CONTENT_LENGTH:
        end = head_len + (framing.length or 0)
        if len(data) < end:
            _incomplete(
                "HTTP body is shorter than its Content-Length",
                field="raw_body",
                offset=head_len,
                expected=end,
                actual=len(data),
                closed=closed,
                protocol=protocol,
            )
        return end, [(head_len, end)], []
    if framing.kind is HTTPFraming.UNTIL_CLOSE:
        if not closed:
            raise TruncatedHeaderError(
                "HTTP body runs until the connection closes",
                protocol=protocol,
                field="raw_body",
                offset=head_len,
                actual=len(data),
            )
        return len(data), [(head_len, len(data))], []
    return head_len, [], []


def _disposition(
    start: _StartLine,
    fields: list[_Field],
    framing: _Framing,
    request_method: bytes | None,
    found: _Found,
) -> HTTPDisposition:
    """What follows this message on the connection (§9.3, §6.1)."""
    if start.is_response and (
        start.status == 101
        or (request_method == b"CONNECT" and 200 <= start.status < 300)
    ):
        return HTTPDisposition.TUNNEL
    connection = _values(fields, b"connection")
    tokens = {
        element.lower()
        for _, element in _parse_list(connection, "connection", found)
    }
    if tokens.intersection(_ROUTING_FIELDS):
        _flag(
            found,
            HTTPAnomalyKind.CONNECTION_LISTS_FRAMING_FIELD,
            "connection",
            connection[0].offset,
        )
    if (
        b"close" in tokens
        or (start.version == (1, 0) and b"keep-alive" not in tokens)
        or framing.kind in (HTTPFraming.UNTIL_CLOSE, HTTPFraming.INVALID)
        or _flagged(found, HTTPAnomalyKind.CL_AND_TE)
        or _flagged(found, HTTPAnomalyKind.TE_IN_HTTP10)
    ):
        return HTTPDisposition.CLOSE
    return HTTPDisposition.CONTINUE


def _check_request_method(
    method: str | None, start: _StartLine, protocol: type[object]
) -> bytes | None:
    """Validate the decode context for a response and keep it only when
    it changes framing: HEAD, or CONNECT answered with a 2xx."""
    if method is None:
        return None
    if not method or any(c > "\x7f" or ord(c) not in _TCHAR for c in method):
        raise InvalidFieldError(
            f"request_method {method!r} is not a token",
            protocol=protocol,
            field="request_method",
            actual=method,
        )
    if not start.is_response:
        raise InvalidFieldError(
            "request_method only applies when decoding a response",
            protocol=protocol,
            field="request_method",
            actual=method,
        )
    raw = method.encode("ascii")
    if raw == b"HEAD" or (raw == b"CONNECT" and 200 <= start.status < 300):
        return raw
    return None


def _parse_message(
    data: bytes,
    request_method: str | None,
    closed: bool,
    protocol: type[object],
) -> _Message:
    """Parse the one HTTP/1.1 message at the start of ``data``."""
    found: _Found = {}
    head_len, start, lines = _scan_head(data, closed, found, protocol)
    method = _check_request_method(request_method, start, protocol)
    fields = _parse_field_lines(lines, found)
    framing = _frame_message(start, fields, method, found, protocol)
    end, spans, trailers = _message_end(
        data, head_len, framing, closed, found, protocol
    )
    disposition = _disposition(start, fields, framing, method, found)
    return _Message(
        head_len=head_len,
        end=end,
        start=start,
        fields=tuple(fields),
        request_method=method,
        framing=framing,
        disposition=disposition,
        content_spans=tuple(spans),
        trailers=tuple(trailers),
        anomalies=_collect(found),
    )
