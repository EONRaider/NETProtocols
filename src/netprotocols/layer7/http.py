"""HTTP/1.1 messages (RFC 9112 framing, RFC 9110 fields).

:class:`HTTP` decodes one complete message from a buffer and encodes it
back byte-exactly. Underneath it, this module's byte-level grammar
finds where the message ends and reports every way it departs from the
RFCs, without choosing silently between readings that real
implementations disagree on. It decodes a single, already-reassembled
buffer; TCP stream reassembly is the caller's.

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
start of the message: the buffer passed to :meth:`HTTP.decode`, or
``head + raw_body`` for a constructed :class:`HTTP`.
"""

from __future__ import annotations

import dataclasses
import enum
import re
from ipaddress import IPv6Address
from typing import ClassVar, NamedTuple, NoReturn, Self

from netprotocols._base import Protocol
from netprotocols.utils.exceptions import (
    InvalidFieldError,
    TruncatedHeaderError,
)

__all__ = [
    "HTTP",
    "MAX_HEAD_BYTES",
    "HTTPAnomaly",
    "HTTPAnomalyKind",
    "HTTPDisposition",
    "HTTPFraming",
    "HTTPHeaderField",
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

#: Literals the grammar functions use, hoisted to module level so
#: mutation testing (which never mutates module-level code) cannot
#: produce equivalent mutants from them (a case-flipped codec name, a
#: padded strip set).
_LATIN_1 = "latin-1"
_ZERO = b"0"

_TCHAR_CLASS = re.escape(bytes(sorted(_TCHAR)))
#: The first word of a start line: tchar or "/" (for "HTTP/"), then
#: whitespace or the end of what has arrived so far.
_FIRST_WORD = re.compile(rb"[" + _TCHAR_CLASS + rb"/]+(?:[ \t\x0b\x0c\r]|\Z)")
_QUOTED_STRING = (
    rb'"(?:[\t !\x23-\x5b\x5d-\x7e\x80-\xff]|\\[\t \x21-\x7e\x80-\xff])*"'
)
#: RFC 9112 §7.1.1 ``chunk-ext = *( BWS ";" BWS chunk-ext-name
#: [ BWS "=" BWS chunk-ext-val ] )``, exactly: no trailing whitespace.
_CHUNK_EXT = re.compile(
    rb"(?:[ \t]*;[ \t]*["
    + _TCHAR_CLASS
    + rb"]+(?:[ \t]*=[ \t]*(?:["
    + _TCHAR_CLASS
    + rb"]+|"
    + _QUOTED_STRING
    + rb"))?)*"
)

_FRAMING_FIELDS = (b"content-length", b"transfer-encoding")
_ROUTING_FIELDS = (*_FRAMING_FIELDS, b"host")

# RFC 3986 §3.2.2 host, for the Host field (RFC 9110 §7.2): an
# IP-literal (checked further by _valid_ip_literal), or a reg-name,
# which also covers IPv4address; then an optional port.
_URI_CHARS = rb"A-Za-z0-9\-._~!$&'()*+,;="
_HOST_FIELD = re.compile(
    rb"(?:\[(?P<literal>[^\]]*)\]|(?:[" + _URI_CHARS + rb"]|%[0-9A-Fa-f]{2})*)"
    rb"(?::[0-9]*)?"
)
_IP_FUTURE = re.compile(rb"[vV][0-9A-Fa-f]+\.[" + _URI_CHARS + rb":]+")
#: ipaddress also accepts a zone ID ("%eth0"), which RFC 3986 does not.
_IPV6_CHARS = _HEXDIG | frozenset(b":.")
#: The authority of an absolute-form request-target (RFC 3986 §3).
_ABSOLUTE_AUTHORITY = re.compile(
    rb"[A-Za-z][A-Za-z0-9+\-.]*://(?P<authority>[^/?#]*)"
)


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
    #: An HTTP/1.1 request with no Host field (§3.2).
    HOST_MISSING = "host_missing"
    #: More than one Host field line (§3.2).
    HOST_DUPLICATE = "host_duplicate"
    #: A Host value that is not ``uri-host [ ":" port ]`` (§3.2).
    HOST_INVALID = "host_invalid"
    #: A valid Host holding a comma or a percent-encoding, which
    #: implementations split or decode differently.
    HOST_AMBIGUOUS = "host_ambiguous"
    #: A Host that differs from an absolute-form target's authority
    #: (§3.2.2); the target wins, but a front end may route on Host.
    HOST_TARGET_MISMATCH = "host_target_mismatch"


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


class HTTPHeaderField(NamedTuple):
    """One field line, as latin-1 text (lossless for any byte): the
    value is unfolded, CR/NUL-replaced and trimmed as the grammar read
    it. A line with no colon is all name, with an empty value."""

    name: str
    value: str


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
    return name.lower().decode(_LATIN_1)


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
    if content and _FIRST_WORD.match(content) is None:
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
            pending = data[cursor:MAX_HEAD_BYTES]
            # A lone CR may be half of a leading CRLF: let _incomplete report.
            if start is None and pending != b"\r":
                _check_first_line_prefix(pending, cursor, protocol)
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
    return content == b" ".join(word for _, word in words)


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
    """Field lines of a head or trailer section, in order (§5): each
    line opening a field, with any obs-fold continuation lines after
    it."""
    groups: list[tuple[_Line, list[_Line]]] = []
    for line in lines:
        if line.content[0] not in _OWS_SET:
            groups.append((line, []))
        elif groups:
            groups[-1][1].append(line)
        else:
            _flag(
                found,
                HTTPAnomalyKind.WHITESPACE_PRECEDED_LINE,
                None,
                line.offset,
            )
    return [_parse_field(line, folded, found) for line, folded in groups]


def _parse_field(line: _Line, folded: list[_Line], found: _Found) -> _Field:
    """One field line plus its obs-fold continuations (§5.1, §5.2)."""
    content = line.content
    colon = content.find(b":")
    if colon == -1:
        _flag(found, HTTPAnomalyKind.FIELD_LINE_NO_COLON, None, line.offset)
        name, is_token = content, False
    else:
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
    parts = (
        []
        if colon == -1
        else [_clean_value(content[colon + 1 :], line.offset, label, found)]
    )
    for continuation in folded:
        _flag(found, HTTPAnomalyKind.OBS_FOLD, label, continuation.offset)
        parts.append(
            _clean_value(
                continuation.content, continuation.offset, label, found
            )
        )
    return _Field(name, _join(parts), line.offset, is_token)


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
) -> bool | None:
    """Whether the final transfer coding is chunked (§6.1, §7), or
    ``None`` when the message has no Transfer-Encoding at all."""
    te_fields = _values(fields, b"transfer-encoding")
    if not te_fields:
        return None
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
    return final_is_chunked


def _parse_content_length(
    fields: list[_Field],
    te_present: bool,
    found: _Found,
    protocol: type[object],
) -> _Framing | None:
    """The framing Content-Length gives the message (§6.3 rules 3 and 5):
    ``None`` when there is none or Transfer-Encoding overrides it."""
    cl_fields = _values(fields, b"content-length")
    if not cl_fields:
        return None
    label = "content-length"
    elements = _parse_list(cl_fields, label, found)
    numeric = [
        (offset, element)
        for offset, element in elements
        if all(b in _DIGIT for b in element)
    ]
    values: set[bytes] = set()
    for offset, element in numeric:
        significant = element.lstrip(_ZERO) or _ZERO
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
    valid = len(numeric) == len(elements) and len(values) == 1
    if te_present:
        _flag(found, HTTPAnomalyKind.CL_AND_TE, label, offset)
        if not valid:
            _flag(found, HTTPAnomalyKind.INVALID_CONTENT_LENGTH, label, offset)
        return None
    if not valid:
        _flag(
            found, HTTPAnomalyKind.CONTENT_LENGTH_UNRECOVERABLE, label, offset
        )
        return _Framing(HTTPFraming.INVALID)
    if len(elements) > 1:
        _flag(found, HTTPAnomalyKind.CONTENT_LENGTH_REPEATED, label, offset)
    return _Framing(HTTPFraming.CONTENT_LENGTH, int(values.pop()))


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
        # _check_request_method keeps CONNECT only for a 2xx response.
        if empty or request_method == b"CONNECT":
            _flag_present(fields, _FRAMING_FIELDS, found)
            return _Framing(HTTPFraming.NONE)
        if start.status == 304 or request_method == b"HEAD":
            return _Framing(HTTPFraming.NONE)
    chunked = _parse_transfer_encoding(fields, start.version, found)
    by_length = _parse_content_length(
        fields, chunked is not None, found, protocol
    )
    if chunked is not None:
        if chunked:
            return _Framing(HTTPFraming.CHUNKED)
        if start.is_response:
            _flag(found, HTTPAnomalyKind.RESPONSE_TE_NOT_CHUNKED, None, 0)
            return _Framing(HTTPFraming.UNTIL_CLOSE)
        _flag(found, HTTPAnomalyKind.REQUEST_FRAMING_UNDETERMINABLE, None, 0)
        return _Framing(HTTPFraming.INVALID)
    if by_length is not None:
        return by_length
    if start.is_response:
        return _Framing(HTTPFraming.UNTIL_CLOSE)
    return _Framing(HTTPFraming.NONE)


def _skip(data: bytes, index: int, allowed: frozenset[int]) -> int:
    while index < len(data) and data[index] in allowed:
        index += 1
    return index


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
    significant = digits.lstrip(_ZERO) or _ZERO
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
        if _CHUNK_EXT.fullmatch(rest) is None:
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
        start.status == 101 or request_method == b"CONNECT"
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


def _valid_ip_literal(literal: bytes) -> bool:
    """``IP-literal = "[" ( IPv6address / IPvFuture ) "]"``, brackets
    removed (RFC 3986 §3.2.2)."""
    if _IP_FUTURE.fullmatch(literal):
        return True
    if any(b not in _IPV6_CHARS for b in literal):
        return False
    try:
        IPv6Address(literal.decode())
    except ValueError:
        return False
    return True


def _valid_host(value: bytes) -> bool:
    """``Host = uri-host [ ":" port ]`` (RFC 9110 §7.2)."""
    match = _HOST_FIELD.fullmatch(value)
    if match is None:
        return False
    literal = match["literal"]
    return literal is None or _valid_ip_literal(literal)


def _target_authority(target: bytes) -> bytes | None:
    """An absolute-form target's authority without its userinfo (§3.2),
    or ``None`` for any other form."""
    match = _ABSOLUTE_AUTHORITY.match(target)
    if match is None:
        return None
    return match["authority"].rpartition(b"@")[2]


def _check_host(start: _StartLine, fields: list[_Field], found: _Found) -> None:
    """A request's Host (§3.2): present in HTTP/1.1, sent once, a valid
    ``uri-host [ ":" port ]``, and identical to an absolute-form
    target's authority. The comparison folds case (the host is case-
    insensitive and the port is digits) but neither percent-decodes nor
    fills in a default port."""
    if start.is_response:
        return
    label = "host"
    hosts = _values(fields, b"host")
    if not hosts:
        if start.version >= (1, 1):
            _flag(found, HTTPAnomalyKind.HOST_MISSING, label, 0)
        return
    for duplicate in hosts[1:]:
        _flag(found, HTTPAnomalyKind.HOST_DUPLICATE, label, duplicate.offset)
    authority = _target_authority(start.target)
    for host in hosts:
        if not _valid_host(host.value):
            _flag(found, HTTPAnomalyKind.HOST_INVALID, label, host.offset)
        elif b"," in host.value or b"%" in host.value:
            _flag(found, HTTPAnomalyKind.HOST_AMBIGUOUS, label, host.offset)
        if authority is not None and host.value.lower() != authority.lower():
            _flag(
                found, HTTPAnomalyKind.HOST_TARGET_MISMATCH, label, host.offset
            )


def _check_request_method(
    method: str | None, start: _StartLine, protocol: type[object]
) -> bytes | None:
    """Validate the decode context for a response and keep it only when
    it changes framing: HEAD, or CONNECT answered with a 2xx."""
    if method is None:
        return None
    if not method or any(ord(c) not in _TCHAR for c in method):
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
    if method == "HEAD" or (method == "CONNECT" and 200 <= start.status < 300):
        return method.encode()
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
    _check_host(start, fields, found)
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


def _check_consistency(
    head: bytes,
    raw_body: bytes,
    request_method: str | None,
    protocol: type[object],
) -> _Message:
    """Parse a constructed message: ``head`` must be exactly one complete
    head and ``raw_body`` exactly the body its framing delimits. A
    constructed message is complete by definition, so it is parsed as
    ``closed``: an ``UNTIL_CLOSE`` body is whatever ``raw_body`` holds."""
    message = _parse_message(head + raw_body, request_method, True, protocol)
    if message.head_len != len(head):
        raise InvalidFieldError(
            "head is not exactly one HTTP head, ending at its empty line",
            protocol=protocol,
            field="head",
            offset=min(message.head_len, len(head)),
            expected=message.head_len,
            actual=len(head),
        )
    if message.end != len(head) + len(raw_body):
        raise InvalidFieldError(
            "raw_body holds bytes past the end of the framed body",
            protocol=protocol,
            field="raw_body",
            offset=message.end,
            expected=message.end - len(head),
            actual=len(raw_body),
        )
    return message


def _text(value: bytes) -> str:
    return value.decode(_LATIN_1)


def _text_or_none(value: bytes | None) -> str | None:
    return None if value is None else _text(value)


def _header_fields(fields: tuple[_Field, ...]) -> tuple[HTTPHeaderField, ...]:
    return tuple(HTTPHeaderField(_text(f.name), _text(f.value)) for f in fields)


def _field_values(fields: tuple[_Field, ...], name: str) -> tuple[str, ...]:
    """Every value of the token-named field ``name``, compared ASCII
    case-insensitively: ``str.lower()`` would fold the Kelvin sign
    into ``k``, which no HTTP implementation does."""
    try:
        wanted = name.encode(_LATIN_1).lower()
    except UnicodeEncodeError:
        return ()
    return tuple(_text(f.value) for f in _values(list(fields), wanted))


def _content(message: _Message, raw_body: bytes) -> bytes:
    """The body with any chunked framing removed (RFC 9110 §6.4)."""
    return b"".join(
        raw_body[begin - message.head_len : end - message.head_len]
        for begin, end in message.content_spans
    )


@dataclasses.dataclass(frozen=True, slots=True)
class HTTP(Protocol):
    """One HTTP/1.1 request or response, held verbatim.

    Everything else is derived from the two byte strings, so encoding
    is exact: ``bytes(msg) == head + raw_body``, whatever odd bytes the
    sender used. Anything the grammar resolved rather than rejected is
    listed in :attr:`anomalies`.

    :param head: The start line through the empty line ending the head,
        leading empty lines included, exactly as on the wire.
    :param raw_body: The message body as framed on the wire (chunk
        lines and trailers included); :attr:`content` strips the
        framing.
    :param request_method: The method of the request this response
        answers, when known. It is decode context, not wire data: only
        ``"HEAD"``, and ``"CONNECT"`` answered with a 2xx, change how a
        response is framed, so any other method is stored as ``None``,
        and two messages with equal bytes and equal framing compare
        equal. Supplying it for a request raises.
    :raises InvalidFieldError: if ``head`` is not one complete head, if
        ``raw_body`` is not exactly the body its framing delimits, or on
        any error :meth:`decode` would raise for ``head + raw_body``.
    """

    head: bytes
    raw_body: bytes = dataclasses.field(default=b"", repr=False)
    request_method: str | None = None
    _message: _Message = dataclasses.field(
        init=False, repr=False, compare=False
    )

    #: Upper bound on the head, on the trailer section, on each chunk
    #: line and on the total chunk-extension bytes of one body.
    MAX_HEAD_BYTES: ClassVar[int] = MAX_HEAD_BYTES

    #: Positional form for ``match``/``case``: a request matches on its
    #: method and target, a response on its status code.
    __match_args__ = ("method", "target", "status_code")

    def __post_init__(self) -> None:
        message = _check_consistency(
            self.head, self.raw_body, self.request_method, type(self)
        )
        object.__setattr__(
            self, "request_method", _text_or_none(message.request_method)
        )
        object.__setattr__(self, "_message", message)

    @classmethod
    def decode(
        cls,
        data: bytes | memoryview,
        *,
        request_method: str | None = None,
        closed: bool = False,
    ) -> Self:
        """Decode the HTTP message at the start of ``data``.

        Trailing bytes (a pipelined next message) are left alone; the
        message ends at :attr:`header_len`.

        :param request_method: For a response, the method of the request
            it answers (see the class docstring).
        :param closed: ``True`` when ``data`` ends where the connection
            closed. A response framed by connection close needs it, and
            input that ends early then raises :class:`InvalidFieldError`
            instead of :class:`TruncatedHeaderError`.
        :raises TruncatedHeaderError: (only when ``closed`` is false)
            ``data`` ends before the message does; retry with more.
        :raises InvalidFieldError: the input is not HTTP/1.x, exceeds a
            hard limit, loses its body boundary, misuses
            ``request_method``, or (when ``closed``) is incomplete.
        """
        buffer = bytes(data)
        message = _parse_message(buffer, request_method, closed, cls)
        # The parse above establishes everything __post_init__ checks,
        # so the instance is built directly (see _base.py).
        instance = object.__new__(cls)
        object.__setattr__(instance, "head", buffer[: message.head_len])
        object.__setattr__(
            instance, "raw_body", buffer[message.head_len : message.end]
        )
        object.__setattr__(
            instance, "request_method", _text_or_none(message.request_method)
        )
        object.__setattr__(instance, "_message", message)
        return instance

    def __bytes__(self) -> bytes:
        return self.head + self.raw_body

    @property
    def header_len(self) -> int:
        """Length of the whole message, head and body."""
        return len(self.head) + len(self.raw_body)

    @property
    def is_response(self) -> bool:
        """Whether this is a response (a status line) or a request."""
        return self._message.start.is_response

    @property
    def method(self) -> str | None:
        """The request method, e.g. ``"GET"``; ``None`` for a response."""
        start = self._message.start
        return None if start.is_response else _text(start.method)

    @property
    def target(self) -> str | None:
        """The request-target as sent; ``None`` for a response."""
        start = self._message.start
        return None if start.is_response else _text(start.target)

    @property
    def http_version(self) -> str:
        """The version from the start line, e.g. ``"HTTP/1.1"``."""
        major, minor = self._message.start.version
        return f"HTTP/{major}.{minor}"

    @property
    def status_code(self) -> int | None:
        """The status code; ``None`` for a request."""
        start = self._message.start
        return start.status if start.is_response else None

    @property
    def reason_phrase(self) -> str | None:
        """The reason phrase (possibly empty); ``None`` for a request."""
        start = self._message.start
        return _text(start.reason) if start.is_response else None

    @property
    def fields(self) -> tuple[HTTPHeaderField, ...]:
        """Every field line of the head, in order, duplicates kept."""
        return _header_fields(self._message.fields)

    def header_values(self, name: str) -> tuple[str, ...]:
        """Every value of the field ``name`` (case-insensitive), in
        order. Fields whose name is not a valid token never match."""
        return _field_values(self._message.fields, name)

    def header(self, name: str) -> str | None:
        """The values of ``name`` combined with ``", "`` (RFC 9110
        §5.3), or ``None`` when absent. ``Set-Cookie`` cannot be
        combined this way (RFC 6265 §3); read it with
        :meth:`header_values`."""
        values = self.header_values(name)
        return ", ".join(values) if values else None

    @property
    def framing(self) -> HTTPFraming:
        """How the body length was determined (RFC 9112 §6.3)."""
        return self._message.framing.kind

    @property
    def connection_disposition(self) -> HTTPDisposition:
        """What the connection carries after this message. A caller
        reading pipelined messages stops at ``CLOSE`` or ``TUNNEL``."""
        return self._message.disposition

    @property
    def content(self) -> bytes:
        """The body with chunked framing removed; content codings such
        as gzip are not decoded."""
        return _content(self._message, self.raw_body)

    @property
    def trailers(self) -> tuple[HTTPHeaderField, ...]:
        """The trailer fields of a chunked body, in order."""
        return _header_fields(self._message.trailers)

    @property
    def anomalies(self) -> tuple[HTTPAnomaly, ...]:
        """Every deviation the grammar resolved, aggregated by kind and
        field, ordered by first offset."""
        return self._message.anomalies
