"""Tests for the HTTP/1.1 message grammar in netprotocols.layer7.http.

One vector per rule, each named for the rule and citing the RFC clause
it pins, plus exhaustive checks of the byte-class tables against the
ABNF they encode (module constants are outside mutation testing's
reach, so these are their only guard).
"""

import string

import pytest

from netprotocols import InvalidFieldError, TruncatedHeaderError
from netprotocols.layer7 import http
from netprotocols.layer7.http import (
    MAX_HEAD_BYTES,
    HTTPAnomaly,
    HTTPAnomalyKind,
    HTTPDisposition,
    HTTPFraming,
)

K = HTTPAnomalyKind


class _Protocol:
    """Stand-in for the class a raise names (the grammar never
    instantiates it)."""


def parse(
    raw: bytes, request_method: str | None = None, closed: bool = False
) -> http._Message:
    return http._parse_message(raw, request_method, closed, _Protocol)


def kinds(raw: bytes, **context: object) -> set[HTTPAnomalyKind]:
    message = parse(raw, **context)  # type: ignore[arg-type]
    return {anomaly.kind for anomaly in message.anomalies}


def request(*fields: bytes, body: bytes = b"", line: bytes = b"") -> bytes:
    start = line or b"POST /submit HTTP/1.1"
    return (
        start + b"\r\n" + b"".join(f + b"\r\n" for f in fields) + b"\r\n" + body
    )


def response(
    *fields: bytes, body: bytes = b"", status: bytes = b"200 OK"
) -> bytes:
    head = b"HTTP/1.1 " + status + b"\r\n"
    return head + b"".join(f + b"\r\n" for f in fields) + b"\r\n" + body


def raises(
    exc: type[Exception], raw: bytes, **context: object
) -> pytest.ExceptionInfo[Exception]:
    with pytest.raises(exc) as excinfo:
        parse(raw, **context)  # type: ignore[arg-type]
    assert excinfo.value.protocol is _Protocol  # type: ignore[attr-defined]
    return excinfo


class TestByteTables:
    """RFC 9110 §5.6.2 / RFC 5234, checked over every byte value."""

    @pytest.mark.parametrize("byte", range(256))
    def test_tchar(self, byte: int) -> None:
        tchar = string.ascii_letters + string.digits + "!#$%&'*+-.^_`|~"
        assert (byte in http._TCHAR) == (chr(byte) in tchar)

    @pytest.mark.parametrize("byte", range(256))
    def test_vchar_digit_hexdig_obs_text(self, byte: int) -> None:
        char = chr(byte)
        assert (byte in http._VCHAR) == (0x21 <= byte <= 0x7E)
        assert (byte in http._DIGIT) == (char in string.digits)
        assert (byte in http._HEXDIG) == (char in string.hexdigits)
        assert (byte in http._OBS_TEXT) == (byte >= 0x80)

    @pytest.mark.parametrize("byte", range(256))
    def test_quoted_string_classes(self, byte: int) -> None:
        qdtext = byte in (0x09, 0x20, 0x21) or 0x23 <= byte <= 0x5B
        qdtext = qdtext or 0x5D <= byte <= 0x7E or byte >= 0x80
        assert (byte in http._QDTEXT) == qdtext
        pair = byte in (0x09, 0x20) or 0x21 <= byte <= 0x7E or byte >= 0x80
        assert (byte in http._QUOTED_PAIR) == pair

    def test_start_line_separators(self) -> None:
        """§3: SP, HTAB, VT, FF or bare CR."""
        assert set(http._START_LINE_WS) == {0x20, 0x09, 0x0B, 0x0C, 0x0D}


class TestHeadScan:
    def test_a_plain_request(self) -> None:
        raw = b"GET /index.html HTTP/1.1\r\nHost: a\r\n\r\ntrailing"
        message = parse(raw)
        assert message.head_len == raw.index(b"trailing")
        assert message.end == message.head_len
        assert message.start.method == b"GET"
        assert message.start.target == b"/index.html"
        assert message.start.version == (1, 1)
        assert message.anomalies == ()

    def test_leading_empty_lines_are_kept_and_flagged(self) -> None:
        """§2.2: a server SHOULD ignore at least one leading empty line."""
        raw = b"\r\n\n" + request()
        message = parse(raw)
        assert message.head_len == len(raw)
        assert message.anomalies[0] == HTTPAnomaly(
            K.LEADING_EMPTY_LINE, None, 0, 2
        )
        assert K.BARE_LF in kinds(raw)

    def test_bare_lf_is_accepted_and_flagged(self) -> None:
        """§2.2: a recipient MAY recognize a single LF."""
        raw = b"GET / HTTP/1.1\nHost: a\n\n"
        message = parse(raw)
        assert message.head_len == len(raw)
        (anomaly,) = message.anomalies
        assert anomaly == HTTPAnomaly(K.BARE_LF, None, 14, 3)

    @pytest.mark.parametrize("raw", [b"", b"GE", b"GET / HTTP/1.1\r\nHost"])
    def test_an_unterminated_head_needs_more(self, raw: bytes) -> None:
        raises(TruncatedHeaderError, raw)

    def test_an_unterminated_head_at_close_is_incomplete(self) -> None:
        err = raises(InvalidFieldError, b"GET / HTTP/1.1\r\n", closed=True)
        assert err.value.field == "head"  # type: ignore[attr-defined]

    def test_head_bound_is_inclusive(self) -> None:
        head = b"GET / HTTP/1.1\r\nX: "
        padded = head + b"a" * (MAX_HEAD_BYTES - len(head) - 4) + b"\r\n\r\n"
        assert len(padded) == MAX_HEAD_BYTES
        assert parse(padded).head_len == MAX_HEAD_BYTES
        over = head + b"a" * (MAX_HEAD_BYTES - len(head) - 3) + b"\r\n\r\n"
        err = raises(InvalidFieldError, over)
        assert err.value.expected == MAX_HEAD_BYTES  # type: ignore[attr-defined]

    def test_a_tls_client_hello_fails_fast(self) -> None:
        """Garbage is rejected at byte 0, not after buffering 64 KiB."""
        raises(InvalidFieldError, b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03")

    @pytest.mark.parametrize(
        "raw", [b" GET / HTTP/1.1\r\n\r\n", b"G\x00T / HTTP/1.1"]
    )
    def test_a_non_token_first_word_fails_fast(self, raw: bytes) -> None:
        raises(InvalidFieldError, raw)


class TestRequestLine:
    @pytest.mark.parametrize(
        "line",
        [
            b"GET /",
            b"G@T / HTTP/1.1",
            b"http/1.1 200 OK",
            b"GET / HTTP/1",
            b"GET / HTTP/1.x",
            b"GET / HTTPS1.1",
            b"GET / HTTP/1-1",
            b"GET / HTTP/2.0",
            b"GET / HTTP/0.9",
        ],
    )
    def test_not_http_1x_raises(self, line: bytes) -> None:
        err = raises(InvalidFieldError, line + b"\r\n\r\n")
        assert err.value.field == "start_line"  # type: ignore[attr-defined]

    def test_the_http2_preface_is_named(self) -> None:
        err = raises(InvalidFieldError, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        assert "HTTP/2 connection preface" in str(err.value)

    @pytest.mark.parametrize(
        "line", [b"GET\t/ HTTP/1.1", b"GET  / HTTP/1.1", b"GET /\x0bHTTP/1.1"]
    )
    def test_unusual_separators_are_flagged(self, line: bytes) -> None:
        assert kinds(request(line=line)) == {K.START_LINE_WHITESPACE}

    def test_trailing_whitespace_is_flagged(self) -> None:
        assert kinds(request(line=b"GET / HTTP/1.1 ")) == {
            K.START_LINE_WHITESPACE
        }

    def test_a_target_with_whitespace_is_kept_and_flagged(self) -> None:
        """§3.2: such targets 'might be deliberately crafted to bypass
        security filters'."""
        message = parse(request(line=b"GET /a b HTTP/1.1"))
        assert message.start.target == b"/a b"
        assert {a.kind for a in message.anomalies} == {
            K.REQUEST_TARGET_INVALID_OCTET
        }

    @pytest.mark.parametrize(
        "line,flagged",
        [
            (b"OPTIONS * HTTP/1.1", False),
            (b"GET * HTTP/1.1", True),
            (b"CONNECT example.com:443 HTTP/1.1", False),
            (b"GET example.com:443 HTTP/1.1", True),
            (b"CONNECT /x HTTP/1.1", True),
            (b"GET http://a/b HTTP/1.1", False),
            (b"CONNECT http://a/ HTTP/1.1", True),
        ],
    )
    def test_target_form_fits_the_method(
        self, line: bytes, flagged: bool
    ) -> None:
        assert (K.REQUEST_TARGET_FORM in kinds(request(line=line))) is flagged


class TestStatusLine:
    def test_a_plain_status_line(self) -> None:
        message = parse(response(b"Content-Length: 0"))
        assert message.start.is_response
        assert (message.start.status, message.start.reason) == (200, b"OK")

    def test_no_reason_without_sp_is_flagged(self) -> None:
        raw = b"HTTP/1.1 200\r\nContent-Length: 0\r\n\r\n"
        assert kinds(raw) == {K.STATUS_LINE_NO_REASON_SP}

    def test_an_empty_reason_after_sp_is_fine(self) -> None:
        message = parse(b"HTTP/1.1 204 \r\n\r\n")
        assert (message.start.reason, message.anomalies) == (b"", ())

    @pytest.mark.parametrize("status", [b"200\tOK", b"200  OK", b"200 OK"])
    def test_reason_separator(self, status: bytes) -> None:
        raw = response(b"Content-Length: 0", status=status)
        flagged = K.START_LINE_WHITESPACE in kinds(raw)
        assert flagged is (status != b"200 OK")
        assert parse(raw).start.reason == b"OK"

    def test_version_separator_is_checked(self) -> None:
        raw = b"HTTP/1.1\t200 OK\r\nContent-Length: 0\r\n\r\n"
        assert kinds(raw) == {K.START_LINE_WHITESPACE}

    @pytest.mark.parametrize("code", [b"099", b"600"])
    def test_out_of_range_status_is_flagged(self, code: bytes) -> None:
        raw = response(b"Content-Length: 0", status=code + b" X")
        assert kinds(raw) == {K.STATUS_CODE_OUT_OF_RANGE}

    @pytest.mark.parametrize(
        "line",
        [
            b"HTTP/1.1",
            b"HTTP/1.10 200 OK",
            b"HTTP/1.1 20",
            b"HTTP/1.1 2x0 OK",
            b"HTTP/1.1 2000 OK",
            b"HTTP/2.0 200 OK",
        ],
    )
    def test_malformed_status_lines_raise(self, line: bytes) -> None:
        raises(InvalidFieldError, line + b"\r\n\r\n")


class TestFieldLines:
    def test_order_and_duplicates_are_kept(self) -> None:
        message = parse(
            request(b"A: 1", b"B: 2", b"a:  3 ", b"Content-Length: 0")
        )
        assert [(f.name, f.value) for f in message.fields] == [
            (b"A", b"1"),
            (b"B", b"2"),
            (b"a", b"3"),
            (b"Content-Length", b"0"),
        ]

    def test_obs_fold_is_unfolded_and_flagged(self) -> None:
        """§5.2: replace each obs-fold with one or more SP."""
        raw = request(b"X: a", b" b", b"\t", b"Content-Length: 0")
        message = parse(raw)
        assert message.fields[0].value == b"a b"
        assert message.anomalies == (
            HTTPAnomaly(K.OBS_FOLD, "x", raw.index(b" b"), 2),
        )

    def test_obs_fold_can_hide_a_framing_field(self) -> None:
        raw = request(b"Transfer-Encoding:", b" chunked", body=b"0\r\n\r\n")
        message = parse(raw)
        assert message.framing.kind is HTTPFraming.CHUNKED
        assert (K.OBS_FOLD, "transfer-encoding") in {
            (a.kind, a.field) for a in message.anomalies
        }

    def test_whitespace_preceded_lines_are_ignored(self) -> None:
        """§2.2: consume each such line without further processing."""
        message = parse(request(b" Content-Length: 5", b"Host: a"))
        assert [f.name for f in message.fields] == [b"Host"]
        assert message.framing.kind is HTTPFraming.NONE
        assert {a.kind for a in message.anomalies} == {
            K.WHITESPACE_PRECEDED_LINE
        }

    def test_whitespace_before_colon_still_frames(self) -> None:
        """§5.1: a strict server rejects this; a proxy strips it."""
        raw = request(b"Transfer-Encoding : chunked", body=b"0\r\n\r\n")
        message = parse(raw)
        assert message.framing.kind is HTTPFraming.CHUNKED
        assert (K.WHITESPACE_BEFORE_COLON, "transfer-encoding") in {
            (a.kind, a.field) for a in message.anomalies
        }

    @pytest.mark.parametrize(
        "line", [b"Content-Length\x00: 5", b"Content Length: 5", b": 5"]
    )
    def test_a_non_token_name_is_excluded(self, line: bytes) -> None:
        message = parse(request(line, body=b"hello"))
        assert message.framing.kind is HTTPFraming.NONE
        assert not message.fields[0].is_token
        assert {a.kind for a in message.anomalies} == {K.INVALID_FIELD_NAME}

    def test_a_line_without_a_colon_is_excluded(self) -> None:
        message = parse(request(b"Content-Length 5", b" folded"))
        assert message.fields[0] == http._Field(
            b"Content-Length 5", b"folded", 23, False
        )
        assert {a.kind for a in message.anomalies} == {
            K.FIELD_LINE_NO_COLON,
            K.OBS_FOLD,
        }

    def test_cr_and_nul_are_replaced_and_flagged(self) -> None:
        """RFC 9110 §5.5; framing reads the replaced value."""
        raw = request(b"Transfer-Encoding: chunked\x00", body=b"0\r\n\r\n")
        message = parse(raw)
        assert message.fields[0].value == b"chunked"
        assert message.framing.kind is HTTPFraming.CHUNKED
        assert (K.CTL_IN_FIELD_VALUE, "transfer-encoding") in {
            (a.kind, a.field) for a in message.anomalies
        }
        assert parse(request(b"X: a\rb")).fields[0].value == b"a b"

    def test_other_ctls_are_retained(self) -> None:
        message = parse(request(b"X: a\x01b"))
        assert (message.fields[0].value, message.anomalies) == (b"a\x01b", ())


class TestContentLength:
    @pytest.mark.parametrize(
        "value,length,anomalies",
        [
            (b"5", 5, set()),
            (b"5,", 5, {K.LIST_EMPTY_ELEMENT}),
            (b",5", 5, {K.LIST_EMPTY_ELEMENT}),
            (b"5, ,5", 5, {K.LIST_EMPTY_ELEMENT, K.CONTENT_LENGTH_REPEATED}),
            (b"5, 5", 5, {K.CONTENT_LENGTH_REPEATED}),
            (b"005", 5, {K.NUMBER_LEADING_ZEROS}),
            (b"0", 0, set()),
            (b"00", 0, {K.NUMBER_LEADING_ZEROS}),
        ],
    )
    def test_recoverable_values(
        self, value: bytes, length: int, anomalies: set[HTTPAnomalyKind]
    ) -> None:
        raw = request(b"Content-Length: " + value, body=b"x" * length)
        message = parse(raw)
        assert message.framing == http._Framing(
            HTTPFraming.CONTENT_LENGTH, length
        )
        assert message.end == len(raw)
        assert {a.kind for a in message.anomalies} == anomalies

    def test_repeated_lines_count_as_a_list(self) -> None:
        raw = request(b"Content-Length: 5", b"Content-Length: 5", body=b"hello")
        assert parse(raw).framing.length == 5
        assert kinds(raw) == {K.CONTENT_LENGTH_REPEATED}

    @pytest.mark.parametrize(
        "value",
        [b"5, 6", b"+5", b"5_0", b"0x10", b"\xd9\xa5", b",", b"5\x0b", b""],
    )
    def test_unrecoverable_values_frame_invalid(self, value: bytes) -> None:
        """§6.3 rule 5: no body is read and the connection must close."""
        message = parse(request(b"Content-Length: " + value, body=b"hello"))
        assert message.framing.kind is HTTPFraming.INVALID
        assert message.end == message.head_len
        assert message.disposition is HTTPDisposition.CLOSE
        assert K.CONTENT_LENGTH_UNRECOVERABLE in {
            a.kind for a in message.anomalies
        }

    def test_too_many_digits_is_a_hard_limit(self) -> None:
        raw = request(b"Content-Length: 1" + b"0" * 18)
        err = raises(InvalidFieldError, raw)
        assert err.value.field == "content-length"  # type: ignore[attr-defined]
        assert (
            parse(
                request(b"Content-Length: " + b"0" * 30 + b"1", body=b"x")
            ).framing.length
            == 1
        )

    def test_a_short_body_needs_more(self) -> None:
        raw = request(b"Content-Length: 10", body=b"abc")
        err = raises(TruncatedHeaderError, raw)
        assert err.value.expected == len(raw) + 7  # type: ignore[attr-defined]
        raises(InvalidFieldError, raw, closed=True)


class TestTransferEncoding:
    @pytest.mark.parametrize(
        "value,framing,anomalies",
        [
            (b"chunked", HTTPFraming.CHUNKED, set()),
            (b"Chunked", HTTPFraming.CHUNKED, set()),
            (b"gzip, chunked", HTTPFraming.CHUNKED, set()),
            (b"chunked, chunked", HTTPFraming.CHUNKED, {K.TE_CHUNKED_REPEATED}),
            (b"chunked,", HTTPFraming.CHUNKED, {K.LIST_EMPTY_ELEMENT}),
            (
                b"chunked, gzip",
                HTTPFraming.INVALID,
                {K.REQUEST_FRAMING_UNDETERMINABLE},
            ),
            (
                b"chunked;q=1",
                HTTPFraming.INVALID,
                {K.TE_PARAMETERS, K.REQUEST_FRAMING_UNDETERMINABLE},
            ),
            (
                b"chunked\x0b",
                HTTPFraming.INVALID,
                {K.TE_INVALID_OCTET, K.REQUEST_FRAMING_UNDETERMINABLE},
            ),
            (
                b"chunked\xa0",
                HTTPFraming.INVALID,
                {K.TE_INVALID_OCTET, K.REQUEST_FRAMING_UNDETERMINABLE},
            ),
            (
                b"",
                HTTPFraming.INVALID,
                {K.LIST_EMPTY_ELEMENT, K.REQUEST_FRAMING_UNDETERMINABLE},
            ),
            (
                b",",
                HTTPFraming.INVALID,
                {K.LIST_EMPTY_ELEMENT, K.REQUEST_FRAMING_UNDETERMINABLE},
            ),
        ],
    )
    def test_request_codings(
        self,
        value: bytes,
        framing: HTTPFraming,
        anomalies: set[HTTPAnomalyKind],
    ) -> None:
        body = b"0\r\n\r\n" if framing is HTTPFraming.CHUNKED else b""
        message = parse(request(b"Transfer-Encoding: " + value, body=body))
        assert message.framing.kind is framing
        assert {a.kind for a in message.anomalies} == anomalies

    def test_a_response_without_final_chunked_runs_until_close(self) -> None:
        raw = response(b"Transfer-Encoding: gzip", body=b"data")
        raises(TruncatedHeaderError, raw)
        message = parse(raw, closed=True)
        assert message.framing.kind is HTTPFraming.UNTIL_CLOSE
        assert message.end == len(raw)
        assert message.disposition is HTTPDisposition.CLOSE
        assert {a.kind for a in message.anomalies} == {
            K.RESPONSE_TE_NOT_CHUNKED
        }

    def test_te_overrides_cl(self) -> None:
        """§6.3 rule 3: the classic request-smuggling signature."""
        raw = request(
            b"Content-Length: 4",
            b"Transfer-Encoding: chunked",
            body=b"0\r\n\r\n",
        )
        message = parse(raw)
        assert message.framing.kind is HTTPFraming.CHUNKED
        assert message.end == len(raw)
        assert message.disposition is HTTPDisposition.CLOSE
        assert {a.kind for a in message.anomalies} == {K.CL_AND_TE}

    def test_te_overrides_an_unrecoverable_cl(self) -> None:
        raw = request(
            b"Content-Length: 4, 5",
            b"Transfer-Encoding: chunked",
            body=b"0\r\n\r\n",
        )
        assert kinds(raw) == {K.CL_AND_TE, K.INVALID_CONTENT_LENGTH}
        long_cl = request(
            b"Content-Length: 1" + b"0" * 30,
            b"Transfer-Encoding: chunked",
            body=b"0\r\n\r\n",
        )
        assert parse(long_cl).framing.kind is HTTPFraming.CHUNKED

    def test_te_in_http10_closes(self) -> None:
        raw = request(
            b"Transfer-Encoding: chunked",
            b"Connection: keep-alive",
            body=b"0\r\n\r\n",
            line=b"POST / HTTP/1.0",
        )
        message = parse(raw)
        assert {a.kind for a in message.anomalies} == {K.TE_IN_HTTP10}
        assert message.disposition is HTTPDisposition.CLOSE


class TestBodylessResponses:
    @pytest.mark.parametrize("status", [b"100 Continue", b"204 No Content"])
    def test_framing_fields_on_1xx_and_204_are_flagged(
        self, status: bytes
    ) -> None:
        raw = response(b"Content-Length: 5", status=status)
        message = parse(raw)
        assert (message.framing.kind, message.end) == (
            HTTPFraming.NONE,
            len(raw),
        )
        assert message.anomalies == (
            HTTPAnomaly(
                K.FRAMING_FIELD_MISPLACED, "content-length", len(status) + 11, 1
            ),
        )

    @pytest.mark.parametrize("status", [b"304 Not Modified", b"200 OK"])
    def test_304_and_head_carry_cl_legitimately(self, status: bytes) -> None:
        raw = response(b"Content-Length: 1234", status=status)
        method = None if status.startswith(b"304") else "HEAD"
        message = parse(raw, request_method=method)
        assert (message.framing.kind, message.end) == (
            HTTPFraming.NONE,
            len(raw),
        )
        assert message.anomalies == ()

    def test_a_connect_2xx_is_a_tunnel(self) -> None:
        raw = response(b"Transfer-Encoding: chunked")
        message = parse(raw, request_method="CONNECT")
        assert message.framing.kind is HTTPFraming.NONE
        assert message.disposition is HTTPDisposition.TUNNEL
        assert message.request_method == b"CONNECT"
        assert {a.kind for a in message.anomalies} == {
            K.FRAMING_FIELD_MISPLACED
        }

    def test_a_connect_4xx_is_an_ordinary_response(self) -> None:
        raw = response(b"Content-Length: 2", body=b"no", status=b"407 Auth")
        message = parse(raw, request_method="CONNECT")
        assert message.request_method is None
        assert message.end == len(raw)

    def test_101_is_a_tunnel(self) -> None:
        raw = response(b"Upgrade: websocket", status=b"101 Switching")
        assert parse(raw).disposition is HTTPDisposition.TUNNEL


class TestRequestMethodContext:
    @pytest.mark.parametrize("method", ["", "GE T", "GéT", "G\x00T"])
    def test_a_non_token_method_is_misuse(self, method: str) -> None:
        err = raises(InvalidFieldError, response(), request_method=method)
        assert err.value.field == "request_method"  # type: ignore[attr-defined]

    def test_a_method_for_a_request_is_misuse(self) -> None:
        raises(InvalidFieldError, request(), request_method="GET")

    @pytest.mark.parametrize(
        "method,kept", [("GET", None), ("HEAD", b"HEAD"), ("head", None)]
    )
    def test_only_framing_relevant_methods_are_kept(
        self, method: str, kept: bytes | None
    ) -> None:
        """Methods are case-sensitive (RFC 9110 §9.1)."""
        raw = response(b"Content-Length: 0")
        assert parse(raw, request_method=method).request_method == kept


class TestUntilClose:
    def test_a_response_without_length_needs_close(self) -> None:
        raw = response(body=b"<html>")
        err = raises(TruncatedHeaderError, raw)
        assert err.value.expected is None  # type: ignore[attr-defined]
        message = parse(raw, closed=True)
        assert message.framing.kind is HTTPFraming.UNTIL_CLOSE
        assert message.content_spans == ((len(raw) - 6, len(raw)),)

    def test_a_request_without_length_has_no_body(self) -> None:
        """§6.3 rule 7: requests are never close-delimited."""
        raw = request(body=b"next request")
        message = parse(raw)
        assert (message.framing.kind, message.end) == (
            HTTPFraming.NONE,
            len(raw) - 12,
        )
        assert message.content_spans == ()


def chunked(body: bytes, *fields: bytes) -> bytes:
    return response(b"Transfer-Encoding: chunked", *fields, body=body)


class TestChunked:
    def test_spans_and_end(self) -> None:
        body = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
        raw = chunked(body) + b"HTTP/1.1 ..."
        message = parse(raw)
        start = raw.index(body)
        assert message.end == start + len(body)
        content = b"".join(raw[a:b] for a, b in message.content_spans)
        assert content == b"hello world"
        assert (message.anomalies, message.trailers) == ((), ())

    @pytest.mark.parametrize(
        "line,anomalies",
        [
            (b"5;a=b", {K.CHUNK_EXTENSION}),
            (b'5 ; a = "q\\"x" ;b', {K.CHUNK_EXTENSION}),
            (b"5;", {K.CHUNK_EXTENSION, K.CHUNK_EXTENSION_INVALID}),
            (b"5;a=", {K.CHUNK_EXTENSION, K.CHUNK_EXTENSION_INVALID}),
            (b'5;a="x', {K.CHUNK_EXTENSION, K.CHUNK_EXTENSION_INVALID}),
            (b'5;a="\\\x01"', {K.CHUNK_EXTENSION, K.CHUNK_EXTENSION_INVALID}),
            (b'5;a="\\', {K.CHUNK_EXTENSION, K.CHUNK_EXTENSION_INVALID}),
            (b'5;a="\x01"', {K.CHUNK_EXTENSION, K.CHUNK_EXTENSION_INVALID}),
            (b"5;a;", {K.CHUNK_EXTENSION, K.CHUNK_EXTENSION_INVALID}),
            (
                b"5;a\nb",
                {
                    K.CHUNK_EXTENSION,
                    K.CHUNK_LINE_BARE_LF,
                    K.CHUNK_EXTENSION_INVALID,
                },
            ),
            (b"5 ", {K.CHUNK_SIZE_TRAILING_WHITESPACE}),
            (b"05", {K.NUMBER_LEADING_ZEROS}),
        ],
    )
    def test_chunk_lines(
        self, line: bytes, anomalies: set[HTTPAnomalyKind]
    ) -> None:
        """§7.1.1 chunk-ext grammar; the TERM.EXT class reads a lone LF
        as part of the line, through to the next CRLF."""
        raw = chunked(line + b"\r\nhello\r\n0\r\n\r\n")
        message = parse(raw)
        assert message.end == len(raw)
        assert {a.kind for a in message.anomalies} == anomalies

    def test_anomalies_aggregate(self) -> None:
        raw = chunked(b"1;x\r\na\r\n" * 1000 + b"0\r\n\r\n")
        (anomaly,) = parse(raw).anomalies
        assert (anomaly.kind, anomaly.occurrences) == (K.CHUNK_EXTENSION, 1000)

    @pytest.mark.parametrize("line", [b"x", b"", b"5 x", b"-5"])
    def test_malformed_chunk_size_raises(self, line: bytes) -> None:
        err = raises(
            InvalidFieldError, chunked(line + b"\r\nhello\r\n0\r\n\r\n")
        )
        assert err.value.field == "chunk-size"  # type: ignore[attr-defined]

    def test_chunk_data_must_end_in_crlf(self) -> None:
        """The SPILL classes: oversized data or a non-CRLF terminator."""
        raw = chunked(b"5\r\nhelloXX\r\n0\r\n\r\n")
        err = raises(InvalidFieldError, raw)
        assert err.value.offset == raw.index(b"XX")  # type: ignore[attr-defined]
        raises(InvalidFieldError, chunked(b"5\r\nhello\n0\r\n\r\n"))

    def test_chunk_size_digit_cap(self) -> None:
        raises(InvalidFieldError, chunked(b"1" + b"0" * 16 + b"\r\n"))
        raw = chunked(b"0" * 40 + b"1\r\nx\r\n0\r\n\r\n")
        assert parse(raw).end == len(raw)

    def test_chunk_line_length_cap(self) -> None:
        line = b"1;" + b"a" * MAX_HEAD_BYTES
        raises(InvalidFieldError, chunked(line + b"\r\nx\r\n0\r\n\r\n"))

    def test_total_extension_cap(self) -> None:
        chunk = b"1;" + b"a" * 1000 + b"\r\nx\r\n"
        raw = chunked(chunk * 70 + b"0\r\n\r\n")
        err = raises(InvalidFieldError, raw)
        assert err.value.field == "chunk-ext"  # type: ignore[attr-defined]

    @pytest.mark.parametrize(
        "body,expected",
        [(b"5", None), (b"5\r\nhel", 10), (b"5\r\nhello\r\n0\r\n", None)],
    )
    def test_incomplete_bodies(self, body: bytes, expected: int | None) -> None:
        raw = chunked(body)
        err = raises(TruncatedHeaderError, raw)
        start = len(raw) - len(body)
        want = None if expected is None else start + expected
        assert err.value.expected == want  # type: ignore[attr-defined]
        raises(InvalidFieldError, raw, closed=True)

    def test_trailers(self) -> None:
        raw = chunked(b"0\r\nExpires: never\nContent-Length: 9\r\n\r\n")
        message = parse(raw)
        assert message.end == len(raw)
        assert [f.name for f in message.trailers] == [
            b"Expires",
            b"Content-Length",
        ]
        assert {(a.kind, a.field) for a in message.anomalies} == {
            (K.BARE_LF, None),
            (K.FRAMING_FIELD_MISPLACED, "content-length"),
        }

    def test_trailer_section_cap(self) -> None:
        trailer = b"X: " + b"a" * MAX_HEAD_BYTES + b"\r\n\r\n"
        raises(InvalidFieldError, chunked(b"0\r\n" + trailer))


class TestDisposition:
    @pytest.mark.parametrize(
        "line,fields,disposition",
        [
            (b"GET / HTTP/1.1", (), HTTPDisposition.CONTINUE),
            (b"GET / HTTP/1.1", (b"Connection: Close",), HTTPDisposition.CLOSE),
            (b"GET / HTTP/1.0", (), HTTPDisposition.CLOSE),
            (
                b"GET / HTTP/1.0",
                (b"Connection: keep-alive",),
                HTTPDisposition.CONTINUE,
            ),
        ],
    )
    def test_persistence(
        self,
        line: bytes,
        fields: tuple[bytes, ...],
        disposition: HTTPDisposition,
    ) -> None:
        assert parse(request(*fields, line=line)).disposition is disposition

    def test_connection_naming_a_framing_field_is_flagged(self) -> None:
        """RFC 9110 §7.6.1: an intermediary strips the named field."""
        raw = request(b"Connection: close, Transfer-Encoding")
        assert kinds(raw) == {K.CONNECTION_LISTS_FRAMING_FIELD}
