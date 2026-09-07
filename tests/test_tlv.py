"""Unit tests for the shared kind/length/value option-TLV walker.

Exercises :func:`netprotocols._tlv.walk_kind_length_value` directly, at
the level of the walker's own parameters, independent of the three call
sites (TCP, IPv4, and the IPv6 options headers) whose protocol-level
tests already cover it indirectly — see tests/test_tcp.py,
tests/test_ip.py, and tests/test_ipv6_ext.py.
"""

import pytest

from netprotocols import InvalidFieldError
from netprotocols._tlv import walk_kind_length_value


class _Protocol:
    """A stand-in protocol class: the walker only ever reads its name
    (for the error message) and identity (for ``err.protocol``), never
    an instance of it."""


def walk(raw: bytes, **overrides: object) -> list[tuple[int, bytes]]:
    """Run the walker with TCP/IPv4-shaped defaults (EOL/NOP as the
    lone bytes, EOL terminating, a 2-byte length floor, and a length
    byte that counts itself), overridable per test."""
    kwargs: dict[str, object] = {
        "lone_byte_kinds": frozenset({0, 1}),
        "terminator_kind": 0,
        "min_option_length": 2,
        "length_includes_header": True,
        "protocol": _Protocol,
    }
    kwargs.update(overrides)
    return list(walk_kind_length_value(raw, **kwargs))  # type: ignore[arg-type]


class TestLoneByteKinds:
    def test_lone_byte_kind_yields_empty_data(self):
        assert walk(b"\x01\x01") == [(1, b""), (1, b"")]

    def test_multiple_lone_bytes_in_a_row(self):
        assert walk(b"\x01\x01\x01") == [(1, b""), (1, b""), (1, b"")]

    def test_lone_byte_kind_without_terminator_keeps_walking(self):
        """IPv6 shape: Pad1 (0) is a lone byte but not a terminator, so
        a TLV option following it still parses."""
        assert walk(
            b"\x00\x05\x02\xca\xfe",
            lone_byte_kinds=frozenset({0}),
            terminator_kind=None,
            min_option_length=None,
            length_includes_header=False,
        ) == [(0, b""), (5, b"\xca\xfe")]


class TestTerminator:
    def test_terminator_stops_the_walk(self):
        """A terminator kind ends the walk right there, even with more
        bytes left in the buffer: those bytes are padding, not more
        options, and are never inspected — not even to notice they
        would otherwise be malformed TLV data."""
        assert walk(b"\x00\xff\xff\xff") == [(0, b"")]

    def test_terminator_as_the_only_byte(self):
        assert walk(b"\x00") == [(0, b"")]

    def test_non_terminator_lone_byte_does_not_stop(self):
        assert walk(b"\x01\x00") == [(1, b""), (0, b"")]

    def test_no_terminator_configured_never_stops_early(self):
        """IPv6 shape: with terminator_kind=None, the lone-byte kind
        (Pad1) never ends the walk, however many appear."""
        assert walk(
            b"\x00\x00\x00",
            lone_byte_kinds=frozenset({0}),
            terminator_kind=None,
            min_option_length=None,
            length_includes_header=False,
        ) == [(0, b""), (0, b""), (0, b"")]


class TestMinOptionLength:
    def test_length_below_minimum_raises(self):
        with pytest.raises(InvalidFieldError) as excinfo:
            walk(b"\x02\x01\x00")
        err = excinfo.value
        assert err.protocol is _Protocol
        assert err.field == "options"
        assert err.offset == 0
        assert err.expected == ">=2"
        assert err.actual == 1
        assert str(err) == "_Protocol option length must be at least 2, got 1"

    def test_length_equal_to_the_minimum_is_accepted(self):
        assert walk(b"\x02\x02") == [(2, b"")]

    def test_no_floor_when_min_option_length_is_none(self):
        """IPv6 has no length floor: a declared length of 0 is legal."""
        assert walk(
            b"\x05\x00",
            lone_byte_kinds=frozenset(),
            terminator_kind=None,
            min_option_length=None,
            length_includes_header=False,
        ) == [(5, b"")]


class TestLengthIncludesHeaderTrue:
    """TCP/IPv4 shape: the length byte counts the kind and length bytes
    themselves, so the data slice is ``raw[cursor+2:cursor+length]``
    and the cursor advances by ``length``."""

    def test_data_slice_excludes_the_two_header_bytes(self):
        assert walk(b"\x02\x04\xca\xfe") == [(2, b"\xca\xfe")]

    def test_cursor_advances_by_the_declared_length(self):
        assert walk(b"\x02\x04\xca\xfe\x01") == [(2, b"\xca\xfe"), (1, b"")]

    def test_length_running_past_the_buffer_raises(self):
        with pytest.raises(InvalidFieldError) as excinfo:
            walk(b"\x02\x05\xca\xfe")
        err = excinfo.value
        assert err.protocol is _Protocol
        assert err.field == "options"
        assert err.offset == 0
        assert str(err) == "_Protocol option value runs past the options bytes"


class TestLengthIncludesHeaderFalse:
    """IPv6 shape: the length byte counts only the trailing data, so
    the data slice is ``raw[cursor+2:cursor+2+length]`` and the cursor
    advances by ``2 + length``."""

    def false_mode(self, raw: bytes) -> list[tuple[int, bytes]]:
        return walk(
            raw,
            lone_byte_kinds=frozenset(),
            terminator_kind=None,
            min_option_length=None,
            length_includes_header=False,
        )

    def test_data_slice_is_exactly_the_declared_length(self):
        assert self.false_mode(b"\x05\x02\xca\xfe") == [(5, b"\xca\xfe")]

    def test_cursor_advances_by_two_plus_the_declared_length(self):
        assert self.false_mode(b"\x05\x02\xca\xfe\x01\x01\x00") == [
            (5, b"\xca\xfe"),
            (1, b"\x00"),
        ]

    def test_length_running_past_the_buffer_raises(self):
        with pytest.raises(InvalidFieldError) as excinfo:
            self.false_mode(b"\x05\x03\xca\xfe")
        err = excinfo.value
        assert err.protocol is _Protocol
        assert err.field == "options"
        assert err.offset == 0
        assert str(err) == "_Protocol option data runs past the header"


class TestMissingLengthByte:
    def test_kind_with_no_following_byte_raises(self):
        with pytest.raises(InvalidFieldError) as excinfo:
            walk(b"\x02")
        err = excinfo.value
        assert err.protocol is _Protocol
        assert err.field == "options"
        assert err.offset == 0
        assert str(err) == "_Protocol option missing its length byte"

    def test_offset_is_relative_to_the_options_bytes(self):
        """A prior option shifts where the failure is reported."""
        with pytest.raises(InvalidFieldError) as excinfo:
            walk(b"\x01\x02")
        assert excinfo.value.offset == 1


class TestFieldParameter:
    def test_field_defaults_to_options(self):
        with pytest.raises(InvalidFieldError) as excinfo:
            walk(b"\x02")
        assert excinfo.value.field == "options"

    def test_field_is_overridable(self):
        with pytest.raises(InvalidFieldError) as excinfo:
            walk(b"\x02", field="sections")
        assert excinfo.value.field == "sections"


class TestEmptyInput:
    def test_empty_buffer_yields_nothing(self):
        assert walk(b"") == []


class TestIsAGenerator:
    def test_no_error_before_iteration_begins(self):
        """``walk_kind_length_value`` is a generator function: calling
        it builds the generator object without running any of its
        body, so a bad buffer only raises once a caller starts pulling
        values from it."""
        generator = walk_kind_length_value(
            b"\x02",
            lone_byte_kinds=frozenset({0, 1}),
            terminator_kind=0,
            min_option_length=2,
            length_includes_header=True,
            protocol=_Protocol,
        )
        with pytest.raises(InvalidFieldError):
            next(generator)
