"""Unit tests for the shared kind/length/value option-TLV walker.

Exercises :func:`netprotocols._tlv.walk_kind_length_value` directly, at
the level of the walker's own parameters, independent of the three call
sites (TCP, IPv4, and the IPv6 options headers) whose protocol-level
tests already cover it indirectly — see tests/test_tcp.py,
tests/test_ip.py, and tests/test_ipv6_ext.py.
"""

import random
from collections.abc import Iterator

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

    @pytest.mark.parametrize("min_option_length", [None, 0, 1])
    @pytest.mark.parametrize("declared_length", [0, 1])
    def test_length_includes_header_enforces_a_floor_of_two_regardless(
        self, min_option_length, declared_length
    ):
        """When the length counts its own two header bytes, a declared
        length below 2 can never advance the cursor (0 leaves it in
        place; 1 backs it up into the length byte) -- this floor is
        structural, so it applies even if a caller passes no
        min_option_length, or one weaker than 2. Regression against a
        hang: every one of these must raise, never loop forever."""
        with pytest.raises(InvalidFieldError) as excinfo:
            walk(
                bytes([2, declared_length]),
                min_option_length=min_option_length,
            )
        err = excinfo.value
        assert err.expected == ">=2"
        assert err.actual == declared_length

    def test_a_floor_stronger_than_two_wins_when_length_includes_header(
        self,
    ):
        """The structural floor of 2 is a minimum, not a replacement: a
        caller's stricter min_option_length still applies on top of it.
        No current call site passes more than 2, so only a direct test
        pins this (it kills the mutant that drops the caller's floor)."""
        with pytest.raises(InvalidFieldError) as excinfo:
            walk(b"\x05\x02", min_option_length=3)
        err = excinfo.value
        assert err.expected == ">=3"
        assert err.actual == 2

    def test_a_floor_applies_when_length_excludes_header(self):
        """Without the structural floor, a caller's min_option_length is
        the only floor there is, so it must still be enforced."""
        with pytest.raises(InvalidFieldError) as excinfo:
            walk(
                b"\x05\x00",
                lone_byte_kinds=frozenset(),
                terminator_kind=None,
                min_option_length=1,
                length_includes_header=False,
            )
        err = excinfo.value
        assert err.expected == ">=1"
        assert err.actual == 0


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


def _byte_wide_walk_before_width(
    raw: bytes,
    *,
    lone_byte_kinds: frozenset[int],
    terminator_kind: int | None,
    min_option_length: int | None,
    length_includes_header: bool,
    protocol: type,
    field: str = "options",
) -> Iterator[tuple[int, bytes]]:
    """The walker as it stood before it took a ``width`` (2.4.0),
    verbatim but for this docstring: the oracle the byte-wide callers'
    behaviour is pinned against."""
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
        effective_min = min_option_length
        if length_includes_header:
            effective_min = (
                2 if effective_min is None else max(2, effective_min)
            )
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


def _outcome(walker: object, raw: bytes, **kwargs: object) -> object:
    """Everything a caller can observe of one walk: the pairs yielded
    up to the point it stopped, and the error it stopped on, if any,
    with every structured field and the message."""
    pairs: list[tuple[int, bytes]] = []
    try:
        for pair in walker(raw, **kwargs):  # type: ignore[operator]
            pairs.append(pair)
    except InvalidFieldError as err:
        return pairs, (
            str(err),
            err.protocol,
            err.field,
            err.offset,
            err.expected,
            err.actual,
        )
    return pairs, None


#: A small alphabet, so lone bytes, the terminator, lengths 0-3 and
#: lengths that overrun turn up far more often than in random bytes.
_ALPHABET = (0, 1, 2, 3, 4, 5, 0x40, 0xFF)


def _byte_wide_cases() -> list[tuple[bytes, dict[str, object]]]:
    """A fixed, seeded sample of inputs and parameter combinations.

    Deterministic rather than a hypothesis property: this file is in the
    mutation audit's test selection (pyproject.toml's [tool.mutmut]),
    which needs every run of a test to exercise the same inputs."""
    rng = random.Random(184)
    cases = []
    for _ in range(3000):
        size = rng.randrange(0, 24)
        if rng.random() < 0.8:
            raw = bytes(rng.choice(_ALPHABET) for _ in range(size))
        else:
            raw = bytes(rng.randrange(256) for _ in range(size))
        kwargs: dict[str, object] = {
            "lone_byte_kinds": rng.choice(
                [frozenset(), frozenset({0}), frozenset({0, 1})]
            ),
            "terminator_kind": rng.choice([None, 0, 1]),
            "min_option_length": rng.choice([None, 0, 1, 2, 3, 4]),
            "length_includes_header": rng.random() < 0.5,
            "protocol": _Protocol,
            "field": rng.choice(["options", "sections"]),
        }
        cases.append((raw, kwargs))
    return cases


class TestByteWideBehaviourIsUnchanged:
    """Generalizing the walker to a ``width`` must leave every byte-wide
    caller (TCP, IPv4, the IPv6 options headers) exactly as it was: the
    same pairs, the same error, message and structured fields included,
    for any bytes and any combination of the other parameters."""

    def test_matches_the_walker_before_width(self) -> None:
        for raw, kwargs in _byte_wide_cases():
            assert _outcome(walk_kind_length_value, raw, **kwargs) == (
                _outcome(_byte_wide_walk_before_width, raw, **kwargs)
            ), (raw, kwargs)

    def test_the_sample_reaches_every_outcome(self) -> None:
        """The sample is only as good as what it reaches: every error
        the walker raises, and walks that yield something and end
        cleanly."""
        messages = set()
        clean = 0
        for raw, kwargs in _byte_wide_cases():
            pairs, error = _outcome(_byte_wide_walk_before_width, raw, **kwargs)
            if error is None:
                clean += bool(pairs)
            else:
                messages.add(str(error[0]).split(" ", 2)[2][:20])
        assert clean > 100
        assert messages == {
            "missing its length b",
            "length must be at le",
            "value runs past the ",
            "data runs past the h",
        }


def walk16(raw: bytes, **overrides: object) -> list[tuple[int, bytes]]:
    """Run the walker in PIM Hello's shape: 2-byte type and length, the
    length counting only the value, nothing lone, no terminator, no
    floor (RFC 7761 §4.9.2)."""
    kwargs: dict[str, object] = {
        "lone_byte_kinds": frozenset(),
        "terminator_kind": None,
        "min_option_length": None,
        "length_includes_header": False,
        "protocol": _Protocol,
        "width": 2,
    }
    kwargs.update(overrides)
    return list(walk_kind_length_value(raw, **kwargs))  # type: ignore[arg-type]


class TestTwoByteWidth:
    def test_type_and_length_read_big_endian(self):
        assert walk16(b"\x01\x02\x00\x02\x00\x69\x00\x14\x00\x00") == [
            (0x0102, b"\x00\x69"),
            (0x14, b""),
        ]

    def test_a_length_above_255(self):
        assert walk16(b"\x00\x18\x01\x00" + bytes(256)) == [(0x18, bytes(256))]

    def test_lone_kinds_advance_by_the_width(self):
        assert walk16(
            b"\x00\x07\x00\x01\x00\x01\xaa", lone_byte_kinds=frozenset({7})
        ) == [
            (7, b""),
            (1, b"\xaa"),
        ]

    @pytest.mark.parametrize("remaining", [1, 2, 3])
    def test_a_cut_type_or_length_raises(self, remaining: int):
        """Fewer than four bytes cannot hold a type and a length."""
        with pytest.raises(InvalidFieldError) as excinfo:
            walk16(b"\x00\x01\x00\x00" + b"\x00\x14\x00"[:remaining])
        err = excinfo.value
        assert err.offset == 4
        assert str(err) == "_Protocol option missing its length field"

    def test_value_running_past_the_buffer_raises(self):
        with pytest.raises(InvalidFieldError) as excinfo:
            walk16(b"\x00\x01\x00\x02\x00\x00\x00\x13\x00\x04\xff")
        err = excinfo.value
        assert err.offset == 6
        assert str(err) == "_Protocol option data runs past the header"

    def test_length_that_counts_the_header_floors_at_four(self):
        """With the length counting the type and length, the structural
        floor is their size, four bytes, not two."""
        with pytest.raises(InvalidFieldError) as excinfo:
            walk16(b"\x00\x01\x00\x03\x00", length_includes_header=True)
        err = excinfo.value
        assert err.expected == ">=4"
        assert err.actual == 3
        assert walk16(
            b"\x00\x01\x00\x06\xca\xfe", length_includes_header=True
        ) == [(1, b"\xca\xfe")]
        with pytest.raises(InvalidFieldError) as excinfo:
            walk16(b"\x00\x01\x00\x07\xca\xfe", length_includes_header=True)
        assert str(excinfo.value) == (
            "_Protocol option value runs past the options bytes"
        )
