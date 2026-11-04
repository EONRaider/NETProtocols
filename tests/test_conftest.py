"""Tests for the allocation tracing helper in conftest.py."""

import tracemalloc
from collections.abc import Iterator

import pytest

from conftest import allocation_peak


@pytest.fixture
def tracing_off() -> Iterator[None]:
    """Run the test with tracemalloc off and restore its state after."""
    was_tracing = tracemalloc.is_tracing()
    frames = tracemalloc.get_traceback_limit()
    tracemalloc.stop()
    yield
    if was_tracing:
        tracemalloc.start(frames)


@pytest.fixture
def tracing_on() -> Iterator[None]:
    """Run the test with tracemalloc on and restore its state after."""
    was_tracing = tracemalloc.is_tracing()
    if not was_tracing:
        tracemalloc.start()
    yield
    if not was_tracing:
        tracemalloc.stop()


SIZE = 1 << 20


class TestAllocationPeak:
    @pytest.mark.usefixtures("tracing_off")
    def test_starts_tracing_and_stops_it_on_exit(self):
        """Trace inside the block and leave tracing off after it."""
        with allocation_peak() as traced:
            assert tracemalloc.is_tracing()
            block = bytes(SIZE)
            del block
        assert not tracemalloc.is_tracing()
        assert SIZE // 2 < traced.peak < 2 * SIZE

    @pytest.mark.usefixtures("tracing_on")
    def test_leaves_tracing_on_that_was_already_on(self):
        """Keep tracing that was on before the block on after it."""
        with allocation_peak() as traced:
            block = bytes(SIZE)
            del block
        assert tracemalloc.is_tracing()
        assert SIZE // 2 < traced.peak < 2 * SIZE

    @pytest.mark.usefixtures("tracing_on")
    def test_does_not_count_memory_allocated_before_entry(self):
        """Measure the peak from the block's entry, not from the start."""
        held = bytes(4 * SIZE)
        with allocation_peak() as traced:
            pass
        assert traced.peak < SIZE
        del held

    @pytest.mark.usefixtures("tracing_on")
    def test_does_not_count_an_earlier_peak(self):
        """Reset the peak on entry, so one reached before is not counted."""
        block = bytes(4 * SIZE)
        del block
        with allocation_peak() as traced:
            pass
        assert traced.peak < SIZE

    @pytest.mark.usefixtures("tracing_off")
    def test_records_the_peak_and_stops_when_the_block_raises(self):
        """Set ``peak`` and stop tracing it started when the block raises."""
        with pytest.raises(ValueError), allocation_peak() as traced:
            block = bytes(SIZE)
            del block
            raise ValueError
        assert not tracemalloc.is_tracing()
        assert SIZE // 2 < traced.peak < 2 * SIZE

    @pytest.mark.usefixtures("tracing_on")
    def test_leaves_tracing_on_when_the_block_raises(self):
        """Keep tracing that was already on when the block raises."""
        with pytest.raises(ValueError), allocation_peak():
            raise ValueError
        assert tracemalloc.is_tracing()
