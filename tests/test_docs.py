"""Tests that documented facts about the corpus match the corpus.

`ARCHITECTURE.md` claimed "93 frames across 16 scenarios" long after the
corpus reached 97 across 17, because three separate files each restated
the figure and only one was updated. ARCHITECTURE.md now defers to the
MANIFEST; these tests hold the two statements that remain — the
MANIFEST's own, and the README's — against the fixtures themselves.

`test_corpus.py` already gates on the corpus being large enough; what it
cannot catch is prose drifting away from it.
"""

import re
from pathlib import Path

import pytest

from conftest import FIXTURES, corpus_frames

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = FIXTURES / "MANIFEST.md"
README = ROOT / "README.md"
ARCHITECTURE = ROOT / "ARCHITECTURE.md"

ACTUAL_FRAMES = len(corpus_frames())
ACTUAL_SCENARIOS = len(list(FIXTURES.glob("*.pcap")))


class TestCorpusFiguresInDocs:
    def test_manifest_states_the_real_counts(self) -> None:
        """MANIFEST.md is the source of truth and must be accurate."""
        match = re.search(
            r"(\d+) frames across (\d+)\s+scenarios", MANIFEST.read_text()
        )
        assert match is not None, (
            "MANIFEST.md no longer states 'N frames across M scenarios'; "
            "update this test if the wording changed deliberately"
        )
        frames, scenarios = int(match.group(1)), int(match.group(2))
        assert (frames, scenarios) == (ACTUAL_FRAMES, ACTUAL_SCENARIOS), (
            f"MANIFEST.md says {frames} frames across {scenarios} "
            f"scenarios; tests/fixtures/ holds {ACTUAL_FRAMES} frames "
            f"across {ACTUAL_SCENARIOS} pcaps"
        )

    def test_readme_states_the_real_counts(self) -> None:
        """The README's front-page figure must match too."""
        text = README.read_text()
        frames = re.search(r"(\d+)-frame corpus", text)
        scenarios = re.search(r"across (\d+) scenarios", text)
        assert frames is not None and scenarios is not None, (
            "README.md no longer states an 'N-frame corpus ... across M "
            "scenarios'; update this test if the wording changed"
        )
        assert (int(frames.group(1)), int(scenarios.group(1))) == (
            ACTUAL_FRAMES,
            ACTUAL_SCENARIOS,
        ), (
            f"README.md says {frames.group(1)} frames across "
            f"{scenarios.group(1)} scenarios; tests/fixtures/ holds "
            f"{ACTUAL_FRAMES} frames across {ACTUAL_SCENARIOS} pcaps"
        )

    def test_architecture_does_not_restate_the_counts(self) -> None:
        """Only the MANIFEST and README should carry the figures.

        A third copy is what drifted last time, so this fails rather
        than inviting someone to re-add one and keep it in sync by hand.
        """
        stale = re.search(
            r"\d+ frames across \d+\s+scenarios", ARCHITECTURE.read_text()
        )
        assert stale is None, (
            f"ARCHITECTURE.md restates the corpus counts "
            f"({stale.group(0) if stale else ''}); it should point at "
            f"tests/fixtures/MANIFEST.md instead of duplicating them"
        )

    @pytest.mark.parametrize(
        "module", ["vlan.py", "gre.py", "dhcp.py", "ipv6_ext.py"]
    )
    def test_layout_map_lists_every_shipped_module(self, module: str) -> None:
        """The layout map went stale by omission, not by wrong values."""
        assert module in ARCHITECTURE.read_text(), (
            f"ARCHITECTURE.md's layout map does not mention {module}, "
            f"which ships in src/netprotocols/"
        )
