"""Tests that documented facts about the corpus match the corpus.

`ARCHITECTURE.md` claimed "93 frames across 16 scenarios" long after the
corpus reached 97 across 17, because three separate files each restated
the figure and only one was updated. ARCHITECTURE.md now defers to the
MANIFEST; these tests hold the two statements that remain — the
MANIFEST's own, and the README's — against the fixtures themselves.

`test_corpus.py` already gates on the corpus being large enough; what it
cannot catch is prose drifting away from it.
"""

import doctest
import inspect
import re
import textwrap
from pathlib import Path

import pytest

import netprotocols.registry as registry_module
from conftest import FIXTURES, corpus_frames
from netprotocols import HTTP, HTTPDisposition, HTTPFraming, Protocol
from netprotocols.registry import (
    DEFAULT,
    TABLE_ETHERTYPE,
    TABLE_IP_PROTO,
)

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = FIXTURES / "MANIFEST.md"
README = ROOT / "README.md"
ARCHITECTURE = ROOT / "ARCHITECTURE.md"
CLAIMS = ROOT / "docs" / "CLAIMS.md"

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
        "module",
        [
            "vlan.py",
            "gre.py",
            "esp.py",
            "ah.py",
            "dhcp.py",
            "http.py",
            "vxlan.py",
            "ipv6_ext.py",
            "_tlv.py",
            "sctp.py",
            "rip.py",
            "vrrp.py",
            "bgp.py",
            "mpls.py",
            "tftp.py",
            "radius.py",
        ],
    )
    def test_layout_map_lists_every_shipped_module(self, module: str) -> None:
        """The layout map went stale by omission, not by wrong values."""
        assert module in ARCHITECTURE.read_text(), (
            f"ARCHITECTURE.md's layout map does not mention {module}, "
            f"which ships in src/netprotocols/"
        )


class TestReadmeRoadmap:
    """The README's Roadmap section listed eight items tracked by #67 —
    all of which had shipped in 1.3.0, with #67 itself closed. Presenting
    finished work as planned is the front page's version of the drift
    ARCHITECTURE.md had, and the cause was the same: a copied list."""

    def test_does_not_point_at_the_superseded_roadmap(self) -> None:
        assert "issues/67" not in README.read_text(), (
            "README links to #67, the closed roadmap superseded by #107"
        )

    def test_points_at_the_current_roadmap(self) -> None:
        """#170 is the open roadmap; #107, the one before it, is closed
        and may only appear as history."""
        roadmap = _readme_section("Roadmap")
        assert "issues/170" in roadmap, (
            "README's Roadmap section should point at the current tracker "
            "(#170) rather than restating planned work"
        )
        assert roadmap.index("issues/170") < roadmap.index("issues/107"), (
            "README's Roadmap section should lead with the current roadmap "
            "(#170), not the completed #107"
        )

    def test_does_not_restate_the_current_tiers(self) -> None:
        """#170's tiers and their target versions live in the issue; a
        copy here drifts the moment a tier moves, as they all did when
        2.3.0 shipped HTTP outside them."""
        roadmap = _readme_section("Roadmap")
        for tier in range(171, 176):
            assert f"issues/{tier}" not in roadmap, (
                f"README's Roadmap section links tier epic #{tier}; point "
                f"at #170 instead of restating its tiers"
            )

    def test_does_not_relist_shipped_work_as_planned(self) -> None:
        """The 1.3.0 items must not reappear as upcoming."""
        text = README.read_text()
        roadmap = text[text.index("## Roadmap") : text.index("## Contributing")]
        for shipped in ("issues/59", "issues/60", "issues/61", "issues/66"):
            assert shipped not in roadmap, (
                f"README's Roadmap section links {shipped}, work that "
                f"shipped in 1.3.0"
            )


def _readme_section(title: str) -> str:
    text = README.read_text()
    start = text.index(f"## {title}\n")
    return text[start : text.index("\n## ", start + 1)]


class TestReadmeHTTPExamples:
    """The README's Decoding HTTP examples, run as written against the
    captured connections in tests/fixtures/http/, so neither the
    pipelining loop nor a shown output can drift from the code."""

    SECTION = _readme_section("Decoding HTTP")
    STREAMS = FIXTURES / "http"

    def test_the_pipelining_loop_splits_a_captured_connection(self) -> None:
        (code,) = re.findall(r"```python\n(.*?)```", self.SECTION, re.S)
        namespace: dict[str, object] = {}
        exec(code, namespace)
        messages = namespace["messages"]
        assert callable(messages)
        requests = list(messages((self.STREAMS / "07.request").read_bytes()))
        assert [r.method for r in requests] == ["GET", "HEAD", "GET"]
        responses = list(
            messages(
                (self.STREAMS / "07.response").read_bytes(),
                [r.method for r in requests],
            )
        )
        assert [r.framing for r in responses] == [
            HTTPFraming.CONTENT_LENGTH,
            HTTPFraming.NONE,
            HTTPFraming.CHUNKED,
        ]
        assert requests[-1].connection_disposition is HTTPDisposition.CLOSE

    def test_the_shown_outputs_are_what_the_code_prints(self) -> None:
        blocks = re.findall(r"```pycon\n(.*?)```", self.SECTION, re.S)
        assert len(blocks) == 2
        for number, block in enumerate(blocks):
            globs = {
                "HTTP": HTTP,
                "response": (self.STREAMS / "02.response").read_bytes(),
            }
            test = doctest.DocTestParser().get_doctest(
                block, globs, f"README Decoding HTTP #{number}", None, 0
            )
            runner = doctest.DocTestRunner()
            runner.run(test)
            assert runner.summarize().failed == 0, block


class _Experiment(Protocol):
    """Stand in for the class registry.py's examples did not write."""


def _registry_examples() -> list[str]:
    """Return the ``register()`` examples in registry.py's docstrings.

    The module docstring shows one; :func:`register`'s shows two.
    """
    blocks = []
    for doc in (registry_module.__doc__, registry_module.register.__doc__):
        literal = re.findall(
            r"::\n\n((?:(?: {4}.*)?\n)+)", inspect.cleandoc(doc or "")
        )
        blocks += [textwrap.dedent(block) for block in literal]
    return [
        block
        for block in blocks
        if re.search(r'register\("(ethertype|ip\.proto)"', block)
    ]


class TestRegisterExample:
    """Run the documented ``register()`` examples as written.

    README.md, ARCHITECTURE.md and docs/CLAIMS.md show one each, and
    registry.py's docstrings three. Each must claim a key no built-in
    decoder holds, or it raises RegistryConflictError: the EtherType
    was 0x8847 until MPLS shipped (#187), and is now 0x88B5, IEEE 802's
    Local Experimental EtherType; the IP protocol is 253, reserved for
    experimentation (RFC 3692).
    """

    @pytest.mark.parametrize(
        "path", [README, ARCHITECTURE, CLAIMS], ids=lambda p: p.name
    )
    def test_the_example_registers_on_a_free_ethertype(
        self, path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        (code,) = [
            block
            for block in re.findall(
                r"```python\n(.*?)```", path.read_text(), re.S
            )
            if '@register("ethertype"' in block
        ]
        # As below: the example registers in a copy of the defaults.
        fresh = DEFAULT.derive()
        monkeypatch.setattr(registry_module, "DEFAULT", fresh)
        namespace: dict[str, object] = {}
        exec(code, namespace)
        assert fresh.get(TABLE_ETHERTYPE, 0x88B5) is namespace["Telemetry"]
        assert DEFAULT.get(TABLE_ETHERTYPE, 0x88B5) is None

    def test_the_registry_py_examples_register_on_free_keys(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Register each registry.py example in a copy of the defaults."""
        examples = _registry_examples()
        assert len(examples) == 3
        for code in examples:
            # register() reads the module's DEFAULT when called, so a
            # copy of the real one keeps the examples out of it.
            fresh = DEFAULT.derive()
            monkeypatch.setattr(registry_module, "DEFAULT", fresh)
            namespace: dict[str, object] = {
                "Protocol": Protocol,
                "register": registry_module.register,
                "Experiment": _Experiment,
            }
            exec(code, namespace)
            expected = {}
            if '@register("ethertype", 0x88B5)' in code:
                expected[TABLE_ETHERTYPE, 0x88B5] = namespace["Telemetry"]
            if 'register("ip.proto", 253, Experiment)' in code:
                expected[TABLE_IP_PROTO, 253] = _Experiment
            assert expected
            for (table, key), cls in expected.items():
                assert DEFAULT.get(table, key) is None
                assert fresh.get(table, key) is cls
