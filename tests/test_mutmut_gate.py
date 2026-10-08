"""Tests for scripts/check_mutmut_survivors.py, the nightly mutation gate.

`mutmut run` exits 0 however many mutants survive, so this script is the
only thing that can fail the mutation workflow on a finding. A gate that
silently passes is worse than none -- it reads as coverage -- so each
way it is meant to fail gets its own test, alongside the committed
triage record and pyproject.toml it actually runs against.
"""

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_mutmut_survivors.py"


def _load_gate() -> ModuleType:
    spec = importlib.util.spec_from_file_location("mutmut_gate", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gate = _load_gate()

MODULES = ["netprotocols.checksum", "netprotocols._tlv"]


def statuses() -> dict[str, str]:
    """A passing status listing: one killed mutant in each of MODULES,
    for a test to add to or override."""
    return {
        "netprotocols.checksum.x_f__mutmut_1": "killed",
        "netprotocols._tlv.x_g__mutmut_1": "killed",
    }


class TestParsing:
    def test_results_lines_map_names_to_statuses(self) -> None:
        lines = [
            "    netprotocols.checksum.x_f__mutmut_1: killed",
            "    netprotocols.checksum.x_f__mutmut_2: check was interrupted"
            " by user",
            "",
            "some unrelated banner line",
        ]
        assert gate.parse_results(lines) == {
            "netprotocols.checksum.x_f__mutmut_1": "killed",
            "netprotocols.checksum.x_f__mutmut_2": (
                "check was interrupted by user"
            ),
        }

    def test_allowlist_ignores_comments_and_blanks(self) -> None:
        lines = ["# why", "", "  a.x_f__mutmut_3  # inline note", "b"]
        assert gate.parse_allowlist(lines) == {"a.x_f__mutmut_3", "b"}

    def test_only_mutate_paths_become_dotted_modules(self) -> None:
        pyproject = (
            '[tool.mutmut]\nonly_mutate = ["src/netprotocols/_tlv.py",'
            ' "src/netprotocols/layer7/dns.py"]\n'
        )
        assert gate.mutated_modules(pyproject) == [
            "netprotocols._tlv",
            "netprotocols.layer7.dns",
        ]


class TestCheck:
    def test_a_clean_run_passes(self) -> None:
        results = statuses()
        results["netprotocols._tlv.x_g__mutmut_2"] = "timeout"
        results["netprotocols.layer7.dns.x_h__mutmut_1"] = "not checked"
        assert gate.check(results, set(), MODULES) == []

    @pytest.mark.parametrize(
        "status", ["survived", "no tests", "suspicious", "a status from v4"]
    )
    def test_an_undetected_mutant_fails(self, status: str) -> None:
        """Unknown statuses fail closed: a mutmut upgrade that adds one
        must be triaged here, not silently counted as a kill."""
        results = statuses()
        results["netprotocols._tlv.x_g__mutmut_2"] = status
        (problem,) = gate.check(results, set(), MODULES)
        assert "undetected mutant: netprotocols._tlv.x_g__mutmut_2" in problem

    def test_an_allowlisted_survivor_passes(self) -> None:
        results = statuses()
        results["netprotocols._tlv.x_g__mutmut_2"] = "survived"
        allowlist = {"netprotocols._tlv.x_g__mutmut_2"}
        assert gate.check(results, allowlist, MODULES) == []

    @pytest.mark.parametrize("status", ["killed", None])
    def test_a_stale_allowlist_entry_fails(self, status: str | None) -> None:
        """An entry whose mutant is now killed, or no longer exists
        (renumbered by an edit), must be removed or re-triaged."""
        results = statuses()
        name = "netprotocols._tlv.x_g__mutmut_9"
        if status is not None:
            results[name] = status
        (problem,) = gate.check(results, {name}, MODULES)
        assert "no longer undetected" in problem
        assert name in problem

    def test_a_scoped_module_with_nothing_checked_fails(self) -> None:
        results = statuses()
        results["netprotocols._tlv.x_g__mutmut_1"] = "not checked"
        (problem,) = gate.check(results, set(), MODULES)
        assert "no mutant of netprotocols._tlv was checked" in problem

    def test_module_prefix_does_not_match_a_sibling(self) -> None:
        """netprotocols.checksum must not be satisfied by a mutant of a
        hypothetical netprotocols.checksum_extra module."""
        results = {
            "netprotocols.checksum_extra.x_f__mutmut_1": "killed",
            "netprotocols._tlv.x_g__mutmut_1": "killed",
        }
        (problem,) = gate.check(results, set(), MODULES)
        assert "no mutant of netprotocols.checksum was checked" in problem

    def test_empty_results_fail(self) -> None:
        assert gate.check({}, set(), MODULES)


class TestMain:
    def test_exit_status_reflects_the_check(self, tmp_path: Path) -> None:
        results = tmp_path / "results.txt"
        allowlist = tmp_path / "allow.txt"
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(
            '[tool.mutmut]\nonly_mutate = ["src/netprotocols/_tlv.py"]\n'
        )
        allowlist.write_text("")
        results.write_text("    netprotocols._tlv.x_g__mutmut_1: killed\n")
        args = [
            str(results),
            "--allowlist",
            str(allowlist),
            "--pyproject",
            str(pyproject),
        ]
        assert gate.main(args) == 0
        results.write_text("    netprotocols._tlv.x_g__mutmut_1: survived\n")
        assert gate.main(args) == 1


class TestCommittedTriageRecord:
    def test_every_entry_is_justified(self) -> None:
        """Each allowlisted name must sit under a comment saying why it
        is accepted -- the file is a triage record, not a mute list."""
        lines = gate.DEFAULT_ALLOWLIST.read_text().splitlines()
        for index, line in enumerate(lines):
            entry = line.split("#", 1)[0].strip()
            if entry:
                assert index and lines[index - 1].startswith("#"), (
                    f"{entry} has no justifying comment directly above it"
                )

    def test_entries_name_modules_the_audit_scopes(self) -> None:
        modules = gate.mutated_modules(gate.DEFAULT_PYPROJECT.read_text())
        entries = gate.parse_allowlist(
            gate.DEFAULT_ALLOWLIST.read_text().splitlines()
        )
        for entry in entries:
            assert any(entry.startswith(f"{m}.") for m in modules), (
                f"{entry} is outside every file pyproject.toml's "
                f"only_mutate scopes, so it can never be reported"
            )
