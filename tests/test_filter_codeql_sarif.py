"""Tests for scripts/filter_codeql_sarif.py, the CodeQL SARIF filter.

The filter sits between CodeQL's analysis and the code scanning upload,
so a mistake in either direction is silent: drop too much and real
alerts never reach the Security tab, drop too little (or nothing, on
SARIF it misreads) and the RFC-mandated MD5 in tests/ and scripts/
turns every pull request red again. Each half gets its own tests here.

tests/fixtures/codeql/python.sarif is CodeQL CLI 2.27.3 output
(the version the pinned CodeQL Action ran when this was written),
produced the way the action runs it: ``database analyze`` with
``--format=sarif-latest --sarif-add-baseline-file-info
--sarif-group-rules-by-pack --sarif-include-query-help=always
--sublanguage-file-coverage`` and no ``--sarif-category``, over a
four-file scratch tree laid out like this repository (RADIUS MD5 in
tests/, a CHAP vector under a directory with a space in its name, a
checker in scripts/, password hashing in src/) and two queries:
py/weak-sensitive-data-hashing and py/clear-text-logging-sensitive-data.
Two host details are scrubbed and nothing else: the CLI's install
directory in ``tool.extensions`` (now ``file:///path/to/codeql/``) and
the kernel version in the ``cli/platform`` notification (now ``0.0.0``).
"""

import copy
import importlib.util
import json
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "filter_codeql_sarif.py"
FIXTURE = ROOT / "tests" / "fixtures" / "codeql" / "python.sarif"


def _load_filter() -> ModuleType:
    spec = importlib.util.spec_from_file_location("filter_codeql_sarif", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


sarif_filter = _load_filter()

RULE = "py/weak-sensitive-data-hashing"
OTHER_RULE = "py/clear-text-logging-sensitive-data"
#: Where absolute file: URIs in the synthetic cases below point.
CHECKOUT = "/home/runner/work/NETProtocols/NETProtocols"


def fixture() -> dict[str, Any]:
    log: dict[str, Any] = json.loads(FIXTURE.read_text(encoding="utf-8"))
    return log


def primary(result: dict[str, Any]) -> tuple[str, str, int]:
    location = result["locations"][0]["physicalLocation"]
    return (
        result["ruleId"],
        location["artifactLocation"]["uri"],
        location["region"]["startLine"],
    )


def target_result() -> dict[str, Any]:
    """A real weak-hashing result from the fixture, for a test to move."""
    for result in fixture()["runs"][0]["results"]:
        if result["ruleId"] == RULE:
            return copy.deepcopy(result)
    raise AssertionError("the fixture has no weak-hashing result")


def log_with(
    *results: dict[str, Any], base_ids: dict[str, Any] | None = None
) -> dict[str, Any]:
    """The fixture's log, its one run holding exactly ``results``."""
    log = fixture()
    log["runs"][0]["results"] = list(results)
    if base_ids is not None:
        log["runs"][0]["originalUriBaseIds"] = base_ids
    return log


def at(artifact_location: dict[str, Any], rule: str = RULE) -> dict[str, Any]:
    """The fixture's weak-hashing result moved to ``artifact_location``."""
    result = target_result()
    result["ruleId"] = rule
    result["rule"]["id"] = rule
    result["locations"][0]["physicalLocation"]["artifactLocation"] = (
        artifact_location
    )
    return result


def drops(result: dict[str, Any], **kwargs: Any) -> bool:
    log = log_with(result, **kwargs)
    dropped = sarif_filter.filter_log(log, CHECKOUT)
    assert len(dropped) + len(log["runs"][0]["results"]) == 1
    return bool(dropped)


class TestTheFixture:
    """Pins what the filter was written against, so a regenerated
    fixture that no longer looks like CodeQL's output fails here rather
    than quietly testing something else."""

    def test_it_is_codeql_sarif_2_1_0(self) -> None:
        log = fixture()
        assert log["version"] == "2.1.0"
        assert log["runs"][0]["tool"]["driver"]["name"] == "CodeQL"

    def test_source_locations_are_relative_to_srcroot(self) -> None:
        for result in fixture()["runs"][0]["results"]:
            artifact = result["locations"][0]["physicalLocation"][
                "artifactLocation"
            ]
            assert artifact["uriBaseId"] == "%SRCROOT%"
            assert not artifact["uri"].startswith(("/", "file:", "./"))
        assert "originalUriBaseIds" not in fixture()["runs"][0]

    def test_without_a_category_the_cli_writes_no_automation_details(
        self,
    ) -> None:
        """Why codeql.yml sets no ``category``: the CLI leaves the
        automation id to the action, which derives the same one in
        analyze and in upload-sarif (see test_workflows.py)."""
        assert "automationDetails" not in fixture()["runs"][0]

    def test_it_holds_every_case_the_filter_distinguishes(self) -> None:
        assert [primary(r) for r in fixture()["runs"][0]["results"]] == [
            (RULE, "src/netprotocols/auth.py", 5),
            (RULE, "scripts/check_fixtures.py", 5),
            (RULE, "tests/chap%20vectors/test_chap.py", 5),
            (RULE, "tests/test_radius.py", 7),
            (RULE, "tests/test_radius.py", 11),
            (OTHER_RULE, "tests/test_radius.py", 16),
        ]


class TestFilterOnRealOutput:
    def test_drops_only_the_rule_on_tests_and_scripts(self) -> None:
        log = fixture()
        dropped = sarif_filter.filter_log(log, CHECKOUT)
        assert dropped == [
            "scripts/check_fixtures.py:5",
            "tests/chap vectors/test_chap.py:5",
            "tests/test_radius.py:7",
            "tests/test_radius.py:11",
        ]
        assert [primary(r) for r in log["runs"][0]["results"]] == [
            (RULE, "src/netprotocols/auth.py", 5),
            (OTHER_RULE, "tests/test_radius.py", 16),
        ]

    def test_changes_nothing_but_the_dropped_results(self) -> None:
        original = fixture()
        log = fixture()
        sarif_filter.filter_log(log, CHECKOUT)
        kept = [
            r
            for r in original["runs"][0]["results"]
            if primary(r)
            in {
                (RULE, "src/netprotocols/auth.py", 5),
                (OTHER_RULE, "tests/test_radius.py", 16),
            }
        ]
        # The kept results whole (fingerprints, code flows, related
        # locations), in order; and every other key of the log and the
        # run (rule definitions, invocations, artifacts, properties).
        assert log["runs"][0]["results"] == kept
        original["runs"][0]["results"] = kept
        assert log == original

    def test_a_log_with_nothing_to_drop_is_left_as_it_was(self) -> None:
        log = log_with(
            *[
                r
                for r in fixture()["runs"][0]["results"]
                if primary(r)[1].startswith("src/")
            ]
        )
        before = copy.deepcopy(log)
        assert sarif_filter.filter_log(log, CHECKOUT) == []
        assert log == before

    def test_every_run_is_filtered(self) -> None:
        log = fixture()
        log["runs"].append(copy.deepcopy(log["runs"][0]))
        assert len(sarif_filter.filter_log(log, CHECKOUT)) == 8
        assert [len(run["results"]) for run in log["runs"]] == [2, 2]


class TestRuleMatching:
    def test_other_rules_on_tests_are_kept(self) -> None:
        assert not drops(at({"uri": "tests/test_radius.py"}, OTHER_RULE))

    def test_other_rules_on_scripts_are_kept(self) -> None:
        assert not drops(at({"uri": "scripts/check_fixtures.py"}, OTHER_RULE))

    @pytest.mark.parametrize(
        "rule",
        [
            "py/weak-sensitive-data-hashing-v2",
            "py/weak-sensitive-data-hashing ",
            "PY/WEAK-SENSITIVE-DATA-HASHING",
            "py/weak-cryptographic-algorithm",
            "js/weak-sensitive-data-hashing",
        ],
    )
    def test_the_rule_id_must_match_exactly(self, rule: str) -> None:
        assert not drops(at({"uri": "tests/test_radius.py"}, rule))

    def test_a_rule_given_only_as_rule_id_still_matches(self) -> None:
        """SARIF §3.27.5 lets a producer give ``rule.id`` without
        ``ruleId``; CodeQL gives both."""
        result = at({"uri": "tests/test_radius.py"})
        del result["ruleId"]
        assert drops(result)

    def test_the_rule_on_src_is_kept(self) -> None:
        assert not drops(at({"uri": "src/netprotocols/layer7/radius.py"}))

    @pytest.mark.parametrize(
        "locations",
        [None, [], [{"message": {"text": "no physical location"}}]],
        ids=["absent", "empty", "logical-only"],
    )
    def test_a_result_with_no_file_is_kept(
        self, locations: list[dict[str, Any]] | None
    ) -> None:
        result = target_result()
        if locations is None:
            del result["locations"]
        else:
            result["locations"] = locations
        assert not drops(result)

    def test_only_the_primary_location_decides(self) -> None:
        """A result in src/ whose second location is in tests/ is a
        finding in src/."""
        result = at({"uri": "src/netprotocols/auth.py"})
        result["locations"].append(
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "tests/test_radius.py"}
                }
            }
        )
        assert not drops(result)


SRCROOT = "%SRCROOT%"

DROPPED_LOCATIONS = {
    "codeql": {"uri": "tests/test_radius.py", "uriBaseId": SRCROOT},
    "scripts": {"uri": "scripts/check_fixtures.py", "uriBaseId": SRCROOT},
    "no-base-id": {"uri": "tests/test_radius.py"},
    "dot-slash": {"uri": "./tests/test_radius.py", "uriBaseId": SRCROOT},
    "dot-slash-no-base-id": {"uri": "./scripts/check_fixtures.py"},
    "percent-encoded": {"uri": "tests/chap%20vectors/test_chap.py"},
    "nested": {"uri": "tests/fuzz/fuzz_radius.py", "uriBaseId": SRCROOT},
    "file-uri": {"uri": f"file://{CHECKOUT}/tests/test_radius.py"},
    "file-uri-localhost": {
        "uri": f"file://localhost{CHECKOUT}/scripts/check_fixtures.py"
    },
    "absolute-path": {"uri": f"{CHECKOUT}/tests/test_radius.py"},
    "file-uri-dot-segments": {
        "uri": f"file://{CHECKOUT}/src/../tests/test_radius.py"
    },
}

KEPT_LOCATIONS = {
    "src": {"uri": "src/netprotocols/auth.py", "uriBaseId": SRCROOT},
    "nested-tests-dir": {"uri": "src/tests/x.py", "uriBaseId": SRCROOT},
    "tests-prefix-word": {"uri": "testsuite/test_x.py"},
    "tests-underscore": {"uri": "tests_old/test_x.py"},
    "scripts-file": {"uri": "scripts.py"},
    "upper-case": {"uri": "Tests/test_radius.py"},
    "climbs-out-of-tests": {"uri": "tests/../src/netprotocols/auth.py"},
    "outside-the-checkout": {"uri": "../tests/test_radius.py"},
    "file-uri-elsewhere": {"uri": "file:///opt/tests/test_radius.py"},
    "file-uri-other-host": {
        "uri": f"file://buildhost{CHECKOUT}/tests/test_radius.py"
    },
    "https": {"uri": "https://example.com/tests/test_radius.py"},
    "http-no-host": {"uri": "http:tests/test_radius.py"},
    "other-scheme-no-host": {"uri": "git:scripts/check_fixtures.py"},
    "unknown-base-id": {"uri": "tests/x.py", "uriBaseId": "%SYSROOT%"},
    "no-uri": {"index": 3},
    "the-checkout-itself": {"uri": f"file://{CHECKOUT}"},
}


class TestUriForms:
    @pytest.mark.parametrize(
        "location",
        DROPPED_LOCATIONS.values(),
        ids=DROPPED_LOCATIONS.keys(),
    )
    def test_is_dropped(self, location: dict[str, Any]) -> None:
        assert drops(at(location))

    @pytest.mark.parametrize(
        "location", KEPT_LOCATIONS.values(), ids=KEPT_LOCATIONS.keys()
    )
    def test_is_kept(self, location: dict[str, Any]) -> None:
        assert not drops(at(location))

    def test_the_path_is_reported_decoded_and_normalized(self) -> None:
        log = log_with(at({"uri": "./tests/chap%20vectors/../test_x.py"}))
        assert sarif_filter.filter_log(log, CHECKOUT) == ["tests/test_x.py:5"]

    def test_a_base_id_the_run_defines_is_resolved(self) -> None:
        base_ids = {
            SRCROOT: {"uri": f"file://{CHECKOUT}/"},
            "TESTS": {"uri": "tests/", "uriBaseId": SRCROOT},
        }
        assert drops(
            at({"uri": "test_radius.py", "uriBaseId": "TESTS"}),
            base_ids=base_ids,
        )
        assert drops(
            at({"uri": "tests/test_radius.py", "uriBaseId": SRCROOT}),
            base_ids=base_ids,
        )
        assert not drops(
            at({"uri": "src/x.py", "uriBaseId": SRCROOT}), base_ids=base_ids
        )

    def test_a_base_id_relative_to_an_undefined_srcroot(self) -> None:
        """CodeQL leaves ``%SRCROOT%`` undefined; a base id built on it
        is then relative to the checkout too."""
        base_ids = {"TESTS": {"uri": "tests/", "uriBaseId": SRCROOT}}
        assert drops(
            at({"uri": "test_radius.py", "uriBaseId": "TESTS"}),
            base_ids=base_ids,
        )
        base_ids = {"SRC": {"uri": "src/", "uriBaseId": SRCROOT}}
        assert not drops(
            at({"uri": "tests/x.py", "uriBaseId": "SRC"}), base_ids=base_ids
        )

    def test_a_base_id_without_a_trailing_slash_is_a_directory(self) -> None:
        base_ids = {"TESTS": {"uri": f"file://{CHECKOUT}/tests"}}
        assert drops(
            at({"uri": "test_radius.py", "uriBaseId": "TESTS"}),
            base_ids=base_ids,
        )

    def test_srcroot_defined_elsewhere_is_not_the_checkout(self) -> None:
        base_ids = {SRCROOT: {"uri": "file:///somewhere/else/"}}
        assert not drops(
            at({"uri": "tests/test_radius.py", "uriBaseId": SRCROOT}),
            base_ids=base_ids,
        )

    @pytest.mark.parametrize(
        "base_ids",
        [
            {
                "A": {"uri": "a/", "uriBaseId": "B"},
                "B": {"uri": "b/", "uriBaseId": "A"},
            },
            {"A": {"uri": "tests/", "uriBaseId": "UNDEFINED"}},
            {"A": {"description": {"text": "no uri"}}},
        ],
        ids=["cycle", "undefined-parent", "no-uri"],
    )
    def test_an_unresolvable_base_id_is_kept(
        self, base_ids: dict[str, Any]
    ) -> None:
        assert not drops(
            at({"uri": "test_radius.py", "uriBaseId": "A"}), base_ids=base_ids
        )


def _set(log: dict[str, Any], path: tuple[Any, ...], value: Any) -> None:
    target: Any = log
    for key in path[:-1]:
        target = target[key]
    if value is DELETE:
        del target[path[-1]]
    else:
        target[path[-1]] = value


DELETE = object()
RESULT = ("runs", 0, "results", 3)
ARTIFACT = (*RESULT, "locations", 0, "physicalLocation", "artifactLocation")

MALFORMED = {
    "no-version": (("version",), DELETE),
    "sarif-2.0.0": (("version",), "2.0.0"),
    "no-runs": (("runs",), DELETE),
    "runs-not-a-list": (("runs",), {"0": {}}),
    "no-run": (("runs",), []),
    "run-not-an-object": (("runs", 0), "run"),
    "no-results": (("runs", 0, "results"), DELETE),
    "null-results": (("runs", 0, "results"), None),
    "results-not-a-list": (("runs", 0, "results"), {}),
    "result-not-an-object": (RESULT, [RULE]),
    "rule-id-not-a-string": ((*RESULT, "ruleId"), 7),
    "null-rule-id": ((*RESULT, "ruleId"), None),
    "rule-not-an-object": ((*RESULT, "rule"), RULE),
    "locations-not-a-list": ((*RESULT, "locations"), {"0": {}}),
    "null-locations": ((*RESULT, "locations"), None),
    "location-not-an-object": ((*RESULT, "locations", 0), "tests/x.py"),
    "physical-not-an-object": (
        (*RESULT, "locations", 0, "physicalLocation"),
        [],
    ),
    "artifact-not-an-object": (ARTIFACT, "tests/test_radius.py"),
    "uri-not-a-string": ((*ARTIFACT, "uri"), ["tests/test_radius.py"]),
    "base-id-not-a-string": ((*ARTIFACT, "uriBaseId"), 0),
    "base-ids-not-an-object": (("runs", 0, "originalUriBaseIds"), []),
}


class TestMalformedInput:
    @pytest.mark.parametrize(
        ("path", "value"), MALFORMED.values(), ids=MALFORMED.keys()
    )
    def test_is_rejected(self, path: tuple[Any, ...], value: Any) -> None:
        log = fixture()
        _set(log, path, value)
        with pytest.raises(sarif_filter.MalformedSarifError):
            sarif_filter.filter_log(log, CHECKOUT)

    @pytest.mark.parametrize("log", [[], "SARIF", None, 2])
    def test_a_log_that_is_not_an_object_is_rejected(self, log: Any) -> None:
        with pytest.raises(sarif_filter.MalformedSarifError):
            sarif_filter.filter_log(log, CHECKOUT)

    def test_a_malformed_base_id_entry_is_rejected(self) -> None:
        log = log_with(
            at({"uri": "x.py", "uriBaseId": "A"}),
            base_ids={"A": {"uri": 7}},
        )
        with pytest.raises(sarif_filter.MalformedSarifError):
            sarif_filter.filter_log(log, CHECKOUT)


class TestMain:
    def test_rewrites_the_files_in_a_directory_and_reports_them(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        (tmp_path / "python.sarif").write_bytes(FIXTURE.read_bytes())
        (tmp_path / "notes.txt").write_text("not SARIF")
        assert sarif_filter.main([str(tmp_path)]) == 0
        out = capsys.readouterr().out
        assert out == (
            f"python.sarif: dropped 4 {RULE} result(s) under tests/, "
            "scripts/: scripts/check_fixtures.py:5, "
            "tests/chap vectors/test_chap.py:5, tests/test_radius.py:7, "
            "tests/test_radius.py:11\n"
        )
        expected = fixture()
        sarif_filter.filter_log(expected, CHECKOUT)
        written = json.loads((tmp_path / "python.sarif").read_text())
        assert written == expected
        assert (tmp_path / "notes.txt").read_text() == "not SARIF"

    def test_a_file_with_nothing_to_drop_is_not_rewritten(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        log = fixture()
        log["runs"][0]["results"] = log["runs"][0]["results"][:1]
        raw = json.dumps(log, separators=(",", ":")).encode()
        sarif = tmp_path / "python.sarif"
        sarif.write_bytes(raw)
        assert sarif_filter.main([str(sarif)]) == 0
        assert sarif.read_bytes() == raw
        assert capsys.readouterr().out == (
            f"python.sarif: dropped 0 {RULE} result(s) under tests/, scripts/\n"
        )

    def test_absolute_file_uris_are_matched_against_source_root(
        self, tmp_path: Path
    ) -> None:
        log = log_with(at({"uri": f"file://{CHECKOUT}/tests/test_x.py"}))
        sarif = tmp_path / "python.sarif"
        sarif.write_text(json.dumps(log))
        assert sarif_filter.main([str(sarif), "--source-root", "/x"]) == 0
        assert len(json.loads(sarif.read_text())["runs"][0]["results"]) == 1
        assert sarif_filter.main([str(sarif), "--source-root", CHECKOUT]) == 0
        assert json.loads(sarif.read_text())["runs"][0]["results"] == []

    @pytest.mark.parametrize(
        "content",
        [b"", b"{not json", b"\xff\xfe", b"[]", b'{"version": "2.1.0"}'],
        ids=["empty", "not-json", "not-utf8", "array", "no-runs"],
    )
    def test_malformed_sarif_fails_and_leaves_the_file_alone(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
        content: bytes,
    ) -> None:
        sarif = tmp_path / "python.sarif"
        sarif.write_bytes(content)
        assert sarif_filter.main([str(tmp_path)]) == 1
        assert sarif.read_bytes() == content
        assert capsys.readouterr().err.startswith(f"FAIL: {sarif}: ")

    def test_files_in_subdirectories_are_filtered_too(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """upload-sarif uploads every ``*.sarif`` under the directory,
        at any depth, so the filter must reach each one of them."""
        nested = tmp_path / "python" / "more"
        nested.mkdir(parents=True)
        (tmp_path / "a.sarif").write_bytes(FIXTURE.read_bytes())
        (nested / "b.sarif").write_bytes(FIXTURE.read_bytes())
        assert sarif_filter.main([str(tmp_path)]) == 0
        expected = fixture()
        sarif_filter.filter_log(expected, CHECKOUT)
        for sarif in (tmp_path / "a.sarif", nested / "b.sarif"):
            assert json.loads(sarif.read_text()) == expected, sarif
        lines = capsys.readouterr().out.splitlines()
        assert [line.partition(":")[0] for line in lines] == [
            "a.sarif",
            "b.sarif",
        ]

    def test_a_directory_with_sarif_only_in_a_subdirectory_is_filtered(
        self, tmp_path: Path
    ) -> None:
        nested = tmp_path / "python"
        nested.mkdir()
        (nested / "python.sarif").write_bytes(FIXTURE.read_bytes())
        assert sarif_filter.main([str(tmp_path)]) == 0
        results = json.loads((nested / "python.sarif").read_text())["runs"][0][
            "results"
        ]
        assert [primary(r)[1] for r in results] == [
            "src/netprotocols/auth.py",
            "tests/test_radius.py",
        ]

    def test_a_directory_without_sarif_fails(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert sarif_filter.main([str(tmp_path)]) == 1
        assert "no *.sarif file" in capsys.readouterr().err

    def test_a_missing_path_fails(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert sarif_filter.main([str(tmp_path / "results.sarif")]) == 1
        assert "no such file" in capsys.readouterr().err

    def test_a_bad_file_fails_the_run_even_after_a_good_one(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "a.sarif").write_bytes(FIXTURE.read_bytes())
        (tmp_path / "b.sarif").write_text("{}")
        assert sarif_filter.main([str(tmp_path)]) == 1
