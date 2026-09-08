"""Tests that the release workflow cannot publish without the QA ladder,
and that every workflow file under .github/workflows/ holds this
project's baseline structural bar.

A published version can only be yanked, never replaced, so the gate that
stops a broken tag reaching PyPI is worth asserting rather than trusting.
The wiring is easy to break silently: drop ``needs:`` from the publish
job, or ``workflow_call:`` from the CI workflow, and releases keep
working while the gate quietly stops existing.

These parse the workflow YAML by indentation rather than with a YAML
library, to avoid adding a dependency for a handful of assertions. The
files are small and uniformly two-space indented; a parse failure here
fails the test loudly instead of passing vacuously.

The commit-SHA-pinning check in particular is parametrized over every
file a glob of .github/workflows/*.yml and *.yaml finds, rather than a
fixed list of workflow names. A fixed list quietly stops covering a file the
moment someone adds a new one and forgets to update the list here --
the same failure mode as ALL_PROTOCOLS silently skipping DNSOverTCP
(see the fuzz-completeness test), just relocated to CI's own workflows.
"""

import re
from pathlib import Path

import pytest

WORKFLOWS = Path(__file__).resolve().parent.parent / ".github" / "workflows"
CI = WORKFLOWS / "ci.yml"
RELEASE = WORKFLOWS / "release.yml"
FUZZ = WORKFLOWS / "fuzz.yml"
MUTATION = WORKFLOWS / "mutation.yml"
DEPENDABOT = WORKFLOWS.parent / "dependabot.yml"
ALL_WORKFLOWS = sorted([*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")])


def job_blocks(workflow: Path) -> dict[str, str]:
    """Map each job name to its raw block text, keyed off ``jobs:``."""
    text = workflow.read_text()
    _, _, after = text.partition("\njobs:\n")
    assert after, f"{workflow.name} has no jobs: mapping"
    blocks: dict[str, str] = {}
    current: str | None = None
    for line in after.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        header = re.fullmatch(r"  ([A-Za-z0-9_-]+):", line)
        if header:
            current = header.group(1)
            blocks[current] = ""
        elif current is not None and line.startswith("    "):
            blocks[current] += line + "\n"
        elif not line.startswith(" "):
            break  # left the jobs: mapping entirely
    return blocks


@pytest.fixture(scope="module")
def release_jobs() -> dict[str, str]:
    return job_blocks(RELEASE)


@pytest.fixture(scope="module")
def ci_jobs() -> dict[str, str]:
    return job_blocks(CI)


class TestReleaseGate:
    def test_ci_workflow_is_callable(self) -> None:
        """The CI workflow must be reusable, or the gate cannot run it."""
        assert re.search(r"^  workflow_call:", CI.read_text(), re.M), (
            "ci.yml no longer declares a workflow_call trigger, so "
            "release.yml cannot invoke it as a gate"
        )

    def test_release_calls_the_ci_workflow(
        self, release_jobs: dict[str, str]
    ) -> None:
        """Some release job must invoke the real CI workflow."""
        callers = {
            name: block
            for name, block in release_jobs.items()
            if "./.github/workflows/ci.yml" in block
        }
        assert callers, (
            "no job in release.yml calls ./.github/workflows/ci.yml — a "
            "tag push runs no checks, because ci.yml's own triggers only "
            "fire on pushes and pull requests targeting master"
        )

    def test_publish_depends_on_the_ci_gate(
        self, release_jobs: dict[str, str]
    ) -> None:
        """Publishing must not start until the gate job has passed."""
        publish = release_jobs.get("publish")
        assert publish is not None, "release.yml has no publish job"

        gates = {
            name
            for name, block in release_jobs.items()
            if "./.github/workflows/ci.yml" in block
        }
        # Match only to end of line: a \s inside the character class
        # would run past the newline and swallow the next key.
        declared: set[str] = set()
        for bracketed, bare in re.findall(
            r"needs:[ \t]*(?:\[([^\]]*)\]|([A-Za-z0-9_-]+))[ \t]*$",
            publish,
            re.M,
        ):
            declared |= {n.strip() for n in (bracketed or bare).split(",")}
        declared.discard("")

        assert declared & gates, (
            f"publish job needs {declared or '{}'}, none of which is the "
            f"CI gate {gates}. Without that dependency a tag publishes to "
            f"PyPI whether or not the checks passed"
        )

    def test_every_local_reusable_reference_resolves(self) -> None:
        """A `uses: ./…` pointing at nothing fails the release, not CI."""
        for workflow in ALL_WORKFLOWS:
            for ref in re.findall(r"uses:\s*(\./\S+)", workflow.read_text()):
                # removeprefix, not lstrip: lstrip("./") would strip the
                # leading dot of ".github" as well.
                target = WORKFLOWS.parent.parent / ref.removeprefix("./")
                assert target.is_file(), (
                    f"{workflow.name} references {ref}, which does not exist"
                )
                assert re.search(
                    r"^  workflow_call:", target.read_text(), re.M
                ), (
                    f"{workflow.name} calls {ref}, but that workflow does "
                    f"not declare a workflow_call trigger"
                )


def uses_ref(line: str) -> str | None:
    """The action reference on a ``uses:`` step line, or ``None`` if the
    line isn't one. Matches both the standard YAML list form
    (``- uses: ...``) and the bare form (``uses: ...``) -- a regex
    anchored past only the list marker's optional dash previously
    missed every real ``- uses:`` line in this repo, silently turning
    :class:`TestActionPinning` into a no-op."""
    match = re.match(r"\s*(?:-\s*)?uses:\s*(\S+)", line)
    return match.group(1) if match else None


class TestUsesRefMatching:
    """Regression coverage for :func:`uses_ref` itself, independent of
    which real workflow files currently exist -- this is what actually
    failed silently before, so it gets tested directly rather than only
    through TestActionPinning's end-to-end check."""

    def test_matches_the_list_form(self):
        assert (
            uses_ref("      - uses: actions/checkout@" + "a" * 40)
            == "actions/checkout@" + "a" * 40
        )

    def test_matches_the_bare_form(self):
        assert (
            uses_ref("      uses: actions/checkout@" + "a" * 40)
            == "actions/checkout@" + "a" * 40
        )

    def test_list_form_with_a_moving_tag_is_still_extracted(self):
        """Extraction doesn't itself judge the ref -- TestActionPinning
        does that -- but it must not silently drop an unpinned list-form
        line the way the pre-fix regex did."""
        assert uses_ref("      - uses: actions/checkout@v4") == (
            "actions/checkout@v4"
        )

    def test_non_uses_line_does_not_match(self):
        assert uses_ref("      run: echo hello") is None


class TestActionPinning:
    """Every third-party action, in every workflow, must be pinned.

    Parametrized over ``ALL_WORKFLOWS`` -- a glob of
    .github/workflows/*.yml -- rather than a fixed list of files, so a
    workflow added after this test was written is covered automatically
    instead of silently skipped.
    """

    @pytest.mark.parametrize("workflow", ALL_WORKFLOWS, ids=lambda p: p.name)
    def test_remote_actions_are_pinned_to_a_commit_sha(
        self, workflow: Path
    ) -> None:
        """A branch or tag ref (`@v4`, `@main`) is a moving target: the
        code that runs under it can change without this repository's
        own history recording it. `uses: ./…` local reusable-workflow
        references are exempt -- they resolve to a file in this repo
        (checked above) and cannot be "pinned" to a SHA at all.
        """
        for line in workflow.read_text().splitlines():
            ref = uses_ref(line)
            if ref is None or ref.startswith("."):
                continue
            _, sep, pin = ref.rpartition("@")
            assert sep and re.fullmatch(r"[0-9a-f]{40}", pin), (
                f"{workflow.name}: {ref!r} is not pinned to a 40-character "
                f"commit SHA"
            )


class TestCIWorkflow:
    """Structural checks on jobs added to ci.yml's own QA ladder."""

    REPRODUCIBILITY_STEP_NAME = "Verify the wheel build is reproducible"

    def test_has_a_dependency_scan_job(self, ci_jobs: dict[str, str]) -> None:
        """Third-party CI dependencies must be audited for known CVEs."""
        block = ci_jobs.get("dependency-scan")
        assert block is not None, "ci.yml has no dependency-scan job"
        assert "pip-audit" in block, (
            "dependency-scan job no longer runs pip-audit"
        )

    @classmethod
    def _reproducibility_step_script(cls, build_job: str) -> str:
        """The literal ``run:`` script of the build job's "Verify the
        wheel build is reproducible" step, isolated from the rest of
        the job.

        ``job_blocks`` returns a job's *entire* raw text -- every other
        step's name, ``run:`` script, and echoed strings besides this
        one. Checking for tokens against that whole blob cannot tell
        the difference between this step's own executed commands and a
        lookalike word occurring anywhere else in the job (another
        step's log message, an unrelated comment, or a step that only
        describes a check in a string it echoes). Isolating this step's
        own script is what lets the checks below tie the hashing and
        the comparison to commands this step actually runs.
        """
        match = re.search(
            rf"(?m)^ {{6}}- name: {re.escape(cls.REPRODUCIBILITY_STEP_NAME)}\n"
            rf" {{8}}run: \|\n"
            rf"(?P<script>(?: {{10}}.*\n)+)",
            build_job,
        )
        assert match is not None, (
            f"build job has no {cls.REPRODUCIBILITY_STEP_NAME!r} step "
            f"with an inline 'run: |' script"
        )
        return match.group("script")

    @staticmethod
    def _assert_diffs_two_independent_builds(script: str) -> None:
        """Verify the reproducibility step's script actually hashes two
        independently built wheels and fails on a reachable mismatch,
        rather than merely containing words that describe doing so.

        A bare substring/regex search over raw text is satisfied by an
        ``echo`` string that narrates "would hash dist-repro-1 and
        dist-repro-2, compare $hash1 != $hash2, and exit 1 on
        mismatch" without ever running a `sha256sum`, or by a real
        `sha256sum`/`if`/`exit 1` that IS present in the script but not
        wired together -- e.g. `exit 1` sitting in an unrelated,
        permanently-false branch while the real `if [ "$hash1" !=
        "$hash2" ]; then` block does nothing. Each check here ties a
        token to the specific, executable bash construct it must
        appear in, and the last one requires `exit 1` to be inside the
        *body* of the actual hash-mismatch `if` block, not merely
        present somewhere in the script.
        """
        assert "uv build -o dist-repro-1" in script, (
            "reproducibility step no longer builds a first independent "
            "wheel into dist-repro-1"
        )
        assert "uv build -o dist-repro-2" in script, (
            "reproducibility step no longer builds a second independent "
            "wheel into dist-repro-2"
        )
        assert re.search(r"hash1=\$\(sha256sum\s+\S*dist-repro-1\S*", script), (
            "reproducibility step no longer assigns hash1 from an "
            "actual sha256sum of the dist-repro-1 wheel"
        )
        assert re.search(r"hash2=\$\(sha256sum\s+\S*dist-repro-2\S*", script), (
            "reproducibility step no longer assigns hash2 from an "
            "actual sha256sum of the dist-repro-2 wheel"
        )
        # Known accepted limitation: `body` is captured non-greedily up
        # to the first line that is just `fi`, not necessarily the one
        # that actually balances this `if`. A deliberately nested dead
        # branch inside the real mismatch block -- e.g. `if false; then
        # exit 1; fi` sitting inside the outer `if [ "$hash1" !=
        # "$hash2" ]; then ... fi` -- would still read as "exit 1 is in
        # body" without being reachable. Closing that would mean
        # tracking `if`/`fi` nesting depth instead of matching to the
        # first `fi`, which is more machinery than a YAML/bash text
        # heuristic like this one is worth carrying for a case the real
        # ci.yml step doesn't (and has no reason to) construct.
        mismatch = re.search(
            r'if \[ "?\$hash1"?\s*!=\s*"?\$hash2"?\s*\];?\s*then\n'
            r"(?P<body>(?:.*\n)*?)"
            r"^ *fi *$",
            script,
            re.M,
        )
        assert mismatch is not None, (
            "reproducibility step no longer has a reachable "
            '\'if [ "$hash1" != "$hash2" ]; then ... fi\' block '
            "comparing the two builds' hashes"
        )
        assert "exit 1" in mismatch.group("body"), (
            "the hash-mismatch branch no longer fails the job with "
            "exit 1 -- a differing hash would be reported without "
            "ever failing CI"
        )

    def test_build_verifies_reproducibility(
        self, ci_jobs: dict[str, str]
    ) -> None:
        """The build job must actually compare two independent builds'
        artifacts, not merely claim to and mention the right words --
        a block containing the word "reproducible" plus echoed
        mentions of "sha256sum", "$hash1 != $hash2", and "exit 1"
        would previously pass this test without ever hashing anything
        or failing on a real mismatch, because every assertion here
        used to search the whole raw `build` job block rather than
        this step's own, actually-executed script."""
        block = ci_jobs.get("build")
        assert block is not None, "ci.yml has no build job"
        script = self._reproducibility_step_script(block)
        self._assert_diffs_two_independent_builds(script)

    def test_build_reproducibility_check_rejects_a_cosmetic_stand_in(
        self,
    ) -> None:
        """Regression test for the gap in the previous version of
        :meth:`test_build_verifies_reproducibility`.

        The old test only checked that "reproducible", "sha256sum",
        a "$hash1 ... != ... $hash2" pattern, and "exit 1" each
        occurred *somewhere* in the raw `build` job block. This
        fixture's step builds both wheels, but its "hashing" and
        "comparison" are just words inside one echoed string -- no
        `sha256sum` call, no `hash1`/`hash2` assignment, and no real
        `if`/`exit 1` ever run. Every old assertion (verified by hand
        against the pre-fix logic) is satisfied by this text, so this
        case would have slipped past it silently; it must fail the
        tightened checks instead.
        """
        cosmetic_step = (
            f"      - name: {self.REPRODUCIBILITY_STEP_NAME}\n"
            "        run: |\n"
            "          uv build -o dist-repro-1\n"
            "          uv build -o dist-repro-2\n"
            '          echo "sha256sum check: would compare "$hash1" '
            '!= "$hash2" and exit 1 on mismatch"\n'
            '          echo "Wheel build is reproducible."\n'
        )
        script = self._reproducibility_step_script(cosmetic_step)
        with pytest.raises(
            AssertionError, match="sha256sum of the dist-repro-1 wheel"
        ):
            self._assert_diffs_two_independent_builds(script)


class TestReleaseWorkflow:
    def test_publish_attests_build_provenance(
        self, release_jobs: dict[str, str]
    ) -> None:
        """Downloaders must be able to verify the wheel/sdist provenance."""
        publish = release_jobs.get("publish")
        assert publish is not None, "release.yml has no publish job"
        assert "attest-build-provenance" in publish, (
            "publish job no longer attests build provenance for the "
            "artifacts it uploads"
        )


class TestFuzzWorkflow:
    def test_has_a_concurrency_group(self) -> None:
        """Without one, an overlapping nightly run could waste a runner
        racing a still-running previous one instead of replacing it."""
        assert re.search(r"^concurrency:", FUZZ.read_text(), re.M), (
            "fuzz.yml no longer declares a top-level concurrency group"
        )


class TestMutationWorkflow:
    # pyproject.toml's [tool.mutmut] only_mutate covers the whole of
    # checksum.py, _tlv.py, and dns.py, but the audited DNS surface is
    # only its name-compression byte walk -- mutmut has no config-level
    # way to scope below a whole file, so pyproject.toml's own comment
    # documents these positional filters as the way to reproduce that
    # narrower scope. If the workflow step doesn't pass them, it mutates
    # (and reports on) all of dns.py's untriaged record/RDATA/dataclass
    # code every night, silently wider than what was ever audited.
    EXPECTED_FILTERS = (
        "netprotocols.checksum.*",
        "netprotocols._tlv.*",
        "netprotocols.layer7.dns.x__read_name*",
        "netprotocols.layer7.dns.x__labels*",
    )

    @staticmethod
    def _parse_mutmut_run_filters(text: str) -> list[str]:
        """Parse the quoted argument lines of a `mutmut run` invocation
        exactly as bash would read the continuation lines -- not just
        anywhere in the file, and not a bare substring check.

        A bare substring check over a loosely-extracted block has two
        independent gaps a more literal, line-by-line parse closes:

        1. Each argument line must end with a continuation backslash
           to keep the shell command going onto the next line. A line
           without one ends the real `mutmut run` invocation right
           there -- anything on later lines, quoted or not, is never
           actually passed to mutmut, no matter how legitimate it
           looks in the source. Requiring the backslash explicitly
           here (rather than tolerating its absence and hoping the
           parse boundary happens to land in the right place) is what
           makes the check trace real bash semantics instead of an
           incidental regex artifact.
        2. A line that bash *does* still consider part of the command
           (because the previous line ended in " \\") but that isn't a
           single-quoted filter -- an unquoted word, say -- is still a
           real positional argument as far as bash and mutmut are
           concerned; bash expands it (glob expansion, in the unquoted
           case) and hands it over like any other argument. Silently
           stopping the parse there, the same as at a legitimate
           unbackslashed last line, would let such a line slip past
           the equality check below unnoticed. So a continued line
           that fails to parse as a quoted filter fails this check
           loudly instead: it is never the normal way for the command
           to end, only a normal-looking line with nothing after it
           is.
        """
        match = re.search(
            r"(?m)^          uv run --frozen mutmut run \\\n"
            r"(?P<rest>(?:.*\n)*)",
            text,
        )
        assert match is not None, (
            "mutation.yml's mutmut run step no longer matches the "
            "expected 'uv run --frozen mutmut run \\' shape"
        )

        filters: list[str] = []
        continues = True
        for line in match.group("rest").splitlines():
            if not continues:
                # The previous line ended the bash command (no
                # trailing " \"). Whatever follows in the file --
                # more workflow steps, comments, blank lines -- was
                # never part of this invocation, so it is out of
                # scope for this parse, not a parse failure.
                break
            argument = re.fullmatch(r"            '([^']+)'( \\)?", line)
            assert argument is not None, (
                "mutation.yml's mutmut run command still continues "
                f"(the previous line ended with ' \\') onto a line "
                f"that is not a single-quoted filter argument: "
                f"{line!r} -- bash would still pass this to mutmut "
                f"as a real positional argument"
            )
            filters.append(argument.group(1))
            continues = argument.group(2) is not None
        return filters

    def test_run_applies_the_documented_dns_scope_filters(self) -> None:
        """Checks the *exact* set of filters `mutmut run` is actually
        invoked with.

        Presence-only checking cannot notice an *extra* filter tacked
        onto the command -- pyproject.toml's only_mutate comment
        documents exactly four filters, and a fifth would silently
        widen the audited DNS scope without failing anything.
        Comparing the complete parsed filter set against
        EXPECTED_FILTERS, rather than checking each expected pattern's
        presence, catches both a missing filter and an extra one.
        """
        filters = self._parse_mutmut_run_filters(MUTATION.read_text())

        assert sorted(filters) == sorted(self.EXPECTED_FILTERS), (
            f"mutation.yml's mutmut run step actually applies "
            f"{sorted(filters)}, which does not exactly match the "
            f"filters documented next to only_mutate in pyproject.toml, "
            f"{sorted(self.EXPECTED_FILTERS)} -- it would mutate either "
            f"more or less of dns.py than was ever audited"
        )

    def test_run_rejects_an_unquoted_argument_on_a_continued_line(
        self,
    ) -> None:
        """Regression test: a continued line that is not a quoted
        filter must fail loudly, not be silently dropped.

        All four real filters are present and correctly continued,
        followed by one more continued line that is an unquoted
        wildcard rather than a quoted filter. Bash would still pass
        that word to mutmut as a fifth positional argument -- it is
        not a shell syntax error, just an argument this parse must not
        let slide by unnoticed. Before the fix that replaced a bare
        `break` with this assertion, the loop stopped as soon as the
        unquoted line failed to match, leaving `filters` holding
        exactly the four expected entries and the equality check in
        `test_run_applies_the_documented_dns_scope_filters` passing
        despite the extra argument -- this proves that gap is closed.
        """
        malformed = (
            "          uv run --frozen mutmut run \\\n"
            "            'netprotocols.checksum.*' \\\n"
            "            'netprotocols._tlv.*' \\\n"
            "            'netprotocols.layer7.dns.x__read_name*' \\\n"
            "            'netprotocols.layer7.dns.x__labels*' \\\n"
            "            some_extra_target\n"
        )

        with pytest.raises(
            AssertionError, match="not a single-quoted filter argument"
        ):
            self._parse_mutmut_run_filters(malformed)


# Each new workflow file's defining job, and one distinctive thing that
# job must still do. A missing file or job fails outright; a present job
# missing its needle means the workflow was gutted without anyone
# noticing, since none of these run on every push the way ci.yml does.
NEW_WORKFLOW_REQUIREMENTS: dict[str, tuple[str, tuple[str, ...]]] = {
    "mutation.yml": ("mutation", ("mutmut run",)),
    "codeql.yml": (
        "analyze",
        ("codeql-action/init", "codeql-action/analyze"),
    ),
    "scorecard.yml": ("analysis", ("ossf/scorecard-action",)),
    "docs-lint.yml": ("lychee", ("lycheeverse/lychee-action",)),
    "pr-title-lint.yml": (
        "lint-pr-title",
        ("action-semantic-pull-request",),
    ),
}


@pytest.mark.parametrize(
    "filename", sorted(NEW_WORKFLOW_REQUIREMENTS), ids=lambda name: name
)
def test_new_workflow_has_its_defining_job(filename: str) -> None:
    workflow = WORKFLOWS / filename
    assert workflow.is_file(), f"{filename} is missing from .github/workflows/"
    job_name, needles = NEW_WORKFLOW_REQUIREMENTS[filename]
    blocks = job_blocks(workflow)
    block = blocks.get(job_name)
    assert block is not None, f"{filename} has no {job_name!r} job"
    for needle in needles:
        assert needle in block, (
            f"{filename}'s {job_name!r} job no longer runs {needle!r}"
        )


def test_dependabot_declares_the_required_ecosystems() -> None:
    """dependabot.yml must keep both Python and Actions pins current.

    Every `uses:` SHA this suite checks (TestActionPinning) will drift
    out of date the moment nothing bumps it -- that's github-actions'
    job. The Python side (uv, or pip as a fallback ecosystem name) is
    what keeps the dev dependency-group underneath dependency-scan
    current.
    """
    assert DEPENDABOT.is_file(), ".github/dependabot.yml is missing"
    ecosystems = set(
        re.findall(
            r'package-ecosystem:\s*"?([A-Za-z0-9_-]+)"?',
            DEPENDABOT.read_text(),
        )
    )
    assert ecosystems & {"uv", "pip"}, (
        f"dependabot.yml declares {ecosystems or '{}'}, none of which is "
        f"'uv' or 'pip' -- Python dependency updates would stop being "
        f"tracked"
    )
    assert "github-actions" in ecosystems, (
        f"dependabot.yml declares {ecosystems or '{}'}, missing "
        f"'github-actions' -- the SHA pins this test suite requires "
        f"would go stale silently"
    )
