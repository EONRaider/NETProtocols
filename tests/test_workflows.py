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

    def test_has_a_dependency_scan_job(self, ci_jobs: dict[str, str]) -> None:
        """Third-party CI dependencies must be audited for known CVEs."""
        block = ci_jobs.get("dependency-scan")
        assert block is not None, "ci.yml has no dependency-scan job"
        assert "pip-audit" in block, (
            "dependency-scan job no longer runs pip-audit"
        )

    def test_build_verifies_reproducibility(
        self, ci_jobs: dict[str, str]
    ) -> None:
        """The build job must diff two independent builds, not just one."""
        block = ci_jobs.get("build")
        assert block is not None, "ci.yml has no build job"
        assert "reproducible" in block.lower(), (
            "build job no longer verifies that the wheel build is reproducible"
        )
        assert block.count("uv build") >= 3, (
            "reproducible-build-diff step must build the wheel twice, in "
            "addition to the job's own initial build, to have anything "
            "to diff"
        )


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
