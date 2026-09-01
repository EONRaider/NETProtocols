"""Tests that the release workflow cannot publish without the QA ladder.

A published version can only be yanked, never replaced, so the gate that
stops a broken tag reaching PyPI is worth asserting rather than trusting.
The wiring is easy to break silently: drop ``needs:`` from the publish
job, or ``workflow_call:`` from the CI workflow, and releases keep
working while the gate quietly stops existing.

These parse the workflow YAML by indentation rather than with a YAML
library, to avoid adding a dependency for four assertions. The files are
small and uniformly two-space indented; a parse failure here fails the
test loudly instead of passing vacuously.
"""

import re
from pathlib import Path

import pytest

WORKFLOWS = Path(__file__).resolve().parent.parent / ".github" / "workflows"
CI = WORKFLOWS / "ci.yml"
RELEASE = WORKFLOWS / "release.yml"


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
        for workflow in sorted(WORKFLOWS.glob("*.yml")):
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
