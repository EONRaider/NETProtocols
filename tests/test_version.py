"""Tests that the package's two in-tree version statements agree.

The version is written in three places: ``pyproject.toml`` (what PyPI
publishes as), ``netprotocols.__version__`` (what a user reads at
runtime), and the ``v*`` release tag. Nothing kept any pair of them in
step, so a bump that missed one would ship a package whose metadata and
``__version__`` disagree.

The two in-tree copies are checked here, on every pull request. The tag
cannot be checked here because it does not exist until release time —
``.github/workflows/release.yml`` compares it against the built artifact
immediately before publishing.
"""

import tomllib
from pathlib import Path

import netprotocols

PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"


def packaged_version() -> str:
    with PYPROJECT.open("rb") as handle:
        version: str = tomllib.load(handle)["project"]["version"]
    return version


class TestVersionAgreement:
    def test_dunder_version_matches_pyproject(self) -> None:
        """A bump must land in both files or neither."""
        declared = packaged_version()
        assert netprotocols.__version__ == declared, (
            f"netprotocols.__version__ is "
            f"{netprotocols.__version__!r} but pyproject.toml publishes "
            f"{declared!r}; a release would ship a package whose metadata "
            f"and __version__ disagree"
        )

    def test_version_is_a_plausible_release(self) -> None:
        """Guards the comparison itself: two empty strings would agree.

        Also rejects the placeholder values that make a bad tag easy to
        push by accident.
        """
        declared = packaged_version()
        assert declared not in ("", "0.0.0"), (
            f"pyproject.toml declares a placeholder version {declared!r}"
        )
        parts = declared.split(".")
        assert len(parts) >= 2 and all(part.isdigit() for part in parts[:2]), (
            f"pyproject.toml version {declared!r} does not start with "
            f"numeric major.minor components"
        )
