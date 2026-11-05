<!--
Thanks for contributing to netprotocols! Fill in the sections below and
delete this comment. CONTRIBUTING.md has the full workflow; the short
version is: keep the QA ladder green and update the docs your change
touches. Relative links below resolve from the repo root once this
becomes the PR description.
-->

## Summary

<!-- What does this change do, and why? Link any related issue, e.g. "Closes #22". -->

## What's included

<!-- The concrete changes, one bullet each: new/edited modules, tests, docs. -->

-

## Verification

<!-- Paste the QA-ladder output, or tick the boxes. The first six boxes cover the seven checks CI runs; the CHANGELOG entry is checked in review. -->

- [ ] `uv run ruff check` and `uv run ruff format --check` are clean
- [ ] `uv run flake8 src` (pydoclint) is clean
- [ ] `uv run mypy` is clean (strict)
- [ ] `uv run pytest` passes locally (CI runs it on Python 3.12 / 3.13 / 3.14)
- [ ] `python3 scripts/check_markers.py` is clean: no work markers
- [ ] `uv run sphinx-build -W -n -b dummy docs <outdir>` is clean: every docstring cross-reference resolves
- [ ] `CHANGELOG.md` has an entry under `## [Unreleased]`

### New protocol or dispatch change — also:

<!-- Delete this block if it doesn't apply. See ARCHITECTURE.md's cookbook. -->

- [ ] Followed the add-a-protocol cookbook in [ARCHITECTURE.md](ARCHITECTURE.md) and the decode contract in `src/netprotocols/_base.py`
- [ ] New `EtherType` / `IPProtocol` numbers carry display names in lockstep (a completeness test enforces it)
- [ ] Registered the class in the fuzz suite (`tests/test_fuzz.py::ALL_PROTOCOLS`)
- [ ] Added a fixture and updated [tests/fixtures/MANIFEST.md](tests/fixtures/MANIFEST.md) — a real capture where possible (see CONTRIBUTING.md for the capture scripts)
- [ ] Updated the README coverage table and the ARCHITECTURE.md chain diagram

## Notes

<!-- Anything reviewers should know: trade-offs, follow-ups, companion PRs. Optional. -->
