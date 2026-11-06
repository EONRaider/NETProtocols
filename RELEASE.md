# Releasing netprotocols

The release procedure, step by step. A release is a lightweight `v*` tag
on `master`. Pushing it runs
[`.github/workflows/release.yml`](.github/workflows/release.yml), which
publishes to PyPI and creates the GitHub release; everything before the
push is done by hand, in the order below.

Run every command from the repository root, after setting:

```bash
export V=X.Y.Z      # the version being released, e.g. 2.10.0
export PREV=A.B.C   # the latest released version, e.g. 2.9.0
export REPO=EONRaider/NETProtocols
```

## 1. Check the preconditions

Stop at the first check that fails.

1. The release's milestone has no open issues. `open_issues` must be
   `0`; keep `number` as `MS` for steps 6 and 12:

   ```bash
   gh api "repos/$REPO/milestones?state=all" \
     --jq ".[] | select(.title == \"$V\") | {number, state, open_issues}"
   export MS=<number>
   ```

2. No pull request is open, dependabot's included. Merge or close each
   one through its own review first:

   ```bash
   gh api "repos/$REPO/pulls?state=open" --jq 'length'    # 0
   ```

3. `master` is clean and equals `origin/master`:

   ```bash
   git fetch origin --tags
   git switch master && git pull --ff-only
   git status --porcelain                                 # nothing
   test "$(git rev-parse master)" = "$(git rev-parse origin/master)" && echo equal
   ```

4. The tag does not exist, locally or on the remote:

   ```bash
   git tag --list "v$V"                                   # nothing
   git ls-remote --tags origin "v$V"                      # nothing
   ```

5. The version still reads the previous release:

   ```bash
   grep -n '^version = ' pyproject.toml                   # "$PREV"
   grep -n '^__version__ = ' src/netprotocols/__init__.py # "$PREV"
   git tag --list 'v*' --sort=-v:refname | head -1        # v$PREV
   ```

6. If an audited module or audited test file changed since `v$PREV`, run
   the mutation audit locally now, before cutting the branch, so that a
   survivor is fixed on `master` before the release PR exists. Step 7
   says what the audit covers.

   ```bash
   git diff --stat "v$PREV" master -- \
     src/netprotocols/checksum.py src/netprotocols/_tlv.py \
     src/netprotocols/layer7/dns.py src/netprotocols/layer7/http.py \
     tests/test_checksum.py tests/test_tlv.py tests/test_dns.py tests/test_http.py
   ```

   If that lists a file, run the commands from CONTRIBUTING's
   [Mutation testing](CONTRIBUTING.md#mutation-testing) section, starting
   from a tree with no `mutants/` directory, as CI does (see the comment
   above the run step in `.github/workflows/mutation.yml`):

   ```bash
   rm -rf mutants
   uv run mutmut run 'netprotocols.checksum.*' 'netprotocols._tlv.*' \
       'netprotocols.layer7.dns.x__read_name*' \
       'netprotocols.layer7.dns.x__labels*' \
       'netprotocols.layer7.http.x__*'
   uv run mutmut results --all true > mutmut-results.txt
   python3 scripts/check_mutmut_survivors.py mutmut-results.txt
   ```

## 2. Cut the release branch

```bash
git switch -c "release-$V" master
```

## 3. Re-measure the quoted numbers (CLAIMS Rule 4)

[Rule 4](docs/CLAIMS.md#rules) requires every number a release quotes to
be re-measured before the release; Rule 3 requires each comparative
number to name the competitor's version and the Python version. Measure
on the release branch before making the release commit (step 4), which
carries the figures.

1. **Which numbers, with which scripts.** Every figure the README's
   [Why NETProtocols](README.md#why-netprotocols) section quotes, each
   reproduced with the command in the table of the latest "Re-measured
   for" section under
   [Measurement baseline](docs/CLAIMS.md#measurement-baseline) in
   `docs/CLAIMS.md`, with the same options and run counts:

   | Claim | Command |
   |---|---|
   | 1.1 / 1.2 decode | `scripts/benchmark.py --compare --repetitions 30 --trials 9`, three runs; quote the run with the median ratio |
   | 1.3 whole-frame encode | `scripts/benchmark_encode.py`, three runs; quote the median-ratio run |
   | 1.4 warm import | `scripts/benchmark_import.py` after an untimed warm-up, three invocations, best of three |
   | 1.5 wheel size | `uv build --wheel` on a `git archive` of the release commit, against scapy's wheel |
   | 1.6 depth | `scripts/benchmark.py --depth` |

   The scripts run under the `bench` dependency group:
   `uv run --frozen --group bench python scripts/<script>`. `--compare`
   also times `dpkt` and `scapy` on the same corpus frames, and
   `benchmark_import.py` times `netprotocols`, `dpkt` and `scapy.all`; the
   versions measured are the ones `uv.lock` pins for the `bench` group.
   Check PyPI for a newer release of either and name the versions in
   CLAIMS. CLAIMS 1.7, 3.1 and 4.1 carry dated re-checks that a release
   repeats or marks as not repeated.

   The wheel embeds `README.md` as its long description, so its size
   moves with every README edit. Build it last, once the README text is
   final, from a `git archive` of the release commit, and correct the
   figure in a follow-up commit if a later README edit changes it (2.8.0
   needed one):

   ```bash
   d=$(mktemp -d) && git archive HEAD | tar -x -C "$d" &&
     (cd "$d" && uv build --wheel) && stat -c %s "$d"/dist/*.whl
   ```
2. **The quiet-machine rule.** Neither CLAIMS' Rules nor the benchmark
   scripts define or enforce a load threshold: the method is recorded in
   each "Re-measured for" section of `docs/CLAIMS.md`. Since 2.7.0 every
   timed run is pinned to one performance core with `taskset -c 2`; 2.9.0
   started each run only once the one-minute load average was under 1.0
   (2.7.0 and 2.8.0 used 1.5). A pass that breaks the threshold is
   discarded and repeated, and CLAIMS records the discarded pass. On
   Linux, gate each run like this:

   ```bash
   until awk '{ exit !($1 < 1.0) }' /proc/loadavg; do sleep 15; done
   taskset -c 2 uv run --frozen --group bench python scripts/benchmark.py \
     --compare --repetitions 30 --trials 9
   ```

3. **A figure that is not re-measured is marked as not repeated, never
   carried over silently.** README and CLAIMS each say which figures were
   not repeated and which release they still come from, and the
   CHANGELOG entry says the same.
4. **The maintainer approves the numbers before they are committed.**
   Show each previous figure, the new one and the individual runs, and
   wait for approval.

## 4. Make the `chore(release): X.Y.Z` commit

One commit holds the release change, in these six files.

1. Set `version = "X.Y.Z"` in `pyproject.toml` and
   `__version__ = "X.Y.Z"` in `src/netprotocols/__init__.py`
   (`tests/test_version.py` checks that they agree).
2. Update the lockfile and check that only the project's version line
   changed:

   ```bash
   uv lock
   git diff --numstat uv.lock     # 1	1	uv.lock
   git diff -U0 uv.lock           # the one line is netprotocols' version
   ```

3. In `CHANGELOG.md`, insert `## [X.Y.Z] - YYYY-MM-DD` directly under
   `## [Unreleased]`, so that everything unreleased moves under the new
   heading and `## [Unreleased]` is left empty. Add a `### Development`
   entry to the new section recording the re-measurement: corpus,
   machine, method, competitor versions, each new figure against the
   previous one, and what was not repeated. `release.yml` publishes this
   section as the GitHub release notes.
4. In `README.md`, update the figures and the "re-measured for" date in
   [Why NETProtocols](README.md#why-netprotocols), and the list of
   versions on PyPI in [Roadmap](README.md#roadmap).
5. In `docs/CLAIMS.md`, add a `### Re-measured for X.Y.Z (YYYY-MM-DD)`
   section after the previous one under Measurement baseline (method,
   command table, what was not re-measured), and update the heading and
   the `**Status: VERIFIED for X.Y.Z**` line of each re-measured claim.
6. Commit:

   ```bash
   git add pyproject.toml src/netprotocols/__init__.py uv.lock \
     CHANGELOG.md README.md docs/CLAIMS.md
   git commit -m "chore(release): $V"
   ```

Review fixes go on the branch as further commits.

## 5. Run the QA ladder

The first seven checks are CONTRIBUTING's
[QA ladder](CONTRIBUTING.md#the-qa-ladder) in the form CI runs them, the
fixture loop is CI's lint job, and bandit, which neither CI nor the
repository configures, is run by hand:

```bash
uv run ruff check
uv run ruff format --check
uv run flake8 src
uv run mypy
uv run --frozen pytest
python3 scripts/check_markers.py
uv run --frozen sphinx-build -W -n -b dummy docs "$(mktemp -d)"; echo "sphinx exit: $?"
git ls-files -- 'tests/fixtures/*.pcap' | xargs -n1 dirname | sort -u |
  while read -r dir; do python3 scripts/check_fixtures.py "$dir" || echo "FAILED: $dir"; done
uvx bandit -r src scripts -q   # without uvx on PATH: uv tool run bandit -r src scripts -q
```

The bandit baseline is 11 Low, 0 Medium, 0 High (2.9.0, bandit 1.9.4).
Investigate any new finding before going on. CI additionally runs the
test matrix on Python 3.12 to 3.14, the allocation tests, the dependency
scan, the wheel build and its reproducibility check, the Pyodide check
and the benchmark gate.

## 6. Open the PR and merge it

1. Push the branch and open the PR. Its body follows
   [`.github/pull_request_template.md`](.github/pull_request_template.md):
   Summary; What's included (the version, the CHANGELOG, the
   re-measurement table, what was not repeated); Verification, with the
   ladder's boxes ticked. Set the milestone.

   ```bash
   git push -u origin "release-$V"
   gh pr create --base master --title "chore(release): $V" --body-file <body.md>
   gh api -X PATCH "repos/$REPO/issues/<pr>" -F milestone="$MS"
   ```

2. Verify each bot review finding (CodeRabbit or any other) against the
   code and the rules before acting on it. A valid one is fixed under
   [`.claude/skills/steward/SKILL.md`](.claude/skills/steward/SKILL.md)
   (independent implementation and independent review); a rejected one
   is answered in its thread with the reason.
3. Wait until every check on the PR's head commit is green: CI, Docs
   lint, CodeQL and PR Title Lint. The `master` ruleset requires only
   `lint`, `typecheck` and `build`, so GitHub allows a merge before the
   test, Pyodide and benchmark jobs finish; do not merge before they do.
4. Merge with a merge commit. Never squash or rebase; the repository
   allows all three, so this is on you:

   ```bash
   gh pr merge <pr> --merge
   ```

## 7. Pass the pre-tag gates on `master`

`release.yml` gates publishing on the CI ladder only, and the nightly
fuzz and mutation workflows never run on a pull request. Dispatch both
by hand on `master`, at the exact commit to be tagged, and tag only once
both are green.

1. Dispatch both, with the commands below or from Actions → the
   workflow → *Run workflow* on `master`. A dispatched run checks out the
   head of `master` at dispatch time, so confirm that each run's
   `headSha` equals `$SHA`, the commit you mean to tag, then wait for
   both:

   ```bash
   git fetch origin && SHA=$(git rev-parse origin/master)
   gh workflow run fuzz.yml --ref master
   gh workflow run mutation.yml --ref master
   gh run list --workflow fuzz.yml --event workflow_dispatch --limit 1 \
     --json databaseId,headSha,status,conclusion
   gh run list --workflow mutation.yml --event workflow_dispatch --limit 1 \
     --json databaseId,headSha,status,conclusion
   gh run watch <run-id> --exit-status
   ```

   Both workflows key their concurrency group on the triggering event, so
   a nightly run cannot cancel a dispatched one. The `push` CI run on the
   same commit must be green too.
2. **What the mutation audit covers.** `pyproject.toml`'s `[tool.mutmut]`
   table mutates four files, `src/netprotocols/checksum.py`, `_tlv.py`,
   `layer7/dns.py` and `layer7/http.py`; `mutation.yml`'s positional
   filters narrow that to all of `checksum.py` and `_tlv.py`, DNS's
   `_read_name` and `_labels`, and HTTP's private module-level functions.
   Only the test files in `pytest_add_cli_args_test_selection` count:
   `tests/test_checksum.py`, `tests/test_tlv.py`, `tests/test_dns.py` and
   `tests/test_http.py`. A test anywhere else kills nothing, however much
   of the code it exercises. `scripts/check_mutmut_survivors.py` fails the
   run on any undetected mutant missing from
   `scripts/mutmut_survivors.txt`, on an entry there that is no longer
   undetected, and on a scoped file with no checked mutant.
3. **A survivor is killed by a test in an audited test file.** Only a
   truly equivalent mutant, or one out of any test's reach, is recorded in
   `scripts/mutmut_survivors.txt` instead, under a comment giving the
   reason (see that file's header and CONTRIBUTING's
   [Mutation testing](CONTRIBUTING.md#mutation-testing)).
4. **A gate fix lands on `master` by its own PR**, with a
   `### Development` entry under `## [Unreleased]`, checked and merged as
   in steps 5 and 6. Then dispatch both gates again on the new `master`
   commit and wait for green. The fix ships in the tagged tree, but its
   entry stays under `## [Unreleased]`: this release's notes do not
   mention it, and the next release's CHANGELOG section lists it.

## 8. Choose the commit to tag

Tag the `master` commit that the green fuzz, mutation and CI runs gated,
the `headSha` from step 7. That is the release PR's merge commit, or a
later `master` commit when gate fixes landed after it.

Check that the commit carries the release before tagging it:

```bash
git show "$SHA:pyproject.toml" | grep '^version = '    # "$V"
git show "$SHA:CHANGELOG.md" | awk -v ver="$V" '
  found && /^## \[/ { exit }
  found { print }
  $0 ~ "^## \\[" ver "\\]" { found=1 }
' | head -5                                             # not empty
```

The `awk` program is `release.yml`'s own. The workflow runs it only after
the PyPI upload, so a missing section caught there leaves a published
version without a GitHub release.

## 9. Tag and push

The tag is lightweight:

```bash
git tag "v$V" "$SHA"
git cat-file -t "v$V"     # commit
git push origin "v$V"
```

## 10. Watch `release.yml`

```bash
gh run list --workflow release.yml --limit 1 --json databaseId,headSha,status
gh run watch <run-id> --exit-status
```

Its stages, in order, and what each one guarantees:

| Stage | Guarantees |
|---|---|
| `ci` (calls `ci.yml`) | The tagged commit passes the whole CI ladder. A tag push matches none of `ci.yml`'s own triggers, so this is the only CI run on the tag. |
| `publish`: `uv build` | The wheel and sdist are built from the tagged commit. |
| `publish`: verify the tag | The tag, without its `v`, equals the version read back from the built wheel. |
| `publish`: attest build provenance | GitHub's attestation API records that this run built the wheel and sdist from this commit; a failed attestation stops the release before any upload. |
| `publish`: rename the bundle, generate the SBOM | `netprotocols-X.Y.Z.sigstore.json` (the attestation bundle) and `netprotocols-X.Y.Z.cdx.json` (a CycloneDX SBOM of the wheel, from `cyclonedx-py environment`) are saved as the `release-assets` artifact, kept for 5 days. |
| `publish`: PyPI | `pypa/gh-action-pypi-publish` uploads the wheel and sdist as a trusted publisher bound to this repository, this workflow file and the `pypi` environment. |
| `github-release` | The tag's `## [X.Y.Z]` CHANGELOG section becomes the release notes (no section fails the job), and the release is created as latest with both assets attached. |

## 11. When something fails

- **Never move, delete or re-push a tag.** No ruleset protects tags, so
  GitHub does not enforce this; the procedure does.
- **A failure before the PyPI upload** (the `ci` job, or a `publish` step
  before the upload) leaves PyPI untouched.
  - A transient cause (a runner or network error): re-run the failed
    jobs. The re-run builds the same commit with the same workflow file.

    ```bash
    gh run rerun <run-id> --failed
    ```

  - A cause in the tagged tree (code, workflow or version): a re-run
    cannot fix it, and the tag cannot move. Stop and decide. The only
    path this procedure allows is to fix `master` and release the next
    patch version from step 1.
- **A failure in or after the PyPI upload.** PyPI never accepts the same
  file name twice, even after a deletion, and the publish step does not
  skip existing files.
  - The upload failed partway: a re-run fails on the file already there.
    Stop and decide.
  - Only `github-release` failed, from a transient cause: re-run it with
    `gh run rerun <run-id> --failed` while the `release-assets` artifact
    is within its 5-day retention.
  - Anything else: stop and decide. X.Y.Z on PyPI is final, and any change
    ships as the next patch release.

## 12. After the release

1. Verify PyPI: the version lists a wheel and an sdist, and installs.

   ```bash
   curl -s "https://pypi.org/pypi/netprotocols/$V/json" |
     python3 -c 'import json, sys; print([u["filename"] for u in json.load(sys.stdin)["urls"]])'
   uv run --isolated --no-project --refresh --with "netprotocols==$V" \
     python -c 'import netprotocols; print(netprotocols.__version__)'
   ```

   The published wheel's size, from the PyPI JSON's `size` field, should
   equal the CLAIMS 1.5 figure.

2. Verify the GitHub release, its two assets, and the published wheel's
   provenance:

   ```bash
   gh api "repos/$REPO/releases/tags/v$V" \
     --jq '{name, draft, prerelease, assets: [.assets[].name]}'
   # assets: netprotocols-X.Y.Z.cdx.json and netprotocols-X.Y.Z.sigstore.json
   DL=$(mktemp -d)
   python3 -m pip download --no-deps --only-binary :all: "netprotocols==$V" -d "$DL"
   gh attestation verify "$DL/netprotocols-$V-py3-none-any.whl" --repo "$REPO"
   ```

3. Close the milestone:

   ```bash
   gh api -X PATCH "repos/$REPO/milestones/$MS" -f state=closed
   ```

4. Comment on the open roadmap issue the release belongs to: the PyPI
   and GitHub release links, that the milestone is closed, and which held
   work is now unblocked.
5. Resume the work held until the release: the PRs and issues the
   roadmap's decisions parked until X.Y.Z was cut.

## 2.9.0 as an example

- One dependabot PR (#345) was open, and was merged so that the
  preconditions held.
- The release PR (#346) held the `chore(release): 2.9.0` commit and one
  follow-up, a CLAIMS wording fix CodeRabbit caught. CodeRabbit's other
  finding asked for the per-capture figures to be re-measured or
  removed; they were already marked as not repeated, and that thread was
  still open at merge.
- Not repeated, and said so in README and CLAIMS: the per-capture decode
  figures and the CLAIMS 1.7, 3.1 and 4.1 re-checks. A first benchmark
  pass, one of whose runs started at a load average of 2.01, was
  discarded and repeated under the 1.0 threshold.
- `uvx` was not on PATH, so bandit ran as `uv tool run bandit`.
- The mutation gate on the release PR's merge commit failed on 15
  unrecorded survivors in `netprotocols.checksum`, because the new tests
  were outside `tests/test_checksum.py`. #347 added tests there that kill
  14 and recorded the 15th, an equivalent mutant, in
  `scripts/mutmut_survivors.txt`. Both gates passed on #347's merge
  commit, and `v2.9.0` was tagged there rather than on the release
  branch's head. Both PRs carry milestone 2.9.0.
- 2.8.0 had dispatched its gates on the `release-2.8.0` branch and tagged
  that branch's head before its PR merged (the merge commit's tree is the
  same). 2.9.0 gated `master` as CONTRIBUTING asks, and a gate fix landed
  after the release PR, so the gated commit was a later `master` commit.
- 2.3.0 is the one release whose tag was re-pointed. Its first run was
  cancelled before any job ran, by a concurrency-group deadlock that #228
  fixed, and the tag was pushed again on #228's merge commit. Step 11
  rules that out.
