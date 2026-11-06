# Releasing netprotocols

The release procedure, step by step. A release is a lightweight `v*` tag
on `master`. Pushing it runs
[`.github/workflows/release.yml`](.github/workflows/release.yml), which
publishes to PyPI and creates the GitHub release; everything before the
push is done by hand, in the order below.

Run every command from the repository root, in one bash shell, after
setting:

```bash
export V=X.Y.Z      # the version being released, e.g. 2.10.0
export PREV=A.B.C   # the latest released version, e.g. 2.9.0
export REPO=EONRaider/NETProtocols
```

Later command blocks set `MS`, `BODY`, `PR`, `HEAD_SHA`, `SHA`, `T0`,
`FUZZ_RUN`, `MUT_RUN` and `RUN` where they are first needed, and the
blocks after them reuse those values.

The blocks assume bash. zsh does not word-split an unquoted `$runs`, so
step 11's guard would treat every run ID as one.

Do not turn on `set -e` in the release shell: any failing command,
including the `(exit 1)` that ends a refused block, then closes it, in
bash as in zsh.

## 1. Check the preconditions

Stop at the first check that fails.

1. The release's milestone has no open issues. `open_issues` must be
   `0`. The second command keeps the milestone's number as `MS` for
   steps 6 and 12:

   ```bash
   gh api "repos/$REPO/milestones?state=all" --paginate \
     --jq ".[] | select(.title == \"$V\") | {number, state, open_issues}"
   MS=$(gh api "repos/$REPO/milestones?state=all" --paginate \
     --jq ".[] | select(.title == \"$V\") | .number")
   echo "MS=$MS"                                          # not empty
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
   survivor is fixed on `master` before the release PR exists. The
   author of each PR that changed an audited module is expected to have
   run the audit by hand (step 7, "What the mutation audit covers"); that
   is a convention, and CI does not run the audit on pull requests. This
   run checks their changes together, on the tree to be released.

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

[Rule 4](docs/CLAIMS.md#rules) requires that, before every release that
quotes a number, each figure is either re-measured or explicitly marked
as not repeated for that release, with the version it was last measured
in; Rule 3 requires each comparative number to name the competitor's
version and the Python version. Measure on the release branch before
making the release commit (step 4), which carries the figures. The
wheel size is the exception: step 4 measures it from the release commit
itself.

1. **Which numbers, with which commands.** Every figure the README's
   [Why NETProtocols](README.md#why-netprotocols) section quotes. The
   table of the latest "Re-measured for" section under
   [Measurement baseline](docs/CLAIMS.md#measurement-baseline) in
   `docs/CLAIMS.md` gives the command and options for each, with run
   counts and environment where they matter (claim 1.4's `PYTHONPATH`
   set to a `git archive` extract's `src` and its
   `env -u PYTHONDONTWRITEBYTECODE`, for instance). As of 2.9.0 that is
   [Re-measured for 2.9.0 (2026-11-06)](docs/CLAIMS.md#re-measured-for-290-2026-11-06).
   The table abbreviates: it names each script and its options, and the
   invocation around them is the one below.

   The benchmark scripts run under the `bench` dependency group, through
   `uv run --frozen --group bench python`, as in the example under item
   2. `--compare`
   also times `dpkt` and `scapy` on the same corpus frames, and
   `benchmark_import.py` times `netprotocols`, `dpkt` and `scapy.all`; the
   versions measured are the ones `uv.lock` pins for the `bench` group.
   Check PyPI for a newer release of either and name the versions in
   CLAIMS. CLAIMS 1.7, 3.1 and 4.1 carry dated re-checks, which Rule 4
   covers too: each is repeated or marked as not repeated.
2. **The quiet-machine convention.** Rule 4 does not define a load
   threshold, and the benchmark scripts do not enforce one. The method
   is a convention, recorded in each "Re-measured for" section of
   `docs/CLAIMS.md`. Since 2.7.0 every timed run is pinned with
   `taskset -c 2`: CPU 2 was chosen as a performance core of the Intel
   Core i7-1355U every release from 2.7.0 on was measured with (CLAIMS'
   "Re-measured for 2.7.0" section). Another machine needs its own
   choice of core, recorded in its "Re-measured for" section. 2.9.0
   started each run only once the one-minute load average was under 1.0
   (2.7.0 and 2.8.0 used 1.5). A pass that breaks the threshold is
   discarded and repeated, and CLAIMS records the discarded pass. On
   Linux, gate each run like this:

   ```bash
   until awk '{ exit !($1 < 1.0) }' /proc/loadavg; do sleep 15; done
   taskset -c 2 uv run --frozen --group bench python scripts/benchmark.py \
     --compare --repetitions 30 --trials 9
   ```

3. **A figure that is not re-measured is marked as not repeated for
   this release, with the version it was last measured in** (Rule 4). It
   is never carried over silently. README and CLAIMS each name the
   figures not repeated and the version each was last measured in, and
   the CHANGELOG entry says the same.
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

7. **Measure the wheel (CLAIMS 1.5) from the release commit.** The
   wheel embeds `README.md` as its long description, so its size moves
   with every README edit; only a build of the committed tree, with the
   new version and the final README, gives the figure. On the release
   branch, with the release commit at `HEAD`:

   ```bash
   git log -1 --format=%s     # chore(release): X.Y.Z, or a later commit on the branch
   d=$(mktemp -d) && git archive HEAD | tar -x -C "$d" &&
     (cd "$d" && uv build --wheel) && stat -c %s "$d"/dist/*.whl
   [ -z "$d" ] || rm -rf -- "$d"
   ```

   If the size differs from the figure in README and CLAIMS, correct it
   in a follow-up commit on the branch and build again from the new
   `HEAD`, since the correction edits the README too. Do the same if a
   later README edit on the branch changes the size (2.8.0 needed such a
   follow-up). Step 8 builds it again from the commit to be tagged when
   that is a later `master` commit.

Review fixes go on the branch as further commits.

## 5. Run the QA ladder

The first seven checks are CONTRIBUTING's
[QA ladder](CONTRIBUTING.md#the-qa-ladder) in the form CI runs them. The
fixture block is the step of CI's lint job that checks every committed
capture, and fails as that step does: when no capture is tracked under
`tests/fixtures`, or when any directory's run fails. Bandit, which
neither CI nor the repository configures, is run by hand:

```bash
uv run ruff check
uv run ruff format --check
uv run flake8 src
uv run mypy
uv run --frozen pytest
python3 scripts/check_markers.py
uv run --frozen sphinx-build -W -n -b dummy docs "$(mktemp -d)"; echo "sphinx exit: $?"
(
  set -euo pipefail
  mapfile -t dirs < <(git ls-files -- 'tests/fixtures/*.pcap' | xargs -n1 dirname | sort -u)
  [ "${#dirs[@]}" -gt 0 ] || { echo "FAILED: no capture tracked under tests/fixtures"; exit 1; }
  for dir in "${dirs[@]}"; do
    python3 scripts/check_fixtures.py "$dir" || { echo "FAILED: $dir"; exit 1; }
  done
); echo "fixtures exit: $?"
uvx bandit==1.9.4 -r src scripts -q   # without uvx on PATH: uv tool run bandit==1.9.4 -r src scripts -q
```

The bandit baseline is 11 Low, 0 Medium, 0 High, taken with bandit
1.9.4 for 2.9.0; it holds for that version, hence the pin. Investigate
any new finding before going on. CI additionally runs the test matrix
on Python 3.12 to 3.14, the allocation tests, the dependency scan, the
wheel build and its reproducibility check, the Pyodide check and the
benchmark gate.

## 6. Open the PR and merge it

1. Push the branch and open the PR. Its body follows
   [`.github/pull_request_template.md`](.github/pull_request_template.md):
   Summary; What's included (the version, the CHANGELOG, the
   re-measurement table, what was not repeated); Verification, with the
   ladder's boxes ticked. Fill in `$BODY` before `gh pr create` reads it.
   Set the milestone.

   ```bash
   BODY=$(mktemp --suffix=.md)
   cp .github/pull_request_template.md "$BODY"   # then fill it in with an editor
   git push -u origin "release-$V"
   gh pr create --base master --head "release-$V" \
     --title "chore(release): $V" --body-file "$BODY"
   PR=$(gh api "repos/$REPO/pulls?state=open&head=${REPO%%/*}:release-$V" \
     --jq '.[0].number')
   echo "PR=$PR"                                          # not empty
   gh api -X PATCH "repos/$REPO/issues/$PR" -F milestone="$MS"
   ```

2. Verify each bot review finding (CodeRabbit or any other) against the
   code and the rules before acting on it. A valid one is fixed under
   [`.claude/skills/steward/SKILL.md`](.claude/skills/steward/SKILL.md)
   (independent implementation and independent review); a rejected one
   is answered in its thread with the reason.
3. **Wait for all CI, not only the required checks.** Every check on the
   PR's head commit must be green: CI, Docs lint, CodeQL and PR Title
   Lint. The `master` ruleset requires only `lint`, `typecheck` and
   `build`, so GitHub allows a merge before the test, Pyodide and
   benchmark jobs finish. Waiting is a convention for whoever merges; the
   ruleset does not enforce it. `HEAD_SHA` is the commit whose checks you
   watched; the merge below refuses to run if the PR's head has moved
   since:

   ```bash
   HEAD_SHA=$(git rev-parse "release-$V")
   test "$(gh api "repos/$REPO/pulls/$PR" --jq .head.sha)" = "$HEAD_SHA" && echo same
   gh api "repos/$REPO/commits/$HEAD_SHA/check-runs?per_page=100" --paginate \
     --jq '.check_runs[] | [.name, .status, .conclusion] | @tsv'
   ```

   Every check run listed is `completed`, and `success`, `neutral` or
   `skipped`; a `cancelled` one is fine only when a later run of the
   same check, also listed, succeeded.
4. **Merge with a merge commit.** Never squash or rebase. The repository
   allows all three methods and the ruleset does not restrict them, so
   this too is a convention for whoever merges, not something GitHub
   enforces:

   ```bash
   gh pr merge "$PR" --merge --match-head-commit "$HEAD_SHA"
   ```

## 7. Pass the pre-tag gates on `master`

`release.yml` gates publishing on the CI ladder only, and the nightly
fuzz and mutation workflows never run on a pull request. Dispatch both
by hand on `master`, at the exact commit to be tagged, and tag only once
both are green.

1. Dispatch both, with the commands below or from Actions → the
   workflow → *Run workflow* on `master`. A dispatched run checks out the
   head of `master` at dispatch time. `SHA` is the commit you mean to
   tag. `T0`, taken just before dispatching, tells the new runs apart
   from earlier dispatches on the same commit; it is read from this
   machine's clock, which must be correct. `wait_run` polls every 10
   seconds until GitHub lists the new run on `$SHA`, and gives up after
   5 minutes with a message and a non-zero status. If it gives up,
   `master` most likely moved after the fetch, so the dispatched run is
   on another commit: start this step again.

   ```bash
   git fetch origin && SHA=$(git rev-parse origin/master) && echo "SHA=$SHA"
   T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)
   gh workflow run fuzz.yml --ref master
   gh workflow run mutation.yml --ref master
   new_run() {  # $1 workflow file, $2 event: its run on $SHA created at or after $T0
     gh run list --workflow "$1" --event "$2" --commit "$SHA" \
       --json databaseId,createdAt \
       --jq "[.[] | select(.createdAt >= \"$T0\")] | .[0].databaseId // empty"
   }
   wait_run() {  # $1 workflow file, $2 event: prints new_run's ID, or fails after 5 minutes
     local id i
     for i in $(seq 30); do
       id=$(new_run "$1" "$2") && [ -n "$id" ] && { echo "$id"; return 0; }
       sleep 10
     done
     echo "No $2 run of $1 on $SHA created since $T0 after 5 minutes." >&2
     return 1
   }
   FUZZ_RUN=$(wait_run fuzz.yml workflow_dispatch) &&
     MUT_RUN=$(wait_run mutation.yml workflow_dispatch) &&
     echo "fuzz $FUZZ_RUN, mutation $MUT_RUN"
   gh run watch "$FUZZ_RUN" --exit-status
   gh run watch "$MUT_RUN" --exit-status
   ```

   Both workflows key their concurrency group on the triggering event, so
   a nightly run cannot cancel a dispatched one. The `push` CI run on the
   same commit must be green too:

   ```bash
   gh run list --workflow ci.yml --event push --commit "$SHA" \
     --json databaseId,status,conclusion
   ```

2. **What the mutation audit covers.** The audit is deliberately
   narrow. `pyproject.toml`'s `[tool.mutmut]` table mutates four files
   (`only_mutate`): `src/netprotocols/checksum.py`, `_tlv.py`,
   `layer7/dns.py` and `layer7/http.py`. The positional filters in
   `mutation.yml` and in CONTRIBUTING's command narrow that to all of
   `checksum.py` and `_tlv.py`, DNS's `_read_name` and `_labels`, and
   HTTP's private module-level functions. Only the test files in
   `pytest_add_cli_args_test_selection` run against the mutants:
   `tests/test_checksum.py`, `tests/test_tlv.py`, `tests/test_dns.py` and
   `tests/test_http.py`. Two rules follow, for every PR and not only at
   release time:
   - **A test meant to kill mutants of an audited module lives in that
     module's audited test file.** A test anywhere else kills nothing,
     however much of the code it exercises.
   - **The author of a PR that changes an audited module runs the audit
     by hand:** CONTRIBUTING's `mutmut run` command and
     `scripts/check_mutmut_survivors.py`, from a tree with no `mutants/`
     directory. This is a convention: `mutation.yml` has no
     `pull_request` trigger, so CI does not run the audit on a PR.

   `scripts/check_mutmut_survivors.py` fails the run on any undetected
   mutant missing from `scripts/mutmut_survivors.txt`, on an entry there
   that is no longer undetected, and on a scoped file with no checked
   mutant.
3. **A survivor is killed by a test in an audited test file.** Only a
   truly equivalent mutant, or one out of any test's reach, is recorded in
   `scripts/mutmut_survivors.txt` instead, under a comment giving the
   reason (see that file's header and CONTRIBUTING's
   [Mutation testing](CONTRIBUTING.md#mutation-testing)).
4. **A gate fix lands on `master` by its own PR**, checked and merged as
   in steps 5 and 6. Then dispatch both gates again on the new `master`
   commit and wait for green. **A change merged to get the release gates
   green before the tag, or before a permitted retag (step 11), goes into
   that release's CHANGELOG section:**
   its entry goes under `## [X.Y.Z]`'s `### Development`, not under
   `## [Unreleased]`, because the tagged tree contains it and
   `release.yml` publishes that section as the release notes.

## 8. Choose the commit to tag

Tag the `master` commit that the green fuzz, mutation and CI runs gated,
`$SHA` from step 7. That is the release PR's merge commit, or a later
`master` commit when gate fixes landed after it.

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

Step 4 measured the wheel on the release branch. When `$SHA` is a later
`master` commit, gate fixes may have changed what the wheel holds, so
build it again from `$SHA` and compare its size with the CLAIMS 1.5
wheel row that names `netprotocols-$V-py3-none-any.whl` and with the
size README states, both read from `$SHA` rather than from the working
tree. CLAIMS gives the size in bytes, in that row (the last one, if
several name it), which is selected by the wheel's file name as a fixed
string, so the dots in `$V` match only dots; README gives it in KiB to
one decimal, in its `**A N KiB wheel …` line. Each
comparison prints `same`, or `DIFFERS: got ... vs want ...`, where a
failed build reads as `got no wheel` and a missing row or line as
`want none`. The first line clears what an earlier pass set, so a stale
size is never compared, and the last removes the build directory:

```bash
d= got= want= got_kib= want_kib=
d=$(mktemp -d) && git archive "$SHA" | tar -x -C "$d" &&
  (cd "$d" && uv build --wheel) &&
  got=$(stat -c %s "$d/dist/netprotocols-$V-py3-none-any.whl") &&
  echo "wheel: $got bytes" || echo "wheel: FAILED: no netprotocols-$V wheel built from $SHA"
want=$(git show "$SHA:docs/CLAIMS.md" | grep '^| 1\.5 wheel |' |
  grep -F "\`netprotocols-$V-py3-none-any.whl\`" |
  sed -n 's/.*`netprotocols-[^`]*-py3-none-any\.whl` \([0-9,]*\) bytes.*/\1/p' |
  tail -1 | tr -d ,)
[ -n "$got" ] && [ "$got" = "$want" ] && echo "CLAIMS: same" ||
  echo "CLAIMS: DIFFERS: got ${got:-no wheel} vs want ${want:-none} (bytes)"
[ -z "$got" ] || got_kib=$(awk -v b="$got" 'BEGIN { printf "%.1f", b / 1024 }')
want_kib=$(git show "$SHA:README.md" |
  sed -n 's/.*\*\*A \([0-9.]*\) KiB wheel.*/\1/p' | head -1)
[ -n "$got_kib" ] && [ "$got_kib" = "$want_kib" ] && echo "README: same" ||
  echo "README: DIFFERS: got ${got_kib:-no wheel} vs want ${want_kib:-none} (KiB)"
[ -z "$d" ] || rm -rf -- "$d"
```

If either differs, correct README and CLAIMS by a PR to `master` as in
step 7's gate fixes, pass the gates again on the new commit, and come
back to this step with `SHA` set to it.

## 9. Tag and push

The tag is lightweight. `T0` is taken again, for step 10:

```bash
git tag "v$V" "$SHA"
git cat-file -t "v$V"     # commit
T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)
git push origin "refs/tags/v$V"
```

## 10. Watch `release.yml`

`new_run` and `wait_run` are the functions step 7 defines, and they
read `SHA` and `T0`. In the shell that ran step 9, or step 11's retag,
both are already set: skip to the second block.

**Only in a new shell:** export `V` and `REPO` again as at the top of
this file, define both functions again, and run this block after
replacing the placeholder with a UTC time, in the same
`%Y-%m-%dT%H:%M:%SZ` format, at or shortly before the push:

```bash
SHA=$(git rev-parse "v$V^{commit}") && echo "SHA=$SHA"
T0=YYYY-MM-DDTHH:MM:SSZ
```

Then, in either shell, find the run and watch it. The block refuses to
start while `SHA` is empty or `T0` is unset or still holds the
placeholder: an empty `SHA` would make `gh run list --commit ""` list
runs on every commit, so a run for another tag could be picked; an unset
`T0` would match an older `push` run on the same commit, and the
placeholder would match none:

```bash
RUN=
if [ -n "$SHA" ] &&
  [[ $T0 =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]]; then
  RUN=$(wait_run release.yml push) && echo "RUN=$RUN" &&
    gh run watch "$RUN" --exit-status
else
  echo "SHA is \"$SHA\" and T0 is \"$T0\": SHA must not be empty and T0" \
    "must be a UTC time; set them as in the block above." >&2
  (exit 1)
fi
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

- **The retagging rule.** A tag may be moved or re-pushed only when no
  `release.yml` run for it uploaded anything to PyPI: every run failed,
  or was cancelled, before the PyPI publish step. Once anything is
  published, the tag is never moved, and the fix goes into the next
  patch release. No ruleset protects tags, so GitHub cannot refuse a
  moved tag; the rule binds whoever tags, and the guard below is the
  check they run before moving or re-pushing one.

  Deleting a file or a release on PyPI never re-opens retagging. A
  deleted file's name can never be uploaded again (see "What PyPI
  accepts" below), so a rebuild would be refused, and once a release is
  deleted PyPI answers 404 for it, which is no evidence that nothing was
  uploaded. That is why the guard checks the runs as well as PyPI.

  The guard defines two functions. `upload_not_reached` reads one run,
  and every job of every attempt of it (`filter=all`, paginated, whatever
  the job's name), and passes only if all of these hold:
  - **The run is `completed`.** `release.yml` has
    `cancel-in-progress: false`, so a run queued or in progress for the
    old tag, a re-run included, still builds and uploads after the tag
    has moved. A queued run can list no jobs yet, which on its own would
    look like a run that uploaded nothing.
  - **Every job is `completed`.**
  - **No job has an upload step whose conclusion is anything but
    `skipped`.** Each step name is normalized before it is compared:
    ASCII letters are lowercased, every run of Unicode whitespace (space,
    tab, newline, vertical tab, form feed, carriage return, U+0085 and
    every space separator, such as the no-break and ideographic spaces)
    becomes one space, and a leading or trailing space is removed. The
    regex class that does this matches the same characters in gh's gojq
    and in jq 1.7, whose `\s` differ. An upload step is one whose
    normalized name is "publish to pypi"; starts with "run
    pypa/gh-action-pypi-publish", as runs from before `release.yml`
    named the step list it; or contains `uv publish` or `twine upload`.
    v1.0.0's runs uploaded with `uv publish`. A job that uploads under
    another name, such as a renamed `publish` job, is caught by its step,
    whatever the ASCII case or whitespace of the step's name.
  - **A `publish` job that was not skipped lists an upload step.** One
    that ran and lists none (an older workflow that uploaded with another
    step, or a job cancelled before its steps were recorded) fails the
    check.
  - **Some attempt lists a job named `publish`.** The name must match
    exactly; the guard quotes each job name as JSON, so a name with a
    newline in it cannot pass for `publish`. The exception is a run
    that lists no jobs at all and concluded `failure` or
    `startup_failure`, which is how GitHub records a run that never
    started a job, such as one with an invalid workflow file. A run that
    lists jobs but none named `publish` (a renamed job, or only `ci`
    jobs), and a cancelled run with no jobs, fail the check.

  2.3.0's first run, 39981620700, passes: it concluded `failure` and
  lists `publish` and `github-release`, both skipped with no steps, and
  no `ci` job. `retag_allowed` passes only if PyPI answers 404 for the
  version and every `release.yml` run for the tag passes
  `upload_not_reached`; it fails if no run is found.

  ```bash
  upload_not_reached() {  # $1 run ID: passes only if the run is completed and no job of any attempt reached an upload step
    local run jobs bad
    run=$(gh api "repos/$REPO/actions/runs/$1" --jq '"\(.status) \(.conclusion)"') ||
      { echo "Could not read run $1." >&2; return 1; }
    case "$run" in
      "completed "*) ;;
      *) echo "Run $1 is $run, not completed." >&2; return 1 ;;
    esac
    jobs=$(gh api "repos/$REPO/actions/runs/$1/jobs?filter=all&per_page=100" --paginate --jq '
      (.jobs // error("no jobs array in the response"))[] |
      [.steps[]? | (.name | ascii_downcase | gsub("[\\s\\x{0B}\\x{85}\\p{Z}]+"; " ") |
                    ltrimstr(" ") | rtrimstr(" ")) as $n |
       select($n == "publish to pypi" or
              ($n | startswith("run pypa/gh-action-pypi-publish")) or
              ($n | contains("uv publish")) or
              ($n | contains("twine upload")))] as $up |
      "job \(.name | @json)",
      (select(.status != "completed" or any($up[]; .conclusion != "skipped") or
              (.name == "publish" and .conclusion != "skipped" and ($up | length) == 0)) |
       "bad run \(.run_id) attempt \(.run_attempt): job \(.name) \(.conclusion // .status), upload steps \([$up[] | "\(.name): \(.conclusion // .status)"])")
    ') || { echo "Could not list the jobs of run $1." >&2; return 1; }
    bad=$(printf '%s\n' "$jobs" | sed -n 's/^bad //p')
    [ -z "$bad" ] || { echo "$bad" >&2; return 1; }
    printf '%s\n' "$jobs" | grep -qxF 'job "publish"' && return 0
    if [ -z "$jobs" ]; then
      case "$run" in "completed failure" | "completed startup_failure") return 0 ;; esac
    fi
    echo "Run $1 ($run) lists no job named publish." >&2
    return 1
  }
  retag_allowed() {  # passes only if PyPI has no $V and no release.yml run for v$V reached its upload
    local code runs run
    code=$(curl -s -o /dev/null -w '%{http_code}' "https://pypi.org/pypi/netprotocols/$V/json")
    [ "$code" = 404 ] || { echo "PyPI answered $code for netprotocols $V, not 404." >&2; return 1; }
    runs=$(gh api "repos/$REPO/actions/workflows/release.yml/runs?branch=v$V&per_page=100" \
      --paginate --jq '.workflow_runs[].id') || { echo "Could not list the runs for v$V." >&2; return 1; }
    [ -n "$runs" ] || { echo "No release.yml run found for v$V." >&2; return 1; }
    for run in $runs; do
      upload_not_reached "$run" || return 1
    done
  }
  ```

  The retag commands in this section run only inside
  `if retag_allowed; then ... else ... fi`, as written below; on a
  refusal the block prints why and ends with a non-zero status, and the
  tag is left as it is.

  When the tag and the packaged version differ, `release.yml`'s "Verify
  the tag matches the version being published" step fails with a message
  that says to retag. That fits this rule: the step runs before the
  publish step, so nothing has been uploaded.
- **A failure before the PyPI upload** (the `ci` job, or a `publish` step
  before the upload) leaves PyPI untouched.
  - A transient cause (a runner or network error): re-run the failed
    jobs. The re-run builds the same commit with the same workflow file.

    ```bash
    gh run rerun "$RUN" --failed
    ```

  - A cause in the tagged tree (code, workflow or version): a re-run
    cannot fix it. Fix it on `master` by its own PR, with its CHANGELOG
    entry in the release's section as step 7 says, pass the gates on the
    new `master` commit (step 7 sets `SHA` to it, and step 8 checks
    it), and move the tag there through the retagging rule's guard
    above. The commands are chained, so an empty `SHA` or a failed
    command stops the block before `git push --force`:

    ```bash
    if retag_allowed; then
      [ -n "$SHA" ] &&
        git tag -f "v$V" "$SHA" &&
        [ "$(git cat-file -t "v$V")" = commit ] &&
        T0=$(date -u +%Y-%m-%dT%H:%M:%SZ) &&
        git push --force origin "refs/tags/v$V" ||
        { echo "Stopped: SHA is empty, or one of these commands failed." >&2
          [ -z "$SHA" ] || echo "The local tag v$V may already point at $SHA;" \
            "git fetch --force origin \"refs/tags/v$V:refs/tags/v$V\" restores it." >&2
          (exit 1); }
    else
      echo "Refusing to move v$V: the retagging rule does not allow it." >&2
      (exit 1)
    fi
    ```

    Then watch the new run as in step 10.
- **A failure in or after the PyPI upload.** What PyPI accepts:
  - **A file name reused with different contents is refused, even after
    the file was deleted.** PyPI's documentation: "PyPI does not allow
    for a filename to be reused, even once a project has been deleted
    and recreated"
    ([Troubleshooting](https://docs.pypi.org/publishing/troubleshooting/)).
    Warehouse's upload handler answers a name that exists with different
    hashes with "File already exists", and the name of a deleted file
    with "This filename was previously used by a file that has since been
    deleted"
    ([`warehouse/forklift/legacy.py`](https://github.com/pypi/warehouse/blob/0fac80550625bdc75baab04c303eddf249b93ab0/warehouse/forklift/legacy.py),
    lines 1202-1224 and 1226-1245, at commit `0fac805`).
  - **A byte-identical re-upload is accepted silently.** When the name
    and the SHA-256 and BLAKE2b-256 digests all match an existing file,
    `_is_duplicate_file` in the same `legacy.py` (lines 419-447) reports
    a duplicate and the handler returns HTTP 200 without storing anything
    (lines 1198-1201).
  - **A missing file can be added only within 14 days of the release's
    creation.** After the duplicate and deleted-name checks, the handler
    refuses a new file for a release older than
    `MAXIMUM_AGE_FOR_NEW_UPLOADS = dt.timedelta(days=14)`
    ([`warehouse/constants.py`](https://github.com/pypi/warehouse/blob/0fac80550625bdc75baab04c303eddf249b93ab0/warehouse/constants.py), line 32)
    with "Uploading new files to releases older than 14 days is not
    allowed" (`legacy.py` lines 1252-1260). A byte-identical duplicate
    still gets HTTP 200 after that, because the duplicate check runs
    first.
  - **The builds are reproducible, within limits.** A local `uv build`
    of a `git archive` of `1e08ecb` matched PyPI's 2.9.0 wheel and sdist
    byte for byte (SHA-256 compared on 2026-11-06), and CI's build job
    fails when two successive wheel builds of a commit differ. But
    `pyproject.toml`'s `[build-system] requires = ["hatchling"]` is not
    pinned, so a later build, local or in a re-run, may resolve a newer
    hatchling and differ from the files on PyPI. PyPI refuses such a
    file with "File already exists", and the job fails.

  So:
  - **The upload failed partway:** re-running the failed jobs
    (`gh run rerun "$RUN" --failed`) is safe when a rebuild of the tagged
    commit is byte-identical to the files already on PyPI, which the
    commands below compare, and when any file still missing is uploaded
    within 14 days of the release's creation on PyPI. The local build
    below and the re-run's build each resolve hatchling afresh, so a
    local match is strong evidence, not proof, that the re-run will
    match. A re-run whose rebuild differs fails with "File already
    exists": stop and decide. The tag is not moved.

    ```bash
    d=$(mktemp -d) && git archive "$SHA" | tar -x -C "$d" &&
      (cd "$d" && uv build) && (cd "$d/dist" && sha256sum -- *)
    curl -s "https://pypi.org/pypi/netprotocols/$V/json" |
      python3 -c 'import json, sys; [print(u["digests"]["sha256"], u["filename"]) for u in json.load(sys.stdin)["urls"]]'
    [ -z "$d" ] || rm -rf -- "$d"
    ```

  - Only `github-release` failed, from a transient cause: re-run it with
    `gh run rerun "$RUN" --failed` while the `release-assets` artifact
    is within its 5-day retention.
  - Anything else: stop and decide. X.Y.Z on PyPI is final, the tag is
    not moved, and any change ships as the next patch release.

## 12. After the release

1. Verify PyPI: the version lists a wheel and an sdist, and installs.

   ```bash
   curl -s "https://pypi.org/pypi/netprotocols/$V/json" |
     python3 -c 'import json, sys; [print(u["filename"], u["size"]) for u in json.load(sys.stdin)["urls"]]'
   uv run --isolated --no-project --refresh --with "netprotocols==$V" \
     python -c 'import netprotocols; print(netprotocols.__version__)'
   ```

   The wheel's size in bytes, printed by the first command, should equal
   the CLAIMS 1.5 figure.

2. Verify the GitHub release, its two assets, and the published wheel's
   provenance:

   ```bash
   gh api "repos/$REPO/releases/tags/v$V" \
     --jq '{name, draft, prerelease, assets: [.assets[].name]}'
   # assets: netprotocols-X.Y.Z.cdx.json and netprotocols-X.Y.Z.sigstore.json
   DL=$(mktemp -d)
   python3 -m pip download --no-deps --only-binary :all: "netprotocols==$V" -d "$DL"
   gh attestation verify "$DL/netprotocols-$V-py3-none-any.whl" --repo "$REPO"
   [ -z "$DL" ] || rm -rf -- "$DL"
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
  branch's head. Both PRs carry milestone 2.9.0. #347's CHANGELOG entry
  was written under `## [Unreleased]`, and was moved into `## [2.9.0]`
  only after `v2.9.0` was tagged and released. So the rule of step 7 was
  not met: the tag's `CHANGELOG.md` has the entry under
  `## [Unreleased]`, and the GitHub release notes, which `release.yml`
  took from the tag's `## [2.9.0]` section, do not contain it. The
  published release was left as it is.
- 2.8.0 had dispatched its gates on the `release-2.8.0` branch and tagged
  that branch's head before its PR merged (the merge commit's tree is the
  same). 2.9.0 gated `master` as CONTRIBUTING asks, and a gate fix landed
  after the release PR, so the gated commit was a later `master` commit.
- 2.3.0 is the one release made with `release.yml` (v1.0.0 on) whose tag
  was re-pointed. Its first run (on #227's merge commit) failed before
  any job started, on the concurrency deadlock #228 fixed; `publish` and
  `github-release` were skipped, so nothing was uploaded. The tag was
  pushed again on #228's merge commit, which step 11's retagging rule
  allows.
