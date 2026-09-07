# Steward: driving PRs to green in this repo

Repo-specific guidance for any Claude Code session babysitting, driving-to-green, or otherwise acting on an open pull request in this repository. This takes precedence over generic PR-babysitting conventions on the points below; it does not expand access or let a session skip anything those generic rules mark as "never."

## Independent implementation and review for CI/CodeRabbit-reported bugs

**Rule 1 — independent implementation.** A fix to a bug reported by CI (a failing check, a CodeRabbit finding, a bot review comment) must be implemented by an independent session or sub-agent — never by the same session/agent that authored the code the bug was found in.

**Rule 2 — independent review.** Each such fix, once implemented, must be reviewed by another independent agent before proceeding (pushing, resolving the finding's thread, moving to the next item). This review is a separate pass from whichever agent wrote the fix.

### Why this exists

Observed directly on [PR #158](https://github.com/EONRaider/NETProtocols/pull/158): the same session that authored a refactor (source dedup, test hardening, new CI workflows) also implemented every fix for what CodeRabbit found in that code. This repeated the exact failure mode being fixed at least once — a regression test written to guard `mutation.yml`'s DNS mutation-testing scope checked `pattern in text` against the whole file rather than the actual executed command block, the same "checks vocabulary, not behavior" bug already fixed twice earlier in the same review pass (a `uses:` line-matching regex, and a reproducible-build test that checked for the word "reproducible" rather than an actual hash comparison). The author's own blind spots — the same assumptions and habits that produced the original bug — carried straight into the fix, and an external reviewer had to catch it again on the next round.

An agent fixing its own bug tends to re-apply the same mental model that produced it. A fresh session or sub-agent, with no investment in the original approach, is more likely to notice when a fix is narrower than the problem, or repeats the original mistake in a new shape.

### How to apply this in practice

When a CI check fails or CodeRabbit (or any other bot/reviewer) reports a finding on a PR in this repo:

1. **Diagnose** in the current session — reading the failure, the diff, and the relevant code is fine and doesn't need to be delegated.
2. **Delegate the fix itself** to an independent sub-agent (e.g. via the Agent tool), giving it the finding and enough context to act, but without it inheriting the current session's authorship of the original code — it should approach the fix fresh, not defend or extend its own prior work.
3. **Delegate review of that fix** to a second, separate sub-agent before pushing — distinct from the agent that implemented the fix. This agent should verify the fix actually closes the gap (ideally by constructing a case that would have slipped past the old code and confirming the new code catches it, not just that the reported symptom is gone), and check it didn't introduce the same class of bug elsewhere.
4. Only after both steps pass does the fix get pushed and the finding marked resolved.

This applies to fixes for bugs reported by CI, CodeRabbit, another bot, or a human reviewer — the fix-a-reported-bug loop, where the risk of an author's blind spots recurring is highest. It does not require every commit or every piece of new feature work in this repo to go through this two-step delegation.
