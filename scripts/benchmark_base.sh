#!/usr/bin/env bash
# Prints the commit that the CI benchmark job compares HEAD against.
#
#   EVENT     the event name: pull_request, push, or another
#   BASE_REF  for pull_request, the base branch, read as origin/BASE_REF
#   BEFORE    for any other event, the commit before the push, if any
#
# For pull_request it prints the merge-base of origin/BASE_REF and
# HEAD. Otherwise it prints BEFORE when that is a proper ancestor of
# HEAD in this clone, and HEAD^1 when it is not, is HEAD itself, is
# empty or is all zeros. It exits non-zero when the commit it needs is
# not in the clone.
set -euo pipefail

if [[ "${EVENT:-}" == pull_request ]]; then
  git merge-base "origin/${BASE_REF:?BASE_REF is not set}" HEAD
  exit
fi
head=$(git rev-parse HEAD)
before=
if [[ -n "${BEFORE:-}" && ! "$BEFORE" =~ ^0+$ ]]; then
  before=$(git rev-parse --verify --quiet "$BEFORE^{commit}" || true)
fi
if [[ -n "$before" && "$before" != "$head" ]] &&
  git merge-base --is-ancestor "$before" HEAD 2>/dev/null; then
  echo "$before"
else
  git rev-parse --verify "HEAD^1^{commit}"
fi
