#!/usr/bin/env bash
# Fast-forward the `stable` branch to the newest commit on main that passed CI,
# E2E and Security. Invoked by .github/workflows/promote.yml when one of them
# completes on main, on a schedule and on demand.
#
# Nothing from the event that started the run is used: main's history and each
# workflow's own list of runs decide.
#   - The candidates are main's newest commits that stable does not contain,
#     newest first, at most $max_commits of them.
#   - A candidate passes when, for each of ci.yml, e2e.yml and security.yml, the
#     latest run for that exact commit started by a push, a schedule or a
#     dispatch completed with success. Pull request runs never count: they test
#     a merge, with the pull request's own workflow files.
#   - A candidate must also be ahead of stable, and its .github/workflows must
#     equal main's head's or stable's. GITHUB_TOKEN cannot have the `workflows`
#     permission, and GitHub refuses its ref writes that point a branch at
#     workflow files main's head does not have, unless the write changes none.
#   - The newest candidate that qualifies becomes stable. It is created if
#     missing, and otherwise updated with force=false, so GitHub itself refuses
#     anything but a fast-forward.
#   - When no candidate qualifies, the script says why for each one and exits 0.
#   - When stable is not an ancestor of main, the script fails: stable only
#     moves forward, so a person has to decide where it goes.
#
# Set DRY_RUN=1 to print the decision without changing anything (usable locally
# with gh auth).
set -euo pipefail

: "${REPO:?}"

# Each candidate costs up to five API calls (three run lists, a compare and its
# workflow files), and GITHUB_TOKEN may make 1,000 an hour per repository.
max_commits=30
workflows="ci.yml e2e.yml security.yml"

nothing() { echo "nothing to promote: $*"; exit 0; }
# The SHA of the .github/workflows tree at commit $1.
workflows_tree() {
  gh api "repos/$REPO/contents/.github?ref=$1" --jq '.[] | select(.name == "workflows" and .type == "dir") | .sha'
}

main=$(gh api "repos/$REPO/git/ref/heads/main" --jq .object.sha)
echo "main is at $main"
# matching-refs answers [] rather than 404 when the branch does not exist, and
# also lists branches whose names only start with "stable".
stable=$(gh api "repos/$REPO/git/matching-refs/heads/stable" \
  --jq '.[] | select(.ref == "refs/heads/stable") | .object.sha')
if [ -n "$stable" ]; then
  echo "stable is at $stable"
  [ "$stable" != "$main" ] || nothing "stable is already at main's head"
  status=$(gh api "repos/$REPO/compare/$stable...$main" --jq .status)
  if [ "$status" != "ahead" ]; then
    echo "::error::stable ($stable) is not an ancestor of main ($main) (compare: $status). stable only moves forward, so a person has to decide where it goes."
    exit 1
  fi
  stable_tree=$(workflows_tree "$stable")
else
  echo "stable does not exist yet"
fi
main_tree=$(workflows_tree "$main")

# The latest run that counts, as one word: its conclusion (success, failure,
# cancelled, ...), its status while it has none (in_progress, queued, ...), or
# missing.
latest='[.workflow_runs[] | select(.event == "push" or .event == "schedule" or .event == "workflow_dispatch")]
  | max_by(.created_at)
  | if . == null then "missing" elif .status != "completed" then .status else .conclusion end'

commits=$(gh api "repos/$REPO/commits?sha=$main&per_page=$max_commits" --jq '.[].sha')
target=
looked=0
for sha in $commits; do
  [ "$sha" != "$stable" ] || break
  looked=$((looked + 1))
  reason=
  for workflow in $workflows; do
    state=$(gh api "repos/$REPO/actions/workflows/$workflow/runs?head_sha=$sha&per_page=100" --jq "$latest")
    if [ "$state" != "success" ]; then
      reason="$workflow is $state"
      break
    fi
  done
  if [ -z "$reason" ] && [ -n "$stable" ]; then
    # In a linear history every candidate is ahead of stable; a merge can bring
    # in commits that are not.
    status=$(gh api "repos/$REPO/compare/$stable...$sha" --jq .status)
    [ "$status" = "ahead" ] || reason="passed, but is not ahead of stable (compare: $status)"
  fi
  if [ -z "$reason" ]; then
    # GitHub refuses the write unless these are main's head's workflow files,
    # or stable's so that the write changes none (see the top).
    tree=$(workflows_tree "$sha")
    if [ "$tree" != "$main_tree" ] && { [ -z "$stable" ] || [ "$tree" != "$stable_tree" ]; }; then
      reason="workflow files differ from main's head; GITHUB_TOKEN cannot move stable there"
    fi
  fi
  if [ -z "$reason" ]; then
    target=$sha
    break
  fi
  echo "$sha: $reason"
done
[ -n "$target" ] \
  || nothing "none of the $looked newest commits on main that stable does not contain qualifies"
echo "$target: $workflows all succeeded"

if [ "${DRY_RUN:-0}" = "1" ]; then
  if [ -n "$stable" ]; then
    echo "DRY RUN: would fast-forward stable from $stable to $target"
  else
    echo "DRY RUN: would create stable at $target"
  fi
  exit 0
fi

if [ -n "$stable" ]; then
  # With force=false GitHub refuses the update unless it is a fast-forward, so
  # stable cannot move back or sideways even if it moved after it was read.
  gh api --method PATCH "repos/$REPO/git/refs/heads/stable" -f sha="$target" -F force=false > /dev/null
  echo "fast-forwarded stable from $stable to $target"
else
  # Fails if stable was created after it was read; the next run moves it on.
  gh api --method POST "repos/$REPO/git/refs" -f ref=refs/heads/stable -f sha="$target" > /dev/null
  echo "created stable at $target"
fi
