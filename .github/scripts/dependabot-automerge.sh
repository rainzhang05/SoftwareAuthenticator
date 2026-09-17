#!/usr/bin/env bash
# Merge a Dependabot cargo PR once it is proven safe. Invoked by
# .github/workflows/dependabot-automerge.yml after CI or Security completes.
#
# Every condition below must hold, otherwise the script explains why and exits 0:
#   - the PR is open, authored by Dependabot, on a dependabot/cargo/ branch
#   - HEAD_SHA is still the PR head (a newer push gets its own evaluation)
#   - the latest pull_request runs of ci.yml, security.yml and e2e.yml for HEAD_SHA
#     succeeded, and of fuzz.yml too if the PR changes anything under fuzz/
#     (the fuzz crate is its own workspace, which only fuzz.yml builds)
#   - the PR changes at least one Cargo.lock, and every package version change
#     in every Cargo.lock it changes (the root one, fuzz/Cargo.lock) is
#     Cargo-semver compatible (see cargo_semver_check.py; Dependabot's own
#     update-type calls 0.12 -> 0.13 "minor", but for Cargo a 0.x minor bump is
#     breaking)
#   - the PR changes nothing except Cargo.toml / Cargo.lock files
#
# Set DRY_RUN=1 to print the decision without merging (usable locally with gh auth).
set -euo pipefail

: "${REPO:?}" "${HEAD_SHA:?}" "${HEAD_BRANCH:?}"

skip() { echo "skip: $*"; exit 0; }

case "$HEAD_BRANCH" in
  dependabot/cargo/*) ;;
  *) skip "branch $HEAD_BRANCH is not a Dependabot cargo update" ;;
esac

pr_json=$(gh pr list --repo "$REPO" --head "$HEAD_BRANCH" --state open \
  --json number,author,headRefOid,files,url --jq '.[0] // empty')
[ -n "$pr_json" ] || skip "no open PR for $HEAD_BRANCH"

number=$(jq -r .number <<<"$pr_json")
author=$(jq -r .author.login <<<"$pr_json")
head=$(jq -r .headRefOid <<<"$pr_json")
echo "PR #$number by $author at $head"

[ "$author" = "app/dependabot" ] || [ "$author" = "dependabot[bot]" ] || [ "$author" = "dependabot" ] \
  || skip "PR #$number is authored by $author, not Dependabot"
[ "$head" = "$HEAD_SHA" ] || skip "PR #$number moved on to $head; that commit gets its own evaluation"

workflows="ci.yml security.yml e2e.yml"
if jq -e 'any(.files[].path; startswith("fuzz/"))' <<<"$pr_json" > /dev/null; then
  workflows="$workflows fuzz.yml"
fi
for workflow in $workflows; do
  conclusion=$(gh api "repos/$REPO/actions/workflows/$workflow/runs?head_sha=$HEAD_SHA&event=pull_request&per_page=20" \
    --jq '[.workflow_runs[]] | sort_by(.created_at) | last | if . == null then "missing" elif .status != "completed" then "in_progress" else .conclusion end')
  echo "$workflow: $conclusion"
  [ "$conclusion" = "success" ] || skip "$workflow is $conclusion for $HEAD_SHA"
done

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
merge_base=$(gh api "repos/$REPO/compare/main...$HEAD_SHA" --jq .merge_base_commit.sha)
workdir=$(mktemp -d)
# Every lockfile the PR changes is judged, whichever directory Dependabot
# updated: judging only the root one would pass a fuzz/Cargo.lock update as
# "no version changes".
lockfiles=$(jq -r '.files[].path | select(test("(^|/)Cargo\\.lock$"))' <<<"$pr_json")
[ -n "$lockfiles" ] || skip "PR #$number changes no Cargo.lock"
index=0
while IFS= read -r lockfile; do
  index=$((index + 1))
  # The raw media type returns the file itself, whatever its size.
  gh api -H "Accept: application/vnd.github.raw+json" "repos/$REPO/contents/$lockfile?ref=$merge_base" \
    > "$workdir/$index.base.lock" 2> /dev/null \
    || skip "$lockfile could not be read on main; a new lockfile needs review"
  gh api -H "Accept: application/vnd.github.raw+json" "repos/$REPO/contents/$lockfile?ref=$HEAD_SHA" \
    > "$workdir/$index.head.lock" \
    || skip "$lockfile could not be read at $HEAD_SHA"
  if ! changes=$(python3 "$script_dir/cargo_semver_check.py" "$workdir/$index.base.lock" "$workdir/$index.head.lock"); then
    skip "$lockfile has semver-incompatible version changes; they need review"
  fi
  echo "$lockfile: compatible changes: $changes"
done <<<"$lockfiles"

unexpected=$(jq -r '.files[].path | select(test("(^|/)Cargo\\.(toml|lock)$") | not)' <<<"$pr_json")
[ -z "$unexpected" ] || skip "PR touches files other than Cargo manifests: $unexpected"

if [ "${DRY_RUN:-0}" = "1" ]; then
  echo "DRY RUN: would merge PR #$number"
  exit 0
fi

gh pr merge "$number" --repo "$REPO" --rebase --match-head-commit "$HEAD_SHA"
echo "merged PR #$number"

# Merges made with GITHUB_TOKEN do not trigger push workflows, so run the
# gates on main explicitly to validate the combined result.
gh workflow run ci.yml --repo "$REPO" --ref main
gh workflow run security.yml --repo "$REPO" --ref main
