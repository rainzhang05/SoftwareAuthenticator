#!/usr/bin/env bash
# Make sure fuzz/Cargo.lock resolves the fuzz crate before it is built. Invoked
# by .github/workflows/fuzz.yml, with NIGHTLY naming the toolchain.
#
# The fuzz crate is a workspace of its own whose path dependencies are the
# crates of the main workspace, so a change to one of their manifests (a new
# dependency, a raised version requirement) leaves fuzz/Cargo.lock behind until
# someone regenerates it. Updates to the root Cargo.lock alone never do.
#
#   - On a pull request the lockfile must be up to date as committed: that is
#     what the pull request would merge.
#   - Otherwise Cargo brings a stale lockfile up to date with the fewest changes
#     it can, the same resolution `cargo metadata` gives a developer, and a
#     warning names the difference to commit. Fuzzing goes on.
set -euo pipefail

: "${NIGHTLY:?}"

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
manifest="$root/fuzz/Cargo.toml"
lockfile="$root/fuzz/Cargo.lock"

if cargo "+$NIGHTLY" metadata --locked --format-version 1 --manifest-path "$manifest" > /dev/null; then
  echo "fuzz/Cargo.lock is up to date"
  exit 0
fi

if [ "${GITHUB_EVENT_NAME:-}" = "pull_request" ]; then
  echo "::error file=fuzz/Cargo.lock::fuzz/Cargo.lock is out of date; run 'cargo metadata --manifest-path fuzz/Cargo.toml' and commit it"
  exit 1
fi

before=$(mktemp)
cp "$lockfile" "$before"
cargo "+$NIGHTLY" metadata --format-version 1 --manifest-path "$manifest" > /dev/null
echo "::warning file=fuzz/Cargo.lock::fuzz/Cargo.lock was out of date and has been brought up to date for this run; run 'cargo metadata --manifest-path fuzz/Cargo.toml' and commit it"
diff -u "$before" "$lockfile" || true
