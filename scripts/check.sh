#!/usr/bin/env bash
# Every check CI runs on a change, in one go:
#
#   scripts/check.sh           everything (the slow checks take a while)
#   scripts/check.sh --quick   formatting, lints and tests only
#
# The daemon, and the fuzz crate that drives it, build only on Linux. On
# macOS the lints and tests are those of CI's macOS job, on the portable
# crates, and the checks that need Linux are skipped.
# Checks whose tool is not installed are skipped and say how to get it.
# The output is in target/scripts/check.log.
set -uo pipefail
. "$(dirname "$0")/lib.sh"

quick=false
case "${1:-}" in
  "") ;;
  --quick) quick=true ;;
  *)
    echo "usage: $0 [--quick]" >&2
    exit 2
    ;;
esac

fuzz=(--manifest-path fuzz/Cargo.toml)
portable=(-p pqkey-ctap -p pqkey-mldsa)
linux=false
[ "$(uname -s)" = Linux ] && linux=true

# on_linux LABEL COMMAND...: step LABEL COMMAND... on Linux; elsewhere only
# say that it was skipped.
on_linux() {
  if $linux; then
    step "$@"
  else
    skipped "$1: needs Linux"
  fi
}

heading "Checks"
step "Formatting" sh -c 'cargo fmt --all -- --check && cargo fmt --manifest-path fuzz/Cargo.toml --all -- --check'
step "Installer regression checks (disposable Linux)" scripts/install-tests.sh
if $linux; then
  step "Lints" cargo clippy --workspace --all-targets --locked -- -D warnings
  step "Lints of the fuzz crate" cargo clippy "${fuzz[@]}" --all-targets -- -D warnings
  step "Tests" cargo test --workspace --locked --all-targets
  step "Tests of the fuzz crate" cargo test "${fuzz[@]}" --lib
  step "Doctests" cargo test --workspace --locked --doc
else
  step "Lints of the portable crates" cargo clippy "${portable[@]}" --all-targets --locked -- -D warnings
  step "Tests of the portable crates" cargo test --locked "${portable[@]}" --all-targets
  step "Doctests of the portable crates" cargo test --locked "${portable[@]}" --doc
  skipped "Lints and tests of the daemon and the fuzz crate: need Linux"
fi

if ! $quick; then
  step "Stack residue tests (release)" \
    cargo test --locked --release -p pqkey-mldsa -p pqkey-ctap --test residue
  on_linux "Heap residue test (release)" \
    cargo test --locked --release -p pqkey --test heap_residue
  on_linux "Release build" cargo build --workspace --locked --release
  on_linux "Documentation" sh -c 'RUSTDOCFLAGS="-D warnings" cargo doc --workspace --locked --no-deps --all-features &&
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --locked --no-deps --all-features --document-private-items'

  msrv=$(sed -nE 's/^rust-version *= *"([^"]+)".*/\1/p' Cargo.toml)
  if ! $linux; then
    skipped "Minimum Rust version ($msrv): needs Linux"
  elif have rustup && rustup toolchain list | grep -q "^$msrv"; then
    step "Minimum Rust version ($msrv)" cargo "+$msrv" check --workspace --locked --all-targets
  else
    skipped "Minimum Rust version: needs \`rustup toolchain install $msrv\`"
  fi

  if cargo hack --version >/dev/null 2>&1; then
    on_linux "Every feature combination" cargo hack check --workspace --locked --all-targets --feature-powerset
    step "Lints of pqkey-mldsa's library in every feature combination" \
      cargo hack clippy -p pqkey-mldsa --lib --feature-powerset --locked -- -D warnings
  else
    skipped "Every feature combination: needs \`cargo install cargo-hack\`"
  fi

  if cargo audit --version >/dev/null 2>&1 && cargo deny --version >/dev/null 2>&1; then
    step "Dependencies: advisories and licences" sh -c 'cargo audit && cargo audit --file fuzz/Cargo.lock &&
      cargo deny --locked check advisories bans licenses sources &&
      cargo deny --manifest-path fuzz/Cargo.toml --locked check advisories bans licenses sources'
  else
    skipped "Dependencies: needs \`cargo install cargo-audit cargo-deny\`"
  fi

  if ! $linux; then
    skipped "Line coverage: needs Linux"
  elif cargo llvm-cov --version >/dev/null 2>&1; then
    step "Line coverage of at least 85%" sh -c 'cargo llvm-cov --workspace --locked --all-features --all-targets --no-report &&
      cargo llvm-cov report --summary-only --fail-under-lines 85'
  else
    skipped "Line coverage: needs \`cargo install cargo-llvm-cov\`"
  fi

  step "Dependabot auto-merge scripts" python3 -m unittest discover -s .github/scripts -p 'test_*.py'
fi

finish
