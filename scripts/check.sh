#!/usr/bin/env bash
# The checks CI runs on a change, in one go: those of the CI and Security
# workflows, and the Fuzz workflow's smoke run.
#
#   scripts/check.sh           all of them (the slow ones take a while)
#   scripts/check.sh --quick   formatting, lints and tests: rustfmt;
#                              actionlint and shellcheck; the fuzz crate's
#                              lockfile; the installer regression checks; the
#                              Python tests of the browser and desktop
#                              harnesses and the ML-DSA verifier; clippy,
#                              tests and doctests
#
# Without --quick it adds the stack and heap residue tests in release mode,
# the release build, rustdoc, the minimum Rust version (a check, and the
# residue tests in debug and release), every feature combination, cargo
# audit and cargo deny, line coverage, the tests of the auto-merge scripts,
# and a build of the fuzz targets with fuzz.yml's nightly and 30 seconds of
# fuzzing each.
#
# The daemon, and the fuzz crate that drives it, build only on Linux. On
# macOS the lints and tests are those of CI's macOS job, on the portable
# crates, and the checks that need Linux are skipped. Checks whose tool is
# not installed are skipped and say how to get it; the installer checks need
# Docker, and fail without it. Each check it does not run gets a line saying
# why, and so do those of the E2E workflow, always: its tests need /dev/uhid,
# and the installer's sudo on a disposable machine too.
# Tracked files are left as they are. The output is in
# target/scripts/check.log.
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
msrv=$(sed -nE 's/^rust-version *= *"([^"]+)".*/\1/p' Cargo.toml)
host=$(rustc -vV | sed -n 's/^host: //p')

# on_linux LABEL COMMAND...: step LABEL COMMAND... on Linux; elsewhere only
# say that it was skipped.
on_linux() {
  if $linux; then
    step "$@"
  else
    skipped "$1: needs Linux"
  fi
}

# installed REGEX: the name, less the host, of the first installed rustup
# toolchain that REGEX matches whole, such as 1.89 or 1.89.0. Commands use
# that name exactly: for a +NAME it lacks, rustup installs one.
installed() {
  rustup toolchain list 2>/dev/null | sed -nE "s/^(.*)-$host( .*)?\$/\1/p" | grep -xE "$1" | head -n 1
}

# fuzz/Cargo.lock as committed, as CI requires it on pull requests.
fuzz_lockfile() {
  cargo metadata --locked --format-version 1 "${fuzz[@]}" >/dev/null ||
    { echo "Run \`cargo metadata ${fuzz[*]}\` and commit fuzz/Cargo.lock"; return 1; }
}
shell_lint() { git ls-files -z '*.sh' | xargs -0 shellcheck -x -P SCRIPTDIR; }

heading "Checks"
step "Formatting" sh -c 'cargo fmt --all -- --check && cargo fmt --manifest-path fuzz/Cargo.toml --all -- --check'
if have actionlint; then
  step "Lints of the workflows" actionlint
else
  skipped "Lints of the workflows: needs actionlint (brew install actionlint, or its GitHub release)"
fi
if have shellcheck; then
  step "Lints of the shell scripts" shell_lint
else
  skipped "Lints of the shell scripts: needs shellcheck (apt or brew install shellcheck)"
fi
fuzz_locked=false
step "Lockfile of the fuzz crate" fuzz_lockfile && fuzz_locked=true
step "Installer regression checks (disposable Linux)" scripts/install-tests.sh

if python3 -c 'import ensurepip' 2>/dev/null; then
  if step "Python test packages" python_env; then
    step "Browser harness and RP regressions" "$python" -m unittest discover -s tests/browser -p 'test_*.py' -v
    step "Desktop acceptance harness" "$python" -m unittest discover -s tests/desktop -p 'test_*.py' -v
    step "ML-DSA verifier of the end-to-end tests" "$python" -m pytest tests/e2e/test_mldsa_verifier.py -q
  fi
else
  skipped "Browser and desktop harnesses, ML-DSA verifier: need python3-venv (on Debian or Ubuntu: sudo apt install python3-venv)"
fi

if $linux; then
  step "Lints" cargo clippy --workspace --all-targets --locked -- -D warnings
  step "Lints of the fuzz crate" cargo clippy "${fuzz[@]}" --all-targets --locked -- -D warnings
  step "Tests" cargo test --workspace --locked --all-targets
  step "Tests of the fuzz crate" cargo test "${fuzz[@]}" --locked --lib
  step "Doctests" cargo test --workspace --locked --doc
  skipped "Lints and tests of the portable crates on macOS: need macOS"
else
  step "Lints of the portable crates" cargo clippy "${portable[@]}" --all-targets --locked -- -D warnings
  step "Tests of the portable crates" cargo test --locked "${portable[@]}" --all-targets
  step "Doctests of the portable crates" cargo test --locked "${portable[@]}" --doc
  skipped "Lints and tests of the daemon and the fuzz crate: need Linux"
fi

if $quick; then
  skipped "Release-mode tests and build, rustdoc, Rust $msrv, feature combinations, dependencies, coverage, auto-merge scripts and fuzzing: not with --quick"
else
  step "Stack residue tests (release)" \
    cargo test --locked --release -p pqkey-mldsa -p pqkey-ctap --test residue
  on_linux "Heap residue test (release)" \
    cargo test --locked --release -p pqkey --test heap_residue
  on_linux "Release build" cargo build --workspace --locked --release
  on_linux "Documentation" sh -c 'RUSTDOCFLAGS="-D warnings" cargo doc --workspace --locked --no-deps --all-features &&
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --locked --no-deps --all-features --document-private-items'

  # A compilation check, and the residue tests, whose stack layouts depend on
  # the compiler, as CI's msrv and msrv-residue jobs run them.
  msrv_toolchain=$(installed "$msrv(\.[0-9]+)?")
  if ! $linux; then
    skipped "Minimum Rust version ($msrv), its check and residue tests: need Linux"
  elif [ -z "$msrv_toolchain" ]; then
    skipped "Minimum Rust version ($msrv), its check and residue tests: need \`rustup toolchain install $msrv\`"
  else
    step "Minimum Rust version ($msrv)" cargo "+$msrv_toolchain" check --workspace --locked --all-targets
    step "Stack residue tests on Rust $msrv (debug)" \
      cargo "+$msrv_toolchain" test --locked -p pqkey-mldsa -p pqkey-ctap --test residue
    step "Stack residue tests on Rust $msrv (release)" \
      cargo "+$msrv_toolchain" test --locked --release -p pqkey-mldsa -p pqkey-ctap --test residue
    step "Heap residue test on Rust $msrv (debug)" \
      cargo "+$msrv_toolchain" test --locked -p pqkey --test heap_residue
    step "Heap residue test on Rust $msrv (release)" \
      cargo "+$msrv_toolchain" test --locked --release -p pqkey --test heap_residue
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

  if have jq; then
    step "Auto-merge and promotion scripts" python3 -m unittest discover -s .github/scripts -p 'test_*.py' -v
  else
    skipped "Auto-merge and promotion scripts: need jq"
  fi

  # The smoke job of fuzz.yml, with the nightly it pins: every target built,
  # then fuzzed for 30 seconds from the committed seeds. cargo fuzz has no
  # --locked, so it runs only after the lockfile check has passed.
  nightly=$(sed -nE 's/^ +NIGHTLY: *([^ #]+).*/\1/p' .github/workflows/fuzz.yml | head -n 1)
  if ! $linux; then
    skipped "Fuzzing, 30 seconds of each target: needs Linux"
  elif [ -z "$(installed "$nightly")" ]; then
    skipped "Fuzzing: needs fuzz.yml's nightly, \`rustup toolchain install $nightly\`"
  elif ! cargo "+$nightly" fuzz --version >/dev/null 2>&1; then
    skipped "Fuzzing: needs \`cargo install cargo-fuzz\`"
  elif ! $fuzz_locked; then
    skipped "Fuzzing: needs fuzz/Cargo.lock up to date"
  else
    cargo_fuzz() { (cd fuzz && cargo "+$nightly" fuzz "$@"); }
    if step "Build of the fuzz targets ($nightly)" cargo_fuzz build -O -a --target "$host"; then
      for target in $(cargo_fuzz list); do
        mkdir -p "fuzz/corpus/$target"
        step "Fuzzing $target for 30 seconds" cargo_fuzz run -O -a --target "$host" "$target" \
          "corpus/$target" "seeds/$target" -- -max_total_time=30 -rss_limit_mb=2048 -timeout=30
      done
    fi
  fi
fi

if $linux; then
  arch=$(uname -m)
  case $arch in
    x86_64) other=aarch64 ;;
    aarch64) other=x86_64 ;;
    *) other="x86_64 and aarch64" ;;
  esac
  skipped "Linux tests on $other: CI runs them on x86_64 and aarch64, and this is $arch"
fi
skipped "End-to-end tests: need /dev/uhid and sudo, and stop your own key; scripts/e2e.sh runs them on Linux"
skipped "Installer end-to-end test: needs a disposable Linux machine with sudo, systemd and /dev/uhid, so only CI runs it"

finish
