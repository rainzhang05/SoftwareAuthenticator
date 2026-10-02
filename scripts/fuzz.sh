#!/usr/bin/env bash
# Fuzz the key with libFuzzer, as CI does:
#
#   scripts/fuzz.sh                  every target for 30 seconds each
#   scripts/fuzz.sh TARGET [SECONDS] one target, for as long as asked
#
# Needs a nightly toolchain and cargo-fuzz (rustup toolchain install nightly;
# cargo install cargo-fuzz). A crash leaves its input in
# fuzz/artifacts/TARGET/; `cargo +nightly fuzz run -O -a TARGET FILE` in fuzz/
# replays it. Add every fixed crash to fuzz/examples/seeds.rs and regenerate
# the seeds with `cargo run --release --manifest-path fuzz/Cargo.toml
# --example seeds`. The output is in target/scripts/fuzz.log.
set -uo pipefail
. "$(dirname "$0")/lib.sh"

{ have rustup && rustup toolchain list | grep -q '^nightly'; } ||
  die "needs a nightly toolchain: rustup toolchain install nightly"
cargo +nightly fuzz --version >/dev/null 2>&1 || die "needs cargo-fuzz: cargo install cargo-fuzz"

seconds=${2:-30}
if [ $# -ge 1 ]; then
  targets=("$1")
else
  mapfile -t targets < <(cd fuzz && cargo +nightly fuzz list)
fi
host=$(rustc +nightly -vV | sed -n 's/^host: //p')

fuzz() {
  local target=$1
  mkdir -p "fuzz/corpus/$target"
  (cd fuzz && cargo +nightly fuzz run -O -a --target "$host" "$target" "corpus/$target" "seeds/$target" -- \
    -max_total_time="$seconds" -rss_limit_mb=2048 -timeout=30)
}

heading "Fuzzing, ${seconds}s per target"
for target in "${targets[@]}"; do
  step "$target" fuzz "$target"
done
finish
