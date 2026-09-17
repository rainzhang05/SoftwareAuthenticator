# Contributing to pqkey

Thank you for helping. This file covers the development setup, the checks a
change has to pass, and the conventions of the repository. How the code is
organised is in [docs/architecture.md](docs/architecture.md); commands for
debugging the device on Linux are in
[docs/development-notes.md](docs/development-notes.md).

## Development setup

- Rust stable. `rust-toolchain.toml` selects the stable channel with `rustfmt`
  and `clippy`. The minimum supported Rust version is 1.89 (`rust-version` in
  the root `Cargo.toml`), and CI checks the workspace builds with it.
- **Linux** is needed to run the daemon: it creates the virtual key through
  `/dev/uhid`. Set up device access as in the README's
  [Installation](README.md#installation) section.
- **macOS** works for everything else: the whole workspace builds, and the
  unit and integration tests run.
- No system libraries are needed to build. The end-to-end tests need
  `fido2-tools`, `dbus-daemon` and Python 3; fuzzing needs a nightly toolchain
  and `cargo-fuzz`.

```bash
cargo build --workspace --locked
cargo test --workspace --locked
RUST_LOG=pqkey=debug,pqkey_ctap=debug cargo run -p pqkey -- attach --foreground   # Linux
```

`Cargo.lock` and `fuzz/Cargo.lock` are committed, and CI passes `--locked`
everywhere, so a change that alters dependencies must update the lockfile in
the same commit.

## Checks

These mirror [`.github/workflows/ci.yml`](.github/workflows/ci.yml) and
[`.github/workflows/security.yml`](.github/workflows/security.yml). All of them
must pass.

```bash
# Formatting, of the workspace and of the fuzz crate (a workspace of its own)
cargo fmt --all -- --check
cargo fmt --manifest-path fuzz/Cargo.toml --all -- --check

# Lints: any warning fails, in the workspace and in the fuzz crate (on stable)
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy --manifest-path fuzz/Cargo.toml --all-targets --locked -- -D warnings

# Tests, including doctests (--all-targets leaves them out)
cargo test --workspace --locked --all-targets
cargo test --workspace --locked --doc

# Every feature combination of every crate (cargo install cargo-hack)
cargo hack check --workspace --locked --all-targets --feature-powerset

# Rustdoc with warnings denied, for the public API and with private items
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --locked --no-deps --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --locked --no-deps --all-features --document-private-items

# Release build
cargo build --workspace --locked --release

# Minimum supported Rust version
cargo +1.89 check --workspace --locked --all-targets

# Supply chain, for both lockfiles (cargo install cargo-audit cargo-deny)
cargo audit
cargo audit --file fuzz/Cargo.lock
cargo deny --locked check advisories bans licenses sources
cargo deny --manifest-path fuzz/Cargo.toml --locked check advisories bans licenses sources

# Tests of the Dependabot auto-merge scripts
python3 -m unittest discover -s .github/scripts -p 'test_*.py' -v
```

CI pins cargo-deny to 0.20.2, because its configuration schema changes between
minor releases; [`deny.toml`](deny.toml) documents every tolerated finding.

### Coverage

CI fails if line coverage of the whole workspace drops below **85%**. To check
locally (`cargo install cargo-llvm-cov`, `rustup component add
llvm-tools-preview`):

```bash
cargo llvm-cov --workspace --locked --all-features --all-targets --no-report
cargo llvm-cov report --summary-only --fail-under-lines 85
cargo llvm-cov report --html --output-dir coverage-html
```

Parts of the daemon (opening `/dev/uhid`, the D-Bus session, daemonizing)
cannot run in unit tests, which is why the floor is below 100%.

### Lints in the code

The workspace lints in the root `Cargo.toml` apply to every crate.
`pqkey-ctap` forbids `unsafe` code and requires documentation on its public
API. In `pqkey`, every `unsafe` block needs a `// SAFETY:` comment. A lint
that is deliberately allowed carries an `#[allow]` with a comment saying why.

## End-to-end tests

[`.github/workflows/e2e.yml`](.github/workflows/e2e.yml) runs the release
daemon on an Ubuntu runner and tests it through its hidraw node with libfido2's
command-line tools and python-fido2. The tests reset the authenticator before
each test: never point them at a pqkey whose credentials matter. They use their
own state directories.

To run them on a Linux machine:

1. Install the tools and build the daemon:

   ```bash
   sudo apt-get install -y fido2-tools dbus-daemon
   cargo build -p pqkey --locked --release
   ```

2. Give your user `/dev/uhid` and the hidraw nodes of product IDs `0001` to
   `0004`. The shipped udev rules grant the hidraw node through `uaccess`,
   which needs a logged-in seat, and match only `1209:0001`, so the workflow
   installs a rule of its own:

   ```bash
   user=$(id -un)
   sudo tee /etc/udev/rules.d/99-e2e-virtual-key.rules >/dev/null <<EOF
   KERNEL=="uhid", SUBSYSTEM=="misc", OWNER="$user", MODE="0600"
   SUBSYSTEM=="hidraw", DEVPATH=="/devices/virtual/misc/uhid/0003:1209:000[1-4].*", OWNER="$user", MODE="0600"
   EOF
   sudo udevadm control --reload-rules
   sudo modprobe uhid
   sudo udevadm trigger --action=change --name-match=uhid --settle
   ```

3. Start the four instances with
   [`tests/e2e/daemon.sh`](tests/e2e/daemon.sh), which runs
   `pqkey attach --foreground` in the background under `$E2E_WORK` and prints
   the hidraw node once it is accessible. The notify instance needs a session
   bus of its own:

   ```bash
   export E2E_WORK=$(mktemp -d)
   export E2E_HIDRAW=$(tests/e2e/daemon.sh start auto-approve 0001 --presence auto-approve --allow-late-reset)
   export E2E_CERTIFICATE_HIDRAW=$(tests/e2e/daemon.sh start certificate 0002 --presence auto-approve --allow-late-reset \
     --attestation certificate --manufacturer "pqkey E2E" --product "pqkey E2E key" --country US)
   export DBUS_SESSION_BUS_ADDRESS="unix:path=$E2E_WORK/session-bus"
   dbus-daemon --config-file=tests/e2e/session-bus.conf --address="$DBUS_SESSION_BUS_ADDRESS" \
     --fork --print-pid > "$E2E_WORK/session-bus.pid"
   export E2E_NOTIFY_HIDRAW=$(tests/e2e/daemon.sh start notify 0003 --presence notify --presence-timeout 3)
   export E2E_UNANSWERED_HIDRAW=$(tests/e2e/daemon.sh start unanswered 0004 --presence unanswered)
   ```

   `--allow-late-reset`, `--presence-timeout` and `--presence unanswered` are
   hidden options for test rigs. The binary is `target/release/pqkey` unless
   `PQKEY` names another.

4. Run the suites. The Python dependencies are pinned with hashes in
   `tests/e2e/requirements.txt` (CI uses Python 3.14):

   ```bash
   tests/e2e/libfido2.sh "$E2E_HIDRAW"
   python3 -m venv "$E2E_WORK/venv"
   "$E2E_WORK/venv/bin/python" -m pip install --require-hashes --only-binary :all: -r tests/e2e/requirements.txt
   "$E2E_WORK/venv/bin/python" -m pytest tests/e2e -v
   ```

5. Stop everything. `stop` also checks that the daemon exited with status 0
   and that its device is gone:

   ```bash
   for instance in "auto-approve 0001" "certificate 0002" "notify 0003" "unanswered 0004"; do
     tests/e2e/daemon.sh stop $instance
   done
   kill "$(cat "$E2E_WORK/session-bus.pid")"
   ```

Behaviour that is broken today is marked with `bugs.known_bug(...)` in the
Python tests: a strict expected failure that also fails the run once the bug is
fixed, so the marker goes away with the fix.

## Fuzzing

The fuzz crate in [`fuzz/`](fuzz/) is a workspace of its own and needs nightly
and [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) (CI uses 0.13.2 and a
dated nightly, see `NIGHTLY` in
[`.github/workflows/fuzz.yml`](.github/workflows/fuzz.yml)). Targets:

| Target | Input |
|--------|-------|
| `ctaphid_packets` | CTAPHID packet sequences into the transport's state machine |
| `ctap_request` | One raw CTAPHID_CBOR message to a fresh engine |
| `ctap_request_structured` | Structure-aware CTAP requests |
| `ctap_sequence` | Stateful request sequences (PIN, tokens, credentials, credential management) |
| `credential_key` | Arbitrary stored key bytes, parsed and used to sign |

```bash
cd fuzz
cargo +nightly fuzz list
cargo +nightly fuzz run -O -a ctap_sequence corpus/ctap_sequence seeds/ctap_sequence -- \
  -max_total_time=300 -rss_limit_mb=2048 -timeout=30
```

`-O -a` builds optimised with debug assertions and overflow checks. On a
musl-built cargo-fuzz, add `--target x86_64-unknown-linux-gnu`, as CI does.
Reproduce a crash with `cargo +nightly fuzz run -O -a <target> <artifact file>`.
The seed corpora in `fuzz/seeds/` are written by
`cargo run --release --manifest-path fuzz/Cargo.toml --example seeds`; add the
input of every fixed crash to them.

CI builds every target and runs each for 30 seconds on pushes to `main` that
touch the crates or the fuzz crate, and fuzzes each target for 30 minutes every
Sunday.

If you change a dependency of a main-workspace crate, update
`fuzz/Cargo.lock` as well (`cargo metadata --manifest-path fuzz/Cargo.toml`
brings it up to date) and commit it. On pull requests CI fails on a stale
`fuzz/Cargo.lock`; on pushes to `main` and scheduled runs
[`sync-fuzz-lockfile.sh`](.github/scripts/sync-fuzz-lockfile.sh) brings it up to
date for the run and warns.

## Commits and pull requests

- One logical change per commit.
- The subject line is in the imperative mood and says what the commit does,
  for example "Pace uhid input reports so hidraw readers do not drop large
  responses". No body is required.
- Keep documentation (README, SECURITY.md, docs/, the udev and systemd files,
  `--help` text) in step with behaviour in the same change.
- Record user-visible changes in [CHANGELOG.md](CHANGELOG.md) under
  `Unreleased`.
- Report security problems privately as described in
  [SECURITY.md](SECURITY.md), not in a pull request.

## Dependency updates

Dependabot ([`.github/dependabot.yml`](.github/dependabot.yml)) opens weekly
pull requests on Mondays: one group for minor and patch updates of the main
workspace, one for the fuzz crate, and one for GitHub Actions. Major updates
come as separate pull requests.

[`.github/workflows/dependabot-automerge.yml`](.github/workflows/dependabot-automerge.yml)
merges a Dependabot cargo pull request without review, by rebase, only if all
of these hold ([`dependabot-automerge.sh`](.github/scripts/dependabot-automerge.sh)):

- it is open, authored by Dependabot, on a `dependabot/cargo/` branch, and the
  evaluated commit is still its head;
- the CI, Security and E2E workflows succeeded for that commit, and Fuzz too if
  it changes anything under `fuzz/`;
- it changes at least one `Cargo.lock`, and every version change in every
  lockfile it changes is compatible under Cargo's semver rules (a 0.x minor
  bump counts as breaking);
- it changes nothing but `Cargo.toml` and `Cargo.lock` files.

After merging it starts CI and Security on `main`. Everything else, including
GitHub Actions updates (which `GITHUB_TOKEN` may not merge), waits for a person.

## License

pqkey is licensed under either of the Apache License, Version 2.0
([LICENSE-APACHE](LICENSE-APACHE)) or the MIT license
([LICENSE-MIT](LICENSE-MIT)), at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
