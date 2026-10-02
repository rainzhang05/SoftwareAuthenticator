# Development notes

Working on the authenticator: the setup, the checks a change has to pass, and
commands that help when debugging the device on a Linux host. The README covers
installing and running it; [architecture.md](architecture.md) covers how the
code is organised.

## Setup

- Rust stable. `rust-toolchain.toml` selects the stable channel with `rustfmt`
  and `clippy`. The minimum supported Rust version is 1.89 (`rust-version` in
  the root `Cargo.toml`), and CI checks the workspace builds with it.
- **Linux** is needed to run the daemon: it creates the virtual key through
  `/dev/uhid`. Set up device access as in the README's
  [Install](../README.md#install) section.
- **macOS** works for everything else: the whole workspace builds, and the
  unit and integration tests run.
- No system libraries are needed to build. The end-to-end tests need
  `fido2-tools`, `dbus-daemon` and Python 3; fuzzing needs a nightly toolchain
  and `cargo-fuzz`.

```bash
cargo build --workspace --locked
cargo test --workspace --locked
```

`Cargo.lock` and `fuzz/Cargo.lock` are committed, and CI passes `--locked`
everywhere, so a change that alters dependencies must update the lockfile in
the same commit.

## Build and run the daemon with debug logs

Set up `/dev/uhid` access once, with the shipped udev rules (the comments in
[`contrib/udev/70-pqkey.rules`](../contrib/udev/70-pqkey.rules) explain them),
exactly as in the README's [Install](../README.md#install) section:

```bash
sudo install -m 644 contrib/udev/70-pqkey.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
echo uhid | sudo tee /etc/modules-load.d/uhid.conf
sudo modprobe uhid
sudo udevadm trigger
sudo usermod -aG plugdev "$USER"   # then log in again, or `newgrp plugdev`
```

Then build and run in the foreground. Debug logs include the relying party
and user names of presence prompts and CTAPHID channel IDs; info logs do not.

```bash
pqkey stop
cargo build --release
RUST_LOG=pqkey=debug,pqkey_ctap=debug cargo run --release -p pqkey -- run
```

`pqkey run` is the key itself, in the foreground; the systemd unit runs it
too. `pqkey status` shows whether a key runs on the state directory, `pqkey
stop` stops it. `run` and `start` take hidden options for test rigs (see
`docs/architecture.md`); `--presence auto-approve` approves every request
without asking and is only for tests. Keep tests away from the state directory
of the key you use: give them `--state-dir` (or `PQKEY_STATE_DIR`) and a
`--product-id` of their own.

## Checks

These mirror [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) and
[`.github/workflows/security.yml`](../.github/workflows/security.yml). All of
them must pass.

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
minor releases; [`deny.toml`](../deny.toml) documents every tolerated finding.

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

The workspace lints in the root `Cargo.toml` apply to every crate. `pqkey-ctap`
and `pqkey-mldsa` forbid `unsafe` code and require documentation on their
public API. In `pqkey`, every `unsafe` block needs a `// SAFETY:` comment. A
lint that is deliberately allowed carries an `#[allow]` with a comment saying
why.

## End-to-end tests

[`.github/workflows/e2e.yml`](../.github/workflows/e2e.yml) runs the release
daemon on an Ubuntu runner and tests it through its hidraw node with libfido2's
command-line tools and python-fido2. Most Python tests reset the
authenticator before they start, and the libfido2 script creates credentials:
never point them at a pqkey whose credentials matter. They use their
own state directories. The CLI tests
([`tests/e2e/test_cli.py`](../tests/e2e/test_cli.py)) also start and stop a
daemon of their own, as product ID `0005` on a temporary state directory: it
needs access to `/dev/uhid`, but not to its hidraw node.

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
   SUBSYSTEM=="hidraw", DEVPATH=="/devices/virtual/misc/uhid/0003:1209:000[1-5].*", OWNER="$user", MODE="0600"
   EOF
   sudo udevadm control --reload-rules
   sudo modprobe uhid
   sudo udevadm trigger --action=change --name-match=uhid --settle
   ```

3. Start the four instances with
   [`tests/e2e/daemon.sh`](../tests/e2e/daemon.sh), which runs `pqkey run`
   in the background under `$E2E_WORK` and prints the hidraw node once it is
   accessible. The notify instance needs a session
   bus of its own:

   ```bash
   export E2E_WORK=$(mktemp -d)
   export E2E_HIDRAW=$(tests/e2e/daemon.sh start auto-approve 0001 --presence auto-approve --allow-late-reset)
   export E2E_CERTIFICATE_HIDRAW=$(tests/e2e/daemon.sh start certificate 0002 --presence auto-approve --allow-late-reset \
     --attestation certificate --manufacturer "pqkey E2E" --product "pqkey E2E key" --country US)
   export DBUS_SESSION_BUS_ADDRESS="unix:path=$E2E_WORK/session-bus"
   dbus-daemon --config-file=tests/e2e/session-bus.conf --address="$DBUS_SESSION_BUS_ADDRESS" \
     --fork --print-pid > "$E2E_WORK/session-bus.pid"
   export E2E_NOTIFY_HIDRAW=$(tests/e2e/daemon.sh start notify 0003 --presence notify --presence-timeout 3 \
     --allow-late-reset)
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

### In a browser

[`tests/browser/`](../tests/browser/README.md) is a local relying party for
manual tests in real browsers: presets for every algorithm and option, a
double check of each response, and a queue a script can fill while a person
approves the prompts. [`contrib/debug/`](../contrib/debug) decodes and verifies
an `strace` of the daemon. Neither runs in CI.

## Fuzzing

The fuzz crate in [`fuzz/`](../fuzz/) is a workspace of its own and needs
nightly and [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) (CI uses
0.13.2 and a dated nightly, see `NIGHTLY` in
[`.github/workflows/fuzz.yml`](../.github/workflows/fuzz.yml)). Targets:

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
mkdir -p corpus/ctap_sequence
cargo +nightly fuzz run -O -a ctap_sequence corpus/ctap_sequence seeds/ctap_sequence -- \
  -max_total_time=300 -rss_limit_mb=2048 -timeout=30
```

`-O -a` builds optimised with debug assertions and overflow checks. On a
musl-built cargo-fuzz, add `--target x86_64-unknown-linux-gnu`, as CI does.
Reproduce a crash with `cargo +nightly fuzz run -O -a <target> <artifact file>`.
The seed corpora in `fuzz/seeds/` are written by
`cargo run --release --manifest-path fuzz/Cargo.toml --example seeds`, which
replaces them entirely: add the input of every fixed crash to
[`fuzz/examples/seeds.rs`](../fuzz/examples/seeds.rs), not to `fuzz/seeds/`
by hand, and commit the regenerated seeds.

CI builds every target and runs each for 30 seconds on pushes to `main` that
touch the crates, the root `Cargo.lock` or the fuzz crate, and on pull requests
that change the fuzz crate's `Cargo.toml` or `Cargo.lock`. It fuzzes each
target for 30 minutes every Sunday, and for as long as asked when the workflow
is started by hand.

If you change a dependency of a main-workspace crate, update
`fuzz/Cargo.lock` as well (`cargo metadata --manifest-path fuzz/Cargo.toml`
brings it up to date) and commit it. On pull requests CI fails on a stale
`fuzz/Cargo.lock`; on pushes to `main` and scheduled runs
[`sync-fuzz-lockfile.sh`](../.github/scripts/sync-fuzz-lockfile.sh) brings it
up to date for the run and warns.

## Dependency updates

Dependabot ([`.github/dependabot.yml`](../.github/dependabot.yml)) opens weekly
pull requests on Mondays: one group for minor and patch updates of the main
workspace, one for the fuzz crate, and one for GitHub Actions. Major updates
come as separate pull requests.

[`.github/workflows/dependabot-automerge.yml`](../.github/workflows/dependabot-automerge.yml)
merges a Dependabot cargo pull request without review, by rebase, only if all of
these hold
([`dependabot-automerge.sh`](../.github/scripts/dependabot-automerge.sh)):

- it is open, authored by Dependabot, on a `dependabot/cargo/` branch, and the
  evaluated commit is still its head;
- the CI, Security and E2E workflows succeeded for that commit, and Fuzz too if
  it changes anything under `fuzz/`;
- it changes at least one `Cargo.lock`, and every version change in every
  lockfile it changes is compatible under Cargo's semver rules (a 0.x minor
  bump counts as breaking);
- it changes nothing but `Cargo.toml` and `Cargo.lock` files.

After merging it starts CI, Security and E2E on `main`, since a merge made
with `GITHUB_TOKEN` starts no push workflows. Everything else, including GitHub
Actions updates (which `GITHUB_TOKEN` may not merge), waits for a person.

## Clients

Tested on 2026-09-30 on Ubuntu 26.04.1 (aarch64, GNOME 50.1):

| Client | ES256 | ML-DSA-44/65/87 | Notes |
|---|---|---|---|
| Chromium 153 (snap) | yes | yes | `getPublicKey()` returns null for ML-DSA and `toJSON()` leaves the key out, so relying parties read it from the attestation object; `getPublicKeyAlgorithm()` returns -48, -49 or -50. Passkeys and requests that require user verification need a PIN on the key. |
| Firefox 154 (snap) | yes | no | Drops algorithms it does not know: an ML-DSA-only request reaches the key with none (`NotAllowedError`), a mixed one as ES256 only. Without a PIN its account chooser shows "Unknown account". |
| python-fido2 2.2.1 | yes | yes | Used by the end-to-end tests. |
| libfido2 1.16 | yes | no | No ML-DSA credential type; `fido2-token -I` lists the algorithms as unknown, and `fido2-token -L -k` cannot list ML-DSA passkeys (`FIDO_ERR_RX_INVALID_CBOR`, or `FIDO_ERR_RX` for ML-DSA-65 and -87); `pqkey passkeys` can. PINs, credential management and `hmac-secret` work. |

Chromium 155 and later are said to return ML-DSA public keys from
`getPublicKey()`; that is not tested yet. Any CTAP 2.1 client can use ES256
credentials, PINs, credential management and `hmac-secret`.

## Troubleshooting

**The browser waits, but no prompt appears.** On GNOME the prompt can be
stuck in the shell's banner queue, for example behind Chromium's "is ready"
banner when Chromium asked from an unfocused window; pqkey nudges the queue
every 2 seconds, so it should appear within that. It is also in the
notification list (click the clock). While you are idle, GNOME keeps a
normal banner up until you move the mouse, and everything waits behind it.

**Every registration or sign-in fails immediately.** No notification could be
shown, so presence was denied. The log says why: `journalctl --user -u pqkey`,
`<state dir>/authenticator.log`, or the terminal of `pqkey run`. Run the
daemon inside your desktop session and check `DBUS_SESSION_BUS_ADDRESS`; the
comments in
[`contrib/systemd/user/pqkey.service`](../contrib/systemd/user/pqkey.service)
cover desktops that start their own bus.

**`warning: cannot open /dev/uhid`.** The udev rules are not installed, you
are not in `plugdev`, or you have not logged in again since joining it.
`pqkey status` says which, and `pqkey setup` fixes it. `ls -l /dev/uhid`
should show group `plugdev` and mode `crw-rw----`.

**The key does not show up in the browser.** Check `pqkey status`, then
`fido2-token -L`. If the key runs but nothing is listed, the hidraw node is
not accessible to you: check the hidraw rule, and its `DEVPATH` pattern if you
changed the USB IDs with `--vendor-id` or `--product-id`.

**Firefox or Chromium from the snap store never asks for the key.** A snap
can only open devices udev tags for it, and snapd tags security keys by USB
IDs, which a virtual key does not have, so pqkey's udev rules tag its device
for the Firefox and Chromium snaps. Rules from before that, or a device
created before the rules were installed, lack the tags: `pqkey status` says
so, `pqkey setup` updates the rules, and `pqkey stop && pqkey start` creates
the device again. For another browser snap, add its tag to the rule (see the
comment there).

**`pqkey passkeys` lists nothing, although sites accepted the key.** It
lists discoverable credentials, the ones the key stores. A site that asks for
a non-discoverable one (`residentKey: "discouraged"`, as for a second factor),
or Chromium asking without a PIN on the key, gets a credential sealed into its
own ID, which the site keeps: signing in works, but the key has nothing to
list. The approval prompt says "Register a security key" for those and
"Create a passkey" for the ones it stores.

**Chromium says "Your device can't be used with this site".** Chromium only
uses a security key for passkeys (sign-in without a user name) or for a
request that requires user verification if the key has a PIN. Set one with
`pqkey pin`.

**Firefox's account chooser shows "Unknown account".** Without user
verification the key leaves user names out of its answer, as CTAP 2.3 §6.2.2
requires, so Firefox has nothing to show. With a PIN set, Firefox asks for it
and shows the names.

**Chromium shows "Something went wrong" after Deny, or after 30 seconds.** The
key answered that the request was denied: you clicked Deny, or nobody
approved it within 30 seconds (the user action timeout CTAP 2.3 §5 calls
reasonable). Firefox reports it at once; Chromium keeps its sheet open until
you click Cancel.

**`fido2-token` fails with `FIDO_ERR_RX` while a browser waits.** While one
program's request waits for approval, the key answers every other program,
also one opening a channel, with ERR_CHANNEL_BUSY (CTAP 2.3 §11.2.5.1: such a
request "will immediately fail with a busy-error message"). The client "SHOULD
retry the request after a short delay"; python-fido2 does, libfido2 1.16 gives
up. Answer or cancel the pending request first. `pqkey status`, `pin` and
`passkeys` meet the same answer and say the key is busy. The busy answer is
for the program that asked, but every program reading the device sees it:
python-fido2 2.2.1 then aborts its own waiting request with "Wrong channel".

**The service and the CLI use different state.** If you set `XDG_DATA_HOME` in
your shell, set it for the systemd user manager too (`environment.d(5)`).

`RUST_LOG` sets the log level (`RUST_LOG=pqkey=debug,pqkey_ctap=debug`).
Without it warnings and errors are logged; debug logs contain relying party IDs
and user names from requests.

## Confirm the virtual HID device is visible to userspace

```bash
ls -l /dev/uhid /dev/hidraw*
fido2-token -L
FIDO_DEBUG=1 fido2-token -I /dev/hidrawN
```

## Kernel-level introspection

The virtual key's HID ID is `0003:1209:0001` unless `--vendor-id` or
`--product-id` says otherwise.

```bash
lsmod | grep uhid
dmesg | grep -i uhid | tail -n 20
cat /sys/class/hidraw/hidraw*/device/uevent
sudo lsof /dev/uhid
sudo sh -c 'cat /sys/kernel/debug/hid/0003:1209:0001.*/rdesc'
```
