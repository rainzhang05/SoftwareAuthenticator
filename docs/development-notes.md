# Development notes

## Building and running

pqkey builds with Rust stable, 1.89 or later; `rust-toolchain.toml` picks the
toolchain. The daemon and CLI require Linux, and fail to compile elsewhere.
`pqkey-ctap` and `pqkey-mldsa` are portable, and CI's "test (macOS, portable
crates)" job checks them on macOS with:

```bash
cargo clippy -p pqkey-ctap -p pqkey-mldsa --all-targets --locked -- -D warnings
cargo test --locked -p pqkey-ctap -p pqkey-mldsa --all-targets
cargo test --locked -p pqkey-ctap -p pqkey-mldsa --doc
```

`./install.sh` rebuilds pqkey and restarts the key with your changes. To watch
the key's debug log, which names sites and users, run it in the foreground;
Ctrl-C stops it, and `pqkey start` brings the service back:

```bash
pqkey stop
RUST_LOG=debug cargo run --release -p pqkey -- run
```

## Scripts

| Script | What it does |
|---|---|
| `scripts/check.sh` | The checks of the CI and Security workflows and of Fuzz's smoke job; `--quick` runs formatting, lints and tests only |
| `scripts/e2e.sh` | The end-to-end tests against four test keys, through libfido2 and python-fido2 |
| `scripts/install-tests.sh` | The installer in disposable Docker containers |
| `scripts/fuzz.sh` | Each fuzz target for 30 seconds, or one for as long as you ask |
| `scripts/diagnose.sh` | The state of the key on this computer: binary, service, devices and log |
| `scripts/browser.sh` | A local relying party for real browsers ([browser tests](../tests/browser/README.md)) |
| `scripts/browser-acceptance.sh`, `scripts/desktop-acceptance.sh` | The [browser](../tests/browser/README.md#acceptance-workflow) and [desktop](../tests/desktop/README.md) acceptance harnesses |

The top of each script says what it needs. `check.sh`, `e2e.sh`, `fuzz.sh`
and `browser.sh` print one line per step and keep each step's output in
`target/scripts/`.

`check.sh --quick` runs formatting, actionlint and shellcheck, a check that
`fuzz/Cargo.lock` is current, the installer tests, the Python tests of the
browser and desktop harnesses and of the end-to-end ML-DSA verifier, and
clippy, tests and doctests: of the workspace and the fuzz crate on Linux, of
the portable crates on macOS. The full run adds the release build, rustdoc,
the residue tests in release, Rust 1.89 (a check, and the residue tests in
debug and release), every feature combination, `cargo audit` and `cargo deny`
on both lockfiles, line coverage of at least 85%, the tests of the auto-merge
and promotion scripts, and a fuzz smoke run (a build with `fuzz.yml`'s nightly
pins, then 30 seconds per target). It says why it skips a check (one that needs
Linux, on macOS; a missing tool, with how to get it; lints CI runs elsewhere),
never runs the end-to-end tests, and leaves tracked files as they are.

## Tests

| Layer | Where |
|---|---|
| Unit tests | in every crate, including the whole daemon over a socket pair |
| Engine tests | `crates/pqkey-ctap/src/ctap/tests/`, every command and its CTAP rules |
| Store tests | `crates/pqkey-ctap/tests/store/`, persistence, tampering and known-answer vectors |
| ML-DSA known answers | `crates/pqkey-mldsa/tests/`, NIST ACVP vectors |
| End to end | `tests/e2e/`, the release daemon driven by libfido2 and python-fido2 |
| Fuzzing | `fuzz/`, CTAPHID packets, CTAP requests, request sequences, credential key bytes and stored records |

Tests inject devices, report links, clocks, seat sources, notification servers
and store faults. Fault controls exist only in unit tests and the fuzz
harness: the shipped executable has no test seam for the protocol or the
state format. Store tests inject errors and process exits at every persistence
checkpoint of registration, repair, reset and PIN writes, in both store
layouts, and check that retrying recovers. CLI and kernel tests run on Linux,
and only the end-to-end tests use real HID.

The residue tests look for secrets left in memory after key generation,
reconstruction, signing (U2F and attestation included) and store roundtrips.
The heap test (`crates/pqkey/tests/heap_residue.rs`) keeps freed blocks until
it has scanned them, under the binary's wiping allocator, and requires every
freed byte to be zero. The stack probes fill 2 MiB below an operation with a
canary, then look for its secrets and for how deep it reached. ML-DSA scrubs
640, 960 and 1,600 KiB of stack for ML-DSA-44, -65 and -87 before returning,
success or error: at least 30% more than its operations reach without the
scrub in debug builds, which go deepest (`scrub_stack` documents the measured
depths). The probe fails unless that bound is at least 25% deeper than an
unscrubbed copy of the calls reaches. Live controls prove that each scan finds
its patterns, and on Linux a forced randomness failure, and an injected panic,
check that cleanup also runs on the error path. CI and `check.sh` run these
tests in debug and release, and under Rust 1.89 on x86_64 and aarch64. They
are bounded empirical checks: a clean scan is weaker evidence than a found
copy, and they cannot prove the erasure of every intermediate, register, live
key, unwinding frame or swap copy.

## End-to-end tests

`scripts/e2e.sh` needs Linux with `/dev/uhid`, fido2-tools, dbus-daemon and
python3-venv; it builds the pinned Python environment in `target/python` and
starts its own D-Bus session. To run `tests/e2e/libfido2.sh` by hand, point
`E2E_PYTHON` at that environment, and start and export a disposable D-Bus
session before each test key, auto-approve ones included, since WINK uses
notifications in every presence mode.

Besides python-fido2's and libfido2's own calls, including U2F in both
directions of CTAP1/CTAP2 compatibility, the tests send raw HID requests:
paced maximum-length PINGs, a competing CID during a reply,
resynchronization, leases, busy replies without client retries, and CBOR
the libraries cannot build (python-fido2 2.2.1 cannot encode null). In
`tests/e2e/libfido2.sh`, every `run_test` line comes before the summary.

- **Payments:** `test_third_party_payment.py` sends real requests, and
  `libfido2_payment.py` checks what libfido2 1.14.0 can, which cannot request
  the extension or show its flag. The portable `payment_compatibility`
  example prints 12 engine assertions for `libfido2_payment.py --fixtures PATH`
  to verify offline. Browser and Secure Payment Confirmation support is the
  client's, and is not tested.
- **Credential management preview:** `test_credential_management_preview.py`
  sends `0x41` through python-fido2's raw command API, whose convenience API
  picks `0x0A`; `ClientPin.get_pin_token(PIN)` gets the legacy grant.
  `libfido2_credman.py` uses libfido2's native I/O, which sends `0x41`: an
  ML-DSA-44 key fits its 2 KiB receive buffer but fails its decoder
  (FIDO_ERR_RX_INVALID_CBOR), and an ML-DSA-87 key exceeds the buffer.
  Credentials are never filtered for older decoders.
- **Brainpool:** `brainpool_vectors.py` regenerates the committed vectors with
  pinned cryptography and OpenSSL, and
  `cargo run --locked -p pqkey-ctap --example brainpool_compatibility` prints
  8 registrations and 16 assertions for
  `brainpool_compatibility.py --fixtures PATH` to verify offline. libfido2
  1.14.0 accepts the advertised identifiers but has no Brainpool type.
- **Persistent read-only management:** `persistent_management.py` builds raw
  `pcmr` requests, and `test_cli.py` covers restarts and PIN rotation.
- **Key agreement:** `test_key_agreement.py` sends malformed COSE metadata.

The E2E workflow also runs `tests/e2e/test_setup.py` with
`PQKEY_INSTALLER_E2E=1` after the other keys stop. It installs, reruns setup
and updates the executable for real, so it needs a disposable host with sudo,
a systemd user manager and `/dev/uhid`, and ordinary runs skip it.

## Installer tests

`scripts/install-tests.sh` runs the real `install.sh` in disposable Docker
containers, with no writable host mounts, host sudo or host devices.
`INSTALL_TEST_IMAGE` may name a preloaded image with Bash, Python 3, coreutils
and Git; the default is `rust:1.89-bookworm`. Fixtures record prerequisite
commands, installed executables, recovery copies, output and exit statuses,
and a PTY checks confirmation and hidden PIN input. Without Docker the check
fails rather than passes.

## Linux checks on macOS

Run the Linux checks in Docker, on a snapshot: `git archive` of a clean commit,
extracted with `tar -xm` (an archive carries the commit time, and cargo judges
freshness by mtime), without build artifacts or macOS extended attributes, in
a shell with `set -o pipefail`. Named volumes, such as `pqkey-cargo`,
`pqkey-cargo-registry`, `pqkey-rustup` and `pqkey-target`, keep caches between
runs. Use separate target directories for each compiler, architecture and
sanitizer, and for experiments on a modified copy, since cargo reuses
artifacts newer than the sources. Containers have no `/dev/uhid`: they run
socket-backed tests and fuzzing, not real HID. Keep the exact commands,
statuses, versions and logs of such checks outside the repository, and report
what could not run (real HID, browsers, another architecture) apart from what
passed.

## Fuzzing

`scripts/fuzz.sh` needs a nightly toolchain and cargo-fuzz; its header says
how to replay a crash. The packet target models partial transmission (report
selection, failed writes, INIT aborts, teardown, leases and identification)
and checks it against an independent request oracle. The sequence model mixes
CTAP2 and U2F, and checks signatures, counters, always-UV, PIN retry budgets,
large-blob visibility, credential management grants and cursors, payment
flags and key-agreement metadata, while it schedules I/O faults, corruption
and unconfirmed commits, each of which must fail only its command.

After changing an input layout or a seed generator, regenerate the seeds in
`fuzz/seeds/` twice with
`cargo run --locked --release --manifest-path fuzz/Cargo.toml --example seeds`
(`-- --ctaphid-only` for the CTAPHID seeds alone), and compare the file names
and contents of both runs; fixture encoders round-trip against the locked
`arbitrary`.

## Adding a signature algorithm

Each algorithm is described once, in the table in
`crates/pqkey-ctap/src/crypto/alg.rs`, and the compiler finds most of what
else has to change.

1. Add a `CoseAlg` variant whose value is its COSE identifier, its row in
   `CoseAlg::properties` and its place in `CoseAlg::ALL`, the order getInfo
   lists. An algorithm that differs from another only in its identifier, as
   ESP256 does from ES256, needs nothing more in Rust.
2. A new scheme needs a `Scheme` variant and a module for its family, like
   `crypto/ecdsa.rs`; a new curve, a `Curve` or `EdwardsCurve` variant, a
   module beside `crypto/ecdsa_p384.rs` or `crypto/eddsa_ed25519.rs`, a case in
   `tests/residue.rs` and, for keys derived from a seed, known answers. A new
   type of key needs a `CredentialSecretKey` variant, and keys kept in a new
   form a `KeyKind`, a `PrivateKeyMaterial` variant and a key type in
   `store/codec.rs`. A key that does not fit a sealed ID, as RSA's primes do
   not, is stored even for a non-discoverable credential
   (`CoseAlg::is_sealable`).
3. Build and run clippy, and handle every match they point to, among them the
   test verifier in `crypto/verify.rs`, which pqkey's tests and the fuzz
   targets reach through the `test-support` feature.
4. Run the tests: the table-driven ones cover the new algorithm, and the
   known-answer tests of the table, getInfo and the CLI say what to add. If
   `UNSUPPORTED_ALGORITHMS` in `fuzz/src/requests.rs` lists the algorithm,
   replace it there with one the key does not support.
5. Outside Rust, add it to `ALGORITHMS` in `tests/e2e/ctap.py`, to
   `test_get_info.py`, to `NAMES` in `tests/browser/q.py` and
   `tests/browser/index.html`, to the `fido2-token -I` line that
   `tests/e2e/libfido2.sh` expects (and its register-and-assert tests, if
   libfido2 implements the algorithm), and to the list in the
   [architecture notes](architecture.md#what-the-key-supports), and the
   README's summary for a new family.

Then run `scripts/check.sh`, regenerate the fuzz seeds (the `credential_key`
seeds pick algorithms by their place in `CoseAlg::ALL`, so give a new one
layouts in `fuzz/examples/seeds.rs` first), run `scripts/fuzz.sh`, and run
`scripts/e2e.sh` on Linux.

## Checking another user's session by hand

Nothing automated switches users: unit tests script logind's record of the
seat, and E2E runners have no logged-in seat. Check it on a desktop with two
accounts, where A runs the key and B is another user, switching with the
desktop's "Switch User" or `loginctl activate SESSION`.

1. As A, `pqkey status` names the device, say `/dev/hidraw3`;
   `getfacl /dev/hidraw3` lists `user:A:rw-`, and `journalctl --user -u pqkey`
   has "watching /run/systemd/seats". Keep a file open on the device:
   `exec 3<>/dev/hidraw3`.
2. Switch to B. `grep ACTIVE_UID /run/systemd/seats/seat0` shows B's uid. As
   B, `fido2-token -L` lists no device `0x1209`:`0x0001` (if B runs no key of
   their own), and `fido2-token -I /dev/hidraw3` fails, unless another device
   has taken that node.
3. Switch back to A. A's journal has "removing the key's device" and
   "the key plugs its device in again"; `pqkey status` names a device again,
   perhaps another node, whose ACL lists A but not B. In step 1's terminal,
   `cat <&3 >/dev/null` fails with an input/output error.
4. As A, end B's session without switching to it:
   `sudo loginctl terminate-session SESSION`, with B's session from
   `loginctl list-sessions`. A's journal has "logind rewrote seat0's record",
   and `pqkey status` names a device again.
5. On a test desktop, remove the record, as systemd 257 and older do when they
   cannot save it: `sudo rm /run/systemd/seats/seat0`. A's journal has
   "cannot tell whose session is active on seat0", and `pqkey status` says
   that logind's record of seat0 is missing. Switch to a text console where nobody
   is logged in, and back: each switch saves the record, and `pqkey status`
   names a device again.

These steps do not race for the device in the moment of a switch
([SECURITY.md](../SECURITY.md#other-users-sessions)).

## Continuous integration and releases

GitHub Actions runs these workflows:

- **CI**: the checks of `scripts/check.sh` but Security's and Fuzz's, on Linux
  with workspace tests on x86_64 and arm64, and the portable crates on macOS.
- **E2E**: the real HID tests of `scripts/e2e.sh`, on Linux.
- **Security**: `cargo audit` and `cargo deny`.
- **Fuzz**: each target for 30 seconds on changes, and for 30 minutes every
  week.

The [browser](../tests/browser/README.md#acceptance-workflow) and
[desktop](../tests/desktop/README.md) acceptance workflows run only when
dispatched.

Dependabot proposes updates every week, for Cargo only to releases at least
seven days old. Cargo updates that are semver-compatible, add no package and
pass every workflow merge automatically. Commit changes to `Cargo.lock` and
`fuzz/Cargo.lock` together, and when Security fails on an advisory, update the
crate by hand rather than wait for Dependabot.

`main` is the development branch, and its commits are tested after they are
pushed. `stable` follows the newest commit on `main` that passed CI, E2E and
Security: the **Promote stable** workflow moves it with
`.github/scripts/promote-stable.sh` when one of those finishes on `main`, and
every six hours, which catches runs another workflow started, such as the
Dependabot auto-merge's; `gh workflow run promote.yml` runs it at once. It
counts only runs started by a push, a schedule or a dispatch, and never moves
`stable` back. Since the workflow's token cannot give `stable` workflow files
that `main`'s head lacks, it skips a commit whose `.github/workflows` differs
from both `main`'s head and `stable`, and `stable` waits for a newer one. With
`DRY_RUN=1` it only prints what it would do:

```bash
DRY_RUN=1 REPO=rainzhang05/SoftwareAuthenticator .github/scripts/promote-stable.sh
```
