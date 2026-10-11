# Development notes

pqkey builds with Rust stable, 1.89 or later; `rust-toolchain.toml` picks the
toolchain. The daemon and CLI require Linux, with a compile-time diagnostic
on other systems. `pqkey-ctap` and `pqkey-mldsa` are portable and can be
tested independently, including on macOS:

```bash
cargo test --locked -p pqkey-ctap -p pqkey-mldsa --all-targets
cargo test --locked -p pqkey-ctap -p pqkey-mldsa --doc
```

`./install.sh` is the Linux installation entry point. It rejects other
systems before creating logs, installing tools or changing system setup.

## Scripts

| Script | What it does |
|---|---|
| `scripts/check.sh` | Runs every check CI runs: formatting, lints, tests, docs, the minimum Rust version, dependencies and coverage. `--quick` runs formatting, installer checks, lints and tests. |
| `scripts/install-tests.sh` | Runs the actual installer in disposable Docker filesystems with controlled prerequisites, PTYs and fault injection; requires Docker. |
| `scripts/e2e.sh` | Runs the end-to-end tests against four test keys, through libfido2 and python-fido2. |
| `scripts/fuzz.sh` | Runs each fuzz target for 30 seconds, or one target for as long as you ask. |
| `scripts/diagnose.sh` | Shows the state of the key on this computer: binary, service, devices and log. |
| `scripts/browser.sh` | Starts a local relying party for testing in real browsers ([details](../tests/browser/README.md)). |

Each script prints one line per step and keeps the full output in
`target/scripts/`. The top of each script says what it needs.

The heap residue test runs credential generation, reconstruction, signing
and store roundtrips under the binary's wiping allocator. Its test allocator
retains freed blocks until they have been scanned, and live controls prove
that the scan finds each secret pattern. CI and `scripts/check.sh` run it in
debug and release, as they do the stack residue tests.
The final cleanup scan also checks blocks released by the last controls.
U2F residue cases cover registration certificates and signatures,
authentication with and without presence, and the provisioned attestation
key. Stack checks independently reconstruct the nonces of U2F signing
bases; heap checks retain released blocks for all three attestation modes.
The packet fuzz target includes U2F APDUs, repeats, approval, denial and
abandonment. Structured and sequence targets mix both protocols; the
sequence model verifies U2F signatures, credential eligibility, application
binding, shared counter monotonicity and always-UV. Its traces retain full
U2F status words. Failed resets retain counter floors; successful resets keep
invalidated IDs for the existing individual retired-ID probes. File-store
reset tests inject failures and process exits at every persistence checkpoint
in both layouts, including key publication, counter deletion, manifest and
PIN writes, and verify explicit retry recovery. Regenerated seeds include protocol crossings and U2F
disabled by always-UV.
Large-blob tests cover fragmented writes, interrupted staging and restart
persistence; the fuzz sequence model checks committed-array visibility and
the lifetime of pending writes, and that credential keys are stable and
returned only when requested. Heap residue tests include those keys and
their registration, assertion and enumeration response copies.

## Running your changes

CTAPHID packet fuzzing models partial transmission explicitly: report selection,
successful and failed writes, INIT aborts and session teardown. A separate
request/worker oracle checks response bytes, ordering and ownership through
the final successful write; its incremental parser rejects stale continuations
and truncation without an explicit abort. Seeds cover single-report and
maximum-length responses, final-report competition, selected-report INIT,
keepalives, late workers, cancellation and U2F pending/cached answers.

Raw HID transport E2E tests pace maximum-length PING requests, send a competing
CID during the reply and resynchronize a transmitting channel. Run them on a
Linux host with `/dev/uhid`; socket and callback tests cannot replace that check.
Management-client recording links verify zero rejected-command reports at
the advertised and HID limits, including authenticated CBOR and getInfo
refreshes. CLI tests preserve PIN policy and the RP list after oversized
configuration; `test_cli.py` repeats this through real HID with and without
a PIN, then successfully authorizes eight shorter RP IDs.

`./install.sh` rebuilds pqkey and restarts the key with your changes. To
watch the key's debug log, run it in the foreground. The log includes site and
user names.

```bash
pqkey stop
RUST_LOG=debug cargo run --release -p pqkey -- run
```

Ctrl-C stops it, and `pqkey start` brings the service back.

## Continuous integration

GitHub Actions runs these workflows:

- **CI** runs the checks of `scripts/check.sh` on Linux, with workspace
  tests on both x86_64 and arm64.
- **E2E** runs `scripts/e2e.sh`'s real HID tests on Linux.
- **Security** runs `cargo audit` and `cargo deny`.
- **Fuzz** runs each target for 30 seconds on changes and for 30 minutes
  every week.

Dependabot proposes updates every week. Cargo updates that are
semver-compatible and pass every workflow are merged automatically. Commit
changes to `Cargo.lock` and `fuzz/Cargo.lock` together.

## Linux platform boundary

The [architecture notes](architecture.md) describe the boundary between
command and protocol logic and the Linux backend. Keep kernel, udev,
systemd, D-Bus and process operations under
`crates/pqkey/src/platform/linux/`. Tests inject devices, clocks and
notification servers while retaining Linux uhid assertions. Run the full
workspace and fuzz checks on Linux and the unchanged E2E suite on a Linux
host with `/dev/uhid`.

On macOS, test the portable crates natively and use a Linux environment,
such as Docker, for daemon and fuzz checks. Container unit tests can use
socket-backed devices; real HID E2E tests require access to `/dev/uhid`.

## Installer regression checks

Run `scripts/install-tests.sh` with Docker running. It sends the installer and
fixtures to disposable Linux containers, with no writable host mounts, host
sudo or host devices. `INSTALL_TEST_IMAGE` may select a compatible preloaded
image (Bash, Python 3 and coreutils); the default is `rust:1.89-bookworm`.
Both `scripts/check.sh` modes and the CI installer job run these checks.
Missing Docker is a failed required check rather than an implicit pass.

Fixtures execute the real `install.sh`, recording prerequisite commands,
installed executables, recovery copies, output and exit statuses. A PTY checks
confirmation and hidden PIN input. Rust setup tests run the shared setup
orchestration in child processes and verify PIN readiness against the existing
socket-backed CTAP client/daemon. No protocol or state-format test seam is
added to the shipped executable.

The E2E workflow additionally runs `tests/e2e/test_setup.py` with
`PQKEY_INSTALLER_E2E=1` after the other test keys stop. This opt-in test requires
a disposable Linux host with sudo, a systemd user manager and `/dev/uhid`.
It executes installation, setup reruns and executable updates using real HID
clients and the existing fake desktop notification server. It is skipped in
ordinary developer E2E runs so it cannot install over a personal key.

For macOS Linux validation, send a source snapshot to Docker and extract it
with `tar -m` (or `tar -xm`) so container rebuilds use the snapshot's contents.
Exclude build artifacts and macOS extended attributes, retain pipeline failure
statuses with `set -o pipefail`, and reuse the `pqkey-cargo`,
`pqkey-cargo-registry`, `pqkey-rustup` and `pqkey-target` volumes. Keep fuzz
build outputs separate within the target volume. Containers without
`/dev/uhid` can run fixture and socket-backed tests, but cannot verify real HID.

## Adding a signature algorithm

Each algorithm is described once, in the table in
`crates/pqkey-ctap/src/crypto/alg.rs`, and the compiler finds most of what
else has to change.

1. Add a `CoseAlg` variant whose value is its COSE identifier, its row in
   `CoseAlg::properties` (its name and signature scheme), and its place in
   `CoseAlg::ALL`, the order getInfo lists the algorithms in. An algorithm
   that differs from another only in its identifier, as ESP256 does from
   ES256, shares its scheme and needs nothing more in Rust.
2. A new scheme needs a `Scheme` variant and a module for its family, as
   `crypto/ecdsa.rs`, `crypto/eddsa.rs`, `crypto/mldsa.rs` and
   `crypto/rsa.rs` are. ECDSA or EdDSA on a new curve needs a `Curve` or
   `EdwardsCurve` variant, a module for the curve next to
   `crypto/ecdsa_p384.rs` or `crypto/eddsa_ed25519.rs`, a case in
   `tests/residue.rs` and, for keys derived from a seed, known answers in its
   family's module. A new type of key needs a `CredentialSecretKey` variant.
   Keys kept in a new form need a `KeyKind`, a `PrivateKeyMaterial` variant
   and a key type in `store/codec.rs`; `KeyKind::is_sealable` says whether
   they fit a sealed credential ID. A key that does not, as RSA's primes do
   not, is stored even for a non-discoverable credential.
3. Build and run clippy, and handle every match they point to, among them
   the test verifier in `crypto/verify.rs`, which pqkey's tests and the fuzz
   targets reach through pqkey-ctap's `test-support` feature. A check at
   compile time says if an algorithm whose key can be sealed does not fit a
   sealed credential ID.
4. Run the tests. The table-driven ones cover the new algorithm, and the
   known-answer tests of the table, of getInfo and of the CLI say what to
   add to them. If `UNSUPPORTED_ALGORITHMS` in `fuzz/src/requests.rs` lists
   the algorithm, the fuzz crate's tests fail: replace it there with an
   identifier the key does not support.
5. Outside Rust, add it to `ALGORITHMS` in `tests/e2e/ctap.py` and to
   `test_get_info.py`, to `NAMES` in `tests/browser/q.py` and
   `tests/browser/index.html`, to the `fido2-token -I` line that
   `tests/e2e/libfido2.sh` expects (and its register-and-assert tests, if
   libfido2 implements the algorithm), and to the algorithm lists in the
   README and the [architecture notes](architecture.md).

Then run `scripts/check.sh`, regenerate the fuzz seeds with `cargo run
--release --manifest-path fuzz/Cargo.toml --example seeds` (the
`credential_key` seeds pick algorithms by their place in `CoseAlg::ALL`, so
give a new one layouts in `fuzz/examples/seeds.rs` first), run
`scripts/fuzz.sh`, and run `scripts/e2e.sh` on Linux.

## Clients

The E2E suite also exercises python-fido2 2.2.1's Ctap1 registration and
signature verification, WebAuthn fido-u2f verification, protocol crossings,
PIN independence, always-UV and notification polling. A helper repeats only
presence-required APDUs. libfido2's forced-U2F commands register and assert
ES256 credentials and verify both directions of protocol compatibility.
Raw HID tests observe busy replies without the client's automatic retries.

These were tested on 2026-09-30 on Ubuntu 26.04.1 (aarch64, GNOME 50.1).

| Client | ES256 | ML-DSA | Notes |
|---|:---:|:---:|---|
| Chromium 153 (snap) | ✓ | ✓ | Passkeys and user verification need a PIN on the key. `getPublicKey()` returns null for ML-DSA and `toJSON()` leaves the key out, so relying parties read it from the attestation object. |
| Firefox 154 (snap) | ✓ | | Drops algorithms it does not know: an ML-DSA-only request fails with `NotAllowedError`. Without a PIN, its account chooser shows "Unknown account". |
| python-fido2 2.2.1 | ✓ | ✓ | Used by the end-to-end tests. |
| libfido2 1.16 | ✓ | | Has no ML-DSA type, so `fido2-token -L -k` cannot list ML-DSA passkeys; `pqkey passkeys` can. PIN, credential management and `hmac-secret` work. |

## Troubleshooting

Start with `pqkey status`, which names what is missing and how to fix it, or
`scripts/diagnose.sh` for the whole picture.

**The key stops answering and `pqkey stop` hangs.** The Linux uhid queue has
an unlocked read race, seen especially on arm64. When it hits, `dmesg` shows
the following, with `uhid_char_read` in the call trace:

```text
usercopy: Kernel memory exposure attempt detected from null address (offset 0, size 4376)
kernel BUG at mm/usercopy.c:102
```

pqkey waits for each event to settle before reading it to avoid the race, but
cannot rule it out. Restart the key; if its process cannot be stopped,
reboot.

**The browser waits, but no prompt appears.** On GNOME a prompt can queue
behind another banner, so pqkey nudges the queue every 2 seconds. The prompt
is also in the notification list (click the clock).

**Every registration or sign-in fails at once.** No notification could be
shown, so the key said no. `journalctl --user -u pqkey` says why. If your
desktop starts its own D-Bus session bus, see the comments in
[`contrib/systemd/user/pqkey.service`](../contrib/systemd/user/pqkey.service).

**A snap browser never asks for the key.** Snaps open only devices tagged for
them, and the udev rules tag the key for the Firefox and Chromium snaps. If
`pqkey status` says the tag is missing, run `./install.sh`.

**`pqkey passkeys` lists nothing, although sites accepted the key.** It lists
passkeys, the credentials the key can find by itself. A site that registers it
as a second factor (`residentKey: "discouraged"`) keeps the credential's ID
and sends it back to sign in, and so does Chromium when the key has no PIN.
Those sign-ins work, but the key does not list them, and their prompt says
"Register a security key" instead of "Create a passkey".

**Chromium says "Your device can't be used with this site".** Chromium uses a
security key for passkeys only if it has a PIN. Set one with `pqkey pin`.

**Firefox's account chooser shows "Unknown account".** Without a PIN, the key
leaves user names out of its answer (CTAP 2.3 §6.2.2). With a PIN set, Firefox
asks for it and shows the names.

**Chromium shows "Something went wrong" after Deny or after 30 seconds.** The
request was denied or timed out. Chromium keeps its sheet open until you click
Cancel.

**Another program fails while a browser waits for approval.** The key serves
one request at a time and answers the others "busy", as CTAP requires. Answer
or cancel the waiting request first.

**The service and the command use different passkeys.** If you set
`XDG_DATA_HOME` in your shell, set it for the systemd user manager too (see
`environment.d(5)`).
