# Development notes

pqkey builds with Rust stable, 1.89 or later; `rust-toolchain.toml` picks the
toolchain. The key runs on Linux. Everything else also builds and tests on
macOS.

## Scripts

| Script | What it does |
|---|---|
| `scripts/check.sh` | Runs every check CI runs: formatting, lints, tests, docs, the minimum Rust version, dependencies and coverage. `--quick` runs only formatting, lints and tests. |
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

## Running your changes

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

- **CI** runs the checks of `scripts/check.sh` on x86_64 and arm64, and the
  lints and tests on macOS too.
- **E2E** runs `scripts/e2e.sh`'s tests.
- **Security** runs `cargo audit` and `cargo deny`.
- **Fuzz** runs each target for 30 seconds on changes and for 30 minutes
  every week.

Dependabot proposes updates every week. Cargo updates that are
semver-compatible and pass every workflow are merged automatically. Commit
changes to `Cargo.lock` and `fuzz/Cargo.lock` together.

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
