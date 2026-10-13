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

ML-DSA drops its owned expanded keys inside a separate operation frame, then
scrubs the retired stack before returning either success or an error. The
bounds are 512 KiB for ML-DSA-44, 768 KiB for ML-DSA-65 and 1 MiB for
ML-DSA-87. Rust 1.89.0 debug on Linux/aarch64 left copies of ML-DSA-65's
rho-prime and K about 567 KiB below the cleanup frame, outside the former
512 KiB wipe. Seed expansion creates plain locals, moves SHAKE state and
clones an expanded key; wiping the final owned values does not erase all
retired copies. Stable's different temporary layout happened to leave no
detected residue. Parameter dispatch now precedes the secret-handling closure,
so each retired frame holds only one parameter set's key and decode result;
the previous combined frame also escaped cleanup on expanded-key success and
malformed-key errors. The larger bound covers the originally measured locations
with about 200 KiB of margin, without additional secret-bearing allocations.

The stack probes retain their 2 MiB scans and controls, and check both
32-byte halves of the 64-byte rho-prime and K after individual seed,
expanded-key, context, malformed-key and CTAP wrapper operations. Linux
children also force an OS randomness failure after seed expansion to check
the returned-error cleanup path. CI forces Rust 1.89.0 for runtime stack
and heap probes in debug and release on x86_64 and aarch64, alongside the
stable tests and the declared-MSRV compilation check.

These are bounded empirical checks of selected patterns and operations.
The stack scanners read uninitialized, retired storage, outside Rust's
defined memory model; a clean scan is weaker evidence than a detected
copy. Compiler, profile and CPU backend change layouts and incidental
overwrites. The probes do not establish erasure of every intermediate,
register, live caller-owned key, unwinding frame or swap copy. Heap probes
separately retain surrendered allocations and require every byte to be
zero; that guarantee comes from the daemon's wiping allocator. Standalone
wrapper consumers still depend on each owned secret's explicit drop cleanup.

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
PIN writes, and verify explicit retry recovery. PIN/configuration regressions
cover every preparation and post-rename checkpoint, both PIN protocols,
legacy and managed stores, live/restarted policy and old-token invalidation.
Private test observations prove unconfirmed retry debits reach no decryption,
comparison or token issuance. The sequence harness schedules pre-publication
failures and committed-but-unconfirmed outcomes, tracks live and published
retry budgets, and reconstructs engines over the same published store. Seeds
cover these outcomes, retry recovery, protocol crossings and U2F disabled by
always-UV. Fault controls exist only in unit tests and the fuzz harness.
Large-blob tests cover fragmented writes, interrupted staging and restart
persistence; the fuzz sequence model checks committed-array visibility and
the lifetime of pending writes, and that credential keys are stable and
returned only when requested. Heap residue tests include those keys and
their registration, assertion and enumeration response copies.

## PIN storage recovery

A successful PIN/configuration command publishes its settings immediately.
A warning about unconfirmed durability means a process restart observes the
new settings, while power loss may roll back the rename. Read getInfo to
observe PIN presence, minimum length, forced change and alwaysUv; RP disclosure
is tested through the minPinLength extension. Avoid treating a durability
warning as evidence that the old PIN or policy is still active.

A retry-write processing error gives no verdict on the supplied PIN and issues
no token. Inspect getPINRetries before further attempts: a failed write can
conservatively reduce the running budget, and an unconfirmed published debit
is visible after restart. Restoring storage permits another attempt if retries
remain. Restart clears the three-mismatch power-cycle block; it does not clear
persisted retry exhaustion. An unreadable record remains untouched and fails
closed until an explicit reset.

Reset preserves attestation and rotates the credential key before removing
counters or policy. Earlier errors may leave partial cleanup, but cannot
revive invalidated credentials or lower surviving credentials' protections.
Retrying explicit reset recovers without needing readable old records. Once
all preceding work completes and default PIN state is published, reset returns
success and adopts defaults even if the final publication is unconfirmed.

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
   and a key type in `store/codec.rs`; `CoseAlg::is_sealable` checks both material width and algorithm encoding.
   Both must fit the existing sealed credential ID. A key that does not, as RSA's primes do
   not, is stored even for a non-discoverable credential.
3. Build and run clippy, and handle every match they point to, among them
   the test verifier in `crypto/verify.rs`, which pqkey's tests and the fuzz
   targets reach through pqkey-ctap's `test-support` feature. Compile-time invariants and explicit eligibility tests keep the signed-byte
   sealed algorithm field separate from the private material width.
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

## Identification and channel lease regression checks

The CTAPHID state machine tests inject monotonic milliseconds and check exact
lease and identification expiry, resynchronization, selected output, and final
successful writes. The independent fuzz model tracks leases and identification
tokens separately from transactions and the CTAP worker. Regenerate only these
seeds with `cargo run --locked --manifest-path fuzz/Cargo.toml --example seeds
-- --ctaphid-only`; the encoder round-trips each seed and runs the oracle.

Real HID tests allocate competing CIDs before acquiring a lease and release
leases in cleanup, including after failed assertions and partial responses.
The disposable notification server checks Python FIDO WINK and libfido2's
forced-U2F touch API, which sends WINK before its separate presence operation.
The two notifications are checked independently. Prepare the pinned Python
environment before running `tests/e2e/libfido2.sh`; `E2E_PYTHON` selects it.

On macOS, distinguish E2E syntax and collection from actual HID execution.
Containers without `/dev/uhid` can run simulated-device tests and sanitizer
fuzzing, but cannot execute the real HID suite. Record validation architecture,
compiler versions, command exit statuses, and each fuzz target's explicit
30-second budget. Source snapshots must come from `git archive`, extracted
with `tar -xm`, with separate cached outputs for each compiler and architecture.

## Third-party payment verification

[CTAP 2.3 §12.9 and §6.8, February 26, 2026 Proposed Standard](https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html)
support is tested at the authenticator boundary for every
advertised algorithm and both credential modalities. Rust regressions verify
signed bytes and counters, mixed next assertions, legacy record encodings,
credential enumeration and updates, restart/reset/replacement, capacity,
filesystem fault/crash recovery, protection and ES256 protocol crossings.
The fuzz model independently follows registration metadata, assertion requests
and per-credential next-assertion outputs. Regenerate all seeds after changing
its input layout; fixture encoders round-trip against the locked `arbitrary`
dependency before the corpus is written.

`tests/e2e/test_third_party_payment.py` covers real Python FIDO HID requests.
Its malformed-input tests bypass client validation and send CBOR null directly,
because python-fido2 2.2.1 cannot encode null. `libfido2_payment.py` uses only
libfido2 1.14.0 APIs: that version cannot request the extension or expose its CM
flag. Its management API always sends prototype command `0x41`; pqkey now
advertises `credentialMgmtPreview` and its native check requires successful
enumeration. Standard `0x0A` enumeration is checked through Python FIDO. The
native library asserts payment-enabled credentials and verifies signed
authenticator data containing the unknown extension. The shell runner includes
the check before its final summary.

The portable `payment_compatibility` example emits 12 real CTAP engine
assertions. Pass its stdout to `libfido2_payment.py --fixtures PATH` in the pinned
Python environment to verify absent/false/true requests, increasing counters
and signature rejection after changing the payment boolean without a HID node.
This verifies signed-byte compatibility; real transport and enumeration checks
still require a Linux host with `/dev/uhid`.

Browser/WebAuthn and Secure Payment Confirmation verification are separate.
The client platform determines payment eligibility and UI; advertising this
extension does not establish browser or SPC support. Historical client results
above concern authentication, and do not claim payment verification.

## Credential management preview verification

[Final CTAP 2.3 §§6.13, 6.8 and 6.5](https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html)
and the [prototype wire format](https://fidoalliance.org/specs/fido2/vendor/CredentialManagementPrototype.pdf)
define compatibility command `0x41`. Subcommand 7 is a documented backport of
standard user updates, required by [libfido2 1.14.0's native implementation](https://github.com/Yubico/libfido2/blob/1.14.0/src/credman.c).

Rust engine regressions exercise both PIN protocols, explicit legacy issuance,
modern permission isolation, RP scopes, expiry and consumption, reissue,
PIN/policy publication failures, restart/reset, family switches and independent
cursors. They check all seven operations, public keys for every advertised
algorithm, capacity, truncation, rejected mutation usability, protection,
largeBlobKey and thirdPartyPayment preservation. Preview uses the current
protocol MAC verifier; repeated MAC failures never debit persistent PIN retries.
The sequence oracle independently tracks authorization and cursor grants,
including valid MAC use before later permission/data rejection. Fixture encoders
round-trip against the locked `arbitrary` graph. After input-layout changes,
regenerate every seed with `cargo run --locked --release --manifest-path
fuzz/Cargo.toml --example seeds`, repeat, and compare filenames and contents.

`tests/e2e/test_credential_management_preview.py` sends actual HID `0x41`
requests. python-fido2 2.2.1's convenience API selects `0x0A` when credMgmt is
present, so preview tests use its raw command API without modifying getInfo.
Calling `ClientPin.get_pin_token(PIN)` obtains the legacy grant; explicit CM
permissions obtain a modern grant. Tests include exact authentication statuses,
RP restrictions, family switches, independent cursors and WINK/LOCK preservation.

`tests/e2e/libfido2_credman.py` keeps libfido2's native HID I/O and exercises
metadata, multi-RP/credential enumeration, user updates and deletion with ES256,
ES384, EdDSA and RS256. Raw checks cover mixed payment flags and large-blob keys;
libfido2 1.14 exposes largeBlobKey but ignores the additional payment field.
Its separate ML-DSA-44 decoder check fits the library's 2 KiB receive buffer and
expects FIDO_ERR_RX_INVALID_CBOR while raw preview enumeration and credential
signing still succeed. An ML-DSA-87 public key exceeds that old receive buffer.
Supported credentials are never filtered for older decoders. Every shell
run_test precedes the summary,
including the existing payment helper's advertised-preview success branch.

Engine checks and E2E syntax/collection can run on macOS and Linux/aarch64
containers. Actual HID execution requires Linux with `/dev/uhid`; container
fixtures and collection do not establish native transport success. Keep exact
commands, statuses, compiler/architecture details, deterministic regeneration
results and unavailable HID/x86_64 execution in validation evidence outside the
repository. Use fresh git archives extracted with `tar -xm`, preserve pipeline
failures, and separate cache outputs by compiler, architecture and sanitizer.

Start and export the disposable D-Bus session before every test key, including
auto-approve keys: WINK identification uses notifications in every presence mode.

## Brainpool validation and client limits

`tests/e2e/brainpool_vectors.py` regenerates the committed independent vectors
with pinned cryptography/OpenSSL, hashlib and Python integers. The vectors cover
two seeds per curve, private/public derivation, SHAKE output, RFC 6979 nonces,
and signatures with the correct and wrong hashes. Existing derivation vectors
remain regression requirements. The stack probe independently computes both
new scalars/nonces, handles bits2octets reduction and rejected candidates, and
retains its full 2 MiB scan; heap controls include scalars, SHAKE output and
nonces in both byte orders and retain the all-freed-bytes-zero requirement.

Run `cargo run --locked -p pqkey-ctap --example brainpool_compatibility` and pass
stdout to `tests/e2e/brainpool_compatibility.py --fixtures PATH` in the pinned
Python environment. It independently verifies eight registrations and sixteen
assertions with OpenSSL, including both stored modalities, payment/blob metadata,
DER and tampering. This offline path does not establish HID or browser support.
Raw HID regressions use the existing Python FIDO cryptography helpers with
Brainpool curves and cover PIN protocols, credProtect and management.

The libfido2 1.14.0 compatibility tests use its existing algorithm getters and
`fido_cred_set_type`, plus native preview management. Advertising -265/-267
succeeds; unsupported native credential types and COSE decoders fail as expected.
Keep ES256/ES384/EdDSA/RS256 and ML-DSA decoder compatibility gates intact;
do not filter authenticator credentials for an older decoder or imply verified
Brainpool browser support. Non-discoverable Brainpool credentials cost a storage
slot even when payment is disabled.

After any algorithm/fixture-layout change, regenerate every committed fuzz seed
with `cargo run --locked --release --manifest-path fuzz/Cargo.toml --example seeds`
twice and compare filenames/content hashes. The explicit sequence fixtures carry
an algorithm index and check their own round trips against locked `arbitrary`.
Keep source snapshots, exact commands/statuses, compiler and architecture
identity, full probe logs, corpus manifests and five explicit 30-second
sanitizer results outside the repository. Linux snapshots come from `git archive`
extracted with `tar -xm`, with separate compiler/architecture/sanitizer caches.
