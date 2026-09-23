# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
The project has not made a release yet, and does not follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) until it does.

## [Unreleased]

This section covers the overhaul since commit `867a591` ("Fix stale CTAPHID
test offsets and drop dead descriptor rewriter"), when the project was the
Trussed-based "FIDO Software Authenticator" with the `pc-hid-runner` binary.

### Breaking changes

Upgrading from `867a591` or earlier is not an in-place update:

- **Stored state is not migrated.** Credentials and the PIN from the old
  format are lost; there is nothing to convert them with. The daemon deletes
  the old files (`master.seed`, `internal.lfs2`, `external.lfs2`,
  `volatile.lfs2`) when it starts, and so does `pqkey reset`.
- **The state directory moved** from `$XDG_DATA_HOME/feitian-mldsa-authenticator`
  (`~/.local/share/feitian-mldsa-authenticator`) to `$XDG_DATA_HOME/pqkey`
  (`~/.local/share/pqkey`). The CLI prints a note while the old directory
  exists; delete it yourself.
- **Renamed:** the project to pqkey; the binary `pc-hid-runner` to `pqkey`; the
  crates `pc-hid-runner`, `authenticator` and `trussed-mldsa` to `pqkey`,
  `pqkey-ctap` and `pqkey-mldsa`, now under `crates/`; the udev rules
  `contrib/udev/70-feitian-authenticator.rules` to
  `contrib/udev/70-pqkey.rules`. The system service
  `contrib/systemd/feitian-authenticator.service` is replaced by the user unit
  `contrib/systemd/user/pqkey.service`.
- **New identity defaults.** AAGUID `46454954-4941-4e98-0616-525a30310000` is
  now `5931e805-a166-4eb7-845a-7f6aa93d9cd8`. USB IDs `096e:0858` are now
  `1209:0001` (pid.codes; a test product ID). The HID product name defaults to
  "pqkey FIDO2 Software Authenticator (ML-DSA)". Relying parties see a
  different authenticator model, and udev rules keyed on the old IDs no longer
  match.
- **User presence is asked for by default.** Presence used to be approved
  automatically unless `--manual-user-presence` was given. Now every
  registration, sign-in, reset and selection shows a desktop notification
  (`--presence notify`), and without a notification server that can show
  buttons every such request is denied. `--presence auto-approve` restores the
  old behaviour for tests.
- **Self attestation by default.** Registrations used to carry basic
  attestation with a certificate naming Feitian Technologies. The default is
  now self attestation; `--attestation certificate` (with the now required
  `--manufacturer` and `--country`) and `--attestation none` select the other
  modes.
- **Removed options:** `--manual-user-presence` (use `--presence`),
  `--suppress-attestation` (use `--attestation none`), and `--pin`,
  `--current` and `--new` of the `pin` commands (PINs are now read from the
  terminal or standard input). `--manufacturer` no longer has a default.
  `--serial`, `--vid`, `--pid` and `--backend` are still accepted but
  ignored.
- **Build requirements:** Rust 1.89 or later (was 1.85), edition 2024.

### Added

- `pqkey` identity: its own AAGUID, product name, pid.codes USB IDs and state
  directory.
- Desktop notification prompt for user presence over D-Bus
  (`org.freedesktop.Notifications`), with Approve and Deny buttons, that
  withdraws itself when the client cancels, and `--presence
  notify|auto-approve`.
- `--attestation self|certificate|none`. Generated attestation certificates meet
  WebAuthn Level 3 §8.2.1, carry the AAGUID extension, and are replaced when
  they name another AAGUID. `--country` is checked against ISO 3166-1 alpha-2.
- Encrypted credential store (`FileStore`): one XChaCha20-Poly1305 envelope per
  record, root keys with HKDF-derived subkeys, atomic writes, and a reset that
  replaces the key protecting credentials and PIN state.
- authenticatorSelection.
- Non-discoverable credentials for `rk` false.
- `FIDO_2_3` in getInfo versions, plus `maxCredentialCountInList`,
  `remainingDiscoverableCredentials`, `attestationFormats` and the
  `makeCredUvNotRqd` option. `clientPin` is reported as false until a PIN is
  set, and the `uv` option is no longer reported (there is no built-in user
  verification).
- attestationFormatsPreference "none" is honoured.
- An exclusive lock on the state directory, so two daemons, or a daemon and a
  `pin` or `reset` command, never use the same state at once; `pqkey status`
  reports a daemon that is still starting.
- Hardened systemd user unit.
- NIST ACVP known-answer tests for ML-DSA-44/65/87; known-answer tests for the
  store's envelope, key hierarchy and record encoding.
- End-to-end tests of the real virtual device with libfido2 and python-fido2 on
  GitHub Actions, including the notification prompt.
- libFuzzer targets for CTAPHID framing, CTAP requests and request sequences,
  and stored key material, run weekly and smoke-tested on pushes to `main`.
- CI: clippy and rustdoc with warnings denied, MSRV check, feature powerset,
  release build, an 85% line coverage floor, cargo-audit and cargo-deny on both
  lockfiles, and formatting and lints of the fuzz crate.
- Dependabot with automatic merging of semver-compatible Cargo updates once CI,
  Security and E2E (and Fuzz, for the fuzz crate) pass.
- `LICENSE` (MIT); README, SECURITY.md and docs/.

### Changed

- Trussed is gone. The CTAP engine talks to injected interfaces for storage,
  randomness and user presence, and the daemon runs its own uhid loop instead
  of the Trussed runner.
- ML-DSA comes from RustCrypto's `ml-dsa` instead of `fips204`, and ML-DSA
  credentials are stored as, and signed from, their 32-byte seed.
- The CTAP engine runs on a worker thread, so the transport keeps sending
  keepalives, answering other channels and passing on CTAPHID_CANCEL while a
  request waits for the user.
- A CTAP reset is accepted at any time when the notification asks for it; with
  `--presence auto-approve` only within 10 seconds of start-up (CTAP 2.3 §6.6).
- `pqkey attach` starts the background daemon by running itself again in a new
  session instead of daemonizing, and reports start-up failures.
- SIGINT and SIGTERM stop the daemon cleanly and remove the virtual device.
- The udev rules grant `/dev/uhid` to `plugdev` and the virtual key's hidraw
  node to the active session user only (`uaccess`, mode 0600).
- Relying party IDs and user names are logged at debug level only.
- Warnings are logged without `RUST_LOG`, not only errors, so the warnings
  about `--presence auto-approve`, `--attestation certificate` and a
  world-accessible hidraw node reach the log.
- CLI errors are printed as messages.
- Dependencies updated to current majors (for example sha2 0.11, p256 0.14,
  getrandom 0.4, rand_core 0.10); `pretty_env_logger` replaced by
  `env_logger`.

### Fixed

- ML-DSA credentials could not be stored: the old store limited records to
  1,024 bytes.
- Large responses (such as ML-DSA-87 assertions) lost packets because uhid
  input reports overflowed the 64-report hidraw buffer; reports are now paced
  1 ms apart.
- PIN/UV auth protocol 2 derived its session keys from the wrong input;
  pinUvAuthParam, saltAuth and hmac-secret now follow the selected protocol.
- PIN length is counted in Unicode code points, as CTAP requires, not bytes.
- setPIN and changePIN store the new PIN before using it, so a failed write no
  longer leaves the running daemon with a PIN that is not on disk.
- getPinToken and getPinUvAuthTokenUsingPinWithPermissions return only the
  encrypted pinUvAuthToken, without pinRetries.
- pinUvAuthToken usage timer, permissions, RP binding and per-protocol key
  agreement keys follow CTAP 2.3.
- CTAP status codes for invalid parameters, wrongly typed parameters
  (CTAP2_ERR_CBOR_UNEXPECTED_TYPE), unsupported options, unimplemented
  clientPIN subcommands and bio enrollment.
- makeCredential and getAssertion follow the CTAP 2.3 steps for `uv`, `up`,
  excludeList, allowList, discoverable credentials once a PIN is set, and user
  names without user verification.
- Non-canonical CBOR in requests is rejected; a response too long for a
  CTAPHID message gets ERR_OTHER.
- CTAPHID: CANCEL while idle or on another channel is ignored, error packets no
  longer overwrite the request buffer, the number of allocated channels is
  bounded, and malformed uhid events are rejected instead of panicking.
- Credential management truncates long RP IDs and user names, continues
  enumerations without pinUvAuthParam, reports totalCredentials only in the
  enumerateCredentialsBegin response, and reports missing parameters before
  it checks pinUvAuthProtocol and pinUvAuthParam.
- The notification prompt gives up on a session bus that accepts the
  connection but never answers after 2 seconds, as it does on a D-Bus call,
  instead of holding the request and the daemon's shutdown forever.
- `status` and `detach` ignore a pid file naming pid 0, 1 or a negative pid,
  which `detach` would have signalled as a process group or as every process.
- The state directory is created with mode 0700 instead of being made
  private after it is created, and a shared directory with the sticky bit set,
  such as `/tmp`, is refused instead of having its permissions changed.
- The udev hidraw rule never matched the uhid-created device.
- Panics removed from fallible ML-DSA paths.

### Removed

- The Trussed dependency and its `[patch.crates-io]` git pin, the
  `transport-core` crate, the unused CCID feature, and the littlefs, p256
  0.9 and bindgen dependencies that came with Trussed. The last pieces,
  ctaphid-app and trussed-core, which only supplied the CTAPHID app trait and
  the interrupt flag, are replaced by local code, which takes postcard 0.7,
  heapless 0.7 and the unmaintained atomic-polyfill out of the dependency
  tree.
- `--manual-user-presence`, `--suppress-attestation` and the PIN arguments of
  the `pin` commands (see Breaking changes).
- The system-wide systemd service.
- Feitian names, AAGUID and USB IDs from the defaults.

### Security

- PINs are no longer accepted as command-line arguments, where other local
  users could read them and shells saved them to history. The terminal prompt
  turns echo off, and PINs are zeroized after use.
- A spent PIN retry is written to disk before the PIN is compared, in the
  engine and in the CLI, so interrupting a check gives no free guess. The
  3-mismatch lockout stays volatile, as CTAP intends.
- The old state format encrypted its littlefs images with a keystream that
  never changed its nonce, so the files exposed the credentials they held. The
  new store uses a fresh random nonce per write and authenticates every file,
  and the old files are deleted.
- User presence is no longer approved without asking by default.
- Self attestation by default avoids linking a user's credentials across sites
  through a shared attestation certificate.
- Supply-chain checks (cargo-audit, cargo-deny) run on every push and weekly,
  and tolerate no advisory.
- pinUvAuthTokens, the authenticatorGetNextAssertion state and the reset
  window after start-up run on CLOCK_BOOTTIME, so time the system spends
  suspended counts and a token no longer outlives a suspend.
