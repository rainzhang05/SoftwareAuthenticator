# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
pqkey is a test project that makes no releases, so it does not follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

This section covers the overhaul since commit `867a591` ("Fix stale CTAPHID
test offsets and drop dead descriptor rewriter"), when the project was the
Trussed-based "FIDO Software Authenticator" with the `pc-hid-runner` binary.

### Breaking changes

Upgrading from `867a591` or earlier is not an in-place update:

- **Stored state is not migrated.** Credentials and the PIN from the old
  format are lost; there is nothing to convert them with. The daemon deletes
  the old files (`master.seed`, `internal.lfs2`, `external.lfs2`,
  `volatile.lfs2`) from the state directory it uses when it starts, and so
  does `pqkey reset`.
- **The state directory moved** from `$XDG_DATA_HOME/feitian-mldsa-authenticator`
  (`~/.local/share/feitian-mldsa-authenticator`) to `$XDG_DATA_HOME/pqkey`
  (`~/.local/share/pqkey`). Nothing touches the old directory: the CLI
  notes that it is unused as long as the new default directory does not exist
  yet, and deleting it is up to you.
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
- **Licence:** MIT only (was Apache-2.0 OR MIT).

Changes since `d61871f`, the commit tested end to end on 2026-09-30, that
also break an existing installation of that commit:

- **Sealed credential IDs changed format.** A non-discoverable credential's
  ID now also seals a random seed for its `hmac-secret` values, which no
  longer derive from its private key, and is 107 bytes instead of 75.
  Non-discoverable credentials registered with an earlier commit stop working
  and must be registered again; their `hmac-secret` outputs are gone with
  them.
- **authenticatorReset only within 10 seconds of start-up, also with
  `--presence notify`.** The notification is not a display of the
  authenticator, so CTAP 2.3 §6.6 applies as it does to a hardware key
  without one: reset right after starting the key, as a hardware key is reset
  right after plugging it in.

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
- Non-discoverable credentials for `rk` false. They are not stored: each
  credential ID holds its credential and a random seed for its `hmac-secret`
  values, sealed with XChaCha20-Poly1305 under a key that a reset replaces and
  bound to the relying party, so they take no room in the store. They count
  their signatures on one global signature counter, stored as a record of its
  own, as hardware security keys do.
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
- `pqkey_mldsa::try_keypair_from_seed` and `try_sign_deterministic`, FIPS 204's
  internal interfaces with caller-chosen randomness, need the new `hazmat`
  feature (FIPS 204 §6: "Other than for testing purposes, [...] should not be
  made available to applications").
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
- Response maps are sorted as CTAP2 canonical CBOR requires, by major type
  first.
- Platform key agreement keys that are not EC2 keys on P-256 are refused, and
  stored ES256 keys that are not exactly 32 bytes are rejected.
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
- updateUserInformation refuses a `name` or `displayName` that is not a text
  string with CTAP2_ERR_CBOR_UNEXPECTED_TYPE. It used to erase the stored
  value.
- A PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity or
  PublicKeyCredentialDescriptor that lacks a required member, or has a member
  of the wrong type (including `rp.name`), gets
  CTAP2_ERR_CBOR_UNEXPECTED_TYPE, as CTAP 2.3 §8 asks, in makeCredential,
  getAssertion and credential management, whether or not the pinUvAuthToken
  is bound to an RP. These were CTAP2_ERR_MISSING_PARAMETER or
  CTAP2_ERR_INVALID_CBOR, and credential management never checked a
  descriptor's `type`. Only a pubKeyCredParams element keeps
  CTAP2_ERR_INVALID_CBOR (§6.1.2 step 3.1.1).
- makeCredential and getAssertion refuse a clientDataHash that is not 32 bytes
  with CTAP1_ERR_INVALID_LENGTH (WebAuthn Level 3 §6.3.2 and §6.3.3 step 1).
  Any length used to be signed. Their required parameters are now checked
  before anything else, so a malformed request, including the zero-length
  pinUvAuthParam probe, no longer shows a prompt.
- getCredsMetadata and enumerateRPsBegin verify their pinUvAuthParam over the
  subcommand byte alone, as CTAP 2.3 §6.8.2 and §6.8.3 define, even when the
  request carries subCommandParams. Such a request used to need a MAC over
  the parameters too.
- Requests whose unknown map keys hold simple values that CBOR leaves
  unassigned (such as `0xF0` or `0xF8 0x20`) are answered instead of failing
  with CTAP2_ERR_INVALID_CBOR: CTAP 2.3 §8 says unknown keys "MUST be
  ignored". Under a known key such a value is a wrong type.
- Credential management cuts a long non-ASCII RP ID at a character boundary,
  within 32 bytes. It used to return up to 34 bytes with U+FFFD in place of
  the split character.
- The relying party's `rp.name` reaches the registration prompt, cut to 64
  bytes, as WebAuthn Level 3 §6.3.2 step 6 recommends
  (`PresenceRequest::rp_name`).
- On GNOME Shell the presence prompt no longer stays invisible behind the
  shell's banner queue for its whole lifetime (seen with Chromium starting a
  request from an unfocused window): an unanswered prompt is nudged every 2
  seconds with an empty, transient notification that is withdrawn at once.
- `--vendor-id` and `--product-id` refuse values above 0xFFFF, which used to
  reach clients truncated, and a `--presence-timeout` under the 10 seconds
  CTAP 2.3 §5 requires is logged as non-conforming.
- Feature reports, which the report descriptor does not declare, are refused
  (the kernel reports EIO, as a USB key stalls) instead of being read as
  CTAPHID packets (SET_REPORT) or answered with 64 zero bytes (GET_REPORT).
- The warning about a world-accessible hidraw node can fire: the node's mode
  is checked once a client first opens the key, after udev has set it. Before,
  it was checked before the node existed or before udev had run.
- A daemon killed while it showed a prompt no longer leaves the prompt on
  screen for good: the next daemon withdraws it, if the same notification
  server still runs (`authenticator.prompt` in the state directory).
- A notification server without the `body` capability gets no prompt and the
  request is denied, as without `actions`: the prompt's question is in the
  body. The prompt sanitiser removes every Unicode 16.0 default-ignorable and
  format character, not a fixed list that let tag characters and others
  through.
- The reset prompt says that every passkey and every other sign-in made with
  the key stops working and that its PIN is removed; it used to say only
  "This deletes all passkeys." The registration prompt also shows the relying
  party's name, quoted after its ID.
- A random number generator failure while generating a credential key fails
  that registration with CTAP1_ERR_OTHER instead of panicking the daemon
  (`PrivateKeyMaterial::try_generate`, `CryptoError::Randomness`).
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
  turns echo off, and PINs are zeroized after use, as are pinUvAuthTokens, PIN
  hashes, PIN/UV auth session keys and hmac-secret outputs.
- HKDF is implemented locally over `hmac` instead of taken from the `hkdf`
  crate, so the pseudorandom key it extracts from a root key or shared secret
  is wiped after use.
- ML-DSA and ES256 intermediates no longer stay in the stack: after every key
  expansion, signature and key agreement the stack that computation used is
  overwritten (64 KiB for P-256, 512 KiB or 1 MiB for ML-DSA), and the SHAKE
  sponges ML-DSA hashes with are wiped on drop. Before, ML-DSA's ρ′, which
  rebuilds the private key, and the ECDSA nonce, which reveals it, were left
  behind (FIPS 204 §3.6.3). Regression tests scan the stack for them.
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
- Supply-chain checks (cargo-audit, cargo-deny) run on every push and pull
  request to `main` and weekly, and tolerate no advisory.
- pinUvAuthTokens, the authenticatorGetNextAssertion state and the reset
  window after start-up run on CLOCK_BOOTTIME, so time the system spends
  suspended counts and a token no longer outlives a suspend.
