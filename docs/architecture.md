# Architecture

This document describes how pqkey is put together. The code documentation is
more detailed and is the authority where the two differ; build it with
`cargo doc --workspace --no-deps --document-private-items --open`. Spec
references are to CTAP 2.3 unless stated otherwise.

## Contents

- [Crates](#crates)
- [The daemon](#the-daemon)
- [CTAPHID](#ctaphid)
- [The CTAP engine](#the-ctap-engine)
- [Credential store](#credential-store)
- [User presence](#user-presence)
- [Attestation](#attestation)
- [Command-line interface and state directory](#command-line-interface-and-state-directory)
- [Testing](#testing)

## Crates

```text
crates/pqkey        daemon and CLI (binary "pqkey")
   │  uhid device, CTAPHID framing, worker thread, D-Bus presence prompt,
   │  attestation certificate, state directory lock, PIN commands
   ▼
crates/pqkey-ctap   CTAP2 engine and credential store (no unsafe code)
   │  commands, PIN/UV auth protocols, COSE keys, ES256, FileStore/MemoryStore
   ▼
crates/pqkey-mldsa  ML-DSA-44/65/87 wrapper around RustCrypto's ml-dsa

fuzz/               libFuzzer targets (separate workspace, nightly)
tests/e2e/          end-to-end tests against a running daemon (Linux)
contrib/            udev rules and systemd user unit
```

- **`pqkey-mldsa`** exposes key generation, signing and verification for the
  three FIPS 204 parameter sets, working from the 32-byte seed. Signing is pure
  ML-DSA over the external interface, hedged (randomised) by default. Each
  parameter set is a Cargo feature; all are on by default.
- **`pqkey-ctap`** implements the `ctaphid_app::App` trait: it takes a
  CTAPHID_CBOR payload and returns a response. Everything outside the protocol
  is injected: a `CredentialStore`, a random number generator and a
  `UserPresence` implementation. It forbids `unsafe` code.
- **`pqkey`** is the Linux program: it creates the uhid device, runs CTAPHID,
  runs the engine on a worker thread, asks for user presence over D-Bus, and
  provides the `attach`/`detach`/`status`/`reset`/`pin` commands. The only
  `unsafe` code in the project is here, in the uhid device, and every block
  carries a safety comment.

## The daemon

`pqkey attach --foreground` takes an exclusive `flock` on
`<state dir>/authenticator.lock`, deletes state files from before the storage
rework (`master.seed`, `internal.lfs2`, `external.lfs2`, `volatile.lfs2`),
opens the credential store, creates the uhid device, writes
`authenticator.pid`, and then serves requests until it is told to stop.
`pqkey attach` without `--foreground` runs the same binary again with
`--foreground` in a new session, with its output appended to
`authenticator.log`, and waits up to 10 seconds for the pid file.

### Threads

```text
            main thread (transport)                      "ctap-app" worker thread
 ┌──────────────────────────────────────────┐      ┌──────────────────────────────┐
 │ loop:                                    │      │ for request in channel:      │
 │   check shutdown flag                    │      │   CtapApp::call(request)     │
 │   read uhid events → CtaphidHost         │ req  │     (may block in presence   │
 │   CANCEL? → InterruptFlag::interrupt()   │─────▶│      prompt, polling the     │
 │   take answers from worker               │◀─────│      interrupt flag)         │
 │   hand next complete request to worker   │ resp │   mark interrupt flag idle   │
 │   send keepalives, write queued packets  │      │   send answer, write a byte  │
 │   poll(uhid fd, wake socket, ≤10 ms)     │◀─wake│   to the wake socket         │
 └──────────────────────────────────────────┘      └──────────────────────────────┘
```

The engine runs on its own thread so that the device keeps being served while
a request waits for the user: the transport sends keepalives, answers
CTAPHID_INIT and PING, tells other channels the device is busy, and passes
CTAPHID_CANCEL on.

- **Requests** go to the worker over an `mpsc` channel. The transport marks
  the `InterruptFlag` as working before it sends a request, so a CANCEL that
  arrives before the worker picks it up is not lost. Only one request is with
  the worker at a time.
- **Answers** come back over a second channel. The worker also writes a byte to
  a `UnixStream` pair that the transport polls together with the uhid file
  descriptor, so the loop wakes up as soon as an answer is ready.
- **Keepalives.** The engine reports through a callback whether it is waiting
  for the user; the transport sends CTAPHID_KEEPALIVE with status
  UPNEEDED or PROCESSING accordingly.
- **Cancel.** CTAPHID_CANCEL on the channel of a CBOR request in progress sets
  the interrupt flag. The presence implementation polls it (every 20 ms),
  withdraws its prompt and returns, and the engine answers
  CTAP2_ERR_KEEPALIVE_CANCEL.
- **Shutdown.** SIGINT and SIGTERM set a flag and nothing else. The transport
  checks the flag on every pass and fails with a dedicated shutdown error. On
  the way out it interrupts the request in progress, destroys the uhid device,
  closes the request channel and joins the worker; the shutdown error then
  becomes a successful exit. A presence prompt must honour cancellation for
  this to finish, which the notification prompt does within about 20 ms plus
  one D-Bus call (each call is limited to 2 seconds). A panic in the engine
  ends the loop with an error.

## CTAPHID

`crates/pqkey/src/transport/ctaphid_host.rs` is a state machine without I/O,
threads or clocks: the transport feeds it packets and the current time, and
sends what it queues. `crates/pqkey/src/uhid.rs` reads and writes kernel
`uhid_event` structures and declares a FIDO HID report descriptor (usage page
`0xF1D0`) with 64-byte input and output reports.

- **Message size.** With 64-byte packets the largest message is
  64 − 7 + 128 × (64 − 5) = **7,609 bytes** (§11.2.4). The engine's response
  buffer has that size. A response that does not fit is answered with
  CTAPHID_ERROR ERR_OTHER.
- **Pacing.** A real USB full-speed HID endpoint delivers at most one report
  per millisecond. uhid has no such flow control: each input report goes
  straight into every hidraw reader's buffer, which holds only 64 reports
  (`HIDRAW_BUFFER_SIZE` in the kernel). Longer bursts lose packets, and an
  ML-DSA-87 assertion is 82 packets. The transport therefore waits **1 ms**
  between the input reports of a message, which costs at most about 130 ms for
  the largest message (129 packets).
- **Transactions.** One transaction is served at a time (§11.2.5.1). Requests
  on other channels get ERR_CHANNEL_BUSY; CTAPHID_INIT on the transaction's
  channel aborts it; continuation packets must arrive within 550 ms of the
  previous one; keepalives go out every 50 ms while a CBOR request is
  processed. A transaction aborted while the engine works on it is cancelled
  through the interrupt flag, and the engine's late answer is discarded.
- **Channels.** CTAPHID_INIT allocates random channel IDs; the 256 most
  recently used are kept.
- **Capabilities.** The INIT response reports CAPABILITY_CBOR and
  CAPABILITY_NMSG (no CTAPHID_MSG, so no U2F).

## The CTAP engine

`CtapApp` in `crates/pqkey-ctap/src/ctap.rs`, one module per command:

| Code | Command | Module |
|------|---------|--------|
| 0x01 | authenticatorMakeCredential | `make_credential.rs` |
| 0x02 | authenticatorGetAssertion | `get_assertion.rs` |
| 0x04 | authenticatorGetInfo | `get_info.rs` |
| 0x06 | authenticatorClientPIN | `pin/client_pin.rs` |
| 0x07 | authenticatorReset | `reset.rs` |
| 0x08 | authenticatorGetNextAssertion | `get_assertion.rs` |
| 0x0A | authenticatorCredentialManagement | `credential_management.rs` |
| 0x0B | authenticatorSelection | `selection.rs` |

authenticatorBioEnrollment (0x09 and 0x40) is answered with
CTAP1_ERR_INVALID_COMMAND. Request parameters must be canonical CBOR.

**Credentials.** Every credential, discoverable or not, is a record in the
store. The engine's credential IDs are 33 bytes: a marker byte (0x01 for
`rk` true, 0x00 for `rk` false) and 32 random bytes. Private keys are a P-256
scalar or an ML-DSA seed. The store holds at most 1,000 credentials. A new
discoverable credential for the same relying party and user ID replaces the
old one. Extensions: `credProtect` (levels 1 to 3) and `hmac-secret`
(`CredRandom` with and without user verification).

**Assertions.** Without an allowList the most recently created credential
comes first; further ones are fetched with authenticatorGetNextAssertion, whose
state is discarded after 30 seconds or on any other command. With `up` false
the assertion is silent (no presence request, UP flag clear); `hmac-secret`
then fails with CTAP2_ERR_UNSUPPORTED_OPTION.

**PIN state machine** (`pin/state.rs`). The persistent state is the PIN hash
`LEFT(SHA-256(PIN), 16)` and pinRetries (maximum 8). A PIN check is split in
two: `begin_attempt` refuses if the PIN is blocked or needs a power cycle and
otherwise decrements pinRetries; the caller persists that; only then does
`finish_attempt` compare, in constant time. So cutting power during a check
never gives a free guess. A match restores pinRetries to 8. Three consecutive
mismatches return CTAP2_ERR_PIN_AUTH_BLOCKED until the daemon restarts; that
count is volatile on purpose (§6.5.2.3). At pinRetries 0 only a reset helps.
The `pqkey pin` commands use the same state machine on the same store.

**PIN/UV auth protocols** (`pin/protocol.rs`). Protocols 2 and 1 are
supported, for PIN operations, pinUvAuthParam verification and hmac-secret.
Each protocol keeps its own key-agreement key, regenerated on a PIN mismatch
and at reset.

**pinUvAuthToken** (`pin/token.rs`). Getting a token resets the tokens of
both protocols and starts a usage timer. Token lifetime follows §6.5.2.1 with
the USB defaults: the token must first be used within 30 seconds, the user
present flag lasts 30 seconds, and the token expires after at most 600
seconds. Permissions (mc, ga, cm, ...) and an optional RP ID bind the token;
a user presence test clears every permission but `lbw`, which pqkey never
grants.

**Reset.** authenticatorReset asks for user presence and calls
`CredentialStore::clear`. Without a display CTAP only accepts it within 10
seconds of power-up (§6.6). The daemon applies that window with
`--presence auto-approve`, and lifts it with `--presence notify`, whose
notification states what a reset deletes.

**Attestation formats.** A request whose attestationFormatsPreference is only
"none" gets "none". A statement that would make the response longer than a
CTAPHID message gives way to the next: basic attestation to self attestation,
self attestation to "none".

## Credential store

`crates/pqkey-ctap/src/store/`. The format below is pinned by tests: the
envelope by a vector computed with an independent XChaCha20-Poly1305
implementation, the key hierarchy by an independent HKDF computation, and the
record encoding by an independent CBOR encoder.

`CredentialStore` has two implementations with the same behaviour, checked by
shared conformance tests: `MemoryStore` for engine tests and fuzzing, and
`FileStore`, which the daemon uses.

### On-disk layout

```text
<state dir>/                0700
├── keys/                   0700  root keys
│   ├── device.key          0600  32 random bytes
│   └── credential.key      0600  32 random bytes, replaced by reset
├── credentials/            0700
│   └── <64 hex digits>     0600  one envelope per credential, record type 1
├── pin-state               0600  envelope, record type 2
└── attestation             0600  envelope, record type 3
```

The daemon and CLI add `authenticator.lock`, `authenticator.pid` and, for a
background daemon, `authenticator.log`. Writes briefly create
`.tmp-<16 hex digits>` files. A credential's file name is the lowercase hex
HMAC-SHA-256 of its credential ID under the credential index key, so a
directory listing reveals neither credential IDs nor relying parties.

### Key hierarchy

```text
device.key ─────HKDF "ftsa-store/v1/device/record-encryption"─────▶ attestation record key
credential.key ─HKDF "ftsa-store/v1/credential/record-encryption"─▶ credential and PIN state key
               └HKDF "ftsa-store/v1/credential/index-hmac"────────▶ credential file name key
```

HKDF-SHA-256 (RFC 5869) with no salt, the root key as input keying material and
a 32-byte output. Root keys are never used directly. The device key survives a
reset; the credential key does not. A root key that is missing while data
encrypted under it exists, or that is malformed (not 32 bytes, or all zeros),
is never silently regenerated: operations that need it fail, and a reset is the
way out. Key files are created race-free (written to a flushed temporary file,
then hard-linked to their name), so concurrent first starts agree on one key.

The `ftsa` prefix is historical and part of the format.

### Envelope

```text
offset  length  field
     0       4  magic, ASCII "FTSA"
     4       1  format version, 1
     5       1  record type: 1 credential, 2 PIN state, 3 attestation
     6      24  XChaCha20-Poly1305 nonce, random for every write
    30       n  ciphertext of the n-byte record encoding
  30+n      16  Poly1305 tag
```

The associated data is `"FTSA" || version || record type || u16 big-endian
length of name || name`, where `name` is the path relative to the state
directory (`pin-state`, `attestation` or `credentials/<64 hex digits>`).
Copying one file over another therefore fails authentication. Envelopes are at
most 1 MiB. Records are canonical CBOR maps with unsigned integer keys; the
field list is in the `FileStore` documentation.

A record that fails authentication or decoding is reported as corrupt (or, when
listing, skipped with a warning) and never deleted automatically.

### Crash safety

Files are never modified in place. A write goes to a fresh temporary file with
its final mode, which is flushed, renamed over its target, and followed by a
flush of the directory, so a crash leaves the old file or the complete new one.
There is no index to fall out of step: the credential limit and creation order
are recomputed from the records.

### Reset and crypto-shredding

`clear` runs these steps, and a crash after any of them leaves a usable state
that another reset completes:

1. Delete every credential file and flush the directory. The PIN still guards
   whatever is left.
2. Delete `pin-state` and flush. A PIN is never removed while a credential it
   guards remains.
3. Rotate the credential key: write the new key to a flushed temporary file,
   rename it over `credential.key`, flush the directory, then overwrite the old
   key's contents with zeros through a handle opened beforehand. From here on
   any copy of the old files is undecryptable.
4. Write the default PIN state under the new key.

No step needs the old key, so a reset also recovers a store whose credential
key is lost. The attestation record, under the device key, is kept.

What this does and does not protect is in
[SECURITY.md](../SECURITY.md#the-encrypted-credential-store).

## User presence

The engine never decides on its own that a user is present. For registration,
assertion with `up`, reset, and selection (including the zero-length
pinUvAuthParam probe) it builds a `PresenceRequest` (operation, relying party
ID, user names, timeout) and asks its `UserPresence` implementation, which
answers Approved, Denied, TimedOut or Cancelled. The default timeout is 30
seconds.

The daemon's implementations (`crates/pqkey/src/presence/`):

- **`NotificationPresence`** (`--presence notify`). For each request it
  connects to the session bus anew, calls `GetCapabilities` and requires
  `actions`, subscribes to `ActionInvoked` and `NotificationClosed` from the
  server's unique bus name, and calls `Notify` with Approve and Deny actions
  and critical urgency. Approve approves; Deny or closing the notification
  denies; expiry or the request timeout times out; cancellation withdraws the
  notification with `CloseNotification`. Any failure to show the notification
  denies the request. Strings from the request are sanitised and shortened, and
  markup-escaped if the server interprets markup. A connection per request
  means the daemon can start before the desktop and survive logging out and in.
- **`AutoApprove`** (`--presence auto-approve`) approves at once.
- **`Unanswered`** (hidden `--presence unanswered`) never answers; the E2E
  tests use it to watch the transport while a prompt is open.

## Attestation

`--attestation self` (default) produces a `packed` statement signed with the
new credential's key. `--attestation none` produces none.
`--attestation certificate` makes the daemon provision an attestation record on
start if the store has none, or if the stored certificate's AAGUID extension
does not match `--aaguid`: a new P-256 key and a self-signed X.509 v3
certificate generated with `rcgen` and signed with `p256`, meeting WebAuthn
Level 3 §8.2.1 (subject C, O, OU "Authenticator Attestation", CN; the
`id-fido-gen-ce-aaguid` extension; basic constraints CA false; a random 20-byte
serial). The record is encrypted under the device key and survives resets. If
the stored record cannot be read, registrations fall back to self attestation.

## Command-line interface and state directory

`crates/pqkey/src/cli.rs`, `state.rs`, `state_lock.rs`, `pin_input.rs`.

- **Locking.** The daemon, `reset` and `pin set|change|remove` hold an
  exclusive `flock` on `authenticator.lock`. `status` and `detach` probe it
  with a shared lock and trust the pid file only while the lock is held, so a
  stale pid file never gets an unrelated process signalled.
- **`detach`** sends SIGTERM and waits up to 10 seconds for the lock to be
  released.
- **`pin status`** only reads, so it needs no lock.
- **PIN input** is read with terminal echo off (a new PIN twice), or one line
  per PIN from a non-terminal standard input. PINs are zeroized on drop and
  never accepted as arguments.
- **State directory** defaults to `$XDG_DATA_HOME/pqkey` or
  `~/.local/share/pqkey`, and is set to mode `0700`. If it does not exist yet
  but the pre-rename default `feitian-mldsa-authenticator` does, the CLI prints
  a note that the old directory is unused.

## Testing

| Layer | Where | What |
|-------|-------|------|
| Unit tests | `#[cfg(test)]` modules in every crate | CTAPHID state machine, uhid event encoding over a socket pair, the worker thread and shutdown, presence prompts against a fake notification server, CLI parsing, PIN commands, state lock |
| Engine tests | `crates/pqkey-ctap/src/ctap/tests/` | Every command and its CTAP 2.3 rules over `MemoryStore`, including PIN retries, token permissions, response sizes |
| Store tests | `crates/pqkey-ctap/tests/store/`, `src/store/` | Conformance tests run against both stores; `FileStore` persistence, tampering, keys, permissions, interrupted reset; known-answer tests for the envelope, HKDF key hierarchy and record encoding |
| Engine over files | `crates/pqkey-ctap/tests/ctap_file_store.rs` | CTAP requests over a real `FileStore`, rebuilding the engine between requests as a restart would |
| ML-DSA KATs | `crates/pqkey-mldsa/tests/fips204_kat.rs` | NIST ACVP key generation, signing and verification vectors for all three parameter sets |
| Attestation | `crates/pqkey/tests/packed_attestation.rs` | The provisioned certificate's AAGUID matches authenticatorData and the signature verifies |
| End to end | `tests/e2e/`, `.github/workflows/e2e.yml` | The release daemon on a GitHub Actions Ubuntu runner, driven through its hidraw node by libfido2's tools and python-fido2: getInfo, ES256 and ML-DSA credentials, PINs with both protocols, CTAPHID edge cases, certificate attestation, notification presence on a private session bus |
| Fuzzing | `fuzz/`, `.github/workflows/fuzz.yml` | libFuzzer targets `ctaphid_packets`, `ctap_request`, `ctap_request_structured`, `ctap_sequence`, `credential_key` |

How to run each of these is in [CONTRIBUTING.md](../CONTRIBUTING.md).
