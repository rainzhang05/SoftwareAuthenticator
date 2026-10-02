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
tests/browser/      local relying party for manual tests in real browsers
contrib/            udev rules, systemd user unit, trace tools (debug/)
```

- **`pqkey-mldsa`** exposes key generation, signing and verification for the
  three FIPS 204 parameter sets, working from the 32-byte seed. Signing is pure
  ML-DSA over the external interface, hedged (randomised) by default. Each
  parameter set is a Cargo feature; all are on by default. The FIPS 204
  internal interfaces that take a caller's randomness (`try_keypair_from_seed`,
  `try_sign_deterministic`) exist only with the `hazmat` feature, for the
  known-answer tests.
- **`pqkey-ctap`** answers CTAP requests: `CtapApp::call` takes a CTAP
  command byte and its CBOR parameters, the payload of a CTAPHID_CBOR message,
  and returns the response, and an `InterruptFlag` lets the transport cancel
  it. It knows nothing about CTAPHID framing or the device, only the largest
  message CTAPHID can carry. Everything outside the protocol is injected: a
  `CredentialStore`, a random number generator for the values the engine
  chooses (credential IDs, `CredRandom`, key agreement keys, tokens, IVs) and
  a `UserPresence` implementation. Credential private keys and the store's
  nonces come straight from the operating system's generator. The crate also
  holds the credential store, including `FileStore`, which does the file I/O.
  It forbids `unsafe` code, as does `pqkey-mldsa`.
- **`pqkey`** is the Linux program: it creates the uhid device, runs CTAPHID,
  runs the engine on a worker thread, asks for user presence over D-Bus, and
  provides the `start`/`stop`/`status`/`pin`/`passkeys`/`reset` commands,
  which manage the running key as a CTAP client. The only `unsafe` code in
  the project is here: the uhid device's kernel structures, `setsid` in
  `pre_exec` when `start` starts the daemon, and the signal handlers of the
  PIN prompt (plus a `setsockopt` in a test helper). Every block carries a
  safety comment.

## The daemon

`pqkey run` (hidden from the help; the systemd unit and test rigs use it)
takes an exclusive `flock` on `<state dir>/authenticator.lock`, opens the
credential store, creates the uhid device, writes `authenticator.pid`, and
then serves requests until it is told to stop. The device's HID unique
identifier is `pqkey-<pid>`, which is how the CLI finds its hidraw node.
`pqkey start` starts `pqkey.service` with `systemctl --user` when that unit
is installed and the default state directory and options are used; otherwise
it runs the same binary's `run` in a new session, with its output appended to
`authenticator.log`. Either way it waits up to 10 seconds for the pid file.

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
a request waits for the user: the transport sends keepalives, answers other
channels (INIT and PING included) with ERR_CHANNEL_BUSY, resynchronises the
request's own channel on CTAPHID_INIT, and passes CTAPHID_CANCEL on.

- **Requests** go to the worker over an `mpsc` channel. The transport marks
  the `InterruptFlag` as working before it sends a request, so a CANCEL that
  arrives before the worker picks it up is not lost. Only one request is with
  the worker at a time.
- **Answers** come back over a second channel. The worker also writes a byte to
  a `UnixStream` pair that the transport polls together with the uhid file
  descriptor, so the loop wakes up as soon as an answer is ready.
- **Keepalives.** The engine reports through a callback whether it is waiting
  for the user; the transport sends CTAPHID_KEEPALIVE with status
  UPNEEDED or PROCESSING accordingly, at once when the status changes and
  every 50 ms otherwise.
- **Cancel.** CTAPHID_CANCEL on the channel of a CBOR request in progress sets
  the interrupt flag. The presence implementation polls it (every 20 ms),
  withdraws its prompt and returns, and the engine answers
  CTAP2_ERR_KEEPALIVE_CANCEL. A CANCEL that arrives before the worker has
  taken the request is answered by the transport itself.
- **Shutdown.** SIGINT and SIGTERM set a flag; a second one while shutdown is
  under way terminates the process at once, in case the orderly path is stuck.
  The transport checks the flag on every pass and fails with a dedicated
  shutdown error. On the way out it interrupts the request in progress and
  closes the request channel, destroys the uhid device, and joins the worker;
  the shutdown error then becomes a successful exit. A presence prompt must
  honour cancellation for this to finish. The notification prompt checks for it
  before showing its notification and every 20 ms while it is shown; connecting
  to the session bus and each D-Bus call are limited to 2 seconds, so a hung
  bus or notification server delays shutdown by seconds, not forever. A panic
  in the engine ends the loop with an error.

## CTAPHID

`crates/pqkey/src/transport/ctaphid_host.rs` is a state machine without I/O,
threads or clocks: the transport feeds it packets and the current time, and
sends what it queues. `crates/pqkey/src/uhid.rs` reads and writes kernel
`uhid_event` structures and declares a FIDO HID report descriptor (usage page
`0xF1D0`) with 64-byte input and output reports.

- **Message size.** With 64-byte packets the largest message is
  64 − 7 + 128 × (64 − 5) = **7,609 bytes** (§11.2.4). The engine keeps its
  responses within that size; an answer that did not fit would go out as
  CTAPHID_ERROR ERR_OTHER.
- **Pacing.** A real USB full-speed HID endpoint delivers at most one report
  per millisecond. uhid has no such flow control: each input report goes
  straight into every hidraw reader's buffer, which holds only 64 reports
  (`HIDRAW_BUFFER_SIZE` in the kernel). Longer bursts lose packets, and an
  ML-DSA-87 assertion is 82 packets. The transport therefore waits **1 ms**
  between any two input reports it writes in a row, which costs at most about
  130 ms for the largest message (129 packets), and reads what the host has
  written in each pause.
- **Requests.** In the other direction the kernel queues the host's output
  reports in a ring of 32 uhid events and drops what does not fit, and
  platforms write a request's packets back to back. getInfo's maxMsgSize is
  therefore 1,768 bytes, the most 30 packets carry, so a request a platform
  sizes by it always arrives whole. Larger requests are still accepted.
- **Transactions.** One transaction is served at a time (§11.2.5.1). Requests
  on other channels get ERR_CHANNEL_BUSY; CTAPHID_INIT on the transaction's
  channel aborts it; continuation packets must arrive within 550 ms of the
  previous one; keepalives go out every 50 ms while a CBOR request is
  processed. A transaction aborted while the engine works on it is cancelled
  through the interrupt flag, and the engine's late answer is discarded.
- **Channels.** CTAPHID_INIT allocates random channel IDs; the 256 most
  recently used are kept. Requests are served on any channel but 0 and the
  broadcast channel, allocated or not, so a long-lived client whose channel
  was forgotten keeps working; only CTAPHID_INIT on such a channel is
  refused.
- **Commands and capabilities.** PING, INIT, CBOR and CANCEL are handled;
  MSG, WINK, LOCK and anything else get ERR_INVALID_CMD. The INIT response
  reports device version 2.1.0, CAPABILITY_CBOR and CAPABILITY_NMSG (no
  CTAPHID_MSG, so no U2F).

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
authenticatorGetInfo reports:

- versions `FIDO_2_3`, `FIDO_2_1` and `FIDO_2_0`;
- extensions `credProtect` and `hmac-secret`;
- options `rk`, `up`, `credMgmt`, `pinUvAuthToken` and `makeCredUvNotRqd`
  true, and `clientPin` true or false as a PIN is or is not set. There is no
  `uv` option: user verification is by PIN only;
- maxMsgSize 1768, PIN/UV auth protocols 2 and 1, maxCredentialCountInList 8,
  maxCredentialIdLength 128, transports `usb`, minPINLength 4;
- algorithms ES256 (-7), ML-DSA-44 (-48), ML-DSA-65 (-49) and ML-DSA-87 (-50);
- remainingDiscoverableCredentials, the free slots of the store;
- attestationFormats `packed`, left out with `--attestation none`.

The algorithm of a new credential is the first one in the relying party's
`pubKeyCredParams` that pqkey supports (CTAP 2.3 §6.1.2 step 3).
draft-vitap-ml-dsa-webauthn-00, an Internet-Draft, also asks authenticators to
prefer ML-DSA when it is offered, to keep their keys under AES-256-GCM in
secure hardware, and to fall back to RS256; pqkey does none of these. The
relying party's order is CTAP's rule, a software key has no secure hardware
(its store uses XChaCha20-Poly1305, see below), and RS256 is not supported.
Zeroization, which the draft also asks for, is as SECURITY.md describes.

**Credentials.** A discoverable credential (`rk` true) is a record in the
store with a 33-byte ID, the marker 0x01 and 32 random bytes. The store holds
at most 1,000 of them, and a new one for the same relying party and user ID
replaces the old one. A non-discoverable credential is not stored: its
107-byte ID is the marker 0x02 followed by its algorithm, credProtect level,
private key and a random 32-byte seed, sealed with XChaCha20-Poly1305 under a
key derived from the credential root key and bound to the SHA-256 hash of the
relying party ID. It works only for that relying party and only until a reset
replaces the key, counts its signatures on the authenticator's global
signature counter, which every sealed credential shares as on hardware keys,
and derives its hmac-secret `CredRandom` values from the seed with HKDF,
never from its key.
Signature counters only grow, which is all relying parties may assume
(WebAuthn Level 3 §6.1.1): a discoverable credential's counter also counts
assertions without user presence, which Firefox and python-fido2 send before
a sign-in to find the credential, so one sign-in can add 2. The counters
saturate at 2³²−1 rather than wrap. Private keys are a P-256 scalar or an
ML-DSA seed. Extensions: `credProtect` (levels 1 to 3) and `hmac-secret`
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
count is volatile on purpose (§6.5.5.6 step 5.7.1.2.2, §6.5.5.7.2 step
4.9.1.2.2, which ask for a power cycle). At pinRetries 0 only a reset helps.
`pqkey pin` goes through the running key's ClientPIN commands, so this state
machine checks its PINs too.

**PIN/UV auth protocols** (`pin/protocol.rs`). Protocols 2 and 1 are
supported, for PIN operations, pinUvAuthParam verification and hmac-secret.
Each protocol keeps its own key-agreement key, regenerated on a PIN mismatch
and at reset.

**pinUvAuthToken** (`pin/token.rs`). Getting a token resets the tokens of
both protocols and starts a usage timer. Token lifetime follows §6.5.2.1 with
the USB defaults: the token must first be used within 30 seconds, the user
present flag lasts 30 seconds, and the token expires after at most 600
seconds. The daemon runs these timers, like the engine's other timers, on
CLOCK_BOOTTIME, which keeps counting while the system is suspended, so a token
does not outlive a suspend. Permissions (mc, ga, cm, ...) and an optional RP ID
bind the token; a user presence test clears every permission but `lbw`, which
pqkey never grants.

**Reset.** authenticatorReset asks for user presence and calls
`CredentialStore::clear`. pqkey has no display, whatever its presence prompt
shows, so CTAP only accepts a reset within 10 seconds of power-up (§6.6), the
start of the daemon. The hidden `--allow-late-reset` lifts that window for
test rigs.

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
├── signature-counter       0600  envelope, record type 4, the global counter
└── attestation             0600  envelope, record type 3
```

The daemon and CLI add `authenticator.lock`, `authenticator.pid`, for a
background daemon `authenticator.log`, and while a presence prompt is on
screen `authenticator.prompt` (the bus ID, the notification server's unique
name and the notification ID), all mode 0600. Writes briefly create
`.tmp-<16 hex digits>` files, and the pid file `authenticator.pid.<pid>.tmp`. A
credential's file name is the lowercase hex HMAC-SHA-256 of its credential ID
under the credential index key, so a directory listing reveals neither
credential IDs nor relying parties.

### Key hierarchy

```text
device.key ─────HKDF "ftsa-store/v1/device/record-encryption"─────▶ attestation record key
credential.key ─HKDF "ftsa-store/v1/credential/record-encryption"─▶ credential and PIN state key
               ├HKDF "ftsa-store/v1/credential/index-hmac"────────▶ credential file name key
               └HKDF "ftsa-store/v1/credential/id-encryption"─────▶ sealed credential ID key
```

HKDF-SHA-256 (RFC 5869) with no salt, the root key as input keying material and
a 32-byte output. The crate implements this one form itself (`hkdf_sha256`)
rather than using the `hkdf` crate, so that the extracted pseudorandom key is
wiped after use. Root keys are never used directly. The device key survives a
reset; the credential key does not. A root key that is missing while data
encrypted under it exists, or that is malformed (not 32 bytes, or all zeros),
is never silently regenerated: operations that need it fail, and a reset is the
way out. Key files are created race-free (written to a flushed temporary file,
then hard-linked to their name), so concurrent first starts agree on one key.

The `ftsa` prefix is part of the format.

### Envelope

```text
offset  length  field
     0       4  magic, ASCII "FTSA"
     4       1  format version, 1
     5       1  record type: 1 credential, 2 PIN state, 3 attestation,
                4 global signature counter
     6      24  XChaCha20-Poly1305 nonce, random for every write
    30       n  ciphertext of the n-byte record encoding
  30+n      16  Poly1305 tag
```

The associated data is `"FTSA" || version || record type || u16 big-endian
length of name || name`, where `name` is the path relative to the state
directory (`pin-state`, `signature-counter`, `attestation` or
`credentials/<64 hex digits>`).
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

1. Delete every credential file and the global signature counter, and flush
   the directories. The PIN still guards whatever is left.
2. Rotate the credential key: write the new key to a flushed temporary file,
   rename it over `credential.key`, flush the directory, then overwrite the old
   key's contents with zeros through a handle opened beforehand. From here on
   any copy of the old files, and every sealed credential ID, is
   undecryptable.
3. Write the default PIN state under the new key, atomically.

The PIN state is replaced only after the rotation, because sealed credentials
die with the key, not with any file: a PIN is never removed while a credential
it guards remains. A crash between steps 2 and 3 leaves a `pin-state` that
reads as corrupt, which the engine treats as a PIN set and blocked until the
next reset. No step needs the old key, so a reset also recovers a store whose
credential key is lost. The attestation record, under the device key, is kept.

Sealing a credential ID writes the default PIN state if there is none, so that
a lost credential key is reported even when only sealed credentials, which
relying parties hold, depend on it.

What this does and does not protect is in
[SECURITY.md](../SECURITY.md#the-encrypted-credential-store).

## User presence

The engine never decides on its own that a user is present. For registration,
assertion with `up`, reset, and selection (including the zero-length
pinUvAuthParam probe) it builds a `PresenceRequest` (operation, relying party
ID, user names, whether a registration stores a passkey, timeout) and asks its
`UserPresence` implementation, which
answers Approved, Denied, TimedOut or Cancelled. The default timeout is 30
seconds.

The implementations the daemon chooses from with `--presence`:

- **`NotificationPresence`** (`--presence notify`, in
  `crates/pqkey/src/presence/`). For each request it connects to the session
  bus anew, calls `GetCapabilities` and requires `actions` and `body`, subscribes to
  `ActionInvoked` and `NotificationClosed` from the server's unique bus name,
  and calls `Notify` with Approve and Deny actions and critical urgency. A
  registration asks to "Create a passkey" when the key stores the credential,
  and to "Register a security key" when the relying party keeps it.
  Approve approves; Deny or closing the notification denies; expiry or the
  request timeout times out; cancellation withdraws the notification. Whatever
  the answer, a notification the server has not closed itself is withdrawn with
  `CloseNotification`. Any failure to show the notification denies the request.
  Strings from the request are sanitised and shortened, and markup-escaped if
  the server interprets markup. A connection per request means the daemon can
  start before the desktop and survive logging out and in. On GNOME Shell
  (`GetServerInformation`), whose banner queue can leave a critical
  notification queued and unseen, an unanswered prompt is nudged every 2
  seconds: an empty, transient notification of normal urgency is posted and
  withdrawn at once, which shows a stuck prompt and changes nothing otherwise.
  A prompt a killed daemon left on screen is withdrawn when the daemon starts
  again (or at its first request if no bus was reachable then), but only from
  the server instance that showed it: `authenticator.prompt` records it.
- **`AutoApprove`** (`--presence auto-approve`, in `pqkey-ctap`) approves at
  once.
- **`Unanswered`** (hidden `--presence unanswered`, in
  `crates/pqkey/src/presence/`) never answers; the E2E tests use it to watch
  the transport while a prompt is open.

The hidden `--presence-timeout` (1 to 600 seconds) replaces the 30-second
default; the E2E tests shorten it. CTAP 2.3 §5 says the user action timeout
MUST be at least 10 seconds, so the daemon logs a warning below that.

## Attestation

`--attestation self` (default) produces a `packed` statement signed with the
new credential's key. `--attestation none` produces none.
`--attestation certificate`, which requires `--manufacturer` (the subject's O)
and `--country` (an ISO 3166-1 alpha-2 code, the subject's C) and takes
`--product` (the CN, by default the HID product name), makes the daemon
provision an attestation record on start if the store has none, or if the stored certificate's AAGUID extension
does not match `--aaguid`: a new P-256 key and a self-signed X.509 v3
certificate generated with `rcgen` and signed with `p256`, meeting WebAuthn
Level 3 §8.2.1 (subject C, O, OU "Authenticator Attestation", CN; the
`id-fido-gen-ce-aaguid` extension; basic constraints CA false; a random 20-byte
serial). The record is encrypted under the device key and survives resets. If
the stored record cannot be read, registrations fall back to self attestation.
The attestation key is P-256 for every credential, ML-DSA ones included, as a
hardware key signs all its attestations with one key: a `packed` statement
names the attestation key's algorithm (ES256) independently of the
credential's. Certificate attestation is meant for testing relying parties
(see SECURITY.md on linkability).

## Command-line interface and state directory

`crates/pqkey/src/cli/`, `client/`, `state.rs`, `state_lock.rs`,
`pin_input.rs`.

- **A CTAP client.** `pin`, `passkeys` and `reset` manage the running key the
  way a security key's management application does (`client/`): CTAPHID over
  its hidraw node, one transaction at a time, then CTAP2 with PIN/UV auth
  protocol 2. `pin` is setPIN or changePIN; `passkeys` gets a
  pinUvAuthToken with the `cm` permission and enumerates or deletes
  credentials (§6.8); `reset` is authenticatorReset. Only the daemon opens the
  store, and the key's own checks (PIN rules, retry counters, user presence,
  the reset window) apply to the CLI as to a browser. Without a running key
  these commands say so and name `pqkey start`.
- **`reset`** asks for confirmation unless `--yes` is given, then restarts the
  key with the options it runs with (read from `/proc/<pid>/cmdline`, or
  `systemctl --user restart`), because a key without a display accepts
  authenticatorReset only within 10 seconds of power-up (§6.6). It starts a
  stopped key for the reset and stops it again afterwards. While the key waits
  for approval, Ctrl-C sends CTAPHID_CANCEL.
- **Wrong PINs.** Before asking for a PIN the CLI reads getPinRetries, so a
  blocked PIN or one that needs a re-plug is reported without a prompt. A PIN
  that could never have been set (fewer than 4 code points, more than 63
  bytes) is refused without sending it, so it costs no retry.
- **Output.** Site and user names come from relying parties, so `passkeys`
  removes control and invisible characters before printing them.
- **Locking.** The daemon holds an exclusive `flock` on `authenticator.lock`
  for as long as it runs. `status` and `stop` probe it with a shared lock and
  trust the pid file only while the lock is held, and whoever takes the lock
  first removes a pid file a killed daemon left behind. So its pid is not
  signalled once reused, unless a `stop` reads it in the moment between the
  two. A pid file naming pid 0, 1 or a negative pid is ignored.
- **`stop`** stops the unit with `systemctl --user` if it runs the key, and
  otherwise sends SIGTERM; it waits up to 10 seconds for the lock to be
  released.
- **`setup`**, which `install.sh` runs, installs the systemd user unit (the
  shipped file, embedded in the binary, with `ExecStart` naming the canonical
  path of the running binary), enables and starts it (or restarts it on a new
  binary), and asks for a PIN if the key has none. What needs root (the
  embedded udev rules into `/etc/udev/rules.d`, `uhid` in
  `/etc/modules-load.d/pqkey.conf`, `modprobe uhid` while its misc device is
  missing, joining `plugdev` with an ACL on `/dev/uhid` until the next login)
  goes into a script in `$XDG_RUNTIME_DIR`, created with mode 0600. Setup lists
  what it sets up and runs it with `sudo sh` once the user agrees, or at once
  with `--yes`; otherwise it prints that command. pqkey itself never runs as
  root. `--uninstall` stops and removes the unit and prints the command that
  undoes the root part, which also removes `/usr/local/bin/pqkey`.
- **`status`** also reports every problem it finds with its fix: missing or
  outdated udev rules, `uhid` not loaded (now or at boot), no access to
  `/dev/uhid` (not in `plugdev`, or in it since after this session started),
  a device node this user cannot open, a snap browser installed but the node
  not tagged for it (from udev's database in `/run/udev/data`), a
  notification server without `actions` or `body`, no systemd unit, and a
  key started by hand where the unit should run it. The checks read files
  under a root directory, so tests run them on a temporary one.
- **Exit status.** 0 on success, also when standard output is closed early
  (`pqkey passkeys | head -1`); 3 when `run` or `start` finds the key already
  running, which the systemd unit does not restart on; 1 for any other error,
  reported as `pqkey: <message>`.
- **PIN input** is read with terminal echo off (a new PIN twice), or one line
  per PIN from a non-terminal standard input, and normalized to NFC (§6.5.1)
  before its length is checked. PINs are zeroized on drop and never accepted
  as arguments.
- **State directory** defaults to `$XDG_DATA_HOME/pqkey` or
  `~/.local/share/pqkey`, and is created with mode `0700` or tightened to it. A
  shared directory with the sticky bit set, such as `/tmp`, is refused rather
  than made private. The hidden `--state-dir` option (or `PQKEY_STATE_DIR`)
  chooses another, for test rigs.
- **Device identity and test options.** `run` and `start` take hidden options
  for test rigs: `--presence`, `--presence-timeout`, `--allow-late-reset`,
  `--name`, `--vendor-id` and `--product-id` (default `1209:0001`),
  `--version`, `--aaguid` (default `5931e805-a166-4eb7-845a-7f6aa93d9cd8`)
  and the attestation options. `start` passes them on to `run`.

## Testing

| Layer | Where | What |
|-------|-------|------|
| Unit tests | `#[cfg(test)]` modules in every crate | CTAPHID state machine, uhid event encoding over a socket pair, the worker thread and shutdown, ES256 and ML-DSA-87 registration and authentication through the whole daemon stack over that socket pair, presence prompts against a fake notification server, CLI parsing, PIN commands, state lock |
| Engine tests | `crates/pqkey-ctap/src/ctap/tests/` | Every command and its CTAP 2.3 rules over `MemoryStore`, including PIN retries, token permissions, response sizes |
| Store tests | `crates/pqkey-ctap/tests/store/`, `src/store/` | Conformance tests run against both stores; `FileStore` persistence, tampering, keys, permissions, interrupted reset; known-answer tests for the envelope, sealed credential IDs, HKDF key hierarchy and record encoding |
| Engine over files | `crates/pqkey-ctap/tests/ctap_file_store.rs` | CTAP requests over a real `FileStore`, rebuilding the engine between requests as a restart would |
| ML-DSA KATs | `crates/pqkey-mldsa/tests/fips204_kat.rs` | NIST ACVP key generation, signing and verification vectors for all three parameter sets |
| Attestation | `crates/pqkey/tests/packed_attestation.rs` | The provisioned certificate's AAGUID matches authenticatorData and the signature verifies |
| End to end | `tests/e2e/`, `.github/workflows/e2e.yml` | The release daemon on GitHub Actions Ubuntu runners (x86_64 and arm64), driven through its hidraw node by libfido2's tools and python-fido2: getInfo, ES256 and ML-DSA credentials, PINs, hmac-secret and credential management with both PIN/UV auth protocols, CTAPHID edge cases, certificate attestation, notification presence on a private session bus, the transport while a prompt stays unanswered, an independent check of the test suite's ML-DSA verifier, and the CLI's `start`, `status`, `stop`, `pin`, `passkeys` and `reset` commands over the key's hidraw node |
| Fuzzing | `fuzz/`, `.github/workflows/fuzz.yml` | libFuzzer targets `ctaphid_packets`, `ctap_request`, `ctap_request_structured`, `ctap_sequence`, `credential_key` |

How to run each of these is in [development-notes.md](development-notes.md).
