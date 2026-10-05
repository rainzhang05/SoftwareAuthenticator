# Architecture

This page gives a short overview of how pqkey works. The code documentation
has the details (`cargo doc --workspace --no-deps --document-private-items
--open`). Section numbers refer to CTAP 2.3.

## Crates

```text
crates/pqkey        the daemon and the pqkey command
crates/pqkey-ctap   the CTAP engine and the credential store (no unsafe code)
crates/pqkey-mldsa  ML-DSA-44/65/87 over RustCrypto's ml-dsa (no unsafe code)
fuzz/               libFuzzer targets
tests/e2e/          end-to-end tests against a running key
tests/browser/      a local relying party for tests in real browsers
contrib/            the udev rules, the systemd user unit and trace tools
scripts/            checks, tests and diagnostics
```

## How a request travels

```text
browser ── /dev/hidrawN ── kernel uhid ── /dev/uhid ── pqkey daemon
                                                        ├─ transport thread: CTAPHID
                                                        └─ worker thread: CTAP engine
                                                             ├─ credential store
                                                             └─ desktop notification
```

The daemon, which the systemd user service starts, creates a virtual USB HID
device through `/dev/uhid`. Browsers open its hidraw node as they would any
security key.

The binary's allocator wipes every heap block before returning it to the
system allocator. Reallocation allocates a replacement, copies the retained
prefix, and wipes the old block, including any discarded tail.

Before opening the store or creating the device, the daemon disables core
files with a zero core size limit. On Linux it makes itself non-dumpable too,
blocking core dumps, ptrace attachment and `/proc` memory reads by other
unprivileged processes. Failures are warned about and startup continues.
The user service also sets `LimitCORE=0`. Memory in use, swap and root remain
outside these protections; the daemon does not lock its memory.

The transport thread speaks CTAPHID (§11.2). It puts requests together from
packets, sends keepalives while the engine waits for you, and answers other
programs "busy". It also passes cancellation on to the engine. The engine
runs on a worker thread, so the device keeps being served while a prompt is
open.

Two details carry ML-DSA's large messages across the kernel:

- The transport paces its reports 1 ms apart, because a hidraw reader buffers
  only 64 of them.
- getInfo reports a maxMsgSize of 1,768 bytes, the most that the kernel's
  queue delivers whole.

## What the key supports

- CTAP 2.3, 2.1 and 2.0 over USB HID.
- ES256 (-7), ML-DSA-44 (-48), ML-DSA-65 (-49), ML-DSA-87 (-50), ESP256 (-9),
  ES384 (-35), ESP384 (-51), ES512 (-36), ESP512 (-52), ES256K (-47), EdDSA
  (-8), Ed25519 (-19), Ed448 (-53), RS256 (-257), RS384 (-258), RS512 (-259),
  PS256 (-37), PS384 (-38) and PS512 (-39), the RSA ones with 2048-bit keys
  and e = 65537. The first algorithm in the relying party's list that the key
  supports wins (§6.1.2).
- A PIN, with PIN/UV auth protocols 1 and 2 and pinUvAuthTokens. After 8
  wrong PINs the PIN is blocked, and after 3 in a row the key must be
  restarted. There is no built-in user verification.
- Up to 1,000 stored credentials. Credential management lists and counts
  discoverable credentials only. Non-discoverable credentials are sealed
  into their own ID when their key fits; RSA credentials are stored and
  consume a slot too.
- The `credProtect` and `hmac-secret` extensions.
- Packed self attestation: each credential signs its own registration.
- A reset only within 10 seconds of the key starting (§6.6), approved in a
  notification.

## Credential store

```text
~/.local/share/pqkey/       0700
├── keys/device.key         root key for the attestation record
├── keys/credential.key     root key for everything else; a reset replaces it
├── credentials/<hash>      one file per stored credential, named by an HMAC of its ID
├── pin-state               the PIN hash and retries
└── signature-counter       the counter that sealed credentials share
```

Every file above except the root keys is encrypted and authenticated with
XChaCha20-Poly1305, under keys derived from a root key with HKDF-SHA-256.
Files are replaced atomically, never changed in place. A reset deletes the
stored credentials and replaces `credential.key`, so old copies of files and
every sealed credential ID can no longer be decrypted.
[SECURITY.md](../SECURITY.md) describes what this protects against.

Discoverable credential IDs are `0x01` and 32 random bytes. Sealed IDs are
107 bytes starting with `0x02`, carrying the algorithm, credProtect, 32-byte
key and a seed for the hmac-secret CredRandom values. Their assertions use
the global signature counter. RSA non-discoverable credentials instead use
`0x00` and 32 random bytes, like older stored non-discoverable credentials.
RSA records contain no user ID or names, and keep random CredRandom values,
credProtect and a counter of their own. They work only through an allowList,
are excluded by an excludeList, consume a slot, and are erased by reset.

## User presence

Each registration, sign-in that needs your presence, reset and authenticator
selection asks for your approval in a desktop notification with Approve and Deny buttons, sent through
`org.freedesktop.Notifications` on the session bus.

- Anything that stops the notification from showing denies the request.
- No answer within 30 seconds times the request out.
- A cancelled request withdraws the notification.

A registration asks to "Create a passkey" for a discoverable credential, and
to "Register a security key" for a non-discoverable credential.

## The `pqkey` command

- `pin`, `passkeys` and `reset` talk to the running key over CTAP through its
  hidraw node, as a security key's management app does. The key's own PIN
  checks and approvals therefore apply to them too.
- `reset` restarts the key first, because of the 10-second window.
- `setup`, which `install.sh` runs, does three things:
  - It installs the udev rules and loads uhid at boot, with sudo after it
    lists what it changes.
  - It installs and starts the systemd user service.
  - It asks for a PIN.
- `status` checks everything the key needs and names the fix for anything
  missing.

The daemon itself is `pqkey run`. It also takes hidden options that only
test rigs use, such as approving every request without asking; they are
documented in `crates/pqkey/src/cli/mod.rs`.

While holding the state lock, it publishes non-secret run options and the
running executable's device and inode in `authenticator.info`, then its
ready pid in `authenticator.pid`. Commands use that information to preserve
options when restarting and to detect an installed replacement binary.
They read another process's `/proc` entries only for older daemons that do
not publish usable information. Both runtime files are removed on exit;
neither is trusted without the lock and a matching pid.

## Tests

| Layer | Where |
|---|---|
| Unit tests | in every crate, including the whole daemon over a socket pair |
| Engine tests | `crates/pqkey-ctap/src/ctap/tests/`, every command and its CTAP rules |
| Store tests | `crates/pqkey-ctap/tests/store/`, persistence, tampering and known-answer vectors |
| ML-DSA known answers | `crates/pqkey-mldsa/tests/`, NIST ACVP vectors |
| End to end | `tests/e2e/`, the release daemon driven by libfido2 and python-fido2 |
| Fuzzing | `fuzz/`, CTAPHID packets, CTAP requests and request sequences |

The heap residue test in `crates/pqkey/tests/heap_residue.rs` scans retained
freed blocks after key operations and store roundtrips. Live controls show
that the scanner can find every secret pattern.

The scripts in `scripts/` run all of them; see the
[development notes](development-notes.md).
