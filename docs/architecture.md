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

The transport loop in `crates/pqkey/src/transport/mod.rs` speaks CTAPHID
(§11.2). It puts requests together from
packets, sends keepalives while the engine waits for you, and answers other
programs "busy". It also passes cancellation on to the engine. The engine
runs on a worker thread, so the device keeps being served while a prompt is
open.

Two details carry ML-DSA's large messages across the kernel:

- The transport paces its reports 1 ms apart, because a hidraw reader buffers
  only 64 of them.
- getInfo reports a maxMsgSize of 1,768 bytes, the most that the kernel's
  queue delivers whole.

The kernel's uhid driver looks at its event queue without the queue's lock,
so a read that comes just as an event arrives can copy from a null pointer,
and the kernel then kills the reading thread. This shows on arm64. The Linux
backend therefore waits 100 µs between seeing an event waiting and reading
it, and looks again for each event, so reading a 30-packet request takes
about 6 ms. The queue holds 31 events: a whole request of that size, plus
the event for a client opening the device, fits before the first read. While
an answer is paced out, the transport reads during the 1 ms pauses. Two
clients sending large requests at the same moment can still fill the queue;
the kernel drops what does not fit, and the request fails or times out.

## Platform boundary

`crates/pqkey/src/platform/mod.rs` selects `linux` or `macos` with
`cfg(target_os)`. Portable modules import this facade. CTAPHID framing and
the loop, the service runner, presence policy, state locking and daemon
information, attestation, the allocator, PIN input, client protocols and
command logic stay outside it. Both builds share Unix locks, signals,
background-process coordination and terminal I/O.

Linux's backend owns uhid, hidraw, device permissions, udev, groups, kernel
checks and modules, snap tags, XDG paths, systemd, D-Bus, the boot clock,
process protections and `/proc/self/exe` identity. These implementations live
under `crates/pqkey/src/platform/linux/`; shipped units and rules stay in
`contrib/`.

The interfaces a backend implements are:

- `Device::new(HidDeviceDescriptor)`, reached through `create_device`, and
  `HidDevice::try_read_frame`, `write_frame` and `wait_with`. Reads return
  an optional complete output report without blocking; writes send an input
  report. `wait_with` takes the worker's wake descriptor and an optional
  timeout, and returns whether anything became ready. Shared report types,
  USB IDs and the FIDO report descriptor live in `transport`.
- `open_client(uniq, wait)`, returning a display label and `ClientLink`.
  `ReportLink::send` and `receive(timeout)` exchange complete reports; the
  client owns CTAPHID and CTAP. The label need not be a device-node path.
- `UserService::installed`, `main_pid`, `install(binary)`, `remove` and
  `action(ServiceAction)`. Actions are start, restart, stop, enable and
  reset-failed. Installation returns whether its file changed; removal
  returns the removed path, if any. Backend descriptions, help and log
  hints keep native names out of command logic.
- `System::real`, `check_setup_caller`, `setup_steps`, `apply_setup_steps`,
  `refresh`, `login_problem`, `start_problems`, `device_problems`,
  `notification_problem` and `uninstall_instructions`. Setup steps carry
  their description, confirmation, deferred instructions and artifact.
  Diagnostics return portable `Problem` values. Commands own confirmation,
  sequencing, PIN setup, readiness waits and output. Linux refreshes its
  membership snapshot after privileged setup.
- `notifications()`, returning `Notifications`, which implements
  `NotificationServer::connect`, `notify`, `next_event`, `close`, `nudge`
  and `disconnect`. It normalizes action/body support, markup, events and
  server identity. An optional refresh interval requests queue nudging;
  Linux supplies GNOME's existing two-second interval. Backend helpers
  format native failures. Prompt text, sanitization, deadlines,
  cancellation and stale-prompt policy stay portable. Linux records the
  same bus, owner and notification ID as before.
- `ensure_supported`, `default_state_dir`, `disable_core_dumps`,
  `current_executable_identity` and `BootTimeClock::new`. Identity is the
  executable's device and inode; `DaemonInfo` owns its format and validation.
  The clock implements the engine's `Clock` and counts through suspend.
  Linux still attempts both memory protections independently, warns on
  failure and continues.

Services, system preparation and runtime helpers are concrete implementations
selected by cfg. Traits are used where tests need substitutes: the device,
client report link, notification server and the engine's existing clock.
There is no trait for an entire platform.

A callback device can queue host output reports and signal a private pipe
that `wait_with` polls alongside the worker socket. It need not expose a
file descriptor or implement `AsFd`. Pending reports must prevent sleep,
and enqueueing must wake a concurrent wait even when earlier wake bytes
have been drained. Drop must stop callbacks and remove the virtual device
before the transport joins the cancelled worker. The loop keeps its 10 ms
idle bound, CTAPHID deadlines and 1 ms input-report pacing.

Tests inject devices, report links, clocks and executable identity. Linux's
socket peer retains uhid encoding and destruction assertions; macOS uses a
callback queue and readiness socket. Portable presence tests script a
notification server. Linux-specific CLI and kernel tests run on Linux.

macOS currently implements only the default state path,
`~/Library/Application Support/pqkey`, with `./pqkey` without `HOME`.
Explicit state-directory overrides still apply. All operational backend
entry points fail with `the key does not run on macOS yet`. The CLI checks
support after parsing and before side effects; help and version work.
A future macOS backend can use IOHIDUserDevice or, on macOS 15 and later,
CoreHID's HIDVirtualDevice, with Apple's required entitlement; IOHIDManager
for the client; a LaunchAgent for the service; and a native prompt provider.
Implementing these interfaces requires no changes to portable command or
protocol logic.

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
- authenticatorConfig (§6.11) with toggleAlwaysUv and setMinPINLength. With
  a PIN set, it needs a pinUvAuthToken with the `acfg` permission.
  - Always-UV makes every registration, and every sign-in with user presence,
    need a pinUvAuthParam; a getAssertion with `up` false still needs none.
  - The minimum PIN length only rises, from 4 up to 63 code points; only a
    reset lowers it. Raising it above the current PIN's length, or setting
    forceChangePin, makes the key refuse new tokens until the PIN changes.
  - Up to 8 RP IDs, each at most 253 bytes, may read the minimum through the
    `minPinLength` extension. An empty list leaves the stored one in place
    (§6.11.4).
  - There is no PIN complexity policy: `pinComplexityPolicy` true is refused
    with CTAP1_ERR_INVALID_PARAMETER, and false changes nothing.
- Up to 1,000 stored credentials. Credential management lists and counts
  discoverable credentials only. Non-discoverable credentials are sealed
  into their own ID when their key fits; RSA credentials are stored and
  consume a slot too.
- authenticatorLargeBlobs (§6.10), with a serialized-array capacity of
  16,384 bytes and fragments of up to 1,704 bytes, maxMsgSize minus 64.
  Reads return committed bytes. Writes use a separate in-memory buffer and
  commit only after the final fragment's trailing hash verifies; the key
  otherwise leaves the contents opaque. A PIN or always-UV requires a
  pinUvAuthToken with the `lbw` permission for each write fragment.
  Another command, a read, 30 idle seconds or the initializing token's
  expiry discards the staged write. Credential deletion leaves the array
  for platforms to collect. Reset restores the initial empty array.
- The `credBlob`, `credProtect`, `hmac-secret`, `hmac-secret-mc`,
  `largeBlobKey` and `minPinLength` extensions. `credBlob` stores up to 32
  bytes with a stored
  credential; sealed credentials refuse it. `hmac-secret-mc` evaluates the
  PRF when a credential is created. `minPinLength` reports the minimum PIN
  length at registration, only to the RP IDs on the stored list.
  `largeBlobKey` creates a random 32-byte key only when requested with
  `rk` true. Registration, requested assertions and credential enumeration
  return it outside authenticator data. Platforms use it to encrypt blobs;
  it is erased with the credential, while the array remains for collection.
- getInfo reports `largeBlobs` true and `maxSerializedLargeBlobArray` 16,384,
  and the options `authnrCfg`, `setMinPINLength`, `alwaysUv` and
  `makeCredUvNotRqd` (the opposite of `alwaysUv`), and no `uvAcfg`. It always
  reports `forcePINChange` and `minPINLength`.
- Packed self attestation: each credential signs its own registration.
- A reset only within 10 seconds of the key starting (§6.6), approved in a
  notification. It erases credentials, their large-blob keys, the large-blob
  array and the PIN, and resets configuration and signature counters.

## Credential store

```text
~/.local/share/pqkey/       0700
├── keys/device.key         root key for the attestation record
├── keys/credential.key     root key for everything else; a reset replaces it
├── credentials/<hash>      one file per stored credential, named by an HMAC of its ID
├── pin-state               the PIN hash, retries and configuration
├── large-blobs             the serialized large-blob array
└── signature-counter       the counter that sealed credentials share
```

Every file above except the root keys is encrypted and authenticated with
XChaCha20-Poly1305, under keys derived from a root key with HKDF-SHA-256.
Credential records can also hold an opaque blob of at most 32 bytes,
protected by the same encryption as their private keys, and an optional
32-byte large-blob key on discoverable credentials. The key is wiped on drop,
redacted from debug output and compared in constant time. Older records read
without a large-blob key. The PIN state also keeps the configuration: the
minimum PIN length and its RP IDs, whether a PIN
change is required, the PIN's length and always-UV. A PIN state written
before these fields existed reads with their defaults, and its PIN counts as
4 code points long.

Files are replaced atomically, never changed in place. If flushing the
directory fails after the new file is in place, the write reports an error
although the new file stays. Large-blob writes instead treat the atomic
rename as the commit: a later directory-flush failure is logged and the
command succeeds. Such a failure can lose an acknowledged write after a
power failure. All errors before the rename keep the previous array.
A missing or unreadable large-blob file is served as the initial array;
the next committed write replaces it. A reset deletes the array and the
stored credentials and replaces `credential.key`, so old copies of files
and every sealed credential ID can no longer be decrypted.
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
selection asks for your approval in a desktop notification with Approve and
Deny buttons, sent through
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
options when restarting and to detect an installed replacement binary, so
they never read the daemon's `/proc` entries. Both runtime files are removed
on exit; neither is trusted without the lock and a matching pid.

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
