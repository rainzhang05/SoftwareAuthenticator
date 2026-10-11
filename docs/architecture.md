# Architecture

This page gives a short overview of how pqkey works. The code documentation
has the details (`cargo doc --workspace --no-deps --document-private-items
--open`). Section numbers refer to CTAP 2.3.

## Crates

```text
crates/pqkey        the Linux daemon and the pqkey command
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
files with a zero core size limit and makes itself non-dumpable, blocking
core dumps, ptrace attachment and `/proc` memory reads by other
unprivileged processes. Failures are warned about and startup continues.
The user service also sets `LimitCORE=0`. Memory in use, swap and root remain
outside these protections; the daemon does not lock its memory.

The transport loop in `crates/pqkey/src/transport/mod.rs` speaks CTAPHID
(§11.2). It puts requests together from
packets, sends keepalives while the engine waits for you, and answers other
programs "busy". It also passes cancellation on to the engine. The engine
runs on a worker thread, so the device keeps being served while a prompt is
open.

A transaction keeps its CID through reception, processing and transmission.
The state machine retains queued reports until `HidDevice::write_frame`
succeeds, and releases the CID only after the final response report succeeds.
Selecting a report or queuing an answer does not release it. Busy errors for
other clients remain in FIFO order and cannot interrupt response fragments or
complete another transaction. During the pacing pauses, the transport keeps
reading competing requests and rejects them as busy.

Valid INIT on the owned CID aborts and resynchronizes it: received data,
unsent response fragments and keepalives are discarded, including a report
already selected by the transport. Output tokens are checked after incoming
packets are processed and before writing. The INIT reply completes the new
transaction when written; any answer from the cancelled worker is suppressed.
Reports successfully written before INIT was processed cannot be recalled.
Read, write and worker errors end the session without acknowledging failed
writes. Shutdown is checked before writes; teardown cancels the worker,
destroys the device and joins the worker.

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

`pqkey` requires Linux; other targets fail at compile time. The protocol
engine in `pqkey-ctap` and the cryptography in `pqkey-mldsa` remain portable
and can be built and tested independently of the daemon.

`crates/pqkey/src/platform/mod.rs` exposes the Linux backend through a
facade. CTAPHID framing and the loop, the service runner, presence policy,
state locking and daemon information, attestation, the allocator, PIN input,
client protocols and command logic stay outside it. The daemon uses Unix
locks, signals, background-process coordination and terminal I/O.

Linux's backend owns uhid, hidraw, device permissions, udev, groups, kernel
checks and modules, snap tags, XDG paths, systemd, D-Bus, the boot clock,
process protections and `/proc/self/exe` identity. These implementations live
under `crates/pqkey/src/platform/linux/`; shipped units and rules stay in
`contrib/`.

The Linux backend exposes these interfaces:

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
  `action(ServiceAction)`, plus `prepare_session` to synchronize the notification
  bus. Actions are start, restart, stop, enable and
  reset-failed. Installation returns whether its file changed; removal
  returns the removed path, if any. Backend descriptions, help and log
  hints keep native names out of command logic.
- `System::real`, `check_setup_caller`, `setup_steps`, `apply_setup_steps`,
  `refresh`, `login_problem`, `start_problems`, `device_problems`,
  `notification_problem` and `uninstall_instructions`. Setup steps carry
  their description, confirmation and script; the script is written only after
  approval, and retained with rerun instructions if a root step fails.
  Diagnostics return `Problem` values. Commands own confirmation, sequencing,
  PIN setup, readiness waits and output. Linux refreshes its
  membership snapshot after privileged setup.
- `notifications()`, returning `Notifications`, which implements
  `NotificationServer::connect`, `notify`, `next_event`, `close`, `nudge`
  and `disconnect`. It normalizes action/body support, markup, events and
  server identity. An optional refresh interval requests queue nudging;
  Linux supplies GNOME's existing two-second interval. Backend helpers
  format native failures. Prompt text, sanitization, deadlines,
  cancellation and stale-prompt policy stay in presence policy. Linux
  records the bus, owner and notification ID.
- `default_state_dir`, `disable_core_dumps`,
  `current_executable_identity` and `BootTimeClock::new`. Identity is the
  executable's device and inode; `DaemonInfo` owns its format and validation.
  The clock implements the engine's `Clock` and counts through suspend.
  Linux attempts both memory protections independently, warns on
  failure and continues.

Services, system preparation and runtime helpers are concrete Linux
implementations. Traits are used where tests need substitutes: the device,
client report link, notification server and the engine's existing clock.
There is no trait for an entire platform.

Tests inject devices, report links, clocks and executable identity. The
Linux socket peer checks uhid encoding and destruction. A queued test
device checks that the transport handles pending reports, worker wakeups,
timeouts and shutdown through its device interface. Presence tests script
a notification server. CLI and kernel tests run on Linux; the real HID E2E
suite requires `/dev/uhid`.

## What the key supports

- CTAP 2.3, 2.1, 2.0 and CTAP1/U2F over USB HID. CTAPHID_INIT advertises
  CBOR, with NMSG and WINK clear; WINK and LOCK remain unimplemented.
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
    The management client discovers `maxMsgSize` before dependent commands
    and refreshes its cached limit with getInfo. Absent limits default to
    1,024 bytes; malformed limits fail discovery. Every complete encoded
    request, including its command byte and authentication, must fit the
    smaller of that limit and CTAPHID's 7,609-byte capacity (§§6.4, 8,
    11.2.4). The HID sender independently checks capacity before its first
    report. Oversized RP lists are rejected locally as one operation;
    shorten the list to fit pqkey's advertised 1,768 bytes.
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
  bytes with a stored credential; sealed credentials refuse it.
  `hmac-secret-mc` evaluates the PRF when a credential is created.
  `minPinLength` reports the minimum PIN length at registration, only to the
  RP IDs on the stored list. `largeBlobKey` creates a random 32-byte key only
  when requested with `rk` true. Registration, requested assertions and
  credential enumeration return it outside the authenticator data.
  Platforms use it to encrypt blobs; it is erased with the credential, while
  the array keeps its blobs for platforms to collect.
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
minimum PIN length and its RP IDs, whether a PIN change is required, the
PIN's length and always-UV. A PIN state written before these fields existed
reads with their defaults, and its PIN counts as 4 code points long.

Discoverable registration replaces all stored discoverable credentials with
exactly the same RP ID and user handle through one store transaction. The
new registration retains its fresh ID, key, extension secrets and creation
order. Replacement succeeds at logical capacity without deleting an old
credential first. Physical space for staging remains necessary; a new account
still respects the configured limit, including stored non-discoverable keys.

Existing stores remain readable. The first atomic registration writes an
encrypted `credential-format` marker and stages the candidate and encrypted
membership manifest inside the legacy directory, where legacy lookup ignores
them. After flushing preparation, an atomic rename from `credentials/` to
`credential-set/` commits the new set. Later transactions commit by atomically
replacing `credential-set/active`. The manifest records sorted, unique opaque
filename HMACs and their locations. Retained legacy ciphertext keeps its
original authenticated logical name; new records live in
`credential-set/records/`. Credential encodings and existing key domains stay
unchanged. The manifest and marker use envelope types 6 and 7 under the
credential record key, authenticated with their logical paths. Membership
metadata has the existing 1 MiB envelope bound.

Only manifest members can be read, listed, counted, asserted or managed.
Staging and retired ciphertext consume no logical slots. Pre-publication
errors preserve the preceding usable credentials. Atomic registration returns
an explicit committed result after publication: `Flushed` or `Unconfirmed`,
with a separate pending-cleanup flag. MemoryStore reports `Volatile`.
`Unconfirmed` means a process restart sees publication, while power loss may
roll it back. Old ciphertext is retained until publication and its namespace
have both been flushed successfully. Cleanup failure never changes membership,
including after restart, further replacement or deletion of the new credential.
A later membership transaction retries cleanup. Managed inserts and deletes
also return success after publication and log subsequent problems.

Missing, corrupt or inconsistent authoritative metadata fails closed; it is
never rebuilt by scanning leftover records. Individual corrupt records retain
the existing lookup-error/list-skip behavior, but replacement must read every
active record successfully to avoid leaving an unknown matching record usable.
Explicit reset uses the following order in both store layouts:

1. Determine the layout without authenticating damaged metadata, then rotate
   the credential key. The new key file is flushed before atomic publication,
   its directory is flushed, and only then is the old key overwritten as a
   best effort and stale key temporary files removed.
2. After rotation succeeds, purge credential records and managed membership,
   remove the shared signature counter and large-blob array, and flush their
   directories. Missing counter/blob records supply zero/the initial array.
3. For a managed store, write the authenticated format marker and publish a
   valid empty manifest under the new key.
4. Publish default PIN/configuration state last. The store returns an explicit
   durability outcome only after the preceding work completes and defaults
   are published. The running engine then resets PIN/UV policy, retries,
   tokens and protocol keys before returning success, even if publication
   durability is unconfirmed. Unconfirmed empty-manifest publication is also
   included in the reset outcome.

A rotation error does not establish which key is active. Before publication,
credentials, counters, membership and PIN/UV policy remain intact; surviving
sealed credentials continue the same saturating shared CTAP2/U2F counter, even
across restart and repeated failures. An error after publication leaves those
records untouched too: they fail authentication under the new key, while an
unflushed rename rolled back by power loss can still use the old key with its
original counter and policy. Key wiping is deferred until successful flushing.
No reset cleanup or counter removal runs on a rotation error.

After durable rotation, old stored and sealed credentials are invalid even if
purging, counter removal, empty-manifest publication or PIN-state writing fails.
Missing/corrupt managed authority fails closed. Until the default PIN write,
old PIN state fails authentication; a restarted engine treats it as set and
blocked and requires always-UV. A failed command keeps the running engine's
preceding PIN/UV state. Final default-state publication completes the command;
errors at subsequent checkpoints become unconfirmed durability warnings and
success, with live and restarted engines observing the same defaults.
An explicit reset retry rotates again and recovers partial or damaged stores
without needing the old key or readable metadata. The device/attestation key
and attestation record survive every step. Checkpoint tests cover errors and
process exits at each persistence boundary; they model rename rollback but do
not simulate physical power loss or override filesystem durability guarantees.

Upgrade is forward-only: back up the complete store and
do not use an older binary on upgraded state.

PIN/configuration writes distinguish publication from durability through
`Result<CommitDurability, StoreError>`. An error means the candidate PIN record
was not published. `Flushed` confirms the file and publication directory were
flushed; `Volatile` describes an intentional memory store. `Unconfirmed` means
rename published the record but a post-rename checkpoint or strict directory
flush did not complete successfully. A process restart sees this published
record, but power loss can restore its predecessor. Flushes are not protection
against filesystem snapshots or hardware that fails to honor them.

setPIN, changePIN and authenticatorConfig treat publication as commitment:
they return CTAP2_OK, adopt the settings and perform required token
invalidations even when durability is unconfirmed. getInfo and subsequent
commands immediately use the published PIN, alwaysUv, minimum length,
authorized RP IDs and forcePINChange. An unconfirmed warning describes the
power-loss limitation, rather than claiming the settings failed to change.
Pre-publication errors keep the preceding PIN and policy; changePIN may still
have legitimately consumed or restored retries while checking the old PIN.

PIN verification has a stronger persistence requirement. The engine debits a
retry before decrypting or comparing pinHashEnc. Only `Flushed` or intentional
`Volatile` writes allow comparison. Failed and unconfirmed debits return
CTAP2_ERR_PROCESSING without a PIN verdict or token and may conservatively
reduce the live budget. Successful comparison stages restoration of retries
until publication. Failed restoration retains the spent budget and preceding
mismatch history; unconfirmed restoration adopts the published retry state but
still returns CTAP2_ERR_PROCESSING without authorizing a token or PIN change.
An observed mismatch remains spent and counts toward the three-mismatch
power-cycle block even if a following write fails. Restart clears this volatile
block, while the published retry budget persists; zero retries requires reset.
Unreadable PIN state remains set, blocked and alwaysUv, and its placeholder is
never written over the stored record.

Other record writes retain their atomic file replacement behavior. Most report
a directory-flush error even though the renamed file remains visible;
large-blob writes return success after rename and log that error. Successful
flushes rely on filesystem and hardware guarantees. Unsupported directory
flushes abort credential transaction preparation or produce `Unconfirmed`
after publication. Authentication provides no trusted anti-rollback counter;
whole-store snapshot restoration or removal of all format evidence cannot be
distinguished reliably from older state. A missing or unreadable large-blob
array is served as the initial array; its next committed write replaces it.
[SECURITY.md](../SECURITY.md) describes the encryption-at-rest threat model.

Discoverable credential IDs are `0x01` and 32 random bytes. Sealed IDs are
107 bytes starting with `0x02`, carrying the algorithm, credProtect, 32-byte
key and a seed for the hmac-secret CredRandom values. Their assertions use
the global signature counter. Sealing and lookup accept the RP ID hash
directly; CTAP2 hashes its RP ID before using them. Counter updates share
one persistence path, which saves the count before signing.
RSA non-discoverable credentials instead use
`0x00` and 32 random bytes, like older stored non-discoverable credentials.
RSA records contain no user ID or names, and keep random CredRandom values,
credProtect and a counter of their own. They work only through an allowList,
are excluded by an excludeList, consume a slot, and are erased by reset.

## User presence

The portable engine also answers U2F REGISTER, AUTHENTICATE and VERSION
APDUs. U2F uses ES256 and the same sealed IDs, RP hashes and counters as
CTAP2; it cannot create a discoverable credential or verify a user. Its
registration always carries a certificate. Certificate mode uses the first
provisioned certificate; self and none modes use a minimal X.509 v3
certificate signed by the new credential itself. Its generic subject,
fixed validity and fresh serial contain no installation identity. rcgen
encodes it without a crypto backend, borrowing the credential key and
signing through the engine's scrubbed ES256 path.

Short APDUs and zero Lc followed by Le are accepted for compatibility. Le
does not truncate HID responses. Signatures use DER's 8–72-byte range,
which CTAP 2.3 §10.3 corrects in the older U2F raw formats.

CTAPHID_MSG reaches that engine on the same worker as CTAPHID_CBOR. If a
presence operation has not answered within 100 ms, the transport returns
SW_CONDITIONS_NOT_SATISFIED while keeping the worker request alive. Exact
repeats on its channel receive that status until the result is ready, then
receive it once within ten seconds of approval. No eventual answer is
sent without a repeat. Other requests are busy while the prompt is open.
Each polling or cached response owns its CID until its last report is
successfully written. Afterward, retained polling, approval or denial state
continues to govern requests. An approval arriving while the short pending
response is transmitting is retained for an exact repeat.
Presence transitions are recorded even between transport polls; a finished
prompt keeps its collection window while the worker prepares its answer.
INIT cancels it; CANCEL applies only to CBOR. More than three seconds
without a repeat cancels the prompt, and denial or timeout suppresses new
prompts for the same request until its repeats stop for that interval.
Suppression is bounded without evicting live denials. A policy change,
reset or another engine operation discards any cached approved result.
Reset also clears denial suppression, so invalidated handles are checked
against the new credential key and rejected before asking for presence.
Always-UV disables U2F registration and authentication and removes U2F_V2
from getInfo. A PIN alone does not affect U2F.

Each registration, sign-in that needs your presence, reset and authenticator
selection asks for your approval in a desktop notification with Approve and
Deny buttons, sent through `org.freedesktop.Notifications` on the session bus.

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
  - It verifies client communication and presence, completes required PIN setup,
    and returns success only when every readiness check passes.
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
