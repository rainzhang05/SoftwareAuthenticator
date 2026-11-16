# Architecture

How pqkey works, in brief; the code documentation has the details
(`cargo doc --workspace --no-deps --document-private-items --open`). Section
numbers refer to CTAP 2.3.

## Crates

```text
crates/pqkey        the Linux daemon and the pqkey command
crates/pqkey-ctap   the CTAP engine and the credential store (no unsafe code)
crates/pqkey-mldsa  ML-DSA-44/65/87 over RustCrypto's ml-dsa (no unsafe code)
fuzz/               libFuzzer targets
tests/              end-to-end tests, and the browser and desktop acceptance runs
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
device through `/dev/uhid`, and browsers open its hidraw node as they would
any security key. The engine runs on a worker thread, so the device keeps
being served while a prompt is open.

The device exists only while the daemon's user, or no one, is active on its
seat ([SECURITY.md](../SECURITY.md#other-users-sessions)). Before each report,
the transport checks that logind's record of the seat is still the file the
device was created under (`crates/pqkey/src/seat.rs`): logind writes each
state as a new file, so any change, or a record that cannot be read, ends the
device. Its replacement serves the same engine, so it is not a new power-up.
The daemon's memory protections are in
[SECURITY.md](../SECURITY.md#what-it-does-not-protect-against).

### CTAPHID

The transport (`crates/pqkey/src/transport/`, §11.2) assembles requests from
packets, sends keepalives while the engine waits for you, answers other
channels "busy" and passes cancellation on to the engine.

- A transaction owns its CID until its final response report is written:
  reports stay queued until a write succeeds, and busy replies to other
  channels never interrupt a response.
- A valid INIT on the owned CID aborts and resynchronizes it, dropping unsent
  data and the cancelled worker's answer; reports already written cannot be
  recalled.
- A read, write or worker error ends the session; teardown cancels the worker,
  destroys the device and joins the worker.
- CTAPHID_LOCK (`0x04`) leases the channel for up to ten seconds, separately
  from transaction ownership, until it expires or its owner releases it with
  zero; INIT on the same CID and authenticatorReset keep the lease. Clients
  should release their leases in cleanup handlers.
- CTAPHID_WINK (`0x08`) shows a two-second notification naming `pqkey-<pid>`,
  with no site data or actions, over its own D-Bus connection in every
  presence mode, within a 500 ms deadline; failing that, it returns ERR_OTHER
  without ending the session.
- WINK and LOCK never reach the engine: they collect no presence, consume no
  token and keep the engine's continuations, and an identification
  notification never approves a request.

The transport paces reports 1 ms apart, because a hidraw reader buffers only
64, and getInfo reports a maxMsgSize of 1,768 bytes, the most the kernel's
queue delivers whole: together they carry ML-DSA's large messages.

The kernel's uhid driver reads its event queue without the queue's lock, so a
read just as an event arrives can copy from a null pointer and kill the
reading thread (seen on arm64). The backend therefore waits 100 µs between
seeing an event and reading it, about 6 ms for a 30-packet request. The
queue's 31 events hold one such request, so two clients sending large requests
at once can still overflow it, and the request fails or times out.

## Platform boundary

`pqkey` requires Linux, and other targets fail at compile time; `pqkey-ctap`
and `pqkey-mldsa` stay portable. Linux code lives behind the facade
`crates/pqkey/src/platform/mod.rs`, in `crates/pqkey/src/platform/linux/`:
uhid and hidraw, device permissions, udev, groups, kernel modules, snap tags,
XDG paths, systemd, D-Bus, the boot clock, process protections and the
executable's identity. Keep such code there. CTAPHID, presence policy, state
locking, attestation, the allocator, PIN input, client protocols and command
logic stay outside it, and shipped units and rules stay in `contrib/`. Traits
exist only where tests need substitutes: the HID device, the client link to a
key's hidraw node, the notification server, the seat source and the engine's
clock.

## What the key supports

- CTAP 2.3, 2.1, 2.0 and CTAP1/U2F over USB HID; CTAPHID_INIT advertises CBOR
  and WINK.
- ES256 (-7), ML-DSA-44 (-48), ML-DSA-65 (-49), ML-DSA-87 (-50), ESP256 (-9),
  ES384 (-35), ESP384 (-51), ES512 (-36), ESP512 (-52), ES256K (-47), EdDSA
  (-8), Ed25519 (-19), Ed448 (-53), RS256 (-257), RS384 (-258), RS512 (-259),
  PS256 (-37), PS384 (-38), PS512 (-39), ESB256 (-265) and ESB384 (-267), the
  RSA ones with 2048-bit keys and e = 65537. The first algorithm in the relying
  party's list that the key supports wins (§6.1.2).
- A PIN, with PIN/UV auth protocols 1 and 2, pinUvAuthTokens and the retry
  limits in [SECURITY.md](../SECURITY.md#what-it-protects-against); no
  built-in user verification. Classic key agreement requires the platform
  key's integer `kty` 2, `crv` 1 and `alg` -25 (or -7, for the OpenSSH case
  that [OpenSK documents](https://github.com/google/OpenSK/issues/90)), and a
  P-256 point on the curve; anything else fails with INVALID_PARAMETER before
  any PIN check.
- authenticatorConfig (§6.11) with toggleAlwaysUv and setMinPINLength, which
  need a token with the `acfg` permission once a PIN is set.
  - Always-UV makes every registration, and every sign-in with user presence,
    need a pinUvAuthParam; a getAssertion with `up` false still needs none.
  - The minimum PIN length only rises. Above the current PIN's length, or
    with forceChangePin set, the key refuses new tokens until the PIN changes.
    The listed RP IDs, each at most 253 bytes, may read it through
    `minPinLength`; an empty list keeps the stored one (§6.11.4).
  - [PIN complexity](pin-complexity-policy.md) starts disabled.
  - The native client refuses any request larger than the key's maxMsgSize
    (1,024 bytes if it reports none) or CTAPHID's 7,609 bytes, so an RP list
    too long for pqkey's 1,768 bytes must be shortened.
- Up to 1,000 stored credentials ([which are stored](#credential-ids)).
- authenticatorLargeBlobs (§6.10): an array of up to 16,384 bytes, written in
  fragments of up to 1,704. A write is staged in memory and committed only once
  the final fragment's hash verifies; another command, a read, 30 idle seconds
  or the expiry of its token drops it. With a PIN, or always-UV, each fragment
  needs a token with the `lbw` permission. Deleting a credential leaves the
  array for platforms to collect.
- The extensions `credBlob` (up to 32 bytes, stored credentials only),
  `credProtect`, `hmac-secret`, `hmac-secret-mc` (the PRF at registration),
  `largeBlobKey` (a random 32-byte key for discoverable credentials, erased
  with them), `minPinLength` (only to the listed RP IDs),
  `pinComplexityPolicy` and `thirdPartyPayment`.
- getInfo reports `largeBlobs`, `maxSerializedLargeBlobArray` 16,384, the
  options `authnrCfg`, `setMinPINLength`, `alwaysUv` and `makeCredUvNotRqd`
  (the opposite of `alwaysUv`), always `forcePINChange` and `minPINLength`, and
  `transportsForReset` `usb`. It omits `uvAcfg`, `encIdentifier`,
  `encCredStoreState` and `firmwareVersion`, which must increase with every
  released code change, while pqkey's version does not change per commit.
- Packed self attestation: each credential signs its own registration.
- [Reset](#reset) (§6.6).

### Credential management

Standard `0x0A` (§6.8) and the backwards-compatible preview `0x41` (§6.13)
share one implementation and see discoverable credentials only; getInfo adds
`credentialMgmtPreview` and `FIDO_2_1_PRE` to `credMgmt`. The preview has the
six prototype subcommands plus standard user updates (subcommand 7), which
libfido2 1.14 sends, and accepts the unscoped token of a legacy getPinToken,
until a registration or sign-in consumes it after user presence, or it
expires or is rotated, or the key is reset or restarted. MAC failures never
spend persistent PIN retries. Enumeration cursors remember their command
family, token and authorization: continuations carry no MAC but recheck them,
and switching families, changing authority or changing the credentials clears
them, while WINK and LOCK do not. The native client uses `0x0A`.

### Persistent read-only management

`perCredMgmtRO` advertises the `pcmr` permission (0x40). Each PIN protocol
keeps its own 32-byte secret and grant in the encrypted PIN state (record keys
11 and 12), and only standard credential-management reads verify them, before
any transient token. A read-only grant allows nothing else and combines with
no other permission; it survives restarts, each use rechecks it, and
reissuing returns the same secret until a PIN change, a reset or a forced PIN
change, which invalidate both protocols. A grant is disclosed only once its
publication is confirmed durable. The native client requests read-only tokens
per protocol, lists with `pcmr` when the key offers it (`cm` otherwise), and
stores no token.

## Credential store

```text
~/.local/share/pqkey/       0700
├── keys/device.key         root key for the attestation record
├── keys/credential.key     root key for everything else; a reset replaces it
├── credentials/<hash>      one file per stored credential, named by an HMAC of its ID
├── pin-state               the PIN hash, retries and configuration
├── large-blobs             the serialized large-blob array
├── signature-counter       the counter that sealed credentials share
└── damaged/<UTC time>/     what `pqkey repair` moved out of the store
```

Every file above but the root keys is encrypted and authenticated with
XChaCha20-Poly1305, under keys derived from a root key with HKDF-SHA-256; a
record without a newer field reads it as its default. A credential record can
hold a `credBlob` and, if discoverable, a 32-byte large-blob key, wiped on
drop and compared in constant time. The PIN state also keeps the PIN policy,
the PIN's length (an old PIN counts as 4 code points) and the persistent
grants.

A discoverable registration replaces every stored discoverable credential with
the same RP ID and user handle in one transaction; makeCredential refuses an
empty user handle for one (CTAP1_ERR_INVALID_LENGTH), so different accounts
never replace each other. Replacement works at full capacity, but staging
needs disk space.

### Membership

The first atomic registration moves a store to the managed layout: it writes
an encrypted `credential-format` marker, stages the candidate and an encrypted
membership manifest inside `credentials/`, flushes them, and renames the
directory to `credential-set/`. Later transactions atomically replace the
manifest, `credential-set/active`, which lists each member's file name HMAC
and location: older records keep theirs, and new ones go to
`credential-set/records/`. The upgrade is forward-only: back up the store
first, and do not use an older binary on upgraded state.

Only manifest members can be used, and only they take slots. An error before
publication keeps the preceding credentials; after it, the transaction has
happened, `Flushed` or `Unconfirmed`, and old record files stay until the
publication is flushed. Cleanup then removes record files the manifest does
not name, or names at their other location when that copy exists, so a
misplacing manifest hides records rather than deleting them. A failed cleanup
never changes membership, and the next transaction retries it.

Missing, corrupt or inconsistent membership metadata fails closed until
`pqkey repair` rebuilds it. A corrupt record fails its lookup and is skipped
by listing, but a replacement must read every member, so that no unknown
matching record stays usable. The daemon at start-up and `pqkey status`
inspect the store read-only, looking again before they report so that a
concurrent commit's cleanup is not taken for damage, and name, in order: a PIN
state or large-blob array that fails authentication or decoding (the PIN is
then blocked and required, and the initial array served), an unreadable or
corrupt shared signature counter (sealed credentials then cannot sign in),
and damage to the set, a missing `credentials/` or `credential-set/`
included. Opening a legacy store creates a missing `credentials/` again,
empty, and logs the loss.

### Repair

`pqkey repair` needs the key stopped, and refuses while the daemon holds the
state lock. It plans without changing anything, takes the lock, plans again,
shows the damage and each step and asks (`--yes` does not), then plans once
more and refuses a store that changed since.
`crates/pqkey-ctap/src/store/repair.rs` documents the rules in full:

- With an authentic manifest, repair drops the members whose records are
  missing or fail authentication or decoding, raising no counter. A legacy
  store leaves its failing records out as it moves to the managed layout.
- Without one, it rebuilds the manifest from the records in `credential-set/`
  that authenticate under the current key, so a deleted or replaced passkey
  whose record was left behind can come back. The plan names any account left
  with several passkeys, which its next registration replaces, and a list over
  the store's limit, which refuses new credentials until it holds fewer. Of
  two authentic copies of a record it keeps the one with the higher counter;
  of an authentic and a damaged one, the authentic one, its counter raised.
- A damaged or missing format marker is written again, and a missing
  namespace is created again, empty; the keys, an undamaged PIN state and the
  shared counter stay, so sealed credential IDs still open.
- A lost shared counter, and a raised record, are written at one more than the
  largest of the clock's seconds since 1970, the newest modification time in
  the state directory and its record directories, and every count planning
  read, leaving out times at or past `u32::MAX` seconds. For a repair before
  2106-02-07, the new count is above every count the key returned on that
  counter if:
  1. at each count, the key had counted fewer times than whole seconds had
     passed, since 1970 and since any earlier repair;
  2. no time that this repair or an earlier one read, the clock's or a file's,
     was ahead of the real time, as a hand edit or a copy that kept its times
     can make one; and
  3. the clock is right during the repair, or the damaged file still has the
     time a right clock gave it at its last count or later.
- Last, a PIN state that fails authentication or decoding is replaced, by a
  rename, with one that has no PIN, always-UV on and default settings
  (removing it would read as no PIN with always-UV off), and such a large-blob
  array is removed, which reads as the initial array. Repair touches neither
  otherwise, even for a PIN blocked by wrong guesses.

Each file that repair replaces or removes is first hard-linked (a directory
renamed) into a new `damaged/<UTC time>/` at its path in the state directory,
and flushed; nothing reads that directory, and no cleanup, inspection or reset
touches it. Counters are written before the new list is published, so an
error or crash at any checkpoint leaves the store serving its old or its
repaired credentials, every file in place or quarantined, and repairing again
finishes. Repair leaves the attestation record and the keys alone, and
rewrites a record only to raise its counter.

### Reset

Reset works alike in both layouts:

1. It rotates the credential key: the new key file is flushed before its
   atomic publication and its directory after it, and only then is the old
   key overwritten, as a best effort, and leftover temporary key files
   removed.
2. It purges credential records and membership, and removes the shared
   counter and the large-blob array, which then read as zero and the initial
   array.
3. A managed store gets a new format marker and an empty manifest.
4. The default PIN state is published last. The engine then resets its PIN
   and UV state, tokens and protocol keys, and returns success, durable or
   not.

A rotation error runs no cleanup: under the old key everything stays intact,
and under a published new key the old records fail authentication. After a
durable rotation, old credentials are invalid even if a later step fails, and
until the defaults are published, a restarted engine treats the PIN as set
and blocked, with always-UV; retrying the reset recovers without the old key
or readable metadata. A partial reset never revives invalidated credentials
or lowers surviving credentials' protections. The attestation key and record
survive every step. Checkpoint tests cover errors and process exits at each
persistence boundary, and rename rollback, but not power loss.

### Durability

PIN and configuration writes return `Result<CommitDurability, StoreError>`: an
error means nothing was published; `Flushed`, that the file and its directory
were flushed; `Volatile`, an intentional memory store; and `Unconfirmed`, that
the rename published it but a later flush did not complete, so power loss can
restore the old record. Flushes do not protect against filesystem snapshots
or hardware that ignores them. setPIN, changePIN and authenticatorConfig treat
publication as commitment: they succeed and adopt the new settings even when
unconfirmed, so a durability warning does not mean the old PIN or policy is
still active.

A PIN check debits a retry before decrypting or comparing, and compares only
after a flushed debit; otherwise it returns CTAP2_ERR_PROCESSING with no
verdict or token. A failed debit spends nothing, so a full disk blocks no PIN,
while an unconfirmed one stays spent, and a match restores the retries only
once that is published. A mismatch stays spent, and counts toward the
three-mismatch block, even if a later write fails; a restart clears that
block, not the stored budget.

The engine rereads its PIN state before persistent access or a PIN check. An
I/O error there fails only that command, with CTAP2_ERR_PROCESSING, and keeps
the live authority and tokens. After an I/O error at start-up, or on the read
that settles a failed reset, the engine instead holds no tokens, answers as a
key whose PIN is set and blocked, with always-UV, writes nothing, and fails
each PIN or credential operation with CTAP2_ERR_PROCESSING (U2F:
SW_INTERNAL_ERROR) until a read succeeds. A record that fails authentication
or decoding, a missing or unusable root key, or no record although a PIN or
grant exists, closes authority: the key answers as one whose PIN is set and
blocked, with always-UV, and PIN checks get PIN_BLOCKED, until a reset,
`pqkey repair`, or a restart that reads a record or finds none. The closed
state is never written over the record. Where the
filesystem cannot flush directories (fsync of the
state directory fails with EINVAL, EOPNOTSUPP/ENOTSUP or ENOSYS), no PIN write
could be confirmed, so setPIN and PIN checks refuse with CTAP2_ERR_PROCESSING
before writing, and `pqkey status` reports it.

Other writes also replace files atomically, and report a failed directory
flush, except large-blob writes, which succeed and log it. A missing or
corrupt large-blob array is served as the initial array, but any other read
error answers CTAP2_ERR_PROCESSING, since a platform that took the array for
empty would write back its own entry alone. Nothing detects a rollback: a
restored snapshot of the whole store looks like older state.

### Credential IDs

Discoverable credential IDs are `0x01` and 32 random bytes. A
non-discoverable credential whose key and algorithm fit, and that is not
payment-enabled, is sealed into a 107-byte ID starting with `0x02`, which
carries the algorithm, credProtect, the 32-byte key and a seed for its
hmac-secret values, bound to the RP ID hash; nothing is stored, and it uses
the shared signature counter. The others, RSA, Brainpool and payment-enabled
ones, are stored under `0x00` and 32 random bytes: their records hold no user
data, keep their own hmac-secret values, credProtect and counter, work only
through an allowList, are excluded by an excludeList, take a slot and are
erased by reset. Every counter update saves the count before signing.

The `thirdPartyPayment` flag is credential-record field 16, omitted when
false. makeCredential stores an explicit true and returns nothing for it;
assertions return each credential's flag, signed with the other extension
outputs, only when asked for true, and enumeration always includes it (field
`0x0C`). Sealed and U2F-created credentials report false. The flag changes no
other rule: payment itself belongs to the client platform.

## User presence and U2F

Each registration, sign-in that needs presence, reset and authenticator
selection asks for approval through `org.freedesktop.Notifications` on the
session bus; the [user guide](user-guide.md#approving-requests) shows what you
see.

The engine also answers U2F REGISTER, AUTHENTICATE and VERSION, with ES256 and
the same sealed IDs, RP hashes and counters as CTAP2; U2F cannot create a
discoverable credential or verify a user. Its registration carries the first
provisioned certificate in certificate mode, and otherwise a minimal X.509
certificate signed by the new credential, which names no installation. Short
APDUs are accepted, and signatures use DER's 8–72-byte range (§10.3).

U2F clients poll: if presence has not answered within 100 ms, the transport
returns SW_CONDITIONS_NOT_SATISFIED and keeps the request alive, and exact
repeats get that status until the result is ready, which then answers one
repeat within ten seconds of the approval. INIT, or three seconds without a
repeat, cancels the prompt, and a denial or timeout suppresses new prompts for
that request until its repeats stop for that long. Another engine operation,
a policy change or a reset discards a cached approval. Always-UV disables U2F
and removes U2F_V2 from getInfo; a PIN alone does not.

## The `pqkey` command

- `pin`, `passkeys` and `reset` talk to the running key over CTAP through its
  hidraw node, as a security key's management app does, so the key's own PIN
  checks and approvals apply.
- `repair` works on the state directory itself, and never stops or starts the
  key, since the advice that leads to it keeps a copy of the directory first.
- `setup`, which `install.sh` runs, installs the udev rules and loads uhid at
  boot through sudo, after listing the changes; the root steps run from a
  script written only once you approve them, and kept with rerun instructions
  if one fails. It then installs and starts the user service, sets the PIN,
  and succeeds only when every readiness check passes.
- `status` looks for the notification server on the running key's session
  bus, or the terminal's when no key runs, never over TCP.
- `run` is the daemon; its hidden options for test rigs are documented in
  `crates/pqkey/src/cli/mod.rs`. Holding the state lock, it publishes its
  non-secret options and its executable's device and inode in
  `authenticator.info`, then its pid in `authenticator.pid`. Commands use them
  to keep options across restarts and to notice a replaced binary without
  reading the daemon's `/proc` entries, and trust neither without the lock and
  a matching pid.

## Brainpool credential keys

ESB256 and ESB384 are ECDSA on brainpoolP256r1 with SHA-256 and
brainpoolP384r1 with SHA-384
([RFC 9864 §2.1](https://www.rfc-editor.org/rfc/rfc9864.html#section-2.1)),
on [COSE](https://www.iana.org/assignments/cose/) curves 256 and 258, with 32-
and 48-byte coordinates and DER signatures; RustCrypto's bp256 and bp384 sign
on the scrubbed-stack path. Each key is a 32-byte seed: the first 40 or 56
bytes of SHAKE256 over `pqkey/v1/ecdsa-key/`, the curve's exact name and the
seed give c, and d = (c mod (n − 1)) + 1
([RFC 5639 §§3.4/3.6](https://www.rfc-editor.org/rfc/rfc5639.html)). Their
algorithm IDs do not fit a sealed ID (`CoseAlg::is_sealable` checks both the
key's width and the algorithm's encoding), so Brainpool credentials are always
stored.
