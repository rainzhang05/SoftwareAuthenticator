# Security policy

## Supported versions

pqkey has not been released. Security fixes go to the `main` branch only.

| Version | Supported |
|---------|-----------|
| `main` | Yes |
| anything else | No |

## Reporting a vulnerability

Please report vulnerabilities privately, not in a public issue or pull request.

GitHub private vulnerability reporting is **not enabled** for
[rainzhang05/SoftwareAuthenticator](https://github.com/rainzhang05/SoftwareAuthenticator)
at the moment, and the repository has no issue tracker or discussions. Until
that changes, contact the maintainer privately through the contact details on
their GitHub profile, [@rainzhang05](https://github.com/rainzhang05), and ask
for a private channel before sending details if you prefer.

Please include:

- the commit you tested;
- how the daemon was started (the `pqkey attach` options, or the systemd unit);
- the client involved (browser and version, libfido2, python-fido2, ...);
- steps to reproduce, and what an attacker gains.

There is no bug bounty. Reports are handled on a best-effort basis by a
volunteer maintainer.

## Threat model

pqkey is a software security key. Its private keys live on the same computer,
under the same user account, as the browser that uses them. It cannot give the
guarantees of a hardware security key, whose keys cannot be read out and whose
touch sensor cannot be driven by software. This section states what pqkey is
designed to protect against and what it does not.

### Assets

- Credential private keys (ES256 scalars and ML-DSA seeds, 32 bytes each).
- The PIN, stored as `LEFT(SHA-256(PIN), 16)`, and the PIN retry counter.
- The attestation private key, when `--attestation certificate` is used.
- The per-credential `CredRandom` values behind the `hmac-secret` extension.

### Who can talk to the key

The virtual key is a hidraw node. The shipped udev rules
([`contrib/udev/70-pqkey.rules`](contrib/udev/70-pqkey.rules)) make it mode
`0600` and grant access to the user of the active local session through
systemd's `uaccess` tag. Any process running as that user can open it and send
CTAP requests: pqkey cannot tell a browser from any other program, and the
relying party ID and user names in a request are whatever that process wrote.

`/dev/uhid` itself is opened by the daemon. The rules give the `plugdev` group
access to it. Anyone who can open `/dev/uhid` can create any HID device,
including a keyboard that types into the active session, so membership in that
group is a privilege in its own right.

### The encrypted credential store

Each record is a separate file encrypted and authenticated with
XChaCha20-Poly1305 under keys derived from two 32-byte root keys. By default
the root keys are files in `keys/` inside the same state directory as the data.
Non-discoverable credentials are not stored at all: each credential ID holds
its private key, sealed the same way under a key derived from the credential
root key and bound to its relying party. Credential IDs are not secret, since a
relying party hands them to anyone who starts a sign-in, so those private keys
are exactly as safe as the credential root key.
The full format is in [docs/architecture.md](docs/architecture.md#credential-store)
and in the documentation of `crates/pqkey-ctap/src/store/`.

It does **not** protect against:

- **Anyone who can read the state directory as your user, or as root.** They
  read the key files and decrypt everything, private keys included. A single
  copy of `keys/credential.key` also yields the private key and hmac-secret of
  every non-discoverable credential until the next reset, including ones
  created after the copy, because their credential IDs come from relying
  parties. The `0700` directory and `0600` file permissions are the access
  control, and they only keep out other unprivileged local users.
- **Offline PIN guessing by such an attacker.** The stored PIN hash is an
  unsalted, truncated SHA-256. The retry counter only limits guessing through
  CTAP.
- **Deleting a record, or replacing a file with an older copy of itself** made
  since the last reset. Integrity is per file, so rolling back `pin-state`
  restores PIN retries and rolling back a credential file restores its
  signature counter.
- **Anyone holding the keys forging records.**
- **Clones, as far as non-discoverable credentials go.** They report a
  signature count of 0, so a relying party cannot spot a copy of the
  authenticator through the counter.
- **Reading the daemon's memory.** Secrets are zeroized when they are dropped,
  but the daemon does not lock its memory or disable core dumps, and a process
  that can debug it (subject to the kernel's ptrace restrictions) can read
  keys while they are in use.

It does provide:

- **Integrity of each file.** The authentication tag covers the record type and
  the file's name, so a modified, truncated, or swapped file is reported as
  corrupt and never used. Corrupt records are not deleted automatically.
- **Crypto-shredding on reset.** `pqkey reset` and authenticatorReset replace
  the key that protects credentials and PIN state. Ciphertext left behind in
  free blocks, snapshots or backups can no longer be decrypted, and neither can
  the non-discoverable credential IDs relying parties hold. The old key
  file is overwritten with zeros as a best effort, but on SSDs and
  copy-on-write filesystems that 32-byte file may survive too.
- **No plaintext secrets in copies that leave out `keys/`**, such as a backup
  that deliberately excludes it.
- **Credential file names that reveal nothing.** A file name is an HMAC of the
  credential ID, so a directory listing shows neither credential IDs nor
  relying parties.

Keeping the root keys in an OS-backed store (systemd-creds, a TPM, the Secret
Service) would change the first point; the store has an interface for that
(`KeySource`), but only the file-based implementation exists today.

### User presence

With `--presence notify`, the default, each registration, each sign-in that
requests user presence, each reset and each authenticator selection shows a
desktop notification through `org.freedesktop.Notifications` on the D-Bus
session bus, with Approve and Deny buttons.

It protects against programs that silently use the key without the user
noticing, as long as they cannot also interact with the desktop session.

It fails closed. The request is **denied** if there is no session bus, no
notification server, a server without the `actions` capability, or any error
talking to it. Deny, dismissing the notification, or closing it any other way
denies the request. If nobody answers within 30 seconds, or the server lets
the notification expire, the request times out. If the client cancels the
request, the notification is withdrawn.

Its limits:

- **Same-user malware with access to the session bus.** A process running as
  you can in principle interfere with the prompt, for example by replacing the
  notification server or driving the desktop. Such a process can also read the
  credential store directly (see above), so user presence is not a boundary
  against it.
- **The prompt shows what the client claims.** The relying party ID and user
  names come from the request, not from a verified origin. They are sanitised
  before they are shown (control and invisible formatting characters removed,
  long strings cut), which limits spoofing through odd characters but cannot
  make a lying client honest. Browsers check the relying party ID against the
  page's origin; other local programs need not.
- **Silent assertions.** As CTAP allows, a getAssertion request with the `up`
  option set to false is answered without a prompt, with the user-present flag
  cleared in the signed authenticator data. A relying party that requires user
  presence rejects such an assertion; one that does not check the flag accepts
  it.
- **No prompt for PIN operations or credential management.** Those are
  protected by the PIN instead.
- **`--presence auto-approve`** approves everything without asking. It exists
  for tests and CI. Never use it on a key with credentials that matter.

Without a display, CTAP 2.3 §6.6 only accepts authenticatorReset within 10
seconds of power-up. With `--presence notify` the notification serves as the
display (it states that a reset deletes all passkeys and needs Approve), so
pqkey accepts a reset at any time; with `auto-approve` the 10-second window
applies.

Logs at info level and above name only the kind of presence request. Relying
party IDs and user names appear only at debug level.

### PIN

The PIN retry counter is persisted before a PIN is compared, both in the
engine and in the `pqkey pin` commands, so interrupting a check never gives a
free guess. 8 wrong PINs block the PIN until a reset. After 3 wrong PINs in a
row the daemon refuses PIN checks until it restarts (the CTAP "power cycle").
The CLI never accepts PINs as command-line arguments.

### Attestation and privacy

- `--attestation self` (default): the attestation statement is signed with the
  new credential's own key and carries no information about the authenticator.
- `--attestation certificate`: every registration carries the same
  per-installation certificate, so relying parties that compare certificates
  can link your credentials across sites (WebAuthn Level 3 §14.4.1). The
  certificate is self-signed and not in any metadata service, so it does not
  prove to a relying party that the key is genuine.
- `--attestation none`: no statement.

The default AAGUID `5931e805-a166-4eb7-845a-7f6aa93d9cd8` is the same for every
pqkey installation. It tells a relying party that the key is pqkey, not which
installation it is.

### USB IDs

The default USB IDs `1209:0001` are a [pid.codes](https://pid.codes/1209/0001/)
test assignment that pid.codes says must not be used on redistributed devices.
They are not unique to pqkey, so other test devices may use them too. A
dedicated product ID has to be registered before a release.

### Testing and its scope

- Unit and integration tests cover the CTAP engine, the CTAPHID state machine,
  the credential store (including tampering, key handling, permissions and
  an interrupted reset), the CLI's PIN handling and the attestation
  certificate. CI enforces a line coverage floor of 85% across the workspace.
- ML-DSA is tested against NIST ACVP known-answer vectors; the store's envelope
  format, record encoding and key derivation are pinned to values computed
  with independent implementations.
- End-to-end tests run the release daemon on a GitHub Actions Ubuntu runner and
  talk to the real hidraw node with libfido2 and python-fido2, including the
  notification prompt against a fake notification server.
- libFuzzer targets cover CTAPHID packet handling, single CTAP requests (raw and
  structure-aware), stateful request sequences, and parsing and signing with
  arbitrary stored key bytes. The engine targets run over the in-memory store.
  Not fuzzed: the uhid device I/O, the D-Bus client, the CLI, and decoding of
  the on-disk envelope and record format (those have unit tests).
- `cargo audit` and `cargo deny` check both lockfiles against the RustSec
  advisory database on every push and weekly.

No independent security audit of pqkey has been published.
