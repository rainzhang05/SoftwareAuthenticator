# Security

## Reporting a vulnerability

Please report vulnerabilities privately, not in a public issue. Contact the
maintainer through their GitHub profile,
[@rainzhang05](https://github.com/rainzhang05). Include the commit you tested,
the client involved, the steps to reproduce, and what an attacker gains.

pqkey has no releases, so only `main` gets fixes. There is no bug bounty.

## Threat model

pqkey is a software security key. Its private keys live on the same computer,
under the same user account, as the browser that uses them. It cannot give the
guarantees of a hardware key, whose keys cannot be read out and whose touch
sensor software cannot press.

### What it protects against

- **Silent use.** Every registration, sign-in that needs your presence, and
  reset asks for your approval in a desktop notification. If the notification
  cannot be shown, the request is denied, never approved.
- **Other users on the computer.** The state directory is `0700`, its files
  are `0600`, and udev gives the key's device only to the user of the active
  local session.
- **Copies of the files without the keys.** The credential, PIN, counter and
  large-blob files in `~/.local/share/pqkey` are encrypted and authenticated with
  XChaCha20-Poly1305 under keys derived from two root keys in `keys/`. A
  modified, truncated or swapped file is reported as corrupt and never used.
  File names are HMACs, so they reveal neither credentials nor sites.
  Discoverable credentials' optional large-blob keys receive the same
  encryption and erasure protections as their private keys.
  An unreadable large-blob array is logged and served as its initial value;
  it is replaced only by a committed write or a reset.
- **Old data after a reset.** A reset replaces the credential root key, so
  leftover copies of files, and the credential IDs that sites hold, can no
  longer be decrypted. It erases credential large-blob keys and restores the
  initial large-blob array.
- **PIN guessing through the key.** The retry count is saved before each
  comparison. After 8 wrong PINs the PIN is blocked until a reset, and after 3
  in a row the key must be restarted.

### What it does not protect against

- **Anything running as you, or as root.** It can read the root keys and so
  every private key, or use the key while a prompt is up, or interfere with the
  notification. A single copy of `keys/credential.key` also opens every
  sealed non-discoverable credential until the next reset; RSA credentials
  require their encrypted stored records as well.
- **Offline PIN guessing by such an attacker.** The stored PIN hash is an
  unsalted, truncated SHA-256.
- **Rolling files back.** Integrity is per file, so an older copy of
  `pin-state` restores PIN retries, and deleting it removes the PIN.
- **Clones.** A copy of the state directory works as well as the original.
  Signature counters may show a relying party that two copies are in use, but
  not a copy used after the original stops.
- **Reading the daemon's memory.** Secrets are wiped after use as far as Rust
  allows. Before opening the store, the daemon sets its core file size limit
  to zero; the systemd user service sets `LimitCORE=0` too. On Linux it also
  makes itself non-dumpable, preventing core dumps and crash handlers from
  collecting its memory, and other unprivileged processes from attaching
  with ptrace or reading its memory through `/proc`. If either setting
  fails, the daemon logs a warning and continues.
  The binary wipes every heap block before releasing it, including old
  blocks and discarded tails from reallocation. This covers the copies RSA
  arithmetic leaves on the heap as well as values explicitly wiped on drop.
  Memory still in use can contain secrets. These protections do not lock
  memory, so copies in swap remain possible, and root can still read live
  memory. They do not prevent the same user from reading the state files.

### Limits of the prompt

- **It shows what the client claims.** Site and user names come from the
  request. They are cleaned of control and invisible characters, but a lying
  local program can still claim any site. Browsers check the site; other
  programs need not.
- **Some requests need no prompt.** As CTAP allows, a sign-in may ask for no
  user presence, and the signed data then says so. PIN changes and passkey
  management are protected by the PIN instead. On a key without a PIN, any
  program that can open the device can set one.
- **Some registrations need no PIN.** A site may register a non-discoverable
  credential without the PIN even when one is set, as getInfo's
  `makeCredUvNotRqd` announces. It still needs your approval. Enabling
  always-UV requires verification for every registration and every sign-in
  with user presence; the CTAP `up=false` exemption still applies.
- **Configuration follows the PIN protection.** A PIN guards configuration
  with an `acfg` token. Before one is set, device access allows changing
  configuration too. Without a PIN, always-UV can still be disabled, so the
  initial-configuration exception cannot strand the key. A required PIN
  change blocks new tokens until a different PIN meets the current minimum.
- **Reset is only possible within 10 seconds of the key starting** (CTAP 2.3
  §6.6), as with a hardware key that has just been plugged in.

### Device access

The daemon opens `/dev/uhid`, which the udev rules give to the `plugdev`
group. Anyone who can open it can create any HID device, including a keyboard
that types into your session, so membership in that group is a privilege of
its own. `pqkey setup` adds you to the group if needed. Until your next login
applies the group, it gives you an ACL on `/dev/uhid` instead. On Ubuntu, the
first user is in `plugdev` already.

The key's own device is mode `0600` and goes to the active session's user. The
rules also tag it for the Firefox and Chromium snaps, which their sandbox
otherwise refuses. Other rules may grant access too, as they do for hardware
keys: on Ubuntu, sssd's rules give the `sssd` user every security token.

### Privacy

- Registrations use self attestation, which says nothing about the key beyond
  its AAGUID. That AAGUID is the same for every installation, so it identifies
  pqkey, not you.
- Non-discoverable credentials share one signature counter, as on most
  hardware keys.
- Logs name sites and users only at debug level.
- The USB IDs `1209:0001` are a [pid.codes](https://pid.codes/1209/0001/) test
  ID that is not unique to pqkey.

### Cryptography and assurance

- Private keys, ML-DSA seeds and signing randomness come from getrandom(2).
  pqkey makes no FIPS 140 claim, and RustCrypto's `ml-dsa` is not a validated
  module.
- ML-DSA is tested against NIST ACVP vectors, and the store's format is pinned
  to values from independent implementations.
- Unit, end-to-end and fuzz tests run in CI, with a coverage floor of 85%.
  `cargo audit` and `cargo deny` check every dependency.
- No independent security audit has been published.
