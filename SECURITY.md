# Security

## Reporting a vulnerability

Please report vulnerabilities privately, not in a public issue. Contact the
maintainer through their GitHub profile,
[@rainzhang05](https://github.com/rainzhang05). Include the commit you tested,
the client involved, the steps to reproduce, and what an attacker gains.

pqkey has no releases: fixes go to `main`, and reach the `stable` branch users
install once they pass CI, E2E and Security. There is no bug bounty.

## Threat model

pqkey is a software security key. Its private keys live on the same computer,
under the same user account, as the browser that uses them. It cannot give the
guarantees of a hardware key, whose keys cannot be read out and whose touch
sensor software cannot press.

### What it protects against

- **Silent use.** Every registration, sign-in that needs your presence, and
  reset asks for your approval in a desktop notification. If the notification
  cannot be shown, the request is denied, never approved. With the test-only
  `--presence auto-approve`, the key approves every request itself.
- **Other users on the computer.** The state directory is `0700` and its
  files `0600`. udev gives the key's device to the user of the session active
  on the seat, not to remote users, and the key removes the device while
  another user's session or a login screen is active; see
  [Other users' sessions](#other-users-sessions).
- **Copies of the files without the keys.** The credential, PIN, counter and
  large-blob files in `~/.local/share/pqkey`, large-blob keys included, are
  encrypted and authenticated with XChaCha20-Poly1305 under keys derived from
  two root keys in `keys/`. A modified, truncated or swapped file is reported
  as corrupt and never used; a corrupt large-blob array reads as empty, and
  an unreadable one fails the read. `pqkey repair` replaces a corrupt PIN
  state with no PIN and always-UV on. File names are HMACs, so they reveal
  neither credentials nor sites.
- **Old data after a reset.** A reset replaces the credential root key, so
  leftover copies of files, and the credential IDs that sites hold, can no
  longer be decrypted, unless a copy of the old key outlives the reset, such
  as a backup of `keys/` or a leftover temporary file that the reset could
  not remove. It also erases large-blob keys and empties the large-blob array.
- **PIN guessing through the key.** The retry count is saved before each
  comparison. After 8 wrong PINs the PIN is blocked until a reset, and after 3
  in a row the key must be restarted.

### What it does not protect against

- **Anything running as you, or as root.** It can read the root keys and so
  every private key and large-blob key, or use the key while a prompt is up,
  or interfere with the notification. A single copy of `keys/credential.key`
  also opens every sealed non-discoverable credential until the next reset;
  stored ones, such as RSA, Brainpool and payment-enabled credentials,
  require their encrypted records as well.
- **Offline PIN guessing by such an attacker.** The stored PIN hash is an
  unsalted, truncated SHA-256.
- **The code that builds pqkey.** The build scripts and procedural macros of
  pqkey's dependencies run as you when `install.sh` builds pqkey, and shape
  the binary that it then runs as `pqkey setup` with your sudo password
  cached. `install.sh` only keeps a password sudo cached before the build
  away from that code.
- **The moment another user's session becomes active.** With systemd 257 and
  older, and with elogind, a program of theirs can use the key without your
  approval in the moment of the switch;
  [Other users' sessions](#other-users-sessions) says what that gives them
  and what to do.
- **Rolling files back.** Integrity is per file, so an older copy of
  `pin-state` restores PIN retries, and deleting it removes the PIN.
- **Clones.** A copy of the state directory works as well as the original.
  Signature counters may show a relying party that two copies are in use, but
  not a copy used after the original stops.
- **Reading the daemon's memory.** Secrets are wiped after use as far as Rust
  allows, and so is every heap block the binary frees, RSA's leftovers
  included. The daemon disables core files, as its service's `LimitCORE=0`
  does, and makes itself non-dumpable, so that neither crash handlers nor
  other unprivileged processes can read its memory; if either fails, it warns
  and continues. Memory in use can still hold secrets and reach swap, and
  root can read it.

### Limits of the prompt

- **U2F cannot verify the user or name the site.** U2F registration and
  ordinary authentication ask for presence without the PIN, and the prompt
  cannot name the site, which the request only hashes. The don't-enforce
  control (`0x08`) allows a silent signature with the presence bit clear.
  Always-UV disables U2F, check-only and silent requests included. An
  approval answers one identical repeat on its channel within ten seconds;
  an unpolled prompt is cancelled after three, and a denial or timeout holds
  off new prompts until polling pauses that long.
- **It shows what the client claims.** Site and user names come from the
  request, cleaned of control and invisible characters, so a lying local
  program can claim any site. Browsers check the site; other programs need
  not.
- **Some requests need no prompt.** As CTAP allows, an assertion may ask for
  no user presence, even with always-UV; the signed data then says so, and
  sites that check it, as WebAuthn requires, do not accept it as a sign-in.
  PIN changes and passkey management need the PIN instead, and on a key
  without one, any program that can open the device can set it.
- **Some registrations need no PIN.** A site may register a non-discoverable
  credential with your approval but without the PIN, even when one is set, as
  getInfo's `makeCredUvNotRqd` announces. Always-UV requires the PIN for every
  registration and every sign-in with user presence.
- **Configuration and large-blob writes follow the PIN.** With a PIN set,
  both need a PIN token, as large-blob writes also do under always-UV;
  otherwise any program that can open the device can make them, which also
  lets always-UV be turned off without a PIN. A required PIN change blocks
  new tokens until a different PIN meets the current policy. Any client can
  read the large-blob array; platforms encrypt each blob under its
  credential's large-blob key, which only a permitted assertion or credential
  management returns, and only a complete write with a valid hash replaces
  the array.
- **Reset is only possible within 10 seconds of the key starting** (CTAP 2.3
  §6.6), as with a hardware key that has just been plugged in.

### Device access

The daemon opens `/dev/uhid`, which the udev rules give to the `plugdev`
group. Anyone who can open it can create any HID device, including a keyboard
that types into your session, so membership in that group is a privilege of
its own. `pqkey setup` adds you to the group if needed, with an ACL on
`/dev/uhid` until your next login applies it; on Ubuntu, the first user is in
it already.

The key's own device is mode `0600`, goes to the active session's user and
is tagged for the Firefox and Chromium snaps. Other rules can grant it too,
as for any hardware key, such as Ubuntu's sssd rules, which give the `sssd`
user every security token, or from systemd 260 an `xaccess-` tag for
sessions that are not active, which the key does not watch for and no rule
that systemd or pqkey ships puts on a security key. A program with such
access can send requests naming any site while you are at your desktop, so
deny any prompt you did not start. It can also keep the key busy, and a wrong
PIN it sends as your client sends yours can make your correct one count as
wrong.

### Other users' sessions

udev gives the key's device to the user whose session logind's record of the
seat names as active, and a program that opened the device keeps it after
that changes. So the key watches the record, in `/run/systemd/seats`: while
another user's session or a login screen is active, it keeps no device,
closing it for every program and withdrawing its prompts, and `pqkey status`
says why. It makes a new one once you, or no one, is active, and replaces it
at every save of the record, even while you stay active. Removing it is not
a restart.

With systemd 258 and later, logind saves the record before udev gives the
new user the device, so the key answers none of their requests, short of a
narrow race. With systemd 257 and older, and with elogind, they get the
device a moment before the record changes: until the key sees the change, a
program of theirs that opens it receives a copy of what the key sends, and
can, without your approval:

- make silent assertions, which sign in nowhere that checks presence but
  reveal the user IDs, credBlobs and large-blob keys of any site's passkeys
  at the default credProtect level, and of any credential below level 3
  whose ID they give;
- read getInfo, the PIN retries left and the large-blob array;
- guess PINs, which can block yours until the key restarts, and the PIN
  until a reset, which erases every passkey;
- on a key without a PIN, change its configuration, write large blobs, or set
  a PIN you do not know, which lets them manage and probe your passkeys and
  read every large blob until a reset.

The key keeps no device while it cannot read the record, or one it has seen
is missing. One it has never seen counts as a seat without logind; as
systemd 257 and older, and elogind, remove a record they fail to save but
still move the device to each new user, do not restart the key while `/run`
is full. Without inotify, the key polls, which can miss a record that comes
and goes between reads, and says so only in its log. If udev takes over 10
seconds to record the device's seat, the key may keep watching seat0 and miss
switches on a seat an administrator's rule chose, until it next replaces its
device.

Keep a PIN set, which closes the last bullet. With systemd 257 and older or
elogind, run `pqkey stop` before you switch users or log out (logging out
may not stop the key at once), and `pqkey start` when you are back. With
lingering, the key also runs from boot and after you log out, when a session
becoming active is a switch too: unless you need lingering, turn it off with
`loginctl disable-linger`, or else `systemctl --user disable pqkey` keeps the
key from starting until `pqkey setup` enables it again.

### Privacy

- Registrations use self attestation, whose AAGUID is the same for every
  installation: it identifies pqkey, not you.
- Sealed non-discoverable credentials share one signature counter, as on
  most hardware keys. Stored ones (RSA, Brainpool and payment-enabled) keep
  their own.
- A counter that `pqkey repair` writes again, or raises, restarts above the
  computer's clock in seconds, or a newer file time or higher count, so a
  site that sees its count can tell roughly when the repair ran.
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
