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
  cannot be shown, the request is denied, never approved.
- **Other users on the computer.** The state directory is `0700`, its files
  are `0600`, and udev gives the key's device to the user of the session that
  is active on the seat, not to remote users. When that becomes another
  user's session, a login screen's included, the key removes its device,
  which also cuts off any program that had it open; see
  [Other users' sessions](#other-users-sessions) for what remains.
- **Copies of the files without the keys.** The credential, PIN, counter and
  large-blob files in `~/.local/share/pqkey` are encrypted and authenticated
  with XChaCha20-Poly1305 under keys derived from two root keys in `keys/`. A
  modified, truncated or swapped file is reported as corrupt and never used.
  File names are HMACs, so they reveal neither credentials nor sites.
  Discoverable credentials' optional large-blob keys receive the same
  encryption and erasure protections as their private keys.
  A corrupt large-blob array is logged and served as its initial value; it
  is replaced only by a committed write or a reset. An array that cannot be
  read fails the read instead.
- **Old data after a reset.** A reset replaces the credential root key, so
  leftover copies of files, and the credential IDs that sites hold, can no
  longer be decrypted. It erases credential large-blob keys and restores the
  initial large-blob array.
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
- **The moment another user's session becomes active.** With systemd 257 and
  older, and with elogind, they get the key's device a moment before logind
  changes its record of the seat, where the key looks for the switch. A
  program of theirs that opens the device in that moment can use the key as
  any program can without your approval, until the key sees the record
  change and removes the device. [Other users' sessions](#other-users-sessions)
  says what that gives them, what else remains and what to do.
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

- **U2F cannot verify the user or name the site.** U2F registration and
  ordinary authentication ask for presence without the PIN, even when a
  PIN is set. The request contains an application hash, so the prompt says
  it is a U2F request and cannot identify the site. The explicit
  don't-enforce control (`0x08`) permits a silent signature whose presence
  bit is clear. Enabling always-UV disables U2F registration and every
  authentication control, including check-only and silent authentication.
  An approval answers one identical polling request on the same channel
  within ten seconds. A prompt abandoned for over three seconds is
  cancelled; denial and timeout suppress further prompts until polling
  stops for that long.

- **It shows what the client claims.** Site and user names come from the
  request. They are cleaned of control and invisible characters, but a lying
  local program can still claim any site. Browsers check the site; other
  programs need not.
- **Some requests need no prompt.** As CTAP allows, an assertion may ask for
  no user presence. The signed data then says so, and sites that check it, as
  WebAuthn requires, do not accept it as a sign-in. PIN changes and passkey
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
- **Large-blob writes follow the PIN protection.** A PIN or always-UV
  requires a token with the `lbw` permission for each fragment. Without
  either, device access permits writes. Any client can read the serialized
  array without presence or verification; platforms encrypt blob contents.
  Only a complete write with a valid trailing hash replaces the array.
  Reading a credential's blob plaintext requires its secret large-blob key,
  returned by a permitted assertion or credential management operation.
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
keys: on Ubuntu, sssd's rules give the `sssd` user every security token. From
systemd 260, a rule that tags the device `xaccess-<name>` also gives it to
every session granted that extra device access, active or not, which the key
does not watch for; no rule that systemd or pqkey ships tags a security key
so. A program with such access can send the key requests while you are at
your desktop, naming any site, so deny any prompt you did not start. With
`--presence auto-approve`, which is for tests only, the key approves such
requests itself.

### Other users' sessions

udev's `uaccess` rule gives the key's device to the user of the session that
logind's record of the device's seat, in `/run/systemd/seats`, names as
active. With systemd 257 and older, and with elogind, logind also moves the
device to the new user itself at each switch, just before it saves that
record. A program that opened the device keeps it open after that changes.

So the key watches the record. As soon as it sees another user's session
become the active one, a login screen's included, it answers no further
request and removes its device. That ends every file opened on the device.
When the record names your session, or none, as active again, the key
creates a new device, and udev gives it to the active session's user, as it
gave the first.

The key also keeps no device while it cannot read the record or understand
it, and while a record that it has seen since it started is missing: it has
seen one once it has read it, or, while it watches with inotify, once a
notification has named it. systemd 257 and older, and elogind, remove a
seat's record when they fail to save it, as when `/run` is full, and still
move the device to each new user, and logind removes the record of a seat
that goes away. The key then reads the record every 100 ms until it is back.
A record it has never seen counts as a seat that logind does not have, to
whose devices udev gives no user: without logind, in the empty
`/run/systemd/seats` that systemd-tmpfiles makes at boot where logind does
not run, or on a seat that does not exist yet.

logind writes each state of the seat to a new file, so the key keeps its
device only while the record is the file it created the device under, or, if
the seat had no record then, while it still has none. It tells files apart by
inode number, which `/run`, a tmpfs, gives each file created there in turn,
whoever creates it, coming back to one only after some four billion others
(or, mounted with `inode64`, practically never). Any other file retires the
device, even one that names your session. A switch to another user and back
that falls between two of the key's looks leaves another file, so it replaces
the device too. The cost: the key replaces its device whenever logind saves
the record, also when you stay active, as when another session on the seat
starts or ends, and a program using the key at that moment sees it unplugged
and plugged in again.

This holds whether the key's user service runs from your login or, with
lingering (`loginctl enable-linger`), from boot and after you log out. While
the record names no active session, no session's user gets the device, and
the key keeps a device. So it does where it has never seen a record of the
seat, as without logind, since udev's `uaccess` rule then gives the device to
no one.

Removing the device is not a restart: a reset is still possible only within
10 seconds of the key's start, and after three wrong PINs in a row the key
still refuses PIN checks until it restarts. While the device is absent,
`pqkey` commands cannot reach the key either; `pqkey status` says when
another user's session is active on seat0, or when seat0's record cannot be
read or is missing from `/run/systemd/seats`.

If the key cannot watch the record with inotify, it says so in a warning, when
it starts or when `/run/systemd/seats` appears later: in the user service's
journal (`journalctl --user -u pqkey`), or in `authenticator.log` in the state
directory for a key that `pqkey start` ran without the service; `pqkey status`
does not show it. It then reads the record at every check instead: before
each report it handles or sends, and every 10 ms or so while idle. It compares
files the same way, but cannot see a record that appears and goes again
between two reads, which it then has not seen.

What the key has not seen, it cannot judge. A record already missing when
the key starts, or when it starts watching another seat, counts as a seat
that logind does not have, and so does one that appears and goes again
between two of the polled fallback's reads. With systemd 257 and older, and
with elogind, such a record may have gone in a failed save; for one missing
at the start, that save failed before the key started, as when `/run` was
already full. While saves keep failing, switches on that seat then leave
nothing for the key to see. A program of the new user's can then open the
device and keep it until the key next removes its device, and for all that
time do what the list below says, receive what the key sends, and send
requests that ask for your approval, naming any site: deny any prompt you did
not start. With `--presence auto-approve` the key approves them itself. So,
with those versions, do not restart the key while `/run` is full.

The key's device is on a seat other than seat0 only if a udev rule your
administrator added puts it there. When such a seat goes away, logind removes
its record, and the key keeps no device until the seat comes back or the key
restarts; while the seat is gone, udev gives its devices to no one, so no one
could use the key's device then anyway. If udev has not recorded the device's
seat within 10 seconds of the key creating it, the key keeps watching the
seat it watched before, seat0 at first.

Apart from those cases, and from rules that grant the device otherwise (see
Device access above), what remains is the moment of a switch. With systemd
258 and later, logind saves the record naming the other user before it has
udev give them the device, and the kernel has queued the notification of that
save by the time the save returns. So their first report already finds
another file, and the key answers none of their requests. Only udev handling
an event of the key's device, as when the key has just created it, in the
instant between the new file appearing and that notification, with logind
then stalled there, could let a program of theirs in before the key sees the
save. With systemd 257 and older, and with elogind, they get the device a
moment before logind saves the record, or removes it. A program of theirs
that opens the device in that moment can, until the key sees the record
change, do what any program of yours can without your approval, including:

- Silent assertions (`up` false), even with always-UV. They do not sign in at
  sites that check the presence flag, as WebAuthn requires, but they probe
  your accounts. For any site they name, the key answers with your passkeys
  of credProtect level 1, the level when a registration asks for none, and
  returns each one's user ID and, if asked, its credBlob and its large-blob
  key, which decrypts its large blob. Given a credential's ID and site, any
  credential below level 3 answers, including non-discoverable ones.
- getInfo (whether a PIN is set, its policy, always-UV and the free passkey
  slots), the PIN retries left and the large-blob array.
- PIN guesses: three in a row, after which your PIN is refused too until the
  key restarts. A restart, or the key accepting your PIN, starts the count
  again. Eight wrong PINs with none accepted between them block the PIN until
  a reset, which erases every passkey.
- On a key without a PIN: configuration changes, large-blob writes and setting
  a PIN. You do not know that PIN, and with it, in that moment or a later
  one, a program of theirs can list, rename and delete your passkeys, read
  every passkey's large-blob key and so every large blob, and make verified
  silent assertions, credProtect 3 included. `pqkey reset` removes such a PIN
  but erases every passkey; deleting `pin-state` with the key stopped removes
  it too (see "Rolling files back" above).

That program also receives a copy of what the key sends in that moment.
Requests that need your approval are not approved: the key withdraws any
prompt for them when it removes the device. With `--presence auto-approve`,
which is for tests only, they are approved too.

Keep a PIN set: it limits what that moment allows, since a program then
cannot change the configuration, write the large-blob array or set a PIN
without it. To close the moment, with systemd 257 and older or elogind, run
`pqkey stop` before you switch users or log out, and `pqkey start` when you
are back. Logging out stops the key only when systemd stops your user
services: by default 10 seconds after your last session has ended, and not
while a program of yours keeps that session closing. With lingering, the key
also keeps running after you log out, and starts at boot, before you log in.
While it runs without you, it has its device whenever logind records no
active session, so another user's session or a login screen becoming active
then is a switch like any other. Unless you need lingering, turn it off with
`loginctl disable-linger`. If you need it, `systemctl --user disable pqkey`
keeps the key from starting at boot or at login, until `pqkey setup` enables
it again, and `pqkey start` starts it when you are back.

### Privacy

- Registrations use self attestation, which says nothing about the key beyond
  its AAGUID. That AAGUID is the same for every installation, so it identifies
  pqkey, not you.
- Sealed non-discoverable credentials share one signature counter, as on
  most hardware keys. Stored ones (RSA, Brainpool and payment-enabled) keep
  their own.
- After `pqkey repair` writes the shared counter again, its count starts
  just above the number of seconds since 1970 by the computer's clock, or
  above a newer time on the store's files or a higher count that repair
  reads. When the clock gave the start, a site that sees the count
  afterwards can tell roughly when the repair ran by that clock. The same
  holds for a stored credential's count that repair raises.
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
