# pqkey

**A FIDO2 security key in software for Linux, with post-quantum ML-DSA
passkeys.**

[![CI](https://github.com/rainzhang05/SoftwareAuthenticator/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/rainzhang05/SoftwareAuthenticator/actions/workflows/ci.yml)
[![E2E](https://github.com/rainzhang05/SoftwareAuthenticator/actions/workflows/e2e.yml/badge.svg?branch=main)](https://github.com/rainzhang05/SoftwareAuthenticator/actions/workflows/e2e.yml)
[![Security](https://github.com/rainzhang05/SoftwareAuthenticator/actions/workflows/security.yml/badge.svg?branch=main)](https://github.com/rainzhang05/SoftwareAuthenticator/actions/workflows/security.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

pqkey shows up in your browser as an ordinary USB security key. A user daemon
creates a virtual HID device through the kernel's `uhid` driver, so any FIDO2
client can use it, and every registration, reset and sign-in that asks for
your presence waits for you to approve it in a desktop notification.

- **Post-quantum:** ML-DSA-44, ML-DSA-65 and ML-DSA-87 credentials (FIPS 204),
  alongside ECDSA (ES256, ESP256, ES384, ESP384, ES512, ESP512, ES256K,
  ESB256 and ESB384),
  EdDSA (EdDSA, Ed25519 and Ed448), and RSA-2048 (RS256, RS384, RS512,
  PS256, PS384 and PS512).
- **CTAP 2.3:** PIN (protocols 1 and 2), passkeys with credential management,
  always-UV, minimum PIN length and PIN complexity configuration,
  `minPinLength`, `pinComplexityPolicy`, `credBlob`,
  `hmac-secret`, `hmac-secret-mc`, `credProtect`, `largeBlobKey`,
  `thirdPartyPayment`, fragmented large-blob storage, and packed self-attestation.
- **U2F:** CTAP1 registration and authentication over USB HID, using ES256
  credentials that also work over CTAP2. U2F uses approval rather than a
  PIN, and its prompt cannot identify the site. Always-UV disables it.
- **Device identification:** CTAPHID_WINK briefly names the software key in a
  desktop notification with no approval buttons. It expires after two seconds
  and does not authorize an operation. CTAPHID_LOCK supports channel leases
  of up to ten seconds, renewed or released by their owner.
- **Rust throughout:** pure-Rust cryptography, and `unsafe` code only where
  pqkey calls into the operating system.

> [!WARNING]
> pqkey is a research project, not for production use. A software key is not a
> hardware key: its private keys are files in your home directory, which
> anything running as you, or as root, can use. See [SECURITY.md](SECURITY.md)
> for the threat model.

FIDO clients can identify a connection with WINK even when a notification
server cannot show action buttons. If delivery fails or exceeds 500 ms, WINK
returns a transport error; the key remains usable. Identification also works
with PIN complexity and always-UV enabled. LOCK is volatile: expiry or daemon
shutdown releases it, while channel resynchronization and authenticator reset
preserve an unexpired lease. Clients should release leases in cleanup handlers.

## Install

You need Linux with systemd and the `uhid` module (Ubuntu, Debian and Fedora
have it), and a desktop whose notifications show request text and support
approval actions (GNOME, KDE Plasma or Dunst). Copy this one command:

```bash
git clone --branch stable https://github.com/rainzhang05/SoftwareAuthenticator.git && SoftwareAuthenticator/install.sh
```

`stable` follows the newest commit on `main` that passed CI, E2E and Security.

The installer says how much disk space it will use (about 1.2 GB with the
build tools and Rust), asks once to continue, and shows its progress as it:

1. installs a C linker, Rust and ACL tools, if they are missing, and updates
   rustup's stable Rust if it is older than pqkey needs;
2. builds pqkey and installs it as `/usr/local/bin/pqkey`;
3. gives the key access to `/dev/uhid` with
   [udev rules](contrib/udev/70-pqkey.rules), and loads the `uhid` module at
   every boot;
4. starts the key as a systemd user service and asks you to choose its PIN.

sudo asks for your password after the build, and also before it when the
installer installs a C linker, curl or ACL tools. After the build it asks
only on a terminal, never through a helper program (`SUDO_ASKPASS`, or
askpass in `sudo.conf`): without a terminal, the installer goes on only where
sudo needs no password, as with a `NOPASSWD` rule, and otherwise stops and
asks you to run it in a terminal. When the installer ends, it has sudo forget
the password, whether it finishes, fails, is interrupted with Ctrl-C or
`kill`, or loses its terminal; a signal that kills it before then, such as
`kill -9`, leaves the password cached until sudo's `timestamp_timeout`
expires.

The installer trusts the system's own commands, the Rust toolchain that
rustup installs, and the pqkey it builds, with the code of pqkey's
dependencies in it: installing a program trusts it. It does not trust the
code the build runs, the build scripts and procedural macros of those
dependencies, nor what that code writes or leaves running. So:

- before it installs or updates Rust or builds pqkey, it has sudo forget
  your password;
- Rust's installer and updates, and the build, run in a session of their
  own, without your terminal, and what they leave running there is stopped
  before sudo asks again;
- the installer reads all of itself before it runs, so that the build cannot
  change what it does by changing the file; it starts again, once, in a clean
  shell, which reads none of your startup files, and from then on sources
  none of your files and runs only `/usr/local/bin/pqkey` and commands from
  directories that only root can change; installing and running Rust, and
  the build, use your `PATH`;
- it clears every `LD_` variable, such as `LD_PRELOAD` and
  `LD_LIBRARY_PATH`, with which a program loads code from files they name,
  and the other variables glibc removes for set-user-ID programs, and gives
  them back only to Rust's installer and updates, and to the build.

What remains, which the installer cannot prevent:

- Whatever your account can do without typing a password, the build can do
  too: with a `NOPASSWD` rule in sudoers, or as a member of a group as good as
  root, such as `docker`, or Debian's `staff` where it is set up to write
  `/usr/local/bin`, which sudo's `secure_path` puts before `/usr/bin`.
- With `timestamp_type=global` in sudoers, sudo caches one password for all
  of your terminals, so the build can use one you type in another terminal
  while it runs, and what the build changed can use the one the installer
  asks for after the build, if it runs while that one is cached: a drop-in
  for pqkey's user service, for example, which `pqkey setup` starts, or the
  startup files of a terminal you open.
- The build itself runs as you, so it can change your files: your shell's
  startup files, which later sessions run; commands in directories on your
  `PATH` that you can write, such as `~/.local/bin` and `~/.cargo/bin`, which
  run when you type them, in this terminal too, and can use any password you
  give sudo afterwards; this clone, which your next update builds and runs;
  and the pqkey it builds, which the installer runs as `pqkey setup` with your
  password cached. Where `kernel.yama.ptrace_scope` is 0, or Yama is absent,
  it can also run code in programs you run, the installer included.
- A process the build starts that leaves its session (with `setsid`, `at` or
  `systemd-run`, say), or that forks and exits faster than the installer can
  find it, can go on doing all that after the build, and also: use the
  password you type after the build, with `timestamp_type=global`; read it
  from the terminal as you type it; and change the script `pqkey setup` hands
  to sudo.

A successful installation means the installed service is running, its HID
client can exchange messages, the configured presence provider is usable,
and its PIN requirements are complete. `pqkey` works in the same terminal,
with no reboot or new login. Missing requirements produce a nonzero exit
status and instructions; the installer log is `~/.cache/pqkey/install.log`
(or `$XDG_CACHE_HOME/pqkey/install.log`).

`./install.sh --yes` approves installation; you still choose and confirm the
PIN. Without terminal input, a fresh key remains installed but setup fails
until you rerun `./install.sh` in a terminal and choose its PIN, except where
sudo needs your password and has no terminal to ask on: then the installer
stops before installing pqkey. A configured key can be updated without PIN
input unless its policy requires a PIN change.
If your terminal's PATH excludes `/usr/local/bin`, run
`export PATH="/usr/local/bin:$PATH"` in that terminal and rerun the installer.

Before upgrading, stop the key and back up its complete state directory,
including the keys. Then run `git pull` and `./install.sh` again in the clone.
If the clone follows `main`, switch it to `stable` once with
`git fetch origin && git switch stable`. Reruns repair
partial setup and preserve credentials, valid PINs and authenticator policy.
Updates replace the executable atomically. If setup fails after replacement,
the previous executable remains at `/usr/local/bin/pqkey.previous`; the
installer prints retry and restore commands. The recovery copy is removed
after successful setup.

Registering or replacing a discoverable credential upgrades older stores to
the [authenticated membership format](docs/architecture.md). Restore only the
executable when the previous version understands that format. A version
predating this format requires its matching complete state backup as well;
credentials created after that backup will be absent.

> [!NOTE]
> Anyone who can open `/dev/uhid` can create any HID device, keyboards
> included. The rules give it to the `plugdev` group, and the installer adds
> you to that group if you are not in it yet (on Ubuntu you already are).
> An ACL grants this user immediate access while the current session and user
> service manager still have their old groups. The key's hidraw device is
> open to the user of the session that is active on the seat (`uaccess`).
> When logind's record of the seat names another user's session, or a login
> screen, the key removes its device, and it creates a new one once the
> record names your session, or none, again. It keeps no device while it
> cannot tell from the record who is active. So that it cannot miss a switch
> away and back, it also replaces its device whenever logind saves the
> record, even when you stay active, as when another session on the seat
> starts or ends. With systemd 257 and older, or elogind, the other user can
> still reach the key in the moment they switch in;
> [SECURITY.md](SECURITY.md#other-users-sessions) says what that allows,
> what else remains and how to close it.

## Usage

Register pqkey on any site that supports passkeys or security keys, and approve
the notification that appears.

Dunst exposes the Approve and Deny actions in its context menu: run
`dunstctl context`, or use your configured context-menu shortcut, then select
the action. Denial and an unanswered request's default 30-second timeout both
reject the request. Cancelling the client or restarting the service withdraws
its pending prompt.

Fresh installation and a baseline-to-current update passed the
[native installed desktop acceptance run](https://github.com/rainzhang05/SoftwareAuthenticator/actions/runs/38828959894)
on Ubuntu 24.04 x86_64 on 2026-10-15. All 49 checks passed, including default
Dunst approval/denial, timeouts, cancellation, restart recovery and retained
passkeys, PIN and policy. The [guide](tests/desktop/README.md) records the exact
source and environment. Actions were automated in real Dunst/dmenu; this does
not establish physical human presence.

| Command | What it does |
|---|---|
| `pqkey` | Shows the key's status, its PIN, its free passkey slots and anything to fix |
| `pqkey pin` | Sets or changes the PIN |
| `pqkey config` | Shows always-UV and PIN policy settings |
| `pqkey config always-uv on\|off` | Requires or stops requiring the PIN |
| `pqkey config min-pin-length N [--rp RP_ID]...` | Raises the PIN minimum |
| `pqkey config pin-complexity [--yes]` | Enables the ASCII letter and digit rule |
| `pqkey config force-pin-change` | Requires a different PIN |
| `pqkey passkeys` | Lists the passkeys stored on the key |
| `pqkey passkeys delete QUERY` | Deletes the passkey whose site, user or ID contains `QUERY` |
| `pqkey repair` | Repairs a damaged credential store, with the key stopped |
| `pqkey reset` | Erases credentials, large blobs and PIN; resets settings |
| `pqkey stop`, `pqkey start` | Unplugs and plugs in the key |

Passkey listing uses CTAP 2.3 persistent read-only credential management when
advertised, with ordinary credential-management authorization for older peers.
The native client keeps its token in memory for that invocation; it adds no disk
cache. Persistent grants survive daemon restarts and transient-token expiry.
Changing the PIN, resetting the authenticator, or publishing a policy that
requires a PIN change revokes them. Deletion obtains writable authorization.

Configuration changes ask for the current PIN when one is set. Always-UV
requires the PIN for registrations and sign-ins that ask for user presence.
Without a PIN, turn always-UV off or set one with `pqkey pin` before using
the key in a browser.

The minimum PIN length counts Unicode code points, from 4 to 63, with a
separate limit of 63 UTF-8 bytes. Raising it asks for confirmation, unless
`--yes` is given: only `pqkey reset`, which erases every passkey and large
blob, can lower it again. Repeated `--rp` options replace the RP IDs allowed
to receive the `minPinLength` extension; omitting them keeps the list. A key
can remember 8 RP IDs, each up to 253 bytes. The complete configuration request
must also fit the key's advertised 1,768-byte message limit, including CBOR
and PIN authentication. If it is too large, pqkey reports its encoded size
and limit before sending the command; use fewer or shorter RP IDs. The list
is applied in one operation. If a PIN change becomes required,
run `pqkey pin` and choose a different PIN meeting the current minimum.

Enable [PIN complexity](docs/pin-complexity-policy.md) with
`pqkey config pin-complexity`. New PINs must then contain an ASCII letter and
digit in addition to meeting the length requirements. Only reset disables it;
enabling with an existing PIN requires one replacement.

`pqkey passkeys` lists only passkeys, which are discoverable credentials. A
site that registers the key as a second factor keeps the credential's ID and
sends it back to sign in, so the key does not list that credential. The
prompt makes the difference clear, saying "Create a passkey" or "Register a
security key".
Like a hardware key, pqkey accepts a reset only within 10 seconds of being
plugged in, so `pqkey reset` restarts it first. The key's state lives in
`~/.local/share/pqkey`.

FIDO clients can store a serialized large-blob array of up to 16,384 bytes,
transferred in fragments of at most 1,704 bytes. Writes require the PIN's
large-blob write permission when a PIN is set or always-UV is on. Reset
restores the empty array; deleting a credential leaves blob collection to
the client. Discoverable credentials registered with `largeBlobKey` keep a
secret 32-byte key for platforms to encrypt and decrypt their blobs.

Credentials explicitly registered with `thirdPartyPayment: true` retain that
metadata for both discoverable and non-discoverable credentials. Assertions
requesting it return the stored boolean inside signed authenticator data;
creation returns no payment extension output. `pqkey passkeys` marks enabled
passkeys in its PAYMENT column. Enabled non-discoverable credentials consume
storage but still require their RP's allow list and remain outside passkey
management. Ordinary eligible credentials continue to use sealed IDs.

The flag does not grant cross-RP access or implement a payment prompt. The client
platform determines payment eligibility and UI, including Secure Payment
Confirmation (SPC). Authenticator regressions and libfido2 signed-byte checks
are separate from browser/SPC verification; see the
[verification notes](docs/development-notes.md#third-party-payment-verification).

Brainpool ESB256 (-265) uses brainpoolP256r1/SHA-256 and ESB384 (-267)
uses brainpoolP384r1/SHA-384, as [RFC 9864 §2.1](https://www.rfc-editor.org/rfc/rfc9864.html#section-2.1)
and the [IANA COSE registries](https://www.iana.org/assignments/cose/) specify.
Public keys carry both coordinates (crv 256/258; 32/48 bytes), and signatures
are ASN.1 DER ECDSA. Both credential modalities use stored 33-byte IDs: even
non-discoverable Brainpool credentials consume one storage slot and reduce
remaining capacity. Both modalities keep their own counters. Non-discoverable
records keep no user information; credential enumeration lists discoverable
credentials only.

Independent Python cryptography/OpenSSL fixtures verify Brainpool derivation,
attestation and assertion signatures. Raw Python FIDO HID tests are provided;
actual HID execution requires Linux with `/dev/uhid`. Chromium 158.0.8107.0
verified both Brainpool algorithms; Firefox 158.0 reported client limits.
libfido2 1.14.0 retains their advertised algorithm IDs but cannot create, verify
or decode these credential keys for enumeration. These
limits do not change authenticator support or the client compatibility table.

## Clients

The browser rows below were verified over real Linux UHID on 2026-10-15 in the
[native acceptance run](https://github.com/rainzhang05/SoftwareAuthenticator/actions/runs/38818030676).
The [acceptance guide](tests/browser/ACCEPTANCE.md) records the exact versions,
source and preset outcomes. Earlier manual observations remain in the
[development notes](docs/development-notes.md#clients).

| Client | ES256 | ML-DSA | Notes |
|---|:---:|:---:|---|
| Chromium 158.0.8107.0 | ✓ | ✓ | All 21 algorithms verified, including Brainpool; passkeys need a PIN |
| Firefox 158.0 | ✓ | | 15 algorithms verified; ML-DSA, Brainpool and ES256K are client limits |
| python-fido2 2.2.1 | ✓ | ✓ | Used by the end-to-end tests |
| libfido2 1.14.0 | ✓ | | PIN, credential management, U2F and `hmac-secret` verified in native HID CI |

Browser acceptance uses Ubuntu 24.04 x86_64 with automated PIN/account prompts
and explicit auto-approve presence. The Python/libfido2 HID suites run on x86_64
and aarch64. Browser signatures are independently verified, including algorithms
whose public keys must be read from the attestation object. See
[Clients](docs/development-notes.md#clients) for outcomes and limits.

Credential management also supports the backwards-compatible `0x41` command
used by libfido2 1.14.0, including its user-update operation. It accepts legacy
ClientPIN tokens and modern CM tokens with their RP restrictions. Older native
clients can decode only their supported classic algorithms; enumeration still
returns every supported credential. The native pqkey client continues to use
standard `0x0A`. See the
[preview verification notes](docs/development-notes.md#credential-management-preview-verification)
for regression coverage and execution limits.

## Troubleshooting

`pqkey status` names anything that is missing and how to fix it, and
`scripts/diagnose.sh` shows the whole state of the key on your computer. For
browser behaviour, see
[Troubleshooting](docs/development-notes.md#troubleshooting).

If the PIN looks blocked, or the key says it could not read or write its
state, restart it with `pqkey stop && pqkey start` and run `pqkey status`
again before you reset it: a restart clears a block that came from a PIN state
the key could not read, while `pqkey reset` erases every passkey.
`journalctl --user -u pqkey` says what the key could not read or write, and
`pqkey reset` asks again if its own restart unblocks the PIN.

**Damaged credential store.** `pqkey status` and `journalctl --user -u pqkey`
name damaged files of the credential store in the key's state directory,
`~/.local/share/pqkey` by default, and what the key cannot do because of
them. To repair the store:

1. Stop the key with `pqkey stop`, and keep a copy of the whole state
   directory, `keys/` included: `cp -a ~/.local/share/pqkey ~/pqkey-copy`.
2. Run `pqkey repair`. It lists the damage and what it will do, and asks
   before it changes the store. Each file of the store that it replaces or
   removes, damaged or not, is kept in a new directory in `damaged/` in the
   state directory.
3. Start the key again with `pqkey start`.

If the key's list of its credentials, `credential-set/active`, is intact,
repair takes the credentials whose records are missing or damaged out of the
list and keeps the rest. If the list itself is missing, damaged or
unreadable, repair builds a new one from the records in `credential-set/`
that are intact. A passkey that was deleted or replaced, or whose
registration failed, can come back that way if its record was left behind,
alone or beside another passkey of its account; the plan names each account
that will have more than one passkey. If records of a store in the older
format, in `credentials/`, are damaged, repair upgrades the store to the
authenticated membership format without them, as registering a passkey
would. A damaged `credential-format` is written again. A lost directory
takes the credentials stored in it with it, and the plan says which
directory repair creates again, without them. Repair leaves the PIN and the
keys in `keys/` as they are, so unlike `pqkey reset` it does not end the
sign-ins of sites that registered the key as a security key, unless the key
stored their credentials: it stores some, such as those with an RSA or
Brainpool key or with payment enabled, and older ones.

Sites that registered the key as a security key see a count of its sign-ins
that grows with each one, up to the largest count, 4294967295. The key keeps
that count in `signature-counter` for all of them, unless it stored their
credentials, which keep their own. If `signature-counter` is damaged, the key
cannot sign in to those sites, and the count is lost. Repair writes a new count
above the number of seconds since 1970 by the computer's clock, above the time
on the damaged file, in case the clock has gone back since that file was
written, and above every count it reads, up to the largest count. It leaves
out a time at or past that count, 06:28:15 UTC on 7 February 2106, whether the
clock's or a file's. When repair builds a new list of the credentials and
keeps one copy of a stored credential's record while another copy is damaged,
it raises that credential's count the same way. An intact list names the copy
the key signed with, which keeps its count, so repair raises nothing there.

For a repair before 06:28:15 UTC on 7 February 2106, each count it writes or
raises this way is above every count the key returned on that counter, so the
count a site sees jumps forward and does not go back, if all of these hold:

- at each sign-in and each repair, the key had signed fewer times than whole
  seconds had passed since 1970, and since any earlier repair ended;
- the clock never ran ahead, and every time on the state directory and its
  files came from this computer's clock, not from a hand edit, a copy that
  kept its times (`cp -a`, `tar`, `rsync -a`) or a fault that damaged the
  file;
- the clock is right during the repair, or the damaged file still has the
  time a right clock gave it when the key last signed or later: nothing has
  changed that time since.

The key never uses what repair moved into `damaged/`, and nothing deletes it.
The records in it stay readable with the key in `keys/`, as the store's own
are, until `pqkey reset` replaces that key. You may delete `damaged/` once the
key works again.

Delete the copy once the key works again: it holds the keys, so it would keep
your passkeys readable even after a later reset. If `pqkey repair` stops
before it lists the damage, unable to read a file or to replace a directory
where `signature-counter` should be, it names it and says what to do: make the
file readable or, for a credential's record that cannot be read at all, or
that directory, check that the computer's clock is right, then move it out of
the state directory, create an empty file of the same name in its place, for
example with `touch`, and run `pqkey repair` again. A clock that is behind
then can let the count go back. Repair then treats the empty file as a damaged
record or counter, and the plan shows what follows. Apart from that, do not
edit, delete or replace `credential-format`, `signature-counter` or the files
in `credential-set/` or `credentials/` by hand: an older
`credential-set/active` hides the passkeys registered since, the next change
to that list can delete the record files it does not name, and a deleted
`signature-counter` counts again from 0. If `pqkey status` says the store
cannot be checked because a key file in `keys/` is missing, restore that file
from a copy of the state directory made since the last reset. `pqkey reset`
erases every passkey, so use it only as a last resort.

## Uninstall

```bash
pqkey setup --uninstall
```

This stops the key and removes its service. It then prints one `sudo` command
that removes pqkey, its udev rules and the `uhid` setting. Your passkeys stay
in `~/.local/share/pqkey` until you delete that directory.

## Documentation

- [SECURITY.md](SECURITY.md): the threat model, and how to report a
  vulnerability
- [Architecture](docs/architecture.md): how pqkey works, and what it supports
  of CTAP 2.3
- [Development notes](docs/development-notes.md): the scripts that run every
  check and test (`scripts/check.sh`, `scripts/e2e.sh` and more), and
  troubleshooting
- [Browser test kit](tests/browser/README.md): a local relying party that
  checks everything the key returns

## License

pqkey is free software under the [MIT License](LICENSE): you may use, change
and share it, as long as the copyright notice comes with it. It comes with no
warranty.
