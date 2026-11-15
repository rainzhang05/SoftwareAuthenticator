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
- **Rust throughout:** pure-Rust cryptography, and `unsafe` code only where
  pqkey calls into the operating system and in the allocator that wipes freed
  memory.

> [!WARNING]
> pqkey is a research project, not for production use. A software key is not a
> hardware key: its private keys are files in your home directory, which
> anything running as you, or as root, can use. See [SECURITY.md](SECURITY.md)
> for the threat model.

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
only on a terminal, never through a helper program (`SUDO_ASKPASS`). The
installer has sudo forget your password before it installs or updates Rust
and builds pqkey, and again when it ends;
[SECURITY.md](SECURITY.md#what-it-does-not-protect-against) says what the
code that builds pqkey can still do.

The installer says "pqkey is ready" only once the key runs as the installed
service, its device opens and answers, a notification server on its session
bus says it can show buttons and text (setup shows no prompt), and its PIN is
set and usable. `pqkey` then works in the same terminal, with no reboot or new
login. Otherwise the installer says what to fix before you rerun it; its log
is `~/.cache/pqkey/install.log` (or `$XDG_CACHE_HOME/pqkey/install.log`).

`./install.sh --yes` skips the question, not the PIN: without a terminal, the
installer stops before installing pqkey if sudo needs your password, and
otherwise at a new key's PIN. If your terminal's PATH excludes
`/usr/local/bin`, run `export PATH="/usr/local/bin:$PATH"` in that terminal
and rerun the installer.

> [!NOTE]
> Anyone who can open `/dev/uhid` can create any HID device, keyboards
> included. The rules give it to the `plugdev` group, and the installer adds
> you to that group if you are not in it yet (on Ubuntu you already are).
> The key removes its own device while another user's session or a login
> screen is active on the seat, but with systemd 257 and older, or elogind,
> that user can still reach it as they switch in
> ([SECURITY.md](SECURITY.md#other-users-sessions)).

## Update

Stop the key with `pqkey stop`, back up its whole state directory, `keys/`
included, and run `git pull && ./install.sh` in the clone; switch a clone of
`main` to `stable` first with `git fetch origin && git switch stable`.
Updates keep passkeys, the PIN and its policy, and ask for no PIN unless the
policy requires a new one. If setup then fails, the previous executable stays
at `/usr/local/bin/pqkey.previous`, and the installer says how to retry or
restore it. Restore it alone only if it reads the store's
[current format](docs/architecture.md#credential-store); otherwise restore
your state backup with it, losing the credentials created since.

## Usage

Register pqkey on any site that supports passkeys or security keys, and approve
the notification that appears.

Dunst shows Approve and Deny in its context menu: run `dunstctl context`, or
use your context-menu shortcut. Denying, or not answering within 30 seconds,
rejects the request; cancelling it in the client, or restarting the key,
withdraws the prompt.

| Command | What it does |
|---|---|
| `pqkey` | Shows the key's status, PIN and free passkey slots, and each problem it finds with its fix |
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

Configuration changes ask for the current PIN when one is set. Always-UV
requires the PIN for registrations and sign-ins that ask for user presence.
Without a PIN, turn always-UV off or set one with `pqkey pin` before using
the key in a browser.

The minimum PIN length counts Unicode code points, from 4 to 63; a PIN also
has at most 63 bytes in UTF-8. Raising the minimum asks for confirmation,
unless `--yes` is given: only `pqkey reset`, which erases every passkey and
large blob, can lower it again. Repeated `--rp` options replace the list of
up to 8 RP IDs allowed to receive the `minPinLength` extension; omitting
them keeps the list. [PIN complexity](docs/pin-complexity-policy.md) requires
an ASCII letter and digit in every new PIN, and only reset disables it. When
a PIN change becomes required, run `pqkey pin` and choose a different PIN
that meets the current policy.

`pqkey passkeys` lists only passkeys, which are discoverable credentials. A
site that registers the key as a second factor keeps the credential's ID and
sends it back to sign in, so the key does not list that credential. The
prompt makes the difference clear, saying "Create a passkey" or "Register a
security key".
Like a hardware key, pqkey accepts a reset only within 10 seconds of being
plugged in, so `pqkey reset` restarts it first. The key's state lives in
`~/.local/share/pqkey`.

The key also stores [large blobs](docs/architecture.md#what-the-key-supports)
for clients, keeps [payment-enabled credentials](docs/architecture.md#credential-store),
marked in the PAYMENT column of `pqkey passkeys` (the browser handles
payment), and creates [Brainpool credentials](docs/architecture.md#brainpool-credential-keys),
which take a storage slot even when they are not passkeys. A client you give
the PIN can get a
[persistent read-only permission](docs/architecture.md#persistent-read-only-management)
that lists your passkeys until the PIN changes or the key is reset.

## Clients

The browser rows were verified over real Linux UHID on Ubuntu 24.04 x86_64 on
2026-10-15, in the
[native acceptance run](https://github.com/rainzhang05/SoftwareAuthenticator/actions/runs/38818030676),
with presence approved automatically; the end-to-end tests run python-fido2
and libfido2 on x86_64 and arm64. [Clients](docs/development-notes.md#clients)
in the development notes gives the versions, outcomes and limits.

| Client | ES256 | ML-DSA | Notes |
|---|:---:|:---:|---|
| Chromium 158.0.8107.0 | ✓ | ✓ | All 21 algorithms verified, including Brainpool; passkeys need a PIN |
| Firefox 158.0 | ✓ | | 15 algorithms verified; ML-DSA, Brainpool and ES256K are client limits |
| python-fido2 2.2.1 | ✓ | ✓ | Used by the end-to-end tests |
| libfido2 1.14.0 | ✓ | | PIN, credential management, U2F and `hmac-secret` verified in native HID CI |

## Troubleshooting

`pqkey status` checks the service, device access, notifications, the state
directory's filesystem and the credential store, and names a fix for each
problem it finds. `scripts/diagnose.sh` shows the whole state of the key on
your computer. For browser behaviour, see
[Troubleshooting](docs/development-notes.md#troubleshooting).

`pqkey status` shows no notification, so it cannot see a notification server
that fails to show a prompt. The key logs why it denied each request it could
not ask about: `journalctl --user -u pqkey`, or `authenticator.log` in the
state directory for a key that `pqkey start` ran without the service.

If the PIN looks blocked, or the key says it could not read or write its
state, restart it with `pqkey stop && pqkey start` and run `pqkey status`
again before you reset it: a restart reads the PIN state again, which clears
a block that came from a disk or permission error, while `pqkey reset` erases
every passkey. `journalctl --user -u pqkey` says what the key could not read
or write, and `pqkey reset` asks again if its own restart unblocks the PIN.

**Damaged credential store.** `pqkey status` and the key's journal name the
damaged files and what the key cannot do because of them. To repair the store:

1. Stop the key with `pqkey stop`, and keep a copy of the whole state
   directory, `keys/` included: `cp -a ~/.local/share/pqkey ~/pqkey-copy`.
2. Check that the computer's clock is right, since repair restarts a damaged
   signature counter from it. Run `pqkey repair`: it shows what it will do
   and asks first, or, if it stops before that, says what to do.
3. Start the key again with `pqkey start`. Once it works, delete the copy:
   it holds the keys, so it would keep your passkeys readable even after a
   later reset.

Repair keeps the PIN, the keys and every passkey whose record is intact
([its rules](docs/architecture.md#credential-store)), and moves what it
replaces or removes into `damaged/` in the state directory. The key never
uses that; its records stay readable with the keys in `keys/` until a reset,
and you may delete it once the key works. Apart from what repair asks, never
edit, delete or replace the store's files by hand: an older
`credential-set/active` hides the passkeys registered since, and the next
change deletes their records; a deleted `signature-counter` counts again
from 0. `pqkey reset` erases every passkey, so use it only as a last resort.

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
  check and test (`scripts/check.sh`, `scripts/e2e.sh` and more), the
  acceptance runs, and troubleshooting
- [Browser test kit](tests/browser/README.md): a local relying party that
  checks everything the key returns

## License

pqkey is free software under the [MIT License](LICENSE): you may use, change
and share it, as long as the copyright notice comes with it. It comes with no
warranty.
