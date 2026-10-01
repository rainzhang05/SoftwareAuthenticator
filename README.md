# pqkey

A FIDO2/WebAuthn security key implemented in software, for Linux. A user daemon
creates a virtual USB HID device through the kernel's `uhid` driver, so
browsers and other FIDO clients see an ordinary USB security key. Besides
ES256 it creates post-quantum **ML-DSA-44, ML-DSA-65 and ML-DSA-87**
credentials (FIPS 204). Written in Rust, with pure-Rust cryptography.

> **A test project, not for production use.** A software key is not a
> hardware key: its private keys are files in your home directory, which
> anything running as your user, or as root, can read and use. User presence
> is a desktop notification, not a touch. See [SECURITY.md](SECURITY.md) for
> the threat model.

## Requirements

- Linux with the `uhid` kernel module.
- A desktop notification server that shows action buttons (GNOME Shell, KDE
  Plasma, dunst). Without one, every request that needs your approval is
  denied.
- Rust 1.89 or later to build.

## Install

```bash
cargo install --locked --git https://github.com/rainzhang05/SoftwareAuthenticator pqkey
pqkey setup
```

Cargo installs `pqkey` in `~/.cargo/bin`, which rustup's installer adds to
your PATH (from your next login). `pqkey setup` installs a systemd user
service that starts the key with your session. The steps that need root it writes to a short script, shows it to
you, and asks you to run it with `sudo sh`, then `pqkey setup` again:

- udev rules ([`contrib/udev/70-pqkey.rules`](contrib/udev/70-pqkey.rules))
  that give `/dev/uhid` to the `plugdev` group, and the key's device to the
  active session's user and to the Firefox and Chromium snaps (Ubuntu's
  browsers);
- loading the `uhid` module at boot;
- adding you to `plugdev`, if you are not in it yet (on Ubuntu you are), after
  which you log in again.

It ends by offering to set a PIN, which Chromium needs before it uses
passkeys. `pqkey status` shows anything that is still missing, and how to fix
it. `pqkey setup --uninstall` removes the service and prints what undoes the
root part; your passkeys stay in `~/.local/share/pqkey`.

> **Warning.** Anyone who can open `/dev/uhid` can create any HID device,
> keyboards included, and so type into the active session. Only add users you
> would trust with that. On Ubuntu the user created at installation is in
> `plugdev` already, so installing the rules gives that user this access.

The comments in
[`contrib/systemd/user/pqkey.service`](contrib/systemd/user/pqkey.service)
cover desktops that start their own D-Bus session bus.

## Usage

```bash
pqkey start                  # plug the key in
pqkey status                 # is it running, its PIN and free passkey slots (also plain `pqkey`)
pqkey stop                   # pull it out

pqkey pin                    # set the PIN, or change it
pqkey passkeys               # list the passkeys stored on the key (needs the PIN)
pqkey passkeys delete QUERY  # delete the one QUERY names: part of its site, user or ID
pqkey reset [--yes]          # erase every passkey and the PIN
```

Every registration, sign-in and reset asks for your approval with a desktop
notification. `pin`, `passkeys` and `reset` talk to the running key over CTAP,
as a browser's security key settings do, so the key itself checks the PIN and
counts its retries. Like a hardware key, it accepts a reset only within 10
seconds of being plugged in, so `pqkey reset` restarts it first. PINs are read
from the terminal with echo off, or one per line from standard input. When the
systemd user unit is installed, `start` and `stop` go through it. The state
lives in `~/.local/share/pqkey`.

## Clients

Tested on 2026-09-30 on Ubuntu 26.04.1 (aarch64, GNOME 50.1):

| Client | ES256 | ML-DSA-44/65/87 | Notes |
|---|---|---|---|
| Chromium 153 (snap) | yes | yes | `getPublicKey()` returns null for ML-DSA and `toJSON()` leaves the key out, so relying parties read it from the attestation object; `getPublicKeyAlgorithm()` returns -48, -49 or -50. Passkeys and requests that require user verification need a PIN on the key. |
| Firefox 154 (snap) | yes | no | Drops algorithms it does not know: an ML-DSA-only request reaches the key with none (`NotAllowedError`), a mixed one as ES256 only. Without a PIN its account chooser shows "Unknown account". |
| python-fido2 2.2.1 | yes | yes | Used by the end-to-end tests. |
| libfido2 1.16 | yes | no | No ML-DSA credential type; `fido2-token -I` lists the algorithms as unknown, and `fido2-token -L -k` cannot list ML-DSA passkeys (`FIDO_ERR_RX_INVALID_CBOR`, or `FIDO_ERR_RX` for ML-DSA-65 and -87); `pqkey passkeys` can. PINs, credential management and `hmac-secret` work. |

Chromium 155 and later are said to return ML-DSA public keys from
`getPublicKey()`; that is not tested yet. Any CTAP 2.1 client can use ES256
credentials, PINs, credential management and `hmac-secret`.

## When something does not work

`pqkey status` lists what is missing and how to fix it. The troubleshooting
section of [docs/development-notes.md](docs/development-notes.md#troubleshooting)
covers browser behaviour: snap browsers, Chromium asking for a PIN, a prompt
that does not appear on GNOME, and Chromium's error sheet after Deny.

## More

- [SECURITY.md](SECURITY.md): the threat model, and how to report a
  vulnerability.
- [docs/architecture.md](docs/architecture.md): how pqkey works, including what
  it supports of CTAP 2.3.
- [docs/development-notes.md](docs/development-notes.md): building, testing,
  fuzzing and troubleshooting.
- [tests/browser/](tests/browser/README.md): a local relying party that checks
  everything the key returns, for testing in real browsers.
- [CHANGELOG.md](CHANGELOG.md): what changed.

MIT licensed; see [LICENSE](LICENSE).
