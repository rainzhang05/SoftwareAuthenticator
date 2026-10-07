# pqkey

**A FIDO2 security key in software for Linux, with post-quantum ML-DSA passkeys.**

[![CI](https://github.com/rainzhang05/SoftwareAuthenticator/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/rainzhang05/SoftwareAuthenticator/actions/workflows/ci.yml)
[![E2E](https://github.com/rainzhang05/SoftwareAuthenticator/actions/workflows/e2e.yml/badge.svg?branch=main)](https://github.com/rainzhang05/SoftwareAuthenticator/actions/workflows/e2e.yml)
[![Security](https://github.com/rainzhang05/SoftwareAuthenticator/actions/workflows/security.yml/badge.svg?branch=main)](https://github.com/rainzhang05/SoftwareAuthenticator/actions/workflows/security.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

pqkey shows up in your browser as an ordinary USB security key. A user daemon
creates a virtual HID device through the kernel's `uhid` driver, so any FIDO2
client can use it, and every registration, reset and sign-in that asks for
your presence waits for you to approve it in a desktop notification.

- **Post-quantum:** ML-DSA-44, ML-DSA-65 and ML-DSA-87 credentials (FIPS 204),
  alongside ECDSA (ES256, ESP256, ES384, ESP384, ES512, ESP512 and ES256K),
  EdDSA (EdDSA, Ed25519 and Ed448), and RSA-2048 (RS256, RS384, RS512,
  PS256, PS384 and PS512).
- **CTAP 2.3:** PIN (protocols 1 and 2), passkeys with credential management,
  `credBlob`, `hmac-secret`, `hmac-secret-mc`, `credProtect`, and packed
  self-attestation.
- **Rust throughout:** pure-Rust cryptography, and `unsafe` code only where
  pqkey calls into the operating system.

> [!WARNING]
> pqkey is a research project, not for production use. A software key is not a
> hardware key: its private keys are files in your home directory, which
> anything running as you, or as root, can use. See [SECURITY.md](SECURITY.md)
> for the threat model.

## Install

You need Linux with systemd and the `uhid` module (Ubuntu, Debian and Fedora
have it), and a desktop whose notifications show buttons (GNOME, KDE Plasma or
dunst). Copy this one command:

```bash
git clone https://github.com/rainzhang05/SoftwareAuthenticator.git && SoftwareAuthenticator/install.sh
```

The installer says how much disk space it will use (about 1.2 GB with the
build tools and Rust), asks once to continue and once for your sudo password,
and shows its progress as it:

1. installs a C linker and Rust, if they are missing;
2. builds pqkey and installs it as `/usr/local/bin/pqkey`;
3. gives the key access to `/dev/uhid` with
   [udev rules](contrib/udev/70-pqkey.rules), and loads the `uhid` module at
   every boot;
4. starts the key as a systemd user service and asks you to choose its PIN.

When it finishes, the key is running and `pqkey` works in the same terminal,
with no reboot or new login. To update, run `git pull` and then
`./install.sh` again.

> [!NOTE]
> Anyone who can open `/dev/uhid` can create any HID device, keyboards
> included. The rules give it to the `plugdev` group, and the installer adds
> you to that group if you are not in it yet (on Ubuntu you already are).

## Usage

Register pqkey on any site that supports passkeys or security keys, and approve
the notification that appears.

| Command | What it does |
|---|---|
| `pqkey` | Shows the key's status, its PIN, its free passkey slots and anything to fix |
| `pqkey pin` | Sets or changes the PIN |
| `pqkey passkeys` | Lists the passkeys stored on the key |
| `pqkey passkeys delete QUERY` | Deletes the passkey whose site, user or ID contains `QUERY` |
| `pqkey reset` | Erases every credential and the PIN |
| `pqkey stop`, `pqkey start` | Unplugs and plugs in the key |

`pqkey passkeys` lists only passkeys, which are discoverable credentials. A
site that registers the key as a second factor keeps the credential's ID and
sends it back to sign in, so the key does not list that credential. The
prompt makes the difference clear, saying "Create a passkey" or "Register a
security key".
Like a hardware key, pqkey accepts a reset only within 10 seconds of being
plugged in, so `pqkey reset` restarts it first. The key's state lives in
`~/.local/share/pqkey`.

## Clients

| Client | ES256 | ML-DSA | Notes |
|---|:---:|:---:|---|
| Chromium 153 | ✓ | ✓ | Needs a PIN on the key for passkeys |
| Firefox 154 | ✓ | | Ignores algorithms it does not know |
| python-fido2 2.2.1 | ✓ | ✓ | Used by the end-to-end tests |
| libfido2 1.16 | ✓ | | PIN, credential management and `hmac-secret` work |

These were tested on Ubuntu 26.04. Each client's limits are listed under
[Clients](docs/development-notes.md#clients) in the development notes.

## Troubleshooting

`pqkey status` names anything that is missing and how to fix it, and
`scripts/diagnose.sh` shows the whole state of the key on your computer. For
browser behaviour, see
[Troubleshooting](docs/development-notes.md#troubleshooting).

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
