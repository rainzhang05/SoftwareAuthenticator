# pqkey

**A FIDO2 security key in software for Linux, with post-quantum ML-DSA
passkeys.**

[![CI](https://github.com/rainzhang05/SoftwareAuthenticator/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/rainzhang05/SoftwareAuthenticator/actions/workflows/ci.yml)
[![E2E](https://github.com/rainzhang05/SoftwareAuthenticator/actions/workflows/e2e.yml/badge.svg?branch=main)](https://github.com/rainzhang05/SoftwareAuthenticator/actions/workflows/e2e.yml)
[![Security](https://github.com/rainzhang05/SoftwareAuthenticator/actions/workflows/security.yml/badge.svg?branch=main)](https://github.com/rainzhang05/SoftwareAuthenticator/actions/workflows/security.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

pqkey shows up in your browser as an ordinary USB security key. A user daemon
creates a virtual HID device through the kernel's `uhid` driver, so any FIDO2
client can use it, and asks you to approve, in a desktop notification, each
registration, reset and sign-in that needs your presence.

- **Post-quantum:** ML-DSA-44, ML-DSA-65 and ML-DSA-87 (FIPS 204), alongside
  ECDSA (NIST, secp256k1 and Brainpool curves), EdDSA (Ed25519 and Ed448) and
  RSA-2048.
- **CTAP 2.3 and U2F:** PIN, passkeys and their management, always-UV, PIN
  policies, large blobs, PRF (`hmac-secret`) and the other
  [standard extensions](docs/architecture.md#what-the-key-supports).
- **Rust throughout:** pure-Rust cryptography, and `unsafe` code only where
  pqkey calls the operating system and in the allocator that wipes freed
  memory.

> [!WARNING]
> pqkey is a research project, not for production use. A software key is not a
> hardware key: its private keys are files in your home directory, which
> anything running as you, or as root, can use. See [SECURITY.md](SECURITY.md).

## Install

You need Linux with systemd and the `uhid` module (Ubuntu, Debian and Fedora
have it), and a desktop whose notifications show request text and support
approval actions (GNOME, KDE Plasma or Dunst). Then run:

```bash
git clone --branch stable https://github.com/rainzhang05/SoftwareAuthenticator.git && SoftwareAuthenticator/install.sh
```

`stable` is the newest commit on `main` that passed CI, E2E and Security. The
installer builds and installs pqkey, starts it as a systemd user service and
asks you to choose a PIN. It says "pqkey is ready" once the key works, and
otherwise what to fix; the [user guide](docs/user-guide.md#install) has the
details.

## Use

Register pqkey on any site that supports passkeys or security keys, and
approve the notification that appears; the
[user guide](docs/user-guide.md#approving-requests) says how on each desktop,
Dunst included.

| Command | What it does |
|---|---|
| `pqkey` | Shows the key's status, and a fix for each problem it finds |
| `pqkey pin` | Sets or changes the PIN |
| `pqkey config` | Shows or changes always-UV and the PIN policy |
| `pqkey passkeys` | Lists passkeys; `pqkey passkeys delete QUERY` deletes one |
| `pqkey repair` | Repairs a damaged credential store, with the key stopped |
| `pqkey reset` | Erases every credential, large blob and the PIN |
| `pqkey stop`, `pqkey start` | Unplugs and plugs in the key |

The key keeps its state in `~/.local/share/pqkey`. If something does not
work, run `pqkey` and follow the fix it names; the
[user guide](docs/user-guide.md#troubleshooting) covers the rest.

## Update

Stop the key with `pqkey stop`, back up `~/.local/share/pqkey`, `keys/`
included, and run `git pull && ./install.sh` in the clone (switch a clone of
`main` to `stable` first: `git fetch origin && git switch stable`). Updates
keep your passkeys, PIN and policy, and ask for a PIN only if the policy
requires a new one.

**Recovery:** if setup fails after an update, the previous executable stays
at `/usr/local/bin/pqkey.previous`, and the installer says how to retry or
restore it. Restore it alone only if it reads the store's
[current format](docs/architecture.md#membership); otherwise restore your
backup with it, losing the credentials created since.

## Uninstall

```bash
pqkey setup --uninstall
```

This stops the key and removes its service, then prints one `sudo` command
that removes pqkey, its udev rules and the `uhid` setting. Your passkeys stay
in `~/.local/share/pqkey` until you delete that directory.

## Documentation

- [User guide](docs/user-guide.md): installing, approving requests, the PIN
  policy, passkeys, browsers, troubleshooting and repair
- [SECURITY.md](SECURITY.md): the threat model, and how to report a
  vulnerability
- [Architecture](docs/architecture.md): how pqkey works, and what it supports
  of CTAP 2.3
- [Development notes](docs/development-notes.md): building, testing and
  releasing pqkey

## License

pqkey is free software under the [MIT License](LICENSE), with no warranty.
