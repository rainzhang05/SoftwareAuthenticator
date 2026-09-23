# pqkey

A FIDO2/WebAuthn security key implemented in software, for Linux. A user daemon
creates a virtual USB HID device through the kernel's `uhid` driver, so
browsers and other FIDO clients see an ordinary USB security key. Besides
ES256 it creates post-quantum **ML-DSA-44, ML-DSA-65 and ML-DSA-87**
credentials (FIPS 204). Written in Rust, with pure-Rust cryptography.

> **A test project (0.1.0), not for production use.** A software key is not a
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
git clone https://github.com/rainzhang05/SoftwareAuthenticator.git
cd SoftwareAuthenticator
cargo build --release --locked -p pqkey
install -D -m 755 target/release/pqkey ~/.local/bin/pqkey
```

Give the `plugdev` group access to `/dev/uhid` with the shipped udev rules,
which also give the key's hidraw node to the active session's user only.
`plugdev` exists on Debian and Ubuntu; the comments in
[`contrib/udev/70-pqkey.rules`](contrib/udev/70-pqkey.rules) cover other
systems.

```bash
sudo install -m 644 contrib/udev/70-pqkey.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
echo uhid | sudo tee /etc/modules-load.d/uhid.conf
sudo modprobe uhid
sudo udevadm trigger
sudo usermod -aG plugdev "$USER"   # then log in again
```

> **Warning.** Anyone who can open `/dev/uhid` can create any HID device,
> keyboards included, and so type into the active session. Only add users you
> would trust with that.

To start the key with your session, install the systemd user unit. Its
comments cover desktops that start their own D-Bus session bus.

```bash
install -D -m 644 contrib/systemd/user/pqkey.service ~/.config/systemd/user/pqkey.service
systemctl --user daemon-reload
systemctl --user enable --now pqkey.service
```

## Usage

```bash
pqkey attach                 # start in the background (--foreground to stay)
pqkey status                 # is it running?
pqkey detach                 # stop it and remove the virtual device

pqkey pin status             # PIN set, retries remaining, blocked
pqkey pin set | change | remove
pqkey reset [--yes]          # delete every credential and the PIN
```

Every registration and sign-in asks for your approval with a desktop
notification. PINs are read from the terminal with echo off, or one per line
from standard input. `pin set|change|remove` and `reset` need the daemon
stopped. The state lives in `~/.local/share/pqkey` (`--state-dir` changes it),
and `pqkey attach --help` lists the other options.

## ML-DSA in clients

A client can only create an ML-DSA credential if it passes the relying party's
ML-DSA algorithms on to the key. As of September 2026, **python-fido2** does,
and **Chromium 155** understands ML-DSA public keys; Firefox and libfido2 drop
them. ES256 credentials, PINs, credential management and `hmac-secret` work
with any CTAP 2.1 client.

## More

- [SECURITY.md](SECURITY.md): the threat model, and how to report a
  vulnerability.
- [docs/architecture.md](docs/architecture.md): how pqkey works, including what
  it supports of CTAP 2.3.
- [docs/development-notes.md](docs/development-notes.md): building, testing,
  fuzzing and troubleshooting.
- [CHANGELOG.md](CHANGELOG.md): what changed.

MIT licensed; see [LICENSE](LICENSE).
