# pqkey

A FIDO2/WebAuthn security key implemented in software, for Linux. It runs as a
user daemon that creates a virtual USB HID device through the kernel's `uhid`
driver, so browsers and other FIDO clients see an ordinary USB security key.

Besides classical ES256 it can create post-quantum **ML-DSA-44, ML-DSA-65 and
ML-DSA-87** credentials (FIPS 204). Written in Rust, with pure-Rust
cryptography and no C dependencies.

> **Pre-release software (0.1.0), and a software key is not a hardware key.**
> Credential private keys are files in your home directory; anything running as
> your user, or as root, can read and use them. User presence is a desktop
> notification, not a touch. The on-disk format and command line may still
> change without migration. See [SECURITY.md](SECURITY.md#threat-model) for the
> threat model and [CHANGELOG.md](CHANGELOG.md) for what changed.

## Requirements

- Linux with the `uhid` kernel module. (The workspace builds and its unit tests
  run on macOS, but the daemon does nothing useful there.)
- A D-Bus session bus and a notification server with action buttons — GNOME
  Shell, KDE Plasma, dunst. Without one, every request needing presence is
  denied.
- Rust 1.89 or later and a C linker to build (`build-essential` on Debian and
  Ubuntu). No other system libraries.
- Optional: `fido2-tools` to inspect the device.

## Install

**1. Build.** `~/.local/bin/pqkey` is where the systemd user unit looks.

```bash
git clone https://github.com/rainzhang05/SoftwareAuthenticator.git
cd SoftwareAuthenticator
cargo build --release --locked -p pqkey
install -D -m 755 target/release/pqkey ~/.local/bin/pqkey
```

**2. Device permissions.** Only root can open `/dev/uhid` by default. The
shipped udev rules give the `plugdev` group access to it, and give the user of
the active local session — nobody else — access to the key's hidraw node.

```bash
sudo install -m 644 contrib/udev/70-pqkey.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
echo uhid | sudo tee /etc/modules-load.d/uhid.conf
sudo modprobe uhid
sudo udevadm trigger
sudo usermod -aG plugdev "$USER"   # then log in again, or `newgrp plugdev`
```

> **Warning.** Anyone who can open `/dev/uhid` can create any HID device,
> keyboards included, and so type into whichever session is active. Only add
> users you would trust with that.

`plugdev` exists on Debian and Ubuntu; elsewhere create it or change the group
in the rules file. The hidraw rule matches the default USB IDs `1209:0001` — if
you use `--vendor-id` or `--product-id`, adjust its `DEVPATH` pattern. The
comments in [`contrib/udev/70-pqkey.rules`](contrib/udev/70-pqkey.rules)
explain both.

**3. Run it as a systemd user service** (or skip to [Usage](#usage) and run
`pqkey attach` by hand).

```bash
install -D -m 644 contrib/systemd/user/pqkey.service ~/.config/systemd/user/pqkey.service
systemctl --user daemon-reload
systemctl --user enable --now pqkey.service
```

The service reaches your notification server through the session bus the user
service manager passes to it. If your desktop starts its own bus with
`dbus-launch`, run `systemctl --user import-environment
DBUS_SESSION_BUS_ADDRESS`. If you set `XDG_DATA_HOME` in your shell, set it for
the user manager too (`environment.d(5)`), or the service and the CLI will use
different state directories.

## Usage

Every command takes `--state-dir <DIR>`, defaulting to `$XDG_DATA_HOME/pqkey`
or `~/.local/share/pqkey`. That directory holds the credential store, the lock
and pid files, and the log when the daemon runs in the background.

```bash
pqkey attach                 # start in the background
pqkey attach --foreground    # run here until Ctrl-C or SIGTERM
pqkey status                 # is a daemon running on this state directory?
pqkey detach                 # stop it and remove the virtual device

pqkey pin status             # PIN set, retries remaining, blocked
pqkey pin set | change | remove
pqkey reset [--yes]          # delete every credential and the PIN
```

Only one daemon can use a state directory at a time. `pin set|change|remove`
and `reset` need the daemon stopped; with the systemd unit use `systemctl
--user start|stop pqkey`. Clients can also set PINs and reset the key over
CTAP.

PINs are never taken from command-line arguments: on a terminal they are
prompted for with echo turned off, otherwise each PIN is one line of standard
input (for `pin change`, the current one first).

```bash
printf '%s\n%s\n' "$CURRENT_PIN" "$NEW_PIN" | pqkey pin change
```

A PIN is at least 4 Unicode code points and at most 63 bytes of UTF-8. A wrong
PIN costs one of 8 retries; at 0 it is blocked until a reset.

### Options worth knowing

`pqkey attach --help` lists them all. The ones that change behaviour:

| Option | Default | Meaning |
|--------|---------|---------|
| `--presence <MODE>` | `notify` | `notify` asks with a desktop notification carrying Approve and Deny buttons. `auto-approve` approves everything without asking — **tests and CI only**. |
| `--attestation <MODE>` | `self` | `self` signs with the new credential's own key. `certificate` uses a per-installation certificate, which lets relying parties link your credentials across sites. `none` sends no statement. |
| `--vendor-id` / `--product-id` | `0x1209` / `0x0001` | USB IDs. The default is a [pid.codes](https://pid.codes/1209/0001/) *test* ID, which must not be used on a redistributed device. |

`RUST_LOG` sets the log level (`RUST_LOG=pqkey=debug,pqkey_ctap=debug`).
Without it warnings and errors are logged; debug logs contain relying party
IDs and user names from requests.

## Client support for ML-DSA

A client can only create an ML-DSA credential if it passes the ML-DSA
algorithm identifiers from the relying party on to the authenticator. As of
September 2026 that means **python-fido2** (2.2.1), which the end-to-end tests
use, and **Chromium 155**, which parses ML-DSA COSE keys. Firefox and libfido2
drop algorithms they do not know, so `fido2-token -I` lists the ML-DSA ones as
unknown.

Everything that is not ML-DSA-specific — ES256 credentials, PINs, credential
management, `hmac-secret` — works with any CTAP 2.1 client.

The device speaks CTAPHID_CBOR only (no U2F/CTAPHID_MSG), reports versions
`FIDO_2_3`, `FIDO_2_1` and `FIDO_2_0`, the `credProtect` and `hmac-secret`
extensions, PIN/UV auth protocols 2 and 1, and stores up to 1,000 credentials.
Non-discoverable credentials count too, and since credential management does
not list them, only a reset frees the room they take. User verification is by
PIN only. The full picture is in
[docs/architecture.md](docs/architecture.md).

## Troubleshooting

**Every registration or sign-in fails immediately.** No notification could be
shown, so presence was denied. The log says why — `journalctl --user -u pqkey`,
`<state dir>/authenticator.log`, or the terminal with `--foreground`. Run the
daemon inside your desktop session and check `DBUS_SESSION_BUS_ADDRESS`.

**`insufficient permissions to access /dev/uhid`.** The udev rules are not
installed, you are not in `plugdev`, or you have not logged in again since
joining it. `ls -l /dev/uhid` should show group `plugdev` and mode
`crw-rw----`. If the file is missing, run `sudo modprobe uhid`.

**The key does not show up in the browser.** Check `pqkey status`, then
`fido2-token -L`. If the daemon runs but nothing is listed, the hidraw node is
not accessible to you — check the hidraw rule and its `DEVPATH` pattern.

More debugging commands are in
[docs/development-notes.md](docs/development-notes.md).

## Development

[docs/development-notes.md](docs/development-notes.md) covers building,
testing, fuzzing and the checks CI runs;
[docs/architecture.md](docs/architecture.md) covers how the code is organised.
Report security issues as described in [SECURITY.md](SECURITY.md).

## License

MIT — see [LICENSE](LICENSE).
