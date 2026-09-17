# pqkey

pqkey is a FIDO2/WebAuthn security key implemented in software, for Linux. It
runs as a user daemon that creates a virtual USB HID device through the
kernel's `uhid` driver, so browsers and other FIDO clients see an ordinary
USB security key. Besides classical ES256 credentials it can create
post-quantum ML-DSA-44, ML-DSA-65 and ML-DSA-87 credentials (FIPS 204). It is
written in Rust with pure-Rust cryptography and no C dependencies.

## Contents

- [Status and limitations](#status-and-limitations)
- [Features](#features)
- [Compatibility](#compatibility)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration reference](#configuration-reference)
- [Troubleshooting](#troubleshooting)
- [Development](#development)
- [License](#license)

## Status and limitations

pqkey is pre-release software (version 0.1.0). No release has been published,
and the on-disk format and command line may still change without migration.

- **Linux only.** The daemon needs `/dev/uhid`. The workspace builds and its
  unit tests run on macOS, but the daemon does nothing useful there.
- **A software key is not a hardware key.** Credential private keys are files
  in your home directory, encrypted with keys stored next to them. Anything
  that runs as your user, or as root, can read and use them. See
  [SECURITY.md](SECURITY.md#threat-model) for exactly what is and is not
  protected.
- **Presence is a desktop notification, not a touch.** Any program that can
  talk to your D-Bus session bus as you can in principle answer or imitate that
  prompt.
- **USB IDs are a test assignment.** By default the device uses vendor ID
  `0x1209` and product ID `0x0001` from [pid.codes](https://pid.codes/1209/0001/).
  pid.codes reserves that product ID for private testing and says it "MUST NOT
  be used on any device that will be redistributed". A dedicated product ID has
  to be registered before pqkey is released.
- **No built-in user verification.** User verification is by PIN only
  (`clientPin`); there is no biometric or `uv` option.
- **Client support for ML-DSA is limited.** See
  [Compatibility](#compatibility).
- **State from earlier versions is not migrated.** Credentials and PINs created
  before the project was renamed and its storage was replaced are lost; the old
  files are deleted when the daemon starts. See [CHANGELOG.md](CHANGELOG.md).

## Features

**Algorithms.** `authenticatorGetInfo` lists these COSE algorithms, and
registration and assertion work with each of them:

| Algorithm | COSE `alg` | Source of the identifier |
|-----------|-----------|--------------------------|
| ES256 (ECDSA P-256 with SHA-256) | -7 | [IANA COSE Algorithms](https://www.iana.org/assignments/cose/cose.xhtml#algorithms) |
| ML-DSA-44 | -48 | [RFC 9964](https://www.rfc-editor.org/info/rfc9964/) |
| ML-DSA-65 | -49 | [RFC 9964](https://www.rfc-editor.org/info/rfc9964/) |
| ML-DSA-87 | -50 | [RFC 9964](https://www.rfc-editor.org/info/rfc9964/) |

ML-DSA public keys are COSE "AKP" keys (key type 7) and signatures are pure,
hedged ML-DSA with an empty context, from RustCrypto's
[`ml-dsa`](https://crates.io/crates/ml-dsa) crate. ML-DSA private keys are
stored as their 32-byte seed.

**Protocol.** The device speaks CTAPHID over a 64-byte HID report and supports
CTAPHID_CBOR only (no U2F/CTAPHID_MSG). `authenticatorGetInfo` reports:

- versions `FIDO_2_3`, `FIDO_2_1` and `FIDO_2_0`;
- extensions `credProtect` and `hmac-secret`;
- options `rk`, `up`, `credMgmt`, `pinUvAuthToken` and `makeCredUvNotRqd`
  (all true) and `clientPin` (true once a PIN is set, false before);
- PIN/UV auth protocols 2 and 1; minimum PIN length 4;
- transport `usb`; the number of credentials that can still be stored (up to
  1,000 in total); attestation format `packed` (omitted with
  `--attestation none`).

**Commands.** authenticatorMakeCredential, GetAssertion, GetNextAssertion,
GetInfo, ClientPIN (getPINRetries, getKeyAgreement, setPIN, changePIN,
getPinToken, getPinUvAuthTokenUsingPinWithPermissions), Reset,
CredentialManagement (metadata, enumerate relying parties and credentials,
delete, update user information) and Selection.

**User presence.** Each registration, sign-in that asks for user presence,
reset and authenticator selection shows a desktop notification with Approve and
Deny buttons (`--presence notify`, the default). If no notification with
buttons can be shown, the request is denied. `--presence auto-approve` approves
everything without asking and is meant for tests only.

**Attestation.** Registrations get self attestation by default: the `packed`
statement is signed with the new credential's own key and identifies nothing
about the authenticator. `--attestation certificate` uses basic attestation
with a certificate generated for this installation; because every credential
carries the same certificate, relying parties can link your credentials across
sites ([WebAuthn Level 3 §14.4.1](https://www.w3.org/TR/webauthn-3/#sctn-attestation-privacy)).
`--attestation none` returns no statement.

**Credential store.** Credentials, the PIN state and the attestation key are
kept in one encrypted, authenticated file per record (XChaCha20-Poly1305) in a
`0700` state directory. A reset replaces the key that protects credentials and
PIN state, so old copies of those files can no longer be decrypted. The design
is described in [docs/architecture.md](docs/architecture.md#credential-store).

## Compatibility

A client can only create an ML-DSA credential if it passes the ML-DSA
algorithm identifiers from the relying party's `pubKeyCredParams` on to the
authenticator. As of September 2026:

| Client | ES256 | ML-DSA |
|--------|-------|--------|
| Chrome / Chromium | Yes | Chromium 155 parses ML-DSA COSE keys, so `getPublicKey()` and `getPublicKeyAlgorithm()` work for them ([commit a609c77](https://chromium.googlesource.com/chromium/src.git/+/a609c77db1d9421494bd274d86cf7717cd596726), first in 155.0.8038.0). Chrome 155 is in beta; its stable release is scheduled for 6 October 2026 ([Chromium Dash schedule](https://chromiumdash.appspot.com/fetch_milestone_schedule?mstone=155)). Earlier versions have not been tested with pqkey. |
| Firefox on Linux | Yes | No. Firefox passes `pubKeyCredParams` through the vendored `authenticator` crate (0.6.0), which drops every algorithm it does not know, and its `COSEAlgorithm` list has no -48, -49 or -50 ([`authrs_bridge/src/lib.rs`](https://github.com/mozilla-firefox/firefox/blob/main/dom/webauthn/authrs_bridge/src/lib.rs), [`authenticator/src/crypto/mod.rs`](https://github.com/mozilla-firefox/firefox/blob/main/third_party/rust/authenticator/src/crypto/mod.rs)). |
| libfido2 (`fido2-token`, `fido2-cred`, `fido2-assert`) | Yes | No. As of release 1.17.0 and its main branch, its COSE algorithms are ES256, EdDSA, ES384, RS256 and RS1 ([`src/fido/param.h`](https://github.com/Yubico/libfido2/blob/main/src/fido/param.h)). `fido2-token -I` lists the ML-DSA algorithms as unknown. |
| python-fido2 2.2.1 | Yes | Yes; the end-to-end tests register and assert ML-DSA credentials with it. |

Everything that is not ML-DSA-specific (ES256 credentials, PINs, credential
management, hmac-secret) works with any CTAP 2.1 client; the end-to-end tests
exercise it with libfido2 and python-fido2.

## Requirements

- Linux with the `uhid` kernel module.
- A D-Bus session bus and a desktop notification server that supports action
  buttons, such as GNOME Shell, KDE Plasma or dunst. Without one every request
  that needs user presence is denied.
- Rust 1.89 or later and a C linker to build (`build-essential` on Debian and
  Ubuntu). No other system libraries are needed.
- Optional: `fido2-tools` (libfido2's command-line tools) to check the device.

## Installation

### 1. Build

```bash
git clone https://github.com/rainzhang05/SoftwareAuthenticator.git
cd SoftwareAuthenticator
cargo build --release --locked -p pqkey
install -D -m 755 target/release/pqkey ~/.local/bin/pqkey
```

`~/.local/bin/pqkey` is where the systemd user unit expects the binary.

### 2. Device permissions

Only root can open `/dev/uhid` by default. The udev rules in
[`contrib/udev/70-pqkey.rules`](contrib/udev/70-pqkey.rules) give the
`plugdev` group access to `/dev/uhid`, and give the user of the active local
session, and nobody else, access to the virtual key's hidraw node. Install
them, load `uhid` now and at every boot, and add yourself to the group:

```bash
sudo install -m 644 contrib/udev/70-pqkey.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
echo uhid | sudo tee /etc/modules-load.d/uhid.conf
sudo modprobe uhid
sudo udevadm trigger
sudo usermod -aG plugdev "$USER"
```

Log out and back in for the group membership to apply (or run `newgrp plugdev`
in the shell you start pqkey from).

> **Warning.** Anyone who can open `/dev/uhid` can create any kind of HID
> device, keyboards included, and so type into whichever session is active.
> Only add users you would trust with that to the group.

`plugdev` exists on Debian and Ubuntu; on other distributions create it or
change the group in the rules file. The hidraw rule matches the default USB
IDs `1209:0001`; if you start pqkey with `--vendor-id` or `--product-id`,
change its `DEVPATH` pattern to match. The comments in the rules file explain
both.

### 3. Run as a systemd user service

[`contrib/systemd/user/pqkey.service`](contrib/systemd/user/pqkey.service)
runs `pqkey attach --foreground` under your user service manager, with
`RUST_LOG=info` and a sandbox that works without privileges:

```bash
install -D -m 644 contrib/systemd/user/pqkey.service ~/.config/systemd/user/pqkey.service
systemctl --user daemon-reload
systemctl --user enable --now pqkey.service
```

The service reaches your desktop's notification server through the session
bus that the user service manager passes to it. If your desktop starts its own
session bus with `dbus-launch` instead, import its address into the user
manager from the desktop session:

```bash
systemctl --user import-environment DBUS_SESSION_BUS_ADDRESS
```

If you set `XDG_DATA_HOME` in your shell, set it for the user manager too (see
`environment.d(5)`), or the service and the CLI will use different state
directories. Do not add `--presence auto-approve` to the unit.

## Usage

Every command takes `--state-dir <DIR>`. The default is `$XDG_DATA_HOME/pqkey`,
or `~/.local/share/pqkey` when `XDG_DATA_HOME` is unset. The directory holds the
credential store (`keys/`, `credentials/`, `pin-state`, `attestation`), the
lock and pid files `authenticator.lock` and `authenticator.pid`, and
`authenticator.log` when the daemon runs in the background.

### Start and stop

```bash
pqkey attach                 # start in the background, log to <state dir>/authenticator.log
pqkey attach --foreground    # run in this terminal until Ctrl-C or SIGTERM
pqkey status                 # is a daemon running on this state directory?
pqkey detach                 # stop it and remove the virtual device
```

`attach` without `--foreground` starts the same binary again in a new session
and returns once the device exists (it gives up after 10 seconds). Only one
daemon can use a state directory at a time. `start` and `stop` are accepted as
aliases of `attach` and `detach`.

With the systemd unit, use `systemctl --user start|stop pqkey` instead;
`pqkey status` reports that daemon too.

### Reset

```bash
pqkey reset          # asks for confirmation
pqkey reset --yes
```

`reset` deletes every credential and the PIN, and replaces the key that
protected them. The attestation key and certificate are kept. The daemon must
be stopped first.

Clients can also reset the key over CTAP (for example from a browser's
security key settings). With `--presence notify` the notification says that a
reset deletes all passkeys and the reset is accepted at any time. With
`--presence auto-approve` it is only accepted within 10 seconds of the daemon
starting, as CTAP 2.3 §6.6 requires of an authenticator without a display.

### PIN

```bash
pqkey pin status     # PIN set, retries remaining, blocked
pqkey pin set
pqkey pin change
pqkey pin remove
```

PINs are never taken from command-line arguments. On a terminal they are
prompted for with echo turned off, and a new PIN must be typed twice. When
standard input is not a terminal, each PIN is one line of standard input; for
`pin change` the current PIN comes first, then the new one:

```bash
printf '%s\n%s\n' "$CURRENT_PIN" "$NEW_PIN" | pqkey pin change
```

A PIN must be at least 4 Unicode code points and at most 63 bytes of UTF-8.
`pin set`, `pin change` and `pin remove` need the daemon stopped; `pin status`
also works while it runs. A wrong PIN uses up one of 8 retries, whether it is
entered here or through a client; at 0 the PIN is blocked until a reset. After
3 wrong PINs in a row the running daemon also refuses PIN checks until it
restarts. Clients can set and change the PIN over CTAP as well.

## Configuration reference

All options below belong to `pqkey attach`. The only option of `detach`,
`status`, `pin set|change|remove|status` is `--state-dir`; `reset` also takes
`--yes`.

| Option | Default | Meaning |
|--------|---------|---------|
| `--state-dir <DIR>` | `$XDG_DATA_HOME/pqkey`, else `~/.local/share/pqkey` | Where the credential store, lock, pid and log files are kept. |
| `--foreground` | off | Run in the foreground (for systemd). |
| `--presence <MODE>` | `notify` | `notify`: ask with a desktop notification with Approve and Deny buttons; without a session bus and a notification server that can show buttons, every request is denied. `auto-approve`: approve every request without asking; anything running as you can then use your passkeys unnoticed. For tests and CI only. |
| `--attestation <MODE>` | `self` | `self`: self attestation with the credential's own key. `certificate`: basic attestation with a certificate generated for this installation; lets relying parties link your credentials across sites. `none`: no attestation statement. |
| `--manufacturer <NAME>` | none | Organization named in a newly generated attestation certificate. Required with `--attestation certificate`. |
| `--country <CODE>` | none | ISO 3166-1 alpha-2 country code named in a newly generated attestation certificate. Required with `--attestation certificate`. |
| `--product <NAME>` | `pqkey FIDO2 Software Authenticator (ML-DSA)` | Product named in a newly generated attestation certificate. |
| `--aaguid <UUID>` | `5931e805-a166-4eb7-845a-7f6aa93d9cd8` | AAGUID reported in authenticatorGetInfo and in every registration; 32 hex digits, hyphens optional. |
| `--name <NAME>` | `pqkey FIDO2 Software Authenticator (ML-DSA)` | HID product name of the virtual device. |
| `--vendor-id <ID>` | `0x1209` | USB vendor ID (pid.codes). Decimal or `0x` hex. |
| `--product-id <ID>` | `0x0001` | USB product ID (a pid.codes test ID, not unique to pqkey). Decimal or `0x` hex. |
| `--version <VERSION>` | `1` | Device version in the HID descriptor. Not the program version, which `pqkey --version` prints. |
| `--backend <BACKEND>` | `uhid` | Transport; `uhid` is the only one. |

The attestation certificate is generated the first time the daemon starts
with `--attestation certificate` and kept across restarts and resets. It is
generated again only if its AAGUID does not match `--aaguid`; changing
`--manufacturer`, `--country` or `--product` later does not replace it.

`RUST_LOG` sets the log level, for example `RUST_LOG=info` or
`RUST_LOG=pqkey=debug,pqkey_ctap=debug`. Without it only errors are logged.
Debug logs contain relying party IDs and user names from requests; info and
higher do not.

## Troubleshooting

**Every registration or sign-in fails immediately.** Presence requests are
denied when no notification can be shown. The log says why, for example "no
D-Bus session bus" or "cannot show Approve and Deny buttons". Read it with
`journalctl --user -u pqkey` (systemd), in `<state dir>/authenticator.log`
(`pqkey attach`), or in the terminal (`--foreground`). Run the daemon inside
your desktop session, check `DBUS_SESSION_BUS_ADDRESS`, and use a notification
server that supports actions.

**`warning: insufficient permissions to access /dev/uhid`.** The udev rules
are not installed, you are not in `plugdev`, or you have not logged in again
since joining it. `ls -l /dev/uhid` should show group `plugdev` and mode
`crw-rw----`. If `/dev/uhid` does not exist, run `sudo modprobe uhid`.

**The key does not show up in the browser.** Check that the device exists and
that you can open it:

```bash
pqkey status
fido2-token -L                  # lists /dev/hidrawN: vendor=0x1209, product=0x0001 ...
ls -l /dev/hidraw*
fido2-token -I /dev/hidrawN     # getInfo, as the key reports it
```

If `fido2-token -L` lists nothing but the daemon runs, the hidraw node is not
accessible to you: check the hidraw rule, and its `DEVPATH` pattern if you
changed the USB IDs.

**`the authenticator daemon is running (pid N); run 'pqkey detach' first`.**
`reset` and `pin set|change|remove` need exclusive use of the state directory.
Stop the daemon (`pqkey detach` or `systemctl --user stop pqkey`) and try again.

**`note: ... is no longer used and can be deleted`.** A state directory from
before the rename (`feitian-mldsa-authenticator`) still exists. pqkey does not
read it.

More commands for debugging on Linux are in
[docs/development-notes.md](docs/development-notes.md).

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md) for building, testing, fuzzing and the
checks CI runs, and [docs/architecture.md](docs/architecture.md) for how the
code is organised. Security issues: see [SECURITY.md](SECURITY.md).

## License

MIT — see [LICENSE](LICENSE).
