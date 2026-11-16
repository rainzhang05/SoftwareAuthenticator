# User guide

Installing, using and fixing pqkey. [SECURITY.md](../SECURITY.md) says what it
can and cannot protect.

## Install

The installer says how much disk space it will use (about 1.2 GB with the
build tools and Rust), asks once to continue, and then:

1. installs a C linker, Rust and ACL tools if they are missing, and updates
   rustup's stable Rust if it is older than pqkey needs;
2. builds pqkey and installs it as `/usr/local/bin/pqkey`;
3. gives the key access to `/dev/uhid` with
   [udev rules](../contrib/udev/70-pqkey.rules), and loads the `uhid` module
   at every boot;
4. starts the key as a systemd user service and asks you to choose its PIN.

sudo asks for your password after the build, and before it too when the
installer installs a C linker, curl or ACL tools. After the build it asks only
on a terminal, never through a helper program (`SUDO_ASKPASS`). The installer
has sudo forget your password before it installs or updates Rust and builds
pqkey, and again when it ends.

The udev rules give `/dev/uhid` to the `plugdev` group, which lets its members
create any HID device ([SECURITY.md](../SECURITY.md#device-access)). The
installer adds you to it if you are not in it yet (on Ubuntu, the first user
already is), with an
ACL on `/dev/uhid` until your next login applies the membership.

"pqkey is ready" means that the key runs as the installed service, its device
opens and answers, a notification server on its session bus says it can show
buttons and text (without showing a prompt), and a PIN is set with no change
pending. `pqkey` then works in the same terminal, with no reboot or new login.
Otherwise the installer says what to fix: fix it and rerun `./install.sh` in
the same desktop terminal. Its log is `~/.cache/pqkey/install.log` (or
`$XDG_CACHE_HOME/pqkey/install.log`).

`./install.sh --yes` skips the question, not the PIN: without a terminal, it
stops before installing pqkey if sudo needs your password, and otherwise at a
new key's PIN. If your terminal's PATH lacks `/usr/local/bin`, run
`export PATH="/usr/local/bin:$PATH"` there and rerun the installer.

## Approving requests

Every registration, reset and sign-in that needs your presence shows a
notification with Approve and Deny. A registration asks to "Create a passkey"
for a discoverable credential, and to "Register a security key" otherwise.
Denying, or not answering within 30 seconds, rejects the request, and so does
a notification that cannot be shown. Cancelling the request in the client, or
restarting the key, withdraws the prompt, and an approval answers only its own
request.

- **Dunst** shows Approve and Deny in its context menu: run `dunstctl context`,
  or use your context-menu shortcut. It needs dmenu or a compatible menu.
- **GNOME** can queue a prompt behind another banner, so pqkey nudges the queue
  every 2 seconds. The prompt is also in the notification list (click the
  clock).

## PIN and policy

`pqkey pin` sets or changes the PIN. `pqkey config` shows the settings below;
changing one asks for the current PIN when one is set.

| Command | What it does |
|---|---|
| `pqkey config always-uv on\|off` | Requires the PIN for every registration, and every sign-in that needs your presence |
| `pqkey config min-pin-length N [--rp RP_ID]...` | Raises the minimum PIN length |
| `pqkey config pin-complexity [--yes]` | Requires an ASCII letter and digit in every new PIN ([policy](pin-complexity-policy.md)) |
| `pqkey config force-pin-change` | Requires a different PIN |

Without a PIN, set one or turn always-UV off before using the key in a
browser. The minimum PIN length counts Unicode code points, from 4 to 63, and
a PIN has at most 63 bytes in UTF-8. Raising the minimum, or enabling PIN
complexity, asks for confirmation unless `--yes` is given, since only
`pqkey reset` undoes either. Repeated `--rp` options replace the list of up to
8 RP IDs that may read the minimum through the `minPinLength` extension;
omitting them keeps the list. When a PIN change is required, run `pqkey pin`
and choose a different PIN that meets the current policy.

## Passkeys

`pqkey passkeys` lists passkeys, the discoverable credentials the key finds by
itself, and marks payment-enabled ones in its PAYMENT column (the browser
handles payment). `pqkey passkeys delete QUERY` deletes the passkey whose site,
user or ID contains `QUERY`.

A site that registers the key as a second factor (`residentKey:
"discouraged"`) keeps the credential's ID and sends it back to sign in, as
Chromium also does when the key has no PIN. Those sign-ins work, but the key
does not list them, and RSA, Brainpool and payment-enabled ones still take one
of its 1,000 storage slots ([why](architecture.md#credential-ids)).

A client you give the PIN can get a
[persistent read-only permission](architecture.md#persistent-read-only-management)
that lists your passkeys until the PIN changes or the key is reset.

## Reset

`pqkey reset` erases every credential, large blob and the PIN, and resets the
settings. A key accepts a reset only within 10 seconds of starting, so
`pqkey reset` restarts it first, and asks again if that restart unblocks the
PIN.

## Browsers and clients

The browsers were measured by the
[browser acceptance run](../tests/browser/README.md#acceptance-workflow), and
the end-to-end tests run python-fido2 and libfido2 on x86_64 and arm64.

| Client | ES256 | ML-DSA | Notes |
|---|:---:|:---:|---|
| Chromium 158 | ✓ | ✓ | All 21 algorithms, Brainpool included |
| Firefox 158 | ✓ | | 15 algorithms: not ML-DSA, Brainpool or ES256K |
| python-fido2 2.2.1 | ✓ | ✓ | Used by the end-to-end tests |
| libfido2 1.14 | ✓ | | PIN, credential management, U2F and `hmac-secret` |

- **Chromium** uses a security key for passkeys only if it has a PIN, and
  otherwise says "Your device can't be used with this site". After Deny, or
  30 seconds, it shows "Something went wrong" until you click Cancel. Its
  `getPublicKey()` returns null for ML-DSA, and `toJSON()` leaves the key out,
  so sites read it from the attestation object.
- **Firefox** drops algorithms it does not know, so an ML-DSA-only request
  fails with `NotAllowedError`. On a key without a PIN, its account chooser
  shows "Unknown account", since the key then leaves user names out (CTAP 2.3
  §6.2.2); with a PIN, Firefox asks for it and shows the names.
- **libfido2** has no ML-DSA type, so `fido2-token -L -k` cannot list ML-DSA
  passkeys; `pqkey passkeys` can.

## Troubleshooting

Start with `pqkey status`. It checks the service, device access,
notifications, the state directory's filesystem and the credential store, and
names a fix for each problem it finds; `scripts/diagnose.sh` shows the whole
state of the key on your computer. `pqkey status` shows no notification, so it
cannot see a notification server that fails to show a prompt. The key logs
why it denied each request it could not ask about, and what it could not read
or write: `journalctl --user -u pqkey`, or `authenticator.log` in the state
directory for a key that `pqkey start` ran without the service.

- **The PIN looks blocked, or the key could not read or write its state.**
  Run `pqkey stop && pqkey start` and `pqkey status` before you reset: a
  restart clears a block from a disk or permission error, and `pqkey status`
  names a damaged `pin-state`, whose repair keeps your passkeys.
- **Every registration or sign-in fails at once.** No notification could be
  shown, so the key said no; its journal says why. If your desktop starts its
  own D-Bus session bus, see the comments in
  [`contrib/systemd/user/pqkey.service`](../contrib/systemd/user/pqkey.service).
- **Programs cannot open the key.** Its device goes to the user of the active
  local desktop session (`uaccess`): a plain SSH session, a container or an
  Xvfb display does not get it. Rerun `./install.sh` to repair permissions,
  and if that does not help, check `getfacl /dev/uhid` and the device that
  `pqkey status` names.
- **A snap browser never asks for the key.** Snaps open only devices tagged
  for them, and the udev rules tag the key for the Firefox and Chromium snaps.
  If `pqkey status` says the tag is missing, run `./install.sh`.
- **Another program fails while a browser waits for approval.** The key serves
  one request at a time and answers the others "busy", as CTAP requires.
  Answer or cancel the waiting request first.
- **The service and the command use different passkeys.** If you set
  `XDG_DATA_HOME` in your shell, set it for the systemd user manager too (see
  `environment.d(5)`).
- **The key stops answering and `pqkey stop` hangs.** The kernel's uhid
  driver has a read race, seen mostly on arm64: `dmesg` then shows
  `kernel BUG at mm/usercopy.c` with `uhid_char_read` in the call trace.
  pqkey avoids the race as far as it can, but cannot rule it out. Restart the
  key, or reboot if its process cannot be stopped.

## Damaged credential store

`pqkey status` and the key's journal name the damaged files and what the key
cannot do. To repair the store:

1. Stop the key with `pqkey stop`, and copy the whole state directory,
   `keys/` included: `cp -a ~/.local/share/pqkey ~/pqkey-copy`.
2. Check that the computer's clock is right, since repair restarts a damaged
   signature counter from it. Run `pqkey repair`: it shows what it will do and
   asks first, or, if it stops before that, says what to do.
3. Start the key with `pqkey start`. Once it works, delete the copy: it holds
   the keys, so it keeps your passkeys readable even after a reset.

Repair keeps the keys and every passkey whose record is intact
([its rules](architecture.md#repair)), and moves what it replaces or removes
into `damaged/` in the state directory, which the key never uses: its records
stay readable until a reset, and you may delete it once the key works. A
damaged `pin-state` becomes one with no PIN and always-UV on, so the key
refuses to register or sign in until you set a PIN with `pqkey pin`, and
always-UV stays on until `pqkey config always-uv off`. A damaged
`large-blobs` loses its large blobs.

Never edit, delete or replace the store's files by hand: an older
`credential-set/active` hides the passkeys registered since, and the next
change deletes their records, and a deleted `signature-counter` counts again
from 0. `pqkey reset` erases every passkey: use it only as a last resort.
