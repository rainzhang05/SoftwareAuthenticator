# pqkey

A software-based FIDO2/WebAuthn authenticator written in Rust. It provides
**Post-Quantum Cryptography** signatures (ML-DSA-44/65/87 per FIPS 204)
alongside classical ES256, with no C dependencies — the cryptography is
entirely pure Rust via the RustCrypto [`ml-dsa`](https://docs.rs/ml-dsa)
crate.

The application runs on a Linux host and provisions a virtual HID token
through `/dev/uhid`. Web browsers and tools like `libfido2` interact with it
as if it were a physical hardware security key — no custom kernel modules
required.

### Key Features
* **Algorithms:** Post-quantum ML-DSA-44/65/87 (FIPS 204) and standard ES256.
* **Virtual Hardware:** Acts as a standard USB HID (CTAPHID) device via `/dev/uhid`.
* **Pure-Rust crypto:** No C libraries or prebuilt `liboqs` binaries required.

---

## Prerequisites

You will need a Linux host with Rust and a system linker installed.

**Ubuntu/Debian Setup:**
```bash
# 1. Install Rust (if you haven't already)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 2. Install required system packages
sudo apt update
sudo apt install -y build-essential

# (Optional) Install libfido2's command-line tools for testing
sudo apt install -y fido2-tools
```

---

## Quick Start

### 1. Build the Project
From the repository root, build the project using Cargo:
```bash
cargo build --release
```

The cryptography is pure Rust — there is no `liboqs` build step and nothing
to add to `LD_LIBRARY_PATH`.

### 2. Set Up the Virtual HID Permissions
The authenticator creates its virtual security key through `/dev/uhid`, which
only root can open by default. The repository ships udev rules,
[`contrib/udev/70-pqkey.rules`](contrib/udev/70-pqkey.rules), that give the
`plugdev` group access to `/dev/uhid` and give the user of the active local
session, and no one else, access to the virtual key's hidraw node. Install
them and have the `uhid` module loaded at every boot:

```bash
# Install the udev rules
sudo install -m 644 contrib/udev/70-pqkey.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules

# Load the uhid module at every boot, and now
echo uhid | sudo tee /etc/modules-load.d/uhid.conf
sudo modprobe uhid
sudo udevadm trigger

# Let your user open /dev/uhid, then log out and back in
# (or run `newgrp plugdev` in the shell you start pqkey from)
sudo usermod -aG plugdev "$USER"
```

Anyone who can open `/dev/uhid` can create any kind of HID device, keyboards
included, so only add users you would trust with that to the group. The group
is `plugdev` as on Debian and Ubuntu; elsewhere create it or change the group in
the rules. If you start the authenticator with `--vendor-id` or
`--product-id`, change the hidraw rule's device pattern to match; the comments
in the rules file explain both.

### 3. Run the Authenticator
Launch the virtual authenticator in the foreground. It handles WebAuthn
requests from your browser, and asks you to approve every registration,
sign-in and reset with a desktop notification:

```bash
RUST_LOG=info cargo run -p pqkey -- attach --foreground
```

`attach` and `detach` are the new primary verbs; the legacy `start` and
`stop` aliases continue to work.

---

## CLI Reference

The `pqkey` binary is the single management tool. Every subcommand takes an
optional `--state-dir <path>` (defaults to `$XDG_DATA_HOME/pqkey`, or
`~/.local/share/pqkey` when `XDG_DATA_HOME` is unset).

### Lifecycle

| Command | Purpose |
|---------|---------|
| `pqkey attach [--foreground]` | Start the daemon and expose the virtual security key |
| `pqkey detach` | Stop a running daemon and remove the virtual device |
| `pqkey status` | Report whether the daemon is currently running |
| `pqkey reset [--yes]` | Wipe all credentials and PIN state (daemon must be detached) |

### PIN management

`pin set`, `pin change` and `pin remove` must be run with the daemon
detached; the daemon reloads the persisted PIN state on its next `attach`.
`pin status` also works while the daemon runs.

| Command | Purpose |
|---------|---------|
| `pqkey pin status` | Show whether a PIN is set, retries remaining, and blocked state |
| `pqkey pin set` | Set a new PIN on a PIN-less device |
| `pqkey pin change` | Change the existing PIN |
| `pqkey pin remove` | Remove the PIN entirely |

PINs are never taken from command-line arguments. On a terminal the CLI
prompts for them with echo turned off (a new PIN twice); otherwise it reads
them from standard input, one PIN per line (for `pin change`, the current PIN
first, then the new one).

### Attach-time flags

| Flag | Purpose |
|------|---------|
| `--foreground` | Run in the foreground (useful for systemd integration) |
| `--presence notify\|auto-approve` | How registrations, sign-ins and resets are approved: a desktop notification with Approve and Deny buttons (`notify`, the default), or approving everything without asking (`auto-approve`, for tests and CI only) |
| `--attestation self\|certificate\|none` | The attestation registrations get: self attestation with the credential's own key (`self`, the default), basic attestation with a certificate generated for this installation (`certificate`), or none (`none`). With `certificate` every registration carries the same certificate, so relying parties can link your credentials across sites (WebAuthn §14.4.1) |
| `--manufacturer <NAME>`, `--country <CODE>` | The manufacturer and its ISO 3166-1 country code named in the attestation certificate; required with `--attestation certificate` |
| `--aaguid <UUID>` | The AAGUID to report (default `5931e805-a166-4eb7-845a-7f6aa93d9cd8`) |
| `--vendor-id <ID>`, `--product-id <ID>` | USB IDs of the virtual device (default `0x1209`:`0x0001`, the pid.codes open source vendor ID and a pid.codes test product ID) |

---

## Supported Algorithms

The authenticator advertises all of the following COSE algorithms in
`authenticatorGetInfo` and will register and assert credentials against any
of them:

* `ES256` (-7) — classical NIST P-256 ECDSA
* `ML-DSA-44` (-48) — post-quantum, NIST level 2
* `ML-DSA-65` (-49) — post-quantum, NIST level 3
* `ML-DSA-87` (-50) — post-quantum, NIST level 5

PIN/UV uses the standard CTAP2.1 protocols (1 and 2). The authenticator
also handles `authenticatorReset` (CTAP command 0x07) so credentials can be
wiped over the wire if needed.
