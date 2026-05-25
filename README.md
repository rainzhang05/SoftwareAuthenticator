# FIDO Software Authenticator

A software-based FIDO2/WebAuthn authenticator written in Rust. It uses the
Trussed framework and provides **Post-Quantum Cryptography** signatures
(ML-DSA-44/65/87 per FIPS 204) alongside classical ES256, with no C
dependencies — the cryptography is entirely pure Rust via the
[`fips204`](https://docs.rs/fips204) crate.

The application runs on a Linux host and provisions a virtual HID token
through `/dev/uhid`. Web browsers and tools like `libfido2` interact with it
as if it were a physical hardware security key — no custom kernel modules
required.

### Key Features
* **Algorithms:** Post-quantum ML-DSA-44/65/87 (FIPS 204) and standard ES256.
* **Virtual Hardware:** Acts as a standard USB HID (CTAPHID) device via `/dev/uhid`.
* **Smartcard Support:** Optional CCID interface.
* **Pure-Rust crypto:** No C toolchain or prebuilt `liboqs` binaries required.

---

## Prerequisites

You will need a Linux host with Rust and a standard C toolchain installed.

**Ubuntu/Debian Setup:**
```bash
# 1. Install Rust (if you haven't already)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 2. Install required system packages
sudo apt update
sudo apt install -y build-essential pkg-config libclang-dev libudev-dev

# (Optional) Install tools for testing
sudo apt install -y libfido2-1 libfido2-dev libfido2-tools usbip python3-pip
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

### 2. Setup Virtual HID Permissions
To allow the authenticator to create a virtual USB device, you need to load the `uhid` kernel module and grant your user the correct permissions.

```bash
# Load the uhid module
sudo modprobe uhid

# Create a udev rule to grant access to the 'plugdev' group
echo 'KERNEL=="uhid", MODE="0660", GROUP="plugdev"' | sudo tee /etc/udev/rules.d/70-uhid.rules
sudo udevadm control --reload-rules
sudo udevadm trigger

# Apply permissions immediately
sudo chown root:plugdev /dev/uhid
sudo chmod 660 /dev/uhid
newgrp plugdev
```

### 3. Run the Authenticator
Launch the virtual authenticator in the foreground. It will automatically
handle WebAuthn requests from your browser:

```bash
RUST_LOG=info cargo run -p pc-hid-runner -- attach --foreground
```

`attach` and `detach` are the new primary verbs; the legacy `start` and
`stop` aliases continue to work.

---

## CLI Reference

The `pc-hid-runner` binary is the single management tool. Every subcommand
takes an optional `--state-dir <path>` (defaults to
`$XDG_DATA_HOME/feitian-mldsa-authenticator`).

### Lifecycle

| Command | Purpose |
|---------|---------|
| `pc-hid-runner attach [--foreground]` | Start the daemon and expose the virtual security key |
| `pc-hid-runner detach` | Stop a running daemon and remove the virtual device |
| `pc-hid-runner status` | Report whether the daemon is currently running |
| `pc-hid-runner reset [--yes]` | Wipe all credentials and PIN state (daemon must be detached) |

### PIN management

`pin` subcommands must be run with the daemon detached; the daemon reloads
the persisted PIN state on its next `attach`.

| Command | Purpose |
|---------|---------|
| `pc-hid-runner pin status` | Show whether a PIN is set, retries remaining, and blocked state |
| `pc-hid-runner pin set [--pin <PIN>]` | Set a new PIN on a PIN-less device |
| `pc-hid-runner pin change [--current <PIN> --new <PIN>]` | Change the existing PIN |
| `pc-hid-runner pin remove [--current <PIN>]` | Remove the PIN entirely |

When `--pin` / `--current` / `--new` are omitted, the CLI reads the values
interactively from stdin.

### Attach-time flags

| Flag | Purpose |
|------|---------|
| `--foreground` | Run in the foreground (useful for systemd integration) |
| `--manual-user-presence` | Require manual approval rather than auto-approving user presence |
| `--suppress-attestation` | Hide attestation certificates for privacy testing |

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
