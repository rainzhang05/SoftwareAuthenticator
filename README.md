# FIDO Software Authenticator

A software-based FIDO2/WebAuthn authenticator written in Rust. It utilizes the Trussed framework and features **Post-Quantum Cryptography** (ML-DSA) via the `liboqs` library. 

The application runs on a Linux host and provisions a virtual HID token through `/dev/uhid`. This allows web browsers and tools like `libfido2` to interact with it seamlessly, exactly as if it were a physical hardware security key—no custom kernel modules required.

### Key Features
* **Algorithms:** Post-quantum ML-DSA (44/65/87) and standard ES256.
* **Virtual Hardware:** Acts as a standard USB HID (CTAPHID) device via `/dev/uhid`.
* **Smartcard Support:** Optional CCID interface.
* **Legacy Support:** Includes a USB/IP backend for legacy testing environments.

---

## Prerequisites

You will need a Linux host with Rust and a standard C toolchain installed.

**Ubuntu/Debian Setup:**
```bash
# 1. Install Rust (if you haven't already)
curl [https://sh.rustup.rs](https://sh.rustup.rs) -sSf | sh

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

### 2. Link the Cryptography Library
The project uses prebuilt ML-DSA binaries located in the `prebuilt_liboqs/` folder. You need to add the correct library path for your architecture to your environment variables so the runner can find it.

**For x86_64 (Standard PC/Server):**
```bash
export LD_LIBRARY_PATH="$PWD/prebuilt_liboqs/linux-x86_64/lib:${LD_LIBRARY_PATH:-}"
```
**For aarch64 (ARM/Raspberry Pi):**
```bash
export LD_LIBRARY_PATH="$PWD/prebuilt_liboqs/linux-aarch64/lib:${LD_LIBRARY_PATH:-}"
```

### 3. Setup Virtual HID Permissions
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

### 4. Run the Authenticator
Launch the virtual authenticator in the foreground. It will automatically handle WebAuthn requests from your browser!

```bash
RUST_LOG=info cargo run -p pc-hid-runner -- start --foreground
```

---

## Configuration Options

When running the `pc-hid-runner`, you can append several useful flags to customize its behavior:

* `--manual-user-presence` : Require manual approval when a site requests user presence (default is auto-approve).
* `--state-dir <path>` : Change where the authenticator saves its internal state and credentials (defaults to `$XDG_DATA_HOME/feitian-mldsa-authenticator`).
* `--suppress-attestation` : Hide attestation certificates for privacy testing.
* `--pqc-policy <prefer|required|disabled>` : Force a specific Post-Quantum Cryptography policy.

*Note: Omit the `--foreground` flag to run the authenticator quietly as a background daemon. You can manage a daemonized instance using the `status` and `stop` subcommands.*
