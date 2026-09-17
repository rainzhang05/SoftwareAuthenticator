# Development notes

Commands that help when working on the authenticator on a Linux host. The
README covers installing and running it.

## Build and run the daemon with debug logs

Set up `/dev/uhid` access once, with the shipped udev rules (the comments in
[`contrib/udev/70-pqkey.rules`](../contrib/udev/70-pqkey.rules) explain them),
exactly as in step 2 of the README's
[Installation](../README.md#installation) section:

```bash
sudo install -m 644 contrib/udev/70-pqkey.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
echo uhid | sudo tee /etc/modules-load.d/uhid.conf
sudo modprobe uhid
sudo udevadm trigger
sudo usermod -aG plugdev "$USER"   # then log in again, or `newgrp plugdev`
```

Then build and run in the foreground. Debug logs include the relying party
and user names of presence prompts and CTAPHID channel IDs; info logs do not.

```bash
pqkey detach 2>/dev/null || true
cargo build --release
RUST_LOG=pqkey=debug,pqkey_ctap=debug cargo run --release -p pqkey -- attach --foreground
```

`pqkey status` shows whether a daemon runs on the state directory, `pqkey
detach` stops it. `--presence auto-approve` approves every request without
asking and is only for tests.

## Checks CI runs

The full list of checks, and how to run the end-to-end tests and the fuzz
targets, is in [CONTRIBUTING.md](../CONTRIBUTING.md#checks).

## Confirm the virtual HID device is visible to userspace

```bash
ls -l /dev/uhid /dev/hidraw*
fido2-token -L
FIDO_DEBUG=1 fido2-token -I /dev/hidrawN
```

## Kernel-level introspection

The virtual key's HID ID is `0003:1209:0001` unless `--vendor-id` or
`--product-id` says otherwise.

```bash
lsmod | grep uhid
dmesg | grep -i uhid | tail -n 20
cat /sys/class/hidraw/hidraw*/device/uevent
sudo lsof /dev/uhid
sudo sh -c 'cat /sys/kernel/debug/hid/0003:1209:0001.*/rdesc'
```
