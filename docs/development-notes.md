# Development notes

Useful shell commands collected while developing the authenticator. These are
the manual procedures the maintainers used during bring-up; the unified CLI
(`pc-hid-runner`) hides most of them in everyday use.

## Rebuild and relaunch the daemon

```bash
sudo pkill -f pc-hid-runner || true

git pull
cargo clean
cargo build --release

sudo rmmod uhid 2>/dev/null || true
sudo modprobe uhid

echo 'KERNEL=="uhid", MODE="0660", GROUP="plugdev"' \
    | sudo tee /etc/udev/rules.d/70-uhid.rules
sudo udevadm control --reload-rules
sudo udevadm trigger
sudo chown root:plugdev /dev/uhid
sudo chmod 660 /dev/uhid
newgrp plugdev

RUST_LOG=pc_hid_runner=debug cargo run -p pc-hid-runner -- start --foreground
```

## Confirm the virtual HID device is visible to userspace

```bash
ls -l /dev/hidraw*
fido2-token -L
FIDO_DEBUG=1 fido2-token -I /dev/hidraw3
```

## Kernel-level introspection

```bash
sudo lsmod | grep uhid
cat /sys/class/hidraw/hidraw*/device/uevent
sudo cat /sys/kernel/debug/hid/0003:096E:0858.0005/rdesc | hexdump -C
```

## Full diagnostic walk-through

```bash
sudo -i
lsmod | grep uhid
ls -l /dev/uhid
ps aux | grep pc-hid-runner
sudo lsof /dev/uhid
cat /proc/bus/input/devices | grep -A5 -i 096e
dmesg | grep -i uhid | tail -n 20
ls -ld /sys/kernel/debug/hid
ls -d /sys/kernel/debug/hid/*096E* 2>/dev/null
stat -c "rdesc size: %s bytes" $(ls -d /sys/kernel/debug/hid/*096E* | tail -1)/rdesc
cat $(ls -d /sys/kernel/debug/hid/*096E* | tail -1)/rdesc | hexdump -C | head -n 20
```
