"""Owned native Linux resources. No installed pqkey service is ever managed."""
from __future__ import annotations

import os
import json
import platform
import shutil
import signal
import stat
import subprocess
import time
from pathlib import Path


class UnavailableRuntime(RuntimeError):
    pass


def preflight():
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise UnavailableRuntime("unavailable runtime: real Linux x86_64 UHID is required; macOS/Docker without UHID cannot run browser acceptance; no services or personal state changed")
    try:
        if not stat.S_ISCHR(Path("/dev/uhid").stat().st_mode):
            raise OSError("not a character device")
        descriptor = os.open("/dev/uhid", os.O_RDWR | os.O_CLOEXEC)
        os.close(descriptor)
    except OSError as error:
        raise UnavailableRuntime(f"unavailable runtime: cannot open real /dev/uhid read/write ({error}); provision UHID/udev first; no services or personal state changed") from error
    for device in Path("/sys/class/hidraw").glob("hidraw*"):
        try:
            report = (device / "device/report_descriptor").read_bytes()
        except OSError as error:
            raise UnavailableRuntime(f"cannot inspect HID descriptor {device}: {error}") from error
        if b"\x06\xd0\xf1" in report:
            raise UnavailableRuntime(f"another FIDO HID device exists ({device.name}); use an isolated host; the harness will not stop your authenticator")
    needed = [name for name in ("Xvfb", "openbox", "dbus-daemon", "xdotool", "scrot", "udevadm", "/usr/bin/python3")
              if not shutil.which(name)]
    if needed:
        raise UnavailableRuntime("missing browser runtime tools: " + ", ".join(needed))
    subprocess.run(["/usr/bin/python3", "-c", "import pyatspi"], check=True, timeout=5,
                   stdout=subprocess.DEVNULL)


class OwnedProcesses:
    def __init__(self):
        self.children = []
        self.ledger = None

    def checkpoint(self):
        if self.ledger:
            temporary = self.ledger.with_suffix('.tmp')
            temporary.write_text(json.dumps([{"pid": p.pid, "start": p._pqkey_identity,
                                              "stopped": p._pqkey_stopped} for p in self.children]))
            temporary.chmod(0o600)
            temporary.replace(self.ledger)

    def start(self, argv, log, *, env=None, **kwargs):
        with open(log, "ab") as output:
            process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=output, stderr=output,
                                       env=env, start_new_session=True, **kwargs)
        self.children.append(process)
        process._pqkey_stopped = False
        identity = Path(f"/proc/{process.pid}/stat")
        try:
            process._pqkey_identity = identity.read_text().rsplit(')', 1)[1].split()[19]
        except FileNotFoundError:
            process._pqkey_identity = None
        self.checkpoint()
        return process

    @staticmethod
    def stop(process):
        if getattr(process, '_pqkey_stopped', False):
            return
        identity = Path(f"/proc/{process.pid}/stat")
        if identity.exists() and getattr(process, '_pqkey_identity', None) is not None:
            if identity.read_text().rsplit(')', 1)[1].split()[19] != process._pqkey_identity:
                raise RuntimeError('refusing to signal a reused PID/process group')
        # Every group was created by start_new_session, never discovered by name.
        # Signal even when the leader exited: its browser descendants may remain.
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
        # The leader may exit before a renderer/accessibility descendant.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process._pqkey_stopped = True

    def cleanup(self):
        failures = []
        for process in reversed(self.children):
            try:
                self.stop(process)
                self.checkpoint()
            except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
                failures.append(f"owned process cleanup: {type(error).__name__}")
        return failures


def fallback_cleanup(control):
    """Workflow cancellation fallback: only recorded, identity-checked groups."""
    ledger = Path(control) / 'processes.json'
    if not ledger.exists():
        return
    records = json.loads(ledger.read_text())
    for record in records:
        if record['stopped']:
            continue
        pid = record['pid']
        if not isinstance(pid, int) or pid <= 1 or record['start'] is None:
            raise RuntimeError('invalid owned-process identity; refusing fallback cleanup')
        identity = Path(f'/proc/{pid}/stat')
        if identity.exists():
            fields = identity.read_text().rsplit(')', 1)[1].split()
            if fields[19] != record['start'] or int(fields[2]) != pid or int(fields[3]) != pid:
                raise RuntimeError('PID/session identity changed; refusing fallback cleanup')
        try:
            os.killpg(pid, signal.SIGTERM)
        except ProcessLookupError:
            continue
    time.sleep(0.5)
    for record in records:
        if not record['stopped']:
            identity = Path(f'/proc/{record["pid"]}/stat')
            if identity.exists() and identity.read_text().rsplit(')', 1)[1].split()[19] != record['start']:
                raise RuntimeError('PID changed during fallback cleanup')
            try:
                os.killpg(record['pid'], signal.SIGKILL)
            except ProcessLookupError:
                pass
    # State is restricted to a harness-created subdirectory of this private control.
    for directory in Path(control).glob('pqkey-browser-*'):
        if directory.is_dir() and not directory.is_symlink():
            shutil.rmtree(directory)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Clean only this run\'s owned browser process groups')
    parser.add_argument('control', type=Path)
    fallback_cleanup(parser.parse_args().control)
