"""The pqkey command line: attach, status and detach of a daemon of the tests'
own, and the pin and reset commands on its state directory.

Every test has a state directory of its own under pytest's tmp_path. The
daemon is attached with product ID 0005, so it never touches the keys the
other tests use (product IDs 0001 to 0004, see .github/workflows/e2e.yml): it
needs /dev/uhid, but nothing opens its hidraw node. The binary is $PQKEY, by
default target/release/pqkey, as for tests/e2e/daemon.sh.

pqkey reports an error as "pqkey: <message>" on standard error and exits with
status 1. Standard input is not a terminal here, so the pin commands read one
PIN per line from it.
"""

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Iterator

import pytest

PQKEY = os.environ.get("PQKEY", "target/release/pqkey")
# Only attach takes these; the other commands refuse options they do not know.
ATTACH = ["attach", "--product-id", "0x0005", "--presence", "auto-approve"]
PIN = "4821"
NEW_PIN = "730915"
WRONG_PIN = "0000"
MAX_RETRIES = 8
# attach and detach each wait up to 10 seconds for the daemon.
TIMEOUT_S = 30


class Pqkey:
    """pqkey commands on one state directory."""

    def __init__(self, state_dir: Path):
        self.state_dir = state_dir

    def run(self, *args: str, stdin: str = "") -> subprocess.CompletedProcess[str]:
        # Standard input is always a pipe, even if empty: on a terminal the pin
        # commands would prompt for PINs with echo off.
        return subprocess.run(
            [PQKEY, *args, "--state-dir", str(self.state_dir)],
            input=stdin,
            capture_output=True,
            text=True,
            timeout=TIMEOUT_S,
        )

    def ok(self, *args: str, stdin: str = "") -> str:
        """The standard output of a command that must succeed."""
        result = self.run(*args, stdin=stdin)
        assert result.returncode == 0, f"pqkey {' '.join(args)} exited with {result.returncode}: {result.stderr}"
        return result.stdout

    def error(self, *args: str, stdin: str = "") -> str:
        """The error message of a command that must fail."""
        result = self.run(*args, stdin=stdin)
        assert result.returncode == 1, f"pqkey {' '.join(args)} exited with {result.returncode}: {result.stdout}"
        lines = result.stderr.splitlines()
        assert lines and lines[-1].startswith("pqkey: "), result.stderr
        return lines[-1].removeprefix("pqkey: ")

    def pin_status(self) -> tuple[bool, int, bool]:
        """Whether a PIN is set, the retries remaining and whether the PIN is
        blocked, as `pin status` shows them."""
        output = self.ok("pin", "status")
        is_set = re.search(r"^PIN set:\s+(true|false)$", output, re.M)
        retries = re.search(r"^Retries remaining:\s+(\d+)$", output, re.M)
        blocked = re.search(r"^Blocked:\s+(true|false)$", output, re.M)
        assert is_set and retries and blocked, output
        return is_set[1] == "true", int(retries[1]), blocked[1] == "true"


@pytest.fixture
def pqkey(request, tmp_path: Path) -> Iterator[Pqkey]:
    """pqkey on a state directory of the test's own. Whatever the test did, a
    daemon it attached is detached afterwards, and under the workflow its log
    joins the diagnostics that a failed run uploads."""
    if not os.access(PQKEY, os.X_OK):
        pytest.fail(f"{PQKEY} must be the pqkey binary: build it with cargo build -p pqkey --release, or set PQKEY")
    cli = Pqkey(tmp_path / "state")
    try:
        yield cli
    finally:
        result = cli.run("detach")
        log = cli.state_dir / "authenticator.log"
        if os.environ.get("E2E_WORK") and log.exists():
            diagnostics = Path(os.environ["E2E_WORK"]) / "e2e-diagnostics"
            diagnostics.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(log, diagnostics / f"cli-{request.node.name}.log")
        assert result.returncode == 0, f"pqkey detach exited with {result.returncode}: {result.stderr}"


def test_attach_status_and_detach(pqkey: Pqkey):
    """A daemon attached in the background, and the other commands while it
    runs: a second daemon, pin set and reset would work on the state the daemon
    holds and are refused, while pin status only reads it and works."""
    output = pqkey.ok(*ATTACH)
    attached = re.fullmatch(r"Authenticator attached \(pid (\d+)\); logging to (.+)\n", output)
    assert attached, output
    pid = int(attached[1])
    assert attached[2] == str(pqkey.state_dir / "authenticator.log")
    assert pqkey.ok("status") == f"Authenticator running (pid {pid})\n"

    running = f"the authenticator daemon is running (pid {pid}); run 'pqkey detach' first"
    assert pqkey.error(*ATTACH) == running
    assert pqkey.error("pin", "set", stdin=f"{PIN}\n") == running
    assert pqkey.error("reset", "--yes") == running
    assert pqkey.pin_status() == (False, MAX_RETRIES, False)

    assert pqkey.ok("detach") == "Authenticator stopped\n"
    assert pqkey.ok("status") == "Authenticator is not running\n"
    assert (pqkey.state_dir / "authenticator.log").is_file()


def test_pin_commands(pqkey: Pqkey):
    """pin set, change and remove, with the daemon stopped. They check PINs
    with the engine's retry state machine, so as over CTAP a wrong PIN costs a
    retry and the right one restores them all (CTAP 2.3 §6.5.2.3)."""
    assert pqkey.ok("pin", "set", stdin=f"{PIN}\n") == "PIN set.\n"
    assert pqkey.pin_status() == (True, MAX_RETRIES, False)

    # pin change reads the current PIN, then the new one.
    wrong = pqkey.error("pin", "change", stdin=f"{WRONG_PIN}\n{NEW_PIN}\n")
    assert wrong == f"PIN is incorrect ({MAX_RETRIES - 1} retries remaining)"
    assert pqkey.pin_status() == (True, MAX_RETRIES - 1, False)
    assert pqkey.ok("pin", "change", stdin=f"{PIN}\n{NEW_PIN}\n") == "PIN changed.\n"
    assert pqkey.pin_status() == (True, MAX_RETRIES, False)

    assert pqkey.ok("pin", "remove", stdin=f"{NEW_PIN}\n") == "PIN removed.\n"
    assert pqkey.pin_status() == (False, MAX_RETRIES, False)


def test_reset(pqkey: Pqkey):
    """reset --yes wipes the stored state, the PIN included, without asking."""
    pqkey.ok("pin", "set", stdin=f"{PIN}\n")
    assert pqkey.ok("reset", "--yes") == "Authenticator state has been reset.\n"
    assert pqkey.pin_status() == (False, MAX_RETRIES, False)
