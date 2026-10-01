"""The pqkey command line: start, status and stop of a key of the tests' own,
and pin, passkeys and reset, which manage it over CTAP through its hidraw
node as a security key's management application does.

Every test has a state directory of its own under pytest's tmp_path. The key
is started with product ID 0005, so it never touches the keys the other tests
use (product IDs 0001 to 0004, see .github/workflows/e2e.yml), and with
`--presence auto-approve` (or `unanswered`), so nothing asks a person. The
binary is $PQKEY, by default target/release/pqkey, as for tests/e2e/daemon.sh.

pqkey reports an error as "pqkey: <message>" on standard error and exits with
status 1, or 3 when the key it would start already runs. Standard input is not a terminal here, so the commands read one PIN
per line from it, and confirmations too.
"""

import os
import re
import shutil
import signal
import subprocess
from pathlib import Path
from typing import Iterator

import pytest
from fido2.ctap2 import ClientPin, Ctap2

import ctap as client

PQKEY = os.environ.get("PQKEY", "target/release/pqkey")
# The options of the tests' key; only start (and run) take them.
START = ["start", "--product-id", "0x0005"]
PIN = "4821"
NEW_PIN = "730915"
WRONG_PIN = "0000"
MAX_RETRIES = 8
# start and stop each wait up to 10 seconds for the key, reset both.
TIMEOUT_S = 40


class Pqkey:
    """pqkey commands on one state directory."""

    def __init__(self, state_dir: Path):
        self.state_dir = state_dir

    def command(self, *args: str) -> list[str]:
        return [PQKEY, *args, "--state-dir", str(self.state_dir)]

    def run(self, *args: str, stdin: str = "") -> subprocess.CompletedProcess[str]:
        # Standard input is always a pipe, even if empty: on a terminal the
        # commands would prompt for PINs with echo off.
        return subprocess.run(
            self.command(*args),
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

    def status(self) -> dict[str, str]:
        """The lines of `pqkey status` about the key, by their label. The
        problems it lists after them (here: the CI's own udev rule is not
        pqkey's) are left out."""
        key = self.ok("status").split("\n\n")[0]
        return dict(re.findall(r"^(\w+): +(.*)$", key, re.M))

    def passkeys(self) -> list[list[str]]:
        """The rows of `pqkey passkeys`, whose columns are at least two spaces
        apart."""
        heading, *rows = self.ok("passkeys", stdin=f"{PIN}\n").splitlines()
        assert re.split(r"\s{2,}", heading) == ["SITE", "USER", "ALGORITHM", "ID"], heading
        return [re.split(r"\s{2,}", row) for row in rows]

    def start(self, presence: str = "auto-approve") -> int:
        output = self.ok(*START, "--presence", presence)
        started = re.fullmatch(r"Key started \(pid (\d+)\); logging to (.+)\n", output)
        assert started, output
        assert started[2] == str(self.state_dir / "authenticator.log")
        return int(started[1])


@pytest.fixture
def pqkey(request, tmp_path: Path) -> Iterator[Pqkey]:
    """pqkey on a state directory of the test's own. Whatever the test did, a
    key it started is stopped afterwards, and under the workflow its log joins
    the diagnostics that a failed run uploads."""
    if not os.access(PQKEY, os.X_OK):
        pytest.fail(f"{PQKEY} must be the pqkey binary: build it with cargo build -p pqkey --release, or set PQKEY")
    cli = Pqkey(tmp_path / "state")
    try:
        yield cli
    finally:
        result = cli.run("stop")
        log = cli.state_dir / "authenticator.log"
        if os.environ.get("E2E_WORK") and log.exists():
            diagnostics = Path(os.environ["E2E_WORK"]) / "e2e-diagnostics"
            diagnostics.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(log, diagnostics / f"cli-{request.node.name}.log")
        assert result.returncode == 0, f"pqkey stop exited with {result.returncode}: {result.stderr}"


def test_start_status_and_stop(pqkey: Pqkey):
    """A key started in the background, found by its device name, and stopped
    again. A second start is refused while it runs."""
    assert pqkey.status() == {"Key": "not running; `pqkey start` starts it"}
    pid = pqkey.start()
    status = pqkey.status()
    assert status["Key"] == f"running (pid {pid})"
    assert re.fullmatch(r"/dev/hidraw\d+", status["Device"]), status
    assert status["PIN"] == "not set; `pqkey pin` sets one (Chromium asks for one)"
    assert status["Passkeys"] == "room for 1000 more"

    # A second key on the same state exits with status 3, which the systemd
    # unit does not restart on.
    result = pqkey.run(*START)
    assert result.returncode == 3, result
    assert result.stderr == f"pqkey: the key is already running (pid {pid})\n"

    assert pqkey.ok("stop") == "Key stopped\n"
    assert pqkey.ok("stop") == "The key is not running\n"
    assert pqkey.status() == {"Key": "not running; `pqkey start` starts it"}
    assert (pqkey.state_dir / "authenticator.log").is_file()


def test_commands_need_a_running_key(pqkey: Pqkey):
    for command in (["pin"], ["passkeys"], ["passkeys", "delete", "x", "--yes"]):
        assert pqkey.error(*command, stdin=f"{PIN}\n") == "the key is not running; start it with `pqkey start`"
    # setup installs the key for the default state directory only.
    assert pqkey.error("setup") == "pqkey setup only sets up the key in the default state directory"


def test_pin_is_set_and_changed_over_ctap(pqkey: Pqkey):
    """pin sets a PIN, then changes it, through the key's ClientPIN command:
    a wrong current PIN costs a retry and the right one restores them all
    (CTAP 2.3 §6.5.2.3)."""
    pqkey.start()
    assert pqkey.ok("pin", stdin=f"{PIN}\n") == "PIN set.\n"
    assert pqkey.status()["PIN"] == f"set ({MAX_RETRIES} retries left)"

    # With a PIN set, pin reads the current PIN, then the new one.
    wrong = pqkey.error("pin", stdin=f"{WRONG_PIN}\n{NEW_PIN}\n")
    assert wrong == f"wrong PIN; {MAX_RETRIES - 1} retries left"
    assert pqkey.status()["PIN"] == f"set ({MAX_RETRIES - 1} retries left)"
    assert pqkey.ok("pin", stdin=f"{PIN}\n{NEW_PIN}\n") == "PIN changed.\n"
    assert pqkey.status()["PIN"] == f"set ({MAX_RETRIES} retries left)"

    # A PIN shorter than any that can be set is wrong without costing a retry.
    assert "no retry was used" in pqkey.error("pin", stdin="12\n")
    assert pqkey.status()["PIN"] == f"set ({MAX_RETRIES} retries left)"


def test_pins_are_normalized_to_nfc(pqkey: Pqkey):
    """PINs are in Unicode normalization form C (CTAP 2.3 §6.5.1): one typed
    with combining characters is the PIN a browser sends for the same text."""
    pqkey.start()
    decomposed = "e\u0301" * 4
    assert pqkey.ok("pin", stdin=f"{decomposed}\n") == "PIN set.\n"
    with client.open_device(pqkey.status()["Device"]) as device:
        ClientPin(Ctap2(device)).get_pin_token("\u00e9" * 4, ClientPin.PERMISSION.CREDENTIAL_MGMT)
    # Four code points as typed, but two characters: too short.
    assert pqkey.error("pin", stdin=f"{decomposed}\n{'e\u0301' * 2}\n") == "PIN must be at least 4 characters long"


def test_passkeys_are_listed_and_deleted(pqkey: Pqkey):
    """passkeys lists the discoverable credentials with a credential
    management token, and passkeys delete removes the one a query names."""
    pqkey.start()
    node = pqkey.status()["Device"]
    with client.open_device(node) as device:
        ctap = Ctap2(device)
        for name in ("alice", "bob"):
            client.register(
                ctap, "example.com", client.ML_DSA_65, user=client.user_entity(name), options={"rk": True}
            )

    assert "`pqkey pin` sets one" in pqkey.error("passkeys")
    pqkey.ok("pin", stdin=f"{PIN}\n")

    listing = pqkey.passkeys()
    assert [row[:3] for row in listing] == [
        ["example.com", "alice (Alice)", "ML-DSA-65"],
        ["example.com", "bob (Bob)", "ML-DSA-65"],
    ], listing
    assert all(re.fullmatch(r"[0-9a-f]{16}", row[3]) for row in listing), listing

    # An ambiguous query lists the passkeys it matches after the error.
    result = pqkey.run("passkeys", "delete", "example", "--yes", stdin=f"{PIN}\n")
    assert result.returncode == 1, result
    assert result.stderr.startswith('pqkey: "example" matches 2 passkeys'), result.stderr
    assert "bob (Bob)" in result.stderr, result.stderr
    # Without --yes it asks, and only "y" deletes.
    result = pqkey.run("passkeys", "delete", "bob", stdin=f"{PIN}\nn\n")
    assert result.returncode == 0 and "Nothing was deleted." in result.stderr, result
    assert pqkey.ok("passkeys", "delete", "bob", stdin=f"{PIN}\ny\n") == "Passkey deleted.\n"
    assert [row[1] for row in pqkey.passkeys()] == ["alice (Alice)"]

    assert pqkey.error("passkeys", stdin=f"{WRONG_PIN}\n") == f"wrong PIN; {MAX_RETRIES - 1} retries left"


def test_reset_replugs_the_key_and_erases_it(pqkey: Pqkey):
    """reset restarts the key with its options, as re-plugging does, so
    authenticatorReset comes within 10 seconds of power-up (CTAP 2.3 §6.6),
    and leaves it running."""
    old_pid = pqkey.start()
    pqkey.ok("pin", stdin=f"{PIN}\n")
    assert pqkey.ok("reset", "--yes") == "The key is reset: its passkeys and its PIN are erased.\n"
    status = pqkey.status()
    assert status["PIN"].startswith("not set"), status
    pid = int(re.fullmatch(r"running \(pid (\d+)\)", status["Key"])[1])
    assert pid != old_pid

    # Declined, nothing happens.
    pqkey.ok("pin", stdin=f"{PIN}\n")
    result = pqkey.run("reset", stdin="no\n")
    assert result.returncode == 0 and "Nothing was reset." in result.stderr, result
    assert pqkey.status()["PIN"] == f"set ({MAX_RETRIES} retries left)"


def test_ctrl_c_cancels_a_reset_waiting_for_approval(pqkey: Pqkey):
    """While the key waits for its user, Ctrl-C sends CTAPHID_CANCEL and the
    key answers CTAP2_ERR_KEEPALIVE_CANCEL (CTAP 2.3 §11.2.9.1.5)."""
    pqkey.start("unanswered")
    process = subprocess.Popen(
        pqkey.command("reset", "--yes"),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        line = process.stderr.readline()
        assert line.startswith("Approve the reset in the notification"), line
        process.send_signal(signal.SIGINT)
        _, stderr = process.communicate(timeout=TIMEOUT_S)
    finally:
        process.kill()
    assert process.returncode == 1, stderr
    assert stderr.splitlines()[-1] == "pqkey: the reset was cancelled; nothing was erased"
