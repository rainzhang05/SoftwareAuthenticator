"""The pqkey command line: start, status and stop of a key of the tests' own,
and config, pin, passkeys and reset, which manage it over CTAP through its
hidraw node as a security key's management application does.

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
from fido2.ctap import CtapError
from fido2.ctap2 import ClientPin, Ctap2
from fido2.ctap2.blob import LargeBlobs

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
        return dict(re.findall(r"^([\w ]+): +(.*)$", key, re.M))

    def config(self) -> dict[str, str]:
        """The advertised settings from `pqkey config`."""
        return dict(line.split(": ", 1) for line in self.ok("config").splitlines())

    def passkeys(self) -> list[list[str]]:
        """The rows of `pqkey passkeys`, whose columns are at least two spaces
        apart."""
        heading, *rows = self.ok("passkeys", stdin=f"{PIN}\n").splitlines()
        assert re.split(r"\s{2,}", heading) == ["SITE", "USER", "ALGORITHM", "ID"], heading
        return [re.split(r"\s{2,}", row) for row in rows]

    def start(self, presence: str = "auto-approve", *options: str) -> int:
        output = self.ok(*START, "--presence", presence, *options)
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
    assert not (pqkey.state_dir / "authenticator.pid").exists()
    assert not (pqkey.state_dir / "authenticator.info").exists()


def test_commands_need_a_running_key(pqkey: Pqkey):
    for command in (["pin"], ["passkeys"], ["passkeys", "delete", "x", "--yes"], ["config"]):
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
    old_pid = pqkey.start("auto-approve", "--name", "CLI reset key",
                          "--attestation", "none", "--presence-timeout", "12")
    old_info = (pqkey.state_dir / "authenticator.info").read_bytes().split(b"\n", 1)
    assert old_info[0].split()[1] == str(old_pid).encode()
    pqkey.ok("pin", stdin=f"{PIN}\n")
    assert pqkey.ok("reset", "--yes") == "The key is reset: its passkeys, large blobs and PIN are erased.\n"
    status = pqkey.status()
    assert status["PIN"].startswith("not set"), status
    pid = int(re.fullmatch(r"running \(pid (\d+)\)", status["Key"])[1])
    assert pid != old_pid
    new_info = (pqkey.state_dir / "authenticator.info").read_bytes().split(b"\n", 1)
    assert new_info[0].split()[1] == str(pid).encode()
    assert new_info[0].split()[2:] == old_info[0].split()[2:]
    assert new_info[1] == old_info[1]

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


def test_config_without_a_pin_and_idempotent_always_uv(pqkey: Pqkey):
    pqkey.start()
    assert pqkey.config() == {
        "Always UV": "off", "Minimum PIN length": "4", "PIN change required": "no",
    }
    assert pqkey.ok("config", "always-uv", "off").startswith("Always UV: off.\n")
    output = pqkey.ok("config", "always-uv", "on")
    assert output.startswith("Always UV: on.\n"), output
    assert "Browsers will need a PIN before they can register or sign in" in output
    assert "`pqkey pin`" in output
    assert pqkey.config()["Always UV"] == "on"
    assert pqkey.status()["Always UV"] == "on; registrations and sign-ins require the PIN"
    assert "`pqkey pin`" in pqkey.error("config", "min-pin-length", "6", "--yes")
    assert pqkey.config()["Minimum PIN length"] == "4"
    assert pqkey.ok("config", "always-uv", "on").startswith("Always UV: on.\n")
    # The no-PIN exception lets the CLI recover without acquiring a token.
    assert pqkey.ok("config", "always-uv", "off").startswith("Always UV: off.\n")
    assert "`pqkey pin`" in pqkey.error("config", "force-pin-change")
    assert pqkey.config()["PIN change required"] == "no"


def test_config_minimum_confirmation_and_rp_ids(pqkey: Pqkey):
    pqkey.start()
    declined = pqkey.run("config", "min-pin-length", "6", stdin="n\n")
    assert declined.returncode == 0, declined
    assert "Only a reset, which erases every passkey and large blob, can lower it again." in declined.stderr
    assert "Nothing was changed." in declined.stdout
    assert pqkey.config()["Minimum PIN length"] == "4"
    assert pqkey.ok("config", "min-pin-length", "6", "--rp", "a.config.example",
                    "--rp", "b.config.example", stdin="y\n") == "Minimum PIN length: 6.\n"
    assert pqkey.config()["Minimum PIN length"] == "6"
    assert pqkey.error("pin", stdin=f"{PIN}\n") == "PIN must be at least 6 characters long"

    # --yes skips confirmation, and omitting --rp preserves the previous list.
    assert pqkey.ok("config", "min-pin-length", "7", "--yes") == "Minimum PIN length: 7.\n"
    with client.open_device(pqkey.status()["Device"]) as device:
        ctap = Ctap2(device)
        for rp_id in ("a.config.example", "b.config.example"):
            credential = client.register(ctap, rp_id, client.ES256, extensions={"minPinLength": True})
            assert credential.auth_data.extensions == {"minPinLength": 7}
    assert pqkey.ok("pin", stdin="7309152\n") == "PIN set.\n"
    assert pqkey.config()["PIN change required"] == "no"


def test_config_with_pin_authentication_and_recovery(pqkey: Pqkey):
    pqkey.start()
    pqkey.ok("pin", stdin=f"{PIN}\n")
    assert pqkey.ok("config", "always-uv", "on", stdin=f"{PIN}\n") == "Always UV: on.\n"
    # An idempotent command needs no PIN and consumes no retries.
    assert pqkey.ok("config", "always-uv", "on", stdin=f"{WRONG_PIN}\n") == "Always UV: on.\n"
    assert pqkey.status()["PIN"] == f"set ({MAX_RETRIES} retries left)"
    assert pqkey.error("config", "always-uv", "off", stdin=f"{WRONG_PIN}\n") == f"wrong PIN; {MAX_RETRIES - 1} retries left"
    assert pqkey.ok("config", "always-uv", "off", stdin=f"{PIN}\n") == "Always UV: off.\n"

    # Confirmation precedes the PIN prompt, so declining reads only one line.
    declined = pqkey.run("config", "min-pin-length", "6", stdin="n\n")
    assert declined.returncode == 0 and "Nothing was changed." in declined.stdout, declined
    assert pqkey.status()["PIN"] == f"set ({MAX_RETRIES} retries left)"
    result = pqkey.ok("config", "min-pin-length", "6", stdin=f"y\n{PIN}\n")
    assert result == "Minimum PIN length: 6.\nA PIN change is required; run `pqkey pin`.\n"
    assert pqkey.config()["PIN change required"] == "yes"
    status = pqkey.ok("status")
    assert "PIN change required; run `pqkey pin`" in status, status
    for args in (("passkeys",), ("config", "always-uv", "on")):
        assert "`pqkey pin`" in pqkey.error(*args, stdin=f"{PIN}\n")
    # A current four-character PIN remains valid below the raised minimum.
    assert pqkey.error("pin", stdin=f"{PIN}\n12345\n") == "PIN must be at least 6 characters long"
    assert pqkey.ok("pin", stdin=f"{PIN}\n{NEW_PIN}\n") == "PIN changed.\n"
    assert pqkey.config()["PIN change required"] == "no"
    assert pqkey.ok("passkeys", stdin=f"{NEW_PIN}\n").startswith("No passkeys are stored on the key.\n")


def test_config_force_change_rejects_reusing_the_pin(pqkey: Pqkey):
    pqkey.start()
    pqkey.ok("pin", stdin=f"{NEW_PIN}\n")
    assert pqkey.ok("config", "force-pin-change", stdin=f"{NEW_PIN}\n") == "A PIN change is required; run `pqkey pin`.\n"
    assert pqkey.config()["PIN change required"] == "yes"
    assert pqkey.error("pin", stdin=f"{NEW_PIN}\n{NEW_PIN}\n") == (
        "the new PIN must differ from the current PIN when a change is required; "
        "run `pqkey pin` and choose another PIN"
    )
    assert pqkey.config()["PIN change required"] == "yes"
    assert pqkey.ok("pin", stdin=f"{NEW_PIN}\n{PIN}\n") == "PIN changed.\n"
    assert pqkey.config()["PIN change required"] == "no"


def test_config_reports_irreversible_minimum_and_rp_capacity_errors(pqkey: Pqkey):
    pqkey.start()
    pqkey.ok("config", "min-pin-length", "6", "--yes")
    error = pqkey.error("config", "min-pin-length", "4", "--yes")
    assert "reset" in error and "every passkey" in error, error
    assert "large blob" in error, error
    assert pqkey.config()["Minimum PIN length"] == "6"
    args = ["config", "min-pin-length", "7", "--yes"]
    for number in range(9):
        args += ["--rp", f"{number}.config.example"]
    error = pqkey.error(*args)
    assert "8" in error and "RP" in error, error
    assert pqkey.config()["Minimum PIN length"] == "6"
    error = pqkey.error("config", "min-pin-length", "7", "--rp", "x" * 254, "--yes")
    assert "253" in error, error
    assert pqkey.config()["Minimum PIN length"] == "6"


def test_config_survives_restart_and_reset_restores_defaults(pqkey: Pqkey):
    pqkey.start()
    pqkey.ok("pin", stdin=f"{PIN}\n")
    pqkey.ok("config", "always-uv", "on", stdin=f"{PIN}\n")
    pqkey.ok("config", "min-pin-length", "6", "--rp", "restart.config.example", "--yes", stdin=f"{PIN}\n")
    settings = pqkey.config()
    assert settings == {
        "Always UV": "on", "Minimum PIN length": "6", "PIN change required": "yes",
    }
    pqkey.ok("stop")
    pqkey.start()
    assert pqkey.config() == settings
    pqkey.ok("pin", stdin=f"{PIN}\n{NEW_PIN}\n")
    with client.open_device(pqkey.status()["Device"]) as device:
        ctap = Ctap2(device)
        protocol = ClientPin(ctap).protocol
        auth = client.pin_uv_auth(
            ctap, protocol, NEW_PIN, ClientPin.PERMISSION.MAKE_CREDENTIAL,
            "restart.config.example",
        )
        credential = client.register(
            ctap, "restart.config.example", client.ES256, uv=True,
            extensions={"minPinLength": True}, **auth,
        )
        assert credential.auth_data.extensions == {"minPinLength": 6}
    pqkey.ok("reset", "--yes")
    assert pqkey.config() == {
        "Always UV": "off", "Minimum PIN length": "4", "PIN change required": "no",
    }
    with client.open_device(pqkey.status()["Device"]) as device:
        credential = client.register(
            Ctap2(device), "restart.config.example", client.ES256,
            extensions={"minPinLength": True},
        )
        assert credential.auth_data.extensions is None


def test_large_blobs_and_keys_survive_restart_and_reset_erases_them(pqkey: Pqkey):
    """Close each HID handle before restarting and rediscover the new node.

    The test uses the CLI's product 0005 key and its own state directory;
    restarting it cannot interrupt another test's channel.
    """
    pqkey.start()
    rp_id = "restart.large-blobs.example"
    value = os.urandom(4096)
    with client.open_device(pqkey.status()["Device"]) as device:
        ctap = Ctap2(device)
        ctap.reset()
        ctap = Ctap2(device)
        credential = client.register(
            ctap, rp_id, client.ES256, options={"rk": True},
            extensions={"largeBlobKey": True},
        )
        assert len(credential.large_blob_key) == 32
        blobs = LargeBlobs(ctap)
        blobs.put_blob(credential.large_blob_key, value)
        array = blobs.read_blob_array()
        assert blobs.get_blob(credential.large_blob_key) == value
        assert len(array[0][1]) > blobs.max_fragment_length
    assert (pqkey.state_dir / "large-blobs").is_file()
    pqkey.ok("stop")
    pqkey.start()
    with client.open_device(pqkey.status()["Device"]) as device:
        ctap = Ctap2(device)
        blobs = LargeBlobs(ctap)
        assert blobs.read_blob_array() == array
        assert blobs.get_blob(credential.large_blob_key) == value
        response, _ = client.authenticate(
            ctap, credential, extensions={"largeBlobKey": True}
        )
        assert response[7] == credential.large_blob_key
    pqkey.ok("reset", "--yes")
    with client.open_device(pqkey.status()["Device"]) as device:
        ctap = Ctap2(device)
        assert LargeBlobs(ctap).read_blob_array() == []
        assert ctap.large_blobs(0, get=1704)[1] == bytes.fromhex(
            "8076be8b528d0075f7aae98d6fa57a6d3c"
        )
        with pytest.raises(CtapError) as error:
            client.authenticate(ctap, credential, extensions={"largeBlobKey": True})
        assert error.value.code == CtapError.ERR.NO_CREDENTIALS
        replacement = client.register(
            ctap, rp_id, client.ES256, options={"rk": True},
            extensions={"largeBlobKey": True},
        )
        assert replacement.large_blob_key != credential.large_blob_key
