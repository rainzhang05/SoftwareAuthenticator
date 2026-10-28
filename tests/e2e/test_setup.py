"""Actual installation/setup on a disposable Linux runner with real HID.

Explicitly opt in: this installs /usr/local/bin/pqkey and a user service.
Ordinary E2E runs skip it to protect a developer's personal installation.

The service runs under the shipped unit's system call filter, and the test
fails if the filter refuses the daemon any call (seccomp_audit.py). That needs
the host prepared as .github/workflows/e2e.yml does: the user manager started
with SYSTEMD_LOG_SECCOMP=1, and kernel.printk_ratelimit=0.
"""
import os
from pathlib import Path

import pytest
from fido2.ctap import CtapError
from fido2.ctap2 import ClientPin, Config, Ctap2, PinProtocolV2

import ctap as client
import seccomp_audit
from notifications import FakeNotificationServer
from setup_support import BINARY, node, run

pytestmark = pytest.mark.skipif(os.environ.get("PQKEY_INSTALLER_E2E") != "1",
                                reason="requires opt-in disposable installer E2E host")
ROOT = Path(__file__).resolve().parents[2]
PIN = "86420000"
NEW_PIN = "97530000"
RP = "setup.e2e.example"
# Lines of the check's records and problems in the job log; the diagnostics
# keep every record.
SHOWN = 100


def first(lines):
    return lines[:SHOWN] + ([f"... and {len(lines) - SHOWN} more"] if len(lines) > SHOWN else [])


@pytest.fixture
def filter_check():
    """From before the first install until the service is uninstalled, a call
    the filter refuses the daemon fails the test at teardown with its kernel
    audit record, as do missing canary records and lost records."""
    check = seccomp_audit.FilterCheck()
    check.begin()
    yield check
    lines, summary, problems = check.finish()
    print("System call filter:", summary, *first(lines), sep="\n")
    if os.environ.get("E2E_WORK"):
        diagnostics = Path(os.environ["E2E_WORK"]) / "e2e-diagnostics"
        diagnostics.mkdir(parents=True, exist_ok=True)
        (diagnostics / "setup-seccomp.log").write_text("".join(line + "\n" for line in lines))
    assert not problems, "the system call filter check failed:\n" + "\n".join(first(problems))


def test_install_setup_rerun_update_and_pin_policy_over_real_hid(tmp_path, filter_check):
    env = dict(os.environ, XDG_CONFIG_HOME=str(tmp_path / "config"),
               XDG_DATA_HOME=str(tmp_path / "data"), XDG_CACHE_HOME=str(tmp_path / "cache"),
               PATH="/usr/local/bin:" + os.environ["PATH"], NO_COLOR="1")
    # Fake notifications use the workflow's real session bus. pqkey setup
    # synchronizes this address with the user manager without changing policy.
    server = FakeNotificationServer().start()
    install = [str(ROOT / "install.sh"), "--yes"]
    try:
        status, output = run(install, env)
        assert status != 0 and "pqkey is ready." not in output, output
        assert "pqkey pin" in output, output
        with client.open_device(node(env)) as device:
            assert Ctap2(device).get_info().options["clientPin"] is False
        filter_check.observe()

        status, output = run(install, env, (("New PIN:", PIN), ("Confirm new PIN:", PIN)))
        assert status == 0 and "pqkey is ready." in output, output
        assert PIN not in output
        assert PIN not in (tmp_path / "cache/pqkey/install.log").read_text()
        with client.open_device(node(env)) as device:
            ctap = Ctap2(device)
            protocol = PinProtocolV2()
            auth = client.pin_uv_auth(ctap, protocol, PIN, ClientPin.PERMISSION.MAKE_CREDENTIAL, RP)
            credential = client.register(ctap, RP, client.ML_DSA_65, uv=True, options={"rk": True}, **auth)
            token = ClientPin(ctap, protocol).get_pin_token(PIN, ClientPin.PERMISSION.AUTHENTICATOR_CFG)
            config = Config(ctap, protocol, token)
            config.set_min_pin_length(6, [RP])
            config.toggle_always_uv()
        filter_check.observe()
        inode = Path(BINARY).stat().st_ino
        status, output = run([BINARY, "setup", "--yes"], env)
        assert status == 0 and "New PIN:" not in output, output
        status, output = run(install, env)
        assert status == 0 and "New PIN:" not in output, output
        assert Path(BINARY).stat().st_ino != inode
        assert not Path(BINARY + ".previous").exists()

        with client.open_device(node(env)) as device:
            ctap = Ctap2(device)
            info = ctap.get_info()
            assert info.options["clientPin"] and info.options["alwaysUv"]
            assert info.min_pin_length == 6
            auth = client.pin_uv_auth(ctap, protocol, PIN, ClientPin.PERMISSION.GET_ASSERTION, RP)
            client.authenticate(ctap, credential, uv=True, allow_list=False, **auth)
            token = ClientPin(ctap, protocol).get_pin_token(PIN, ClientPin.PERMISSION.AUTHENTICATOR_CFG)
            Config(ctap, protocol, token).set_min_pin_length(force_change_pin=True)
        filter_check.observe()
        status, output = run([BINARY, "setup", "--yes"], env)
        assert status != 0 and "pqkey is ready." not in output, output
        status, output = run([BINARY, "setup", "--yes"], env,
                             (("Current PIN:", PIN), ("New PIN:", NEW_PIN), ("Confirm new PIN:", NEW_PIN)))
        assert status == 0, output
        with client.open_device(node(env)) as device:
            ctap = Ctap2(device)
            auth = client.pin_uv_auth(ctap, protocol, NEW_PIN, ClientPin.PERMISSION.GET_ASSERTION, RP)
            client.authenticate(ctap, credential, uv=True, **auth)
        filter_check.observe()

        server.stop()
        server = None
        status, output = run([BINARY, "setup", "--yes"], env)
        assert status != 0 and "pqkey is ready." not in output, output
        server = FakeNotificationServer().start()
        status, output = run([BINARY, "setup", "--yes"], env)
        assert status == 0, output
        status, output = run([BINARY, "stop"], env)
        assert status == 0, output
        status, output = run([BINARY, "setup", "--yes"], env)
        assert status == 0, output
        with client.open_device(node(env)) as device:
            assert Ctap2(device).get_info().options["clientPin"]
            # CTAPHID_WINK: the service names the key in a notification
            # without actions, and the session stays usable.
            shown = len(server.shown)
            device.wink()
            identification = server.wait_for_shown(shown + 1)
            assert (identification.summary, identification.actions) == ("Identify the security key", [])
            assert device.ping(b"identified") == b"identified"
        filter_check.observe()

        # authenticatorReset is accepted only within 10 seconds of power-up
        # (CTAP 2.3 §6.6), so pqkey reset restarts the service first; the fake
        # server approves the reset's notification. It erases the PIN, the
        # policy and the passkey.
        shown = len(server.shown)
        status, output = run([BINARY, "reset", "--yes"], env)
        assert status == 0 and "The key is reset" in output, output
        assert "Reset the security key" in [notification.summary for notification in server.shown[shown:]]
        filter_check.observe()
        with client.open_device(node(env)) as device:
            ctap = Ctap2(device)
            info = ctap.get_info()
            assert info.options["clientPin"] is False and info.options.get("alwaysUv") is False
            assert info.min_pin_length == 4 and not info.force_pin_change
            with pytest.raises(CtapError) as error:
                ctap.get_assertion(RP, os.urandom(32), [{"type": "public-key", "id": credential.credential_id}],
                                   options={"up": False})
            assert error.value.code == CtapError.ERR.NO_CREDENTIALS
    finally:
        status, output = run([BINARY, "setup", "--uninstall"], env)
        if server is not None:
            server.stop()
        assert status == 0, output
