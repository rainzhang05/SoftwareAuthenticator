"""Actual installation/setup on a disposable Linux runner with real HID.

Explicitly opt in: this installs /usr/local/bin/pqkey and a user service.
Ordinary E2E runs skip it to protect a developer's personal installation.
"""
import os
from pathlib import Path

import pytest
from fido2.ctap2 import ClientPin, Config, Ctap2, PinProtocolV2

import ctap as client
from notifications import FakeNotificationServer
from setup_support import BINARY, node, run

pytestmark = pytest.mark.skipif(os.environ.get("PQKEY_INSTALLER_E2E") != "1",
                                reason="requires opt-in disposable installer E2E host")
ROOT = Path(__file__).resolve().parents[2]
PIN = "86420000"
NEW_PIN = "97530000"
RP = "setup.e2e.example"


def test_install_setup_rerun_update_and_pin_policy_over_real_hid(tmp_path):
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
        status, output = run([BINARY, "setup", "--yes"], env)
        assert status != 0 and "pqkey is ready." not in output, output
        status, output = run([BINARY, "setup", "--yes"], env,
                             (("Current PIN:", PIN), ("New PIN:", NEW_PIN), ("Confirm new PIN:", NEW_PIN)))
        assert status == 0, output
        with client.open_device(node(env)) as device:
            ctap = Ctap2(device)
            auth = client.pin_uv_auth(ctap, protocol, NEW_PIN, ClientPin.PERMISSION.GET_ASSERTION, RP)
            client.authenticate(ctap, credential, uv=True, **auth)

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
    finally:
        status, output = run([BINARY, "setup", "--uninstall"], env)
        if server is not None:
            server.stop()
        assert status == 0, output
