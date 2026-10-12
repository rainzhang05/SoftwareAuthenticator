"""Identification is transport-only, independent of policy and presence."""

import concurrent.futures
import time

import pytest
from fido2.ctap import CtapError
from fido2.ctap2 import ClientPin, Ctap2
from fido2.ctap2.config import Config
from fido2.ctap2.pin import PinProtocolV1

import ctap as client
from notifications import FakeNotificationServer, wait_for


@pytest.fixture
def server():
    server = FakeNotificationServer().start()
    try:
        yield server
    finally:
        server.stop()


@pytest.fixture
def key(notify_hidraw_path):
    device = client.open_device(notify_hidraw_path)
    try:
        yield device
    finally:
        device.close()


def check_identification(shown, key):
    assert shown.summary == "Identify the security key"
    identity = key.serial_number
    assert identity and identity.startswith("pqkey-")
    assert shown.body == f"pqkey software security key (device {identity})."
    assert shown.actions == []
    assert shown.expire_timeout == 2000
    assert shown.hints["urgency"] == ("y", 1)
    assert shown.hints["transient"] == ("b", True)


def test_wink_without_action_capability_expires_and_leaves_the_session_usable(key, server):
    server.capabilities = []
    key.wink()
    shown = server.wait_for_shown()
    check_identification(shown, key)
    assert key.ping(b"identified") == b"identified"
    wait_for(lambda: shown.id not in server._open, 3, "identification did not expire")
    assert shown.id not in server.close_requests


@pytest.mark.parametrize("failure", ["notify_error", "ignore_notify"])
def test_identification_delivery_failure_is_bounded_and_recoverable(key, server, failure):
    setattr(server, failure, True)
    started = time.monotonic()
    with pytest.raises(CtapError) as error:
        key.wink()
    assert error.value.code == CtapError.ERR.OTHER
    assert time.monotonic() - started < 1.5
    assert key.ping(b"still usable") == b"still usable"
    setattr(server, failure, False)
    key.wink()
    check_identification(server.wait_for_shown(), key)


def test_identification_without_a_server_returns_other(key):
    with pytest.raises(CtapError) as error:
        key.wink()
    assert error.value.code == CtapError.ERR.OTHER
    assert key.ping(b"usable") == b"usable"


def test_identification_action_cannot_approve_a_presence_request(key, server):
    server.answer = None
    key.wink()
    identification = server.wait_for_shown()
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(Ctap2(key).selection)
        prompt = server.wait_for_shown(2)
        try:
            server.answer_notification(identification.id, "approve")
            wait_for(lambda: identification.id not in server._open, 1, "action was not emitted")
            time.sleep(0.05)
            assert not future.done(), "identification approved a presence request"
            server.answer_notification(prompt.id, "approve")
            future.result(timeout=5)
        finally:
            server.answer_notification(prompt.id, "deny")


def test_wink_is_independent_of_pin_complexity_and_always_uv(key, server):
    ctap = Ctap2(key)
    ctap.reset()
    Config(ctap).set_min_pin_length(pin_complexity_policy=True)
    protocol = PinProtocolV1()
    pin = ClientPin(ctap, protocol)
    pin.set_pin("Ab12")
    token = pin.get_pin_token("Ab12", ClientPin.PERMISSION.AUTHENTICATOR_CFG)
    config = Config(ctap, protocol, token)
    config.toggle_always_uv()
    before = ctap.send_cbor(Ctap2.CMD.GET_INFO)
    count = len(server.shown)
    key.wink()
    check_identification(server.wait_for_shown(count + 1), key)
    assert ctap.send_cbor(Ctap2.CMD.GET_INFO) == before
    # The configuration token remains usable across WINK and LOCK.
    key.lock(1)
    try:
        config.toggle_always_uv()
    finally:
        key.lock(0)
    assert not ctap.get_info().options["alwaysUv"]
