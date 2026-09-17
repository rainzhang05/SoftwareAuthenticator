"""User presence through desktop notifications (`--presence notify`).

The key under test talks to a real D-Bus session bus; the notification server
on it is the fake in notifications.py, which answers as the test tells it to.
The key was started with `--presence-timeout 3`.
"""

import os
import time

import pytest
from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2

import ctap as client
import ctaphid
from notifications import FakeNotificationServer, wait_for

RP_ID = "presence.e2e.example"
PRESENCE_TIMEOUT_S = 3
ACTIONS = ["approve", "Approve", "deny", "Deny"]


@pytest.fixture
def notifications():
    server = FakeNotificationServer().start()
    try:
        yield server
    finally:
        server.stop()


@pytest.fixture
def notify_device(notify_hidraw_path):
    device = client.open_device(notify_hidraw_path)
    try:
        yield device
    finally:
        device.close()


@pytest.fixture
def notify_ctap(notify_device, notifications) -> Ctap2:
    """A CTAP2 session on the notify key, reset with the user's approval.

    The key has been running for longer than the 10 seconds after power-up
    CTAP 2.3 §6.6 allows a key without a display to reset in, and it was not
    started with --allow-late-reset: the notification counts as a display.
    """
    notifications.answer = "approve"
    session = Ctap2(notify_device)
    session.reset()
    reset = notifications.wait_for_shown(1)
    assert reset.summary == "Reset the security key"
    assert reset.body == "Reset the security key? This deletes all passkeys."
    assert reset.actions == ACTIONS
    notifications.shown.clear()
    notifications.close_requests.clear()
    return session


def test_approve_registers_and_signs_in_with_user_presence(notify_ctap, notifications):
    credential = client.register(notify_ctap, RP_ID, client.ES256, user=client.user_entity("alice"))
    shown = notifications.wait_for_shown(1)
    assert shown.summary == "Create a passkey"
    assert shown.body == f"Create a passkey for {RP_ID} as alice (Alice)?"
    assert shown.actions == ACTIONS
    assert shown.hints.get("urgency") == ("y", 2)
    assert shown.id in notifications.close_requests

    # authenticate() checks the UP flag and the signature.
    client.authenticate(notify_ctap, credential)
    shown = notifications.wait_for_shown(2)
    assert shown.summary == "Sign in with a passkey"
    assert shown.body == f"Sign in to {RP_ID}?"


def test_signing_in_with_the_only_discoverable_credential_names_its_account(notify_ctap, notifications):
    credential = client.register(notify_ctap, RP_ID, client.ES256, user=client.user_entity("frank"), options={"rk": True})
    notifications.wait_for_shown(1)

    response, _ = client.authenticate(notify_ctap, credential, allow_list=False)
    shown = notifications.wait_for_shown(2)
    assert shown.summary == "Sign in with a passkey"
    assert shown.body == f"Sign in to {RP_ID} as frank (Frank)?"
    # The account is only shown to the user: without user verification the
    # response carries the user ID alone (CTAP 2.3 §6.2.2 step 12).
    assert set(response[4]) == {"id"}


def test_selection_asks_the_user_to_select_the_key(notify_ctap, notifications):
    """authenticatorSelection (CTAP 2.3 §6.9)."""
    notify_ctap.selection()
    shown = notifications.wait_for_shown(1)
    assert shown.summary == "Select a security key"
    assert shown.body == "Select this security key?"

    notifications.answer = "deny"
    with pytest.raises(CtapError) as excinfo:
        notify_ctap.selection()
    assert excinfo.value.code == CtapError.ERR.OPERATION_DENIED
    notifications.wait_for_shown(2)


@pytest.mark.parametrize("answer", ["deny", "dismiss"])
def test_deny_or_dismiss_refuses_the_operation(notify_ctap, notifications, answer):
    notifications.answer = answer
    with pytest.raises(CtapError) as excinfo:
        client.make_credential(notify_ctap, RP_ID, client.user_entity("bob"), [client.ES256], os.urandom(32))
    assert excinfo.value.code == CtapError.ERR.OPERATION_DENIED
    notifications.wait_for_shown(1)


def test_no_answer_times_out_and_withdraws_the_notification(notify_ctap, notifications):
    notifications.answer = None
    started = time.monotonic()
    with pytest.raises(CtapError) as excinfo:
        client.make_credential(notify_ctap, RP_ID, client.user_entity("carol"), [client.ES256], os.urandom(32))
    elapsed = time.monotonic() - started
    # CTAP 2.3 §6.1.2 step 14.2.1.2: a timeout is CTAP2_ERR_OPERATION_DENIED.
    assert excinfo.value.code == CtapError.ERR.OPERATION_DENIED
    assert PRESENCE_TIMEOUT_S - 0.5 <= elapsed < PRESENCE_TIMEOUT_S + 5, elapsed
    shown = notifications.wait_for_shown(1)
    assert shown.id in notifications.close_requests

    # §6.6: for authenticatorReset it is CTAP2_ERR_USER_ACTION_TIMEOUT.
    with pytest.raises(CtapError) as excinfo:
        notify_ctap.reset()
    assert excinfo.value.code == CtapError.ERR.USER_ACTION_TIMEOUT
    assert notifications.wait_for_shown(2).id in notifications.close_requests


def test_without_a_notification_server_requests_are_denied(notify_device):
    started = time.monotonic()
    with pytest.raises(CtapError) as excinfo:
        client.make_credential(Ctap2(notify_device), RP_ID, client.user_entity("dave"), [client.ES256], os.urandom(32))
    assert excinfo.value.code == CtapError.ERR.OPERATION_DENIED
    # Denied at once, not after waiting for an answer that cannot come.
    assert time.monotonic() - started < PRESENCE_TIMEOUT_S


def test_a_server_that_cannot_show_buttons_gets_nothing_and_requests_are_denied(notify_device, notifications):
    notifications.capabilities = ["body", "body-markup"]
    with pytest.raises(CtapError) as excinfo:
        client.make_credential(Ctap2(notify_device), RP_ID, client.user_entity("erin"), [client.ES256], os.urandom(32))
    assert excinfo.value.code == CtapError.ERR.OPERATION_DENIED
    assert notifications.shown == []


def test_names_are_escaped_for_servers_that_interpret_markup(notify_device, notifications):
    notifications.capabilities = ["actions", "body", "body-markup"]
    notifications.answer = "deny"
    user = {"id": os.urandom(16), "name": "<b>mallory</b> & co", "displayName": "<b>mallory</b> & co"}
    with pytest.raises(CtapError) as excinfo:
        client.make_credential(Ctap2(notify_device), RP_ID, user, [client.ES256], os.urandom(32))
    assert excinfo.value.code == CtapError.ERR.OPERATION_DENIED
    body = notifications.wait_for_shown(1).body
    assert body == f"Create a passkey for {RP_ID} as &lt;b&gt;mallory&lt;/b&gt; &amp; co?"


def test_cancel_withdraws_the_notification(notify_hidraw_path, notifications):
    """CTAPHID_CANCEL while the notification is showing: the request is
    answered with CTAP2_ERR_KEEPALIVE_CANCEL, nothing else is sent, and the
    notification is withdrawn."""
    notifications.answer = None
    hid = ctaphid.RawHid(notify_hidraw_path)
    try:
        cid = hid.allocate_channel()
        hid.send(cid, ctaphid.CBOR, client.make_credential_request(RP_ID, client.user_entity("frank")))
        shown = notifications.wait_for_shown(1)
        hid.send(cid, ctaphid.CANCEL)
        cancelled_at = time.monotonic()
        response = hid.receive()
        assert (response.cid, response.cmd, response.payload) == (cid, ctaphid.CBOR, bytes([0x2D])), str(response)
        wait_for(lambda: shown.id in notifications.close_requests, 1.0, "the notification was not withdrawn")
        assert time.monotonic() - cancelled_at < 1.0

        payload = os.urandom(16)
        hid.send(cid, ctaphid.PING, payload)
        message = hid.receive()
        assert (message.cid, message.cmd, message.payload) == (cid, ctaphid.PING, payload), str(message)
    finally:
        hid.close()
