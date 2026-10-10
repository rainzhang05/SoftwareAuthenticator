"""U2F polling and notifications, including transport-level busy replies."""

import os
import struct
import time

import pytest

import ctaphid
from notifications import FakeNotificationServer, wait_for


@pytest.fixture
def server():
    server = FakeNotificationServer().start()
    try:
        yield server
    finally:
        server.stop()


@pytest.fixture
def hid(notify_hidraw_path):
    raw = ctaphid.RawHid(notify_hidraw_path)
    cid = raw.allocate_channel()
    try:
        yield raw, cid
    finally:
        raw.send(cid, ctaphid.INIT, os.urandom(8))
        raw.expect(cid, ctaphid.INIT)
        raw.close()


def request():
    return bytes([0, 1, 0, 0, 0, 0, 64]) + os.urandom(64)


def exchange(hid, payload):
    raw, cid = hid
    raw.send(cid, ctaphid.MSG, payload)
    return raw.expect(cid, ctaphid.MSG).payload


def test_pending_repeats_share_one_prompt_and_other_requests_are_busy(hid, server):
    server.answer = None
    payload = request()
    assert exchange(hid, payload) == b"\x69\x85"
    shown = server.wait_for_shown()
    assert shown.summary == "Register a U2F security key"
    assert shown.body == "Register this security key for a U2F request? The site cannot be identified."
    for _ in range(3):
        assert exchange(hid, payload) == b"\x69\x85"
    assert len(server.shown) == 1
    raw, cid = hid
    changed = payload[:-1] + bytes([payload[-1] ^ 1])
    for channel, command, body in [
        (cid, ctaphid.MSG, changed), (cid + 1, ctaphid.MSG, payload),
        (cid, ctaphid.CBOR, bytes([4])), (cid, ctaphid.MSG, bytes([0, 3, 0, 0])),
    ]:
        raw.send(channel, command, body)
        assert raw.expect(channel, ctaphid.ERROR).payload == bytes([6])
    raw.send(cid, ctaphid.CANCEL)
    assert exchange(hid, payload) == b"\x69\x85"
    assert len(server.shown) == 1


def test_approval_returns_registration_once_on_a_repeat(hid, server):
    server.answer = None
    payload = request()
    assert exchange(hid, payload) == b"\x69\x85"
    shown = server.wait_for_shown()
    server.answer_notification(shown.id, "approve")
    deadline = time.monotonic() + 5
    pending = 1
    while True:
        response = exchange(hid, payload)
        if response.endswith(b"\x90\0"):
            break
        assert response == b"\x69\x85"
        pending += 1
        assert time.monotonic() < deadline
        time.sleep(0.1)
    assert pending >= 1
    assert response[0] == 5 and response[66] == 107
    assert len(server.shown) == 1
    server.answer = None
    assert exchange(hid, payload) == b"\x69\x85"
    server.wait_for_shown(2)
    assert len(server.shown) == 2


def test_an_approval_expires_after_ten_seconds(hid, server):
    server.answer = None
    payload = request()
    assert exchange(hid, payload) == b"\x69\x85"
    shown = server.wait_for_shown()
    server.answer_notification(shown.id, "approve")
    wait_for(lambda: shown.id in server.close_requests, 2, "approved notification was not closed")
    time.sleep(10.2)
    assert exchange(hid, payload) == b"\x69\x85"
    server.wait_for_shown(2)


@pytest.mark.parametrize("answer", ["deny", None], ids=["denied", "timeout"])
def test_denial_and_timeout_do_not_restart_a_prompt_while_polling(hid, server, answer):
    server.answer = answer
    payload = request()
    assert exchange(hid, payload) == b"\x69\x85"
    shown = server.wait_for_shown()
    deadline = time.monotonic() + 4
    while time.monotonic() < deadline:
        assert exchange(hid, payload) == b"\x69\x85"
        time.sleep(0.1)
    assert len(server.shown) == 1
    assert shown.id in server.close_requests or answer == "deny"
    time.sleep(3.2)
    assert exchange(hid, payload) == b"\x69\x85"
    server.wait_for_shown(2)
    assert len(server.shown) == 2


def test_stopping_repeats_cancels_an_abandoned_prompt(hid, server):
    server.answer = None
    assert exchange(hid, request()) == b"\x69\x85"
    shown = server.wait_for_shown()
    wait_for(lambda: shown.id in server.close_requests, 4, "abandoned U2F prompt was not closed")
    raw, cid = hid
    raw.send(cid, ctaphid.MSG, bytes([0, 3, 0, 0]))
    assert raw.expect(cid, ctaphid.MSG).payload == b"U2F_V2\x90\0"


def test_abandonment_frees_a_key_whose_presence_timeout_is_thirty_seconds(unanswered_hidraw_path):
    raw = ctaphid.RawHid(unanswered_hidraw_path)
    try:
        cid = raw.allocate_channel()
        raw.send(cid, ctaphid.MSG, request())
        assert raw.expect(cid, ctaphid.MSG).payload == b"\x69\x85"
        time.sleep(3.2)
        started = time.monotonic()
        raw.send(cid, ctaphid.MSG, bytes([0, 3, 0, 0]))
        assert raw.expect(cid, ctaphid.MSG).payload == b"U2F_V2\x90\0"
        assert time.monotonic() - started < 5
    finally:
        raw.close()


def test_invalid_requests_and_check_only_do_not_open_a_prompt(hid, server):
    for payload, status in [
        (bytes([0]), 0x6700), (bytes([1, 3, 0, 0]), 0x6E00),
        (bytes([0, 255, 0, 0]), 0x6D00), (bytes([0, 3, 1, 0]), 0x6A86),
        (bytes([0, 2, 3, 0, 0, 0, 65]) + os.urandom(64) + b"\0", 0x6A80),
        (bytes([0, 2, 7, 0, 0, 0, 65]) + os.urandom(64) + b"\0", 0x6A80),
    ]:
        assert exchange(hid, payload) == struct.pack(">H", status)
    assert not server.shown
