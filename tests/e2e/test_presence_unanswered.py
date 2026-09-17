"""The CTAPHID transport while the key waits for the user.

The key under test was started with `--presence unanswered`: it asks for user
presence and never gets an answer, so a request waits until it is cancelled.
Its credential store is never changed, so these tests need no reset.
"""

import os
import struct
import time

import pytest

import ctap as client
import ctaphid

RP_ID = "unanswered.e2e.example"

STATUS_PROCESSING = 1
STATUS_UPNEEDED = 2
ERR_CHANNEL_BUSY = 0x06
CTAP2_ERR_KEEPALIVE_CANCEL = 0x2D

# CTAP 2.3 §11.2.9.1.7: while processing, the authenticator sends a keepalive
# "at least every 100ms".
KEEPALIVE_MAX_GAP_S = 0.100


@pytest.fixture
def hid(unanswered_hidraw_path):
    raw = ctaphid.RawHid(unanswered_hidraw_path)
    try:
        yield raw
    finally:
        raw.close()


def _packet(hid):
    """The next packet, when it arrived, and its channel, command and first
    payload byte. Keepalives and errors fit in one packet."""
    packet = hid.read_packet(timeout=1.0)
    at = time.monotonic()
    cid, cmd, length = struct.unpack(">IBH", packet[:7])
    if not cmd & 0x80:
        raise ctaphid.UnexpectedPacket(f"continuation packet {packet.hex()}")
    return at, cid, cmd & 0x7F, packet[7 : 7 + length]


def _cancel_and_expect_only_keepalive_cancel(hid, cid):
    """CTAP 2.3 §11.2.9.1.5: CANCEL is not answered itself, and the cancelled
    request is answered with CTAP2_ERR_KEEPALIVE_CANCEL in a CTAPHID_CBOR
    response. Anything sent for the CANCEL would arrive before the PING's
    echo."""
    hid.send(cid, ctaphid.CANCEL)
    response = hid.receive()
    assert (response.cid, response.cmd, response.payload) == (
        cid,
        ctaphid.CBOR,
        bytes([CTAP2_ERR_KEEPALIVE_CANCEL]),
    ), str(response)
    payload = os.urandom(16)
    hid.send(cid, ctaphid.PING, payload)
    message = hid.receive()
    assert (message.cid, message.cmd, message.payload) == (cid, ctaphid.PING, payload), str(message)


def test_keepalives_report_up_needed_and_other_channels_are_busy(hid):
    cid, other = hid.allocate_channel(), hid.allocate_channel()
    hid.send(cid, ctaphid.CBOR, client.make_credential_request(RP_ID, client.user_entity("alice")))
    sent_at = time.monotonic()

    keepalives = []
    busy = None
    while time.monotonic() - sent_at < 1.5:
        at, channel, cmd, payload = _packet(hid)
        if (channel, cmd) == (cid, ctaphid.KEEPALIVE):
            keepalives.append((at, payload[0]))
            if len(keepalives) == 5:
                # CTAP 2.3 §11.2.5.1: another channel is told the device is busy.
                hid.send(other, ctaphid.PING, b"are you there?")
        elif (channel, cmd) == (other, ctaphid.ERROR):
            busy = payload[0]
        else:
            raise ctaphid.UnexpectedPacket(f"command {cmd:#04x} {payload.hex()} on channel {channel:#010x}")
    assert busy == ERR_CHANNEL_BUSY, busy

    statuses = [status for _, status in keepalives]
    assert STATUS_UPNEEDED in statuses, statuses
    first_up_needed = statuses.index(STATUS_UPNEEDED)
    assert all(s == STATUS_PROCESSING for s in statuses[:first_up_needed]), statuses
    assert all(s == STATUS_UPNEEDED for s in statuses[first_up_needed:]), statuses

    previous = sent_at
    for at, _ in keepalives:
        gap = at - previous
        assert gap <= KEEPALIVE_MAX_GAP_S, f"{gap * 1000:.1f} ms without a keepalive"
        previous = at

    _cancel_and_expect_only_keepalive_cancel(hid, cid)


def test_cancel_during_the_prompt_gets_only_a_keepalive_cancel_response(hid):
    cid = hid.allocate_channel()
    hid.send(cid, ctaphid.CBOR, client.make_credential_request(RP_ID, client.user_entity("bob")))
    deadline = time.monotonic() + 5
    while True:
        assert time.monotonic() < deadline, "no UPNEEDED keepalive"
        _, channel, cmd, payload = _packet(hid)
        assert (channel, cmd) == (cid, ctaphid.KEEPALIVE), f"command {cmd:#04x} on channel {channel:#010x}"
        if payload[0] == STATUS_UPNEEDED:
            break

    _cancel_and_expect_only_keepalive_cancel(hid, cid)
