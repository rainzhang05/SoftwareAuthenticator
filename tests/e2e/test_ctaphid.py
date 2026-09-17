"""CTAPHID transport behaviour, checked packet by packet on the hidraw node."""

import os
import struct
import time

import pytest
from fido2 import cbor
from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2

import ctap as client
import ctaphid


@pytest.fixture
def hid(hidraw_path):
    """Raw access to a freshly reset authenticator.

    The reset goes through its own descriptor, which is closed before the raw
    one is opened: every open descriptor receives every input report.
    """
    device = client.open_device(hidraw_path)
    try:
        Ctap2(device).reset()
    finally:
        device.close()
    raw = ctaphid.RawHid(hidraw_path)
    try:
        yield raw
    finally:
        raw.close()


def test_init_allocates_distinct_channels(hid):
    nonce = os.urandom(8)
    hid.send(ctaphid.BROADCAST_CID, ctaphid.INIT, nonce)
    response = hid.expect(ctaphid.BROADCAST_CID, ctaphid.INIT)
    assert len(response.payload) == 17
    assert response.payload[:8] == nonce
    cid, protocol, _major, _minor, _build, capabilities = struct.unpack(">IBBBBB", response.payload[8:])
    assert cid not in (0, ctaphid.BROADCAST_CID)
    assert protocol == 2
    assert capabilities & 0x04, "CBOR capability"
    assert capabilities & 0x08, "NMSG capability"
    assert hid.allocate_channel() != cid


def test_ping_echoes_a_multi_packet_payload(hid):
    cid = hid.allocate_channel()
    payload = os.urandom(300)
    hid.send(cid, ctaphid.PING, payload)
    assert hid.expect(cid, ctaphid.PING).payload == payload


def test_cancel_while_idle_gets_no_response(hid):
    cid = hid.allocate_channel()
    hid.send(cid, ctaphid.CANCEL)
    # The authenticator handles packets in order, so a response to the CANCEL
    # would arrive before the PING's echo.
    payload = os.urandom(16)
    hid.send(cid, ctaphid.PING, payload)
    message = hid.receive()
    if (message.cid, message.cmd, message.payload) != (cid, ctaphid.PING, payload):
        raise ctaphid.UnexpectedPacket(f"CANCEL on an idle channel was answered with {message}")


def test_request_from_another_channel_does_not_corrupt_a_request_in_progress(hid):
    first, second = hid.allocate_channel(), hid.allocate_channel()
    rp_id = "interleaved.e2e.example"
    client_data_hash = os.urandom(32)
    request = bytes([Ctap2.CMD.MAKE_CREDENTIAL]) + cbor.encode(
        {
            1: client_data_hash,
            2: {"id": rp_id},
            3: client.user_entity("a-user-name-long-enough-to-need-several-packets"),
            4: [{"type": "public-key", "alg": client.ES256}],
        }
    )
    packets = hid.init_packets(first, ctaphid.CBOR, request)
    assert len(packets) > 1

    # The second channel talks while the first channel's request is half sent.
    hid.write_packet(packets[0])
    hid.send(second, ctaphid.PING, b"interleaved")
    for packet in packets[1:]:
        hid.write_packet(packet)

    responses = {}
    while len(responses) < 2:
        message = hid.receive()
        assert message.cid in (first, second), f"response on unknown channel: {message}"
        responses[message.cid] = message

    # Busy, or served after the first request: both are allowed.
    other = responses[second]
    assert (other.cmd, other.payload) in ((ctaphid.ERROR, bytes([0x06])), (ctaphid.PING, b"interleaved")), str(other)

    response = responses[first]
    assert response.cmd == ctaphid.CBOR, str(response)
    if response.payload[0] != 0:
        raise CtapError(response.payload[0])
    auth_data = client.AuthData.parse(cbor.decode(response.payload[1:])[2])
    auth_data.check(rp_id, up=True, uv=False, at=True)


def test_cancel_of_a_request_in_flight_gets_only_the_cbor_response(hid):
    """CTAP 2.3 §11.2.9.1.5: CANCEL is never answered itself, and a cancelled
    request is answered with CTAP2_ERR_KEEPALIVE_CANCEL in a CTAPHID_CBOR
    response, not a CTAPHID_ERROR.

    getInfo usually finishes before the CANCEL is seen, so either status is
    fine; what matters is that exactly one CBOR response comes back.
    """
    cid = hid.allocate_channel()
    hid.send(cid, ctaphid.CBOR, bytes([Ctap2.CMD.GET_INFO]))
    hid.send(cid, ctaphid.CANCEL)
    response = hid.receive()
    assert (response.cid, response.cmd) == (cid, ctaphid.CBOR), str(response)
    assert response.payload[0] in (0x00, 0x2D), str(response)

    # Anything sent for the CANCEL would arrive before the PING's echo.
    payload = os.urandom(16)
    hid.send(cid, ctaphid.PING, payload)
    message = hid.receive()
    assert (message.cid, message.cmd, message.payload) == (cid, ctaphid.PING, payload), str(message)


def test_init_resynchronises_a_channel_in_the_middle_of_a_message(hid):
    """CTAP 2.3 §11.2.5.3: INIT on the channel of the transaction under way
    aborts it, and the INIT is answered."""
    cid = hid.allocate_channel()
    packets = hid.init_packets(cid, ctaphid.PING, os.urandom(200))
    hid.write_packet(packets[0])

    nonce = os.urandom(8)
    hid.send(cid, ctaphid.INIT, nonce)
    response = hid.expect(cid, ctaphid.INIT)
    assert response.payload[:8] == nonce
    assert struct.unpack(">I", response.payload[8:12]) == (cid,)

    # The rest of the aborted message is ignored and the channel works.
    for packet in packets[1:]:
        hid.write_packet(packet)
    payload = os.urandom(16)
    hid.send(cid, ctaphid.PING, payload)
    message = hid.receive()
    assert (message.cid, message.cmd, message.payload) == (cid, ctaphid.PING, payload), str(message)


def test_a_message_sent_slowly_packet_by_packet_is_received(hid):
    """CTAP 2.3 §11.2.5.4: the device assembles a message "until all parts of
    it has been received or that the transaction times out". The timeout runs
    between packets (550 ms), so a message whose packets are 300 ms apart
    completes although it takes well over a second."""
    cid = hid.allocate_channel()
    payload = os.urandom(300)
    packets = hid.init_packets(cid, ctaphid.PING, payload)
    assert len(packets) == 6
    for packet in packets:
        hid.write_packet(packet)
        time.sleep(0.3)
    assert hid.expect(cid, ctaphid.PING).payload == payload


def test_a_stalled_message_times_out(hid):
    """CTAP 2.3 §11.2.5.2: a message whose next packet does not come is backed
    out with ERR_MSG_TIMEOUT, and the device is free again."""
    cid = hid.allocate_channel()
    packets = hid.init_packets(cid, ctaphid.PING, os.urandom(100))
    hid.write_packet(packets[0])
    message = hid.expect(cid, ctaphid.ERROR)
    assert message.payload == bytes([0x05]), str(message)

    payload = os.urandom(16)
    hid.send(cid, ctaphid.PING, payload)
    assert hid.expect(cid, ctaphid.PING).payload == payload
