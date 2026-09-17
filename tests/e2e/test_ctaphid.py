"""CTAPHID transport behaviour, checked packet by packet on the hidraw node."""

import os
import struct

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
