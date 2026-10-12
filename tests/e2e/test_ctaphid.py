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
    assert not capabilities & 0x08, "MSG is implemented"
    assert capabilities & 0x01, "WINK capability"
    assert hid.allocate_channel() != cid


def test_ping_echoes_a_multi_packet_payload(hid):
    cid = hid.allocate_channel()
    payload = os.urandom(300)
    hid.send(cid, ctaphid.PING, payload)
    assert hid.expect(cid, ctaphid.PING).payload == payload


def send_long_ping(hid, cid, payload):
    """Keep the maximum-length request within uhid's small output queue."""
    for packet in hid.init_packets(cid, ctaphid.PING, payload):
        hid.write_packet(packet)
        time.sleep(0.001)


def test_other_channel_is_busy_while_a_maximum_ping_response_is_transmitted(hid):
    first, second = hid.allocate_channel(), hid.allocate_channel()
    payload = os.urandom(7609)
    send_long_ping(hid, first, payload)
    packet = hid.read_packet()
    assert struct.unpack(">IBH", packet[:7]) == (first, 0x80 | ctaphid.PING, len(payload))
    echoed = packet[7:]
    hid.send(second, ctaphid.PING, b"competing")
    for seq in range(128):
        packet = hid.read_packet()
        assert struct.unpack(">IB", packet[:5]) == (first, seq), "response fragments were interleaved"
        echoed += packet[5:]
    assert echoed == payload
    assert hid.expect(second, ctaphid.ERROR).payload == bytes([0x06])
    hid.send(second, ctaphid.PING, b"after completion")
    assert hid.expect(second, ctaphid.PING).payload == b"after completion"


def test_init_truncates_a_transmitting_response_without_stale_output(hid):
    cid = hid.allocate_channel()
    payload = os.urandom(7609)
    send_long_ping(hid, cid, payload)
    packet = hid.read_packet()
    assert struct.unpack(">IBH", packet[:7]) == (cid, 0x80 | ctaphid.PING, len(payload))
    nonce = os.urandom(8)
    hid.send(cid, ctaphid.INIT, nonce)
    prefix, seq = packet[7:], 0
    while True:
        packet = hid.read_packet()
        next_cid, command = struct.unpack(">IB", packet[:5])
        assert next_cid == cid
        if command == 0x80 | ctaphid.INIT:
            assert struct.unpack(">H", packet[5:7]) == (17,)
            assert packet[7:15] == nonce
            assert struct.unpack(">I", packet[15:19]) == (cid,)
            break
        assert command == seq, "unexpected output before resynchronization"
        prefix += packet[5:]
        seq += 1
    # Reports successfully written before INIT was read cannot be recalled.
    assert seq < 128, "INIT waited for the entire old response"
    assert prefix == payload[:len(prefix)]
    hid.send(cid, ctaphid.PING, b"resynchronized")
    assert hid.expect(cid, ctaphid.PING).payload == b"resynchronized"


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

    other = responses[second]
    assert (other.cmd, other.payload) == (ctaphid.ERROR, bytes([0x06])), str(other)

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


@pytest.mark.parametrize("command,payload,error", [
    (ctaphid.WINK, b"x", 0x03),
    (ctaphid.WINK, b"x" * 70, 0x03),
    (ctaphid.LOCK, b"", 0x03),
    (ctaphid.LOCK, b"\0\0", 0x03),
    (ctaphid.LOCK, b"\x0b", 0x02),
    (ctaphid.LOCK, b"\xff", 0x02),
])
def test_identification_and_lease_validation(hid, command, payload, error):
    cid = hid.allocate_channel()
    hid.send(cid, command, payload)
    assert hid.expect(cid, ctaphid.ERROR).payload == bytes([error])
    hid.send(cid, ctaphid.PING, b"usable")
    assert hid.expect(cid, ctaphid.PING).payload == b"usable"


def test_lock_arbitration_init_and_zero_release(hid):
    owner, competitor = hid.allocate_channel(), hid.allocate_channel()
    with hid.lease(owner):
        for command, payload in [(ctaphid.PING, b""), (ctaphid.WINK, b""),
                                 (ctaphid.LOCK, b"\0"), (ctaphid.INIT, os.urandom(8))]:
            hid.send(competitor, command, payload)
            assert hid.expect(competitor, ctaphid.ERROR).payload == b"\x06"
        hid.send(ctaphid.BROADCAST_CID, ctaphid.INIT, os.urandom(8))
        assert hid.expect(ctaphid.BROADCAST_CID, ctaphid.ERROR).payload == b"\x06"
        hid.send(owner, ctaphid.INIT, b"resync!!")
        assert hid.expect(owner, ctaphid.INIT).payload[:8] == b"resync!!"
        hid.send(competitor, ctaphid.PING)
        assert hid.expect(competitor, ctaphid.ERROR).payload == b"\x06"
        hid.send(owner, ctaphid.CANCEL)
        hid.send(competitor, ctaphid.CANCEL)
        hid.send(owner, ctaphid.PING, b"owner")
        assert hid.expect(owner, ctaphid.PING).payload == b"owner"
    hid.send(competitor, ctaphid.PING, b"released")
    assert hid.expect(competitor, ctaphid.PING).payload == b"released"


def test_lock_renewal_and_expiry(hid):
    owner, competitor = hid.allocate_channel(), hid.allocate_channel()
    with hid.lease(owner, 1):
        time.sleep(0.6)
        hid.send(owner, ctaphid.LOCK, b"\x01")
        assert hid.expect(owner, ctaphid.LOCK).payload == b""
        renewed = time.monotonic()
        time.sleep(0.5)
        hid.send(competitor, ctaphid.PING)
        assert hid.expect(competitor, ctaphid.ERROR).payload == b"\x06"
        time.sleep(max(0, renewed + 1.05 - time.monotonic()))
        hid.send(competitor, ctaphid.PING, b"expired")
        assert hid.expect(competitor, ctaphid.PING).payload == b"expired"


def test_authenticator_reset_preserves_a_transport_lease(hid):
    owner, competitor = hid.allocate_channel(), hid.allocate_channel()
    with hid.lease(owner):
        hid.send(owner, ctaphid.CBOR, bytes([Ctap2.CMD.RESET]))
        assert hid.expect(owner, ctaphid.CBOR).payload == b"\0"
        hid.send(competitor, ctaphid.PING)
        assert hid.expect(competitor, ctaphid.ERROR).payload == b"\x06"


def test_python_fido_lock_and_unlock(device):
    try:
        device.lock(1)
        assert device.ping(b"leased") == b"leased"
    finally:
        device.lock(0)
    assert device.ping(b"released") == b"released"
