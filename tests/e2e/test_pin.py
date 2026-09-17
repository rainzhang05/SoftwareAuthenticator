"""clientPIN with PIN/UV auth protocols 1 and 2, and PIN-authorised requests.

A PIN set through either protocol is the same PIN, so tests of one operation
set the PIN up through protocol 1 where needed. That keeps a failure in, say,
protocol 2's setPIN from hiding whether its getPinToken works.
"""

import os

import pytest
from fido2.ctap import CtapError
from fido2.ctap2 import ClientPin, Ctap2
from fido2.ctap2.pin import PinProtocolV1, PinProtocolV2

import ctap as client
from bugs import known_bug

RP_ID = "pin.e2e.example"
PIN = "4821"
NEW_PIN = "730915"
WRONG_PIN = "0000"
MAX_RETRIES = 8

PROTOCOL_1 = pytest.param(PinProtocolV1, id="protocol-1")


def _protocols(**protocol_2_marks):
    marks = [known_bug(**protocol_2_marks)] if protocol_2_marks else []
    return [PROTOCOL_1, pytest.param(PinProtocolV2, id="protocol-2", marks=marks)]


def _client_pin(ctap: Ctap2, protocol) -> ClientPin:
    return ClientPin(ctap, protocol())


def _token(ctap: Ctap2, protocol, pin: str, permissions) -> bytes:
    return _client_pin(ctap, protocol).get_pin_token(pin, permissions, RP_ID)


def _retries(ctap: Ctap2) -> int:
    return _client_pin(ctap, PinProtocolV1).get_pin_retries()[0]


@pytest.mark.parametrize(
    "protocol",
    _protocols(),
)
def test_set_pin(ctap: Ctap2, protocol):
    _client_pin(ctap, protocol).set_pin(PIN)

    assert _retries(ctap) == MAX_RETRIES
    assert _token(ctap, PinProtocolV1, PIN, ClientPin.PERMISSION.GET_ASSERTION)
    with pytest.raises(CtapError) as excinfo:
        _client_pin(ctap, protocol).set_pin(NEW_PIN)
    assert excinfo.value.code == CtapError.ERR.PIN_AUTH_INVALID, "setPIN must refuse to replace a PIN"


@pytest.mark.parametrize(
    "protocol",
    _protocols(),
)
def test_change_pin(ctap: Ctap2, protocol):
    _client_pin(ctap, PinProtocolV1).set_pin(PIN)

    _client_pin(ctap, protocol).change_pin(PIN, NEW_PIN)

    assert _token(ctap, PinProtocolV1, NEW_PIN, ClientPin.PERMISSION.GET_ASSERTION)
    with pytest.raises(CtapError) as excinfo:
        _token(ctap, PinProtocolV1, PIN, ClientPin.PERMISSION.GET_ASSERTION)
    assert excinfo.value.code == CtapError.ERR.PIN_INVALID


@pytest.mark.parametrize("protocol", _protocols())
def test_pin_token_authorises_make_credential_and_get_assertion(ctap: Ctap2, protocol):
    _client_pin(ctap, PinProtocolV1).set_pin(PIN)
    pin_protocol = protocol()

    token = _token(ctap, protocol, PIN, ClientPin.PERMISSION.MAKE_CREDENTIAL)
    client_data_hash = os.urandom(32)
    credential = client.register(
        ctap,
        RP_ID,
        client.ES256,
        uv=True,
        client_data_hash=client_data_hash,
        pin_uv_param=pin_protocol.authenticate(token, client_data_hash),
        pin_uv_protocol=pin_protocol.VERSION,
    )

    token = _token(ctap, protocol, PIN, ClientPin.PERMISSION.GET_ASSERTION)
    client_data_hash = os.urandom(32)
    client.authenticate(
        ctap,
        credential,
        uv=True,
        client_data_hash=client_data_hash,
        pin_uv_param=pin_protocol.authenticate(token, client_data_hash),
        pin_uv_protocol=pin_protocol.VERSION,
    )

    # A pinUvAuthParam computed with the wrong token is refused.
    client_data_hash = os.urandom(32)
    with pytest.raises(CtapError) as excinfo:
        client.make_credential(
            ctap,
            RP_ID,
            client.user_entity("mallory"),
            [client.ES256],
            client_data_hash,
            pin_uv_param=pin_protocol.authenticate(os.urandom(32), client_data_hash),
            pin_uv_protocol=pin_protocol.VERSION,
        )
    assert excinfo.value.code == CtapError.ERR.PIN_AUTH_INVALID


@pytest.mark.parametrize("protocol", _protocols())
def test_wrong_pin_decrements_retries(ctap: Ctap2, protocol):
    _client_pin(ctap, PinProtocolV1).set_pin(PIN)
    assert _retries(ctap) == MAX_RETRIES

    # Two wrong PINs: a third consecutive one would block PIN use until a
    # power cycle.
    for attempt in (1, 2):
        with pytest.raises(CtapError) as excinfo:
            _token(ctap, protocol, WRONG_PIN, ClientPin.PERMISSION.GET_ASSERTION)
        assert excinfo.value.code == CtapError.ERR.PIN_INVALID
        assert _retries(ctap) == MAX_RETRIES - attempt

    assert _token(ctap, protocol, PIN, ClientPin.PERMISSION.GET_ASSERTION)
    assert _retries(ctap) == MAX_RETRIES
