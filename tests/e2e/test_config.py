"""authenticatorConfig and PIN policy through python-fido2 2.2.1.

Config exercises the real platform API; direct CBOR requests cover malformed
or forbidden inputs that its convenience methods do not send. The ctap
fixture resets the key before every test, including each PIN protocol case.
"""

import os

import pytest
from fido2 import cbor
from fido2.ctap import CtapError
from fido2.ctap2 import ClientPin, Ctap2
from fido2.ctap2.config import Config
from fido2.ctap2.pin import PinProtocolV1, PinProtocolV2
from fido2.hid import CTAPHID

import ctap as client

RP_ID = "config.e2e.example"
OTHER_RP_ID = "other.config.e2e.example"
PIN = "4821"
NEW_PIN = "730915"
WRONG_PIN = "0000"
MAX_RETRIES = 8
CONFIG = Ctap2.CMD.CONFIG
ERR = CtapError.ERR


@pytest.fixture(params=[
    pytest.param(PinProtocolV1, id="protocol-1"),
    pytest.param(PinProtocolV2, id="protocol-2"),
])
def protocol(request):
    return request.param()


def _info(ctap: Ctap2) -> dict:
    return ctap.send_cbor(Ctap2.CMD.GET_INFO)


def _config(ctap: Ctap2, protocol, pin: str = PIN, rp_id=None) -> Config:
    token = ClientPin(ctap, protocol).get_pin_token(
        pin, ClientPin.PERMISSION.AUTHENTICATOR_CFG, rp_id
    )
    return Config(ctap, protocol, token)


def _error(ctap: Ctap2, request: dict, expected) -> None:
    with pytest.raises(CtapError) as excinfo:
        ctap.send_cbor(CONFIG, request)
    assert excinfo.value.code == expected


def test_without_a_pin_configuration_needs_no_token(ctap: Ctap2):
    config = Config(ctap)
    config.set_min_pin_length(6, [RP_ID])
    info = _info(ctap)
    assert info[0x0D] == 6
    assert info[0x0C] is False
    assert info[4]["clientPin"] is False

    config.toggle_always_uv()
    info = _info(ctap)
    assert info[4]["alwaysUv"] is True
    assert info[4]["makeCredUvNotRqd"] is False
    _error(ctap, {1: 3, 2: {1: 7}}, ERR.PUAT_REQUIRED)
    assert _info(ctap)[0x0D] == 6

    with pytest.raises(CtapError) as excinfo:
        client.register(ctap, RP_ID, client.ES256)
    assert excinfo.value.code == ERR.PUAT_REQUIRED

    # §6.11 step 3 permits turning always-UV off without authentication when
    # no PIN protects the key, even if unusable authentication is supplied.
    ctap.config(2, pin_uv_protocol=99, pin_uv_param=b"wrong")
    info = _info(ctap)
    assert info[4]["alwaysUv"] is False
    assert info[4]["makeCredUvNotRqd"] is True
    client.register(ctap, RP_ID, client.ES256)


def test_no_pin_always_uv_preserves_the_up_false_exemption(ctap: Ctap2):
    credential = client.register(ctap, RP_ID, client.ES256)
    Config(ctap).toggle_always_uv()
    with pytest.raises(CtapError) as excinfo:
        client.authenticate(ctap, credential)
    assert excinfo.value.code == ERR.PUAT_REQUIRED

    digest = os.urandom(32)
    response = client.get_assertion(
        ctap, RP_ID, digest, [credential.credential_id], options={"up": False}
    )
    client.AuthData.parse(response[2]).check(RP_ID, up=False, uv=False, at=False)
    client.verify_signature(credential.public_key, response[2] + digest, response[3])


def test_pin_authenticates_both_configuration_subcommands(ctap: Ctap2, protocol):
    ClientPin(ctap, PinProtocolV1()).set_pin(NEW_PIN)
    # The acfg permission remains usable when a permissions RP ID is bound;
    # unlike credential management, configuration has no RP binding check.
    config = _config(ctap, protocol, NEW_PIN, RP_ID)
    config.toggle_always_uv()
    config.set_min_pin_length(6, [RP_ID])
    info = _info(ctap)
    assert info[4]["alwaysUv"] is True
    assert info[4]["makeCredUvNotRqd"] is False
    assert info[0x0D] == 6
    assert info[0x0C] is False
    config.toggle_always_uv()
    assert _info(ctap)[4]["alwaysUv"] is False


def test_configuration_requires_the_acfg_permission(ctap: Ctap2, protocol):
    pin = ClientPin(ctap, protocol)
    pin.set_pin(PIN)
    for permission in (None, ClientPin.PERMISSION.CREDENTIAL_MGMT):
        token = pin.get_pin_token(PIN, permission)
        with pytest.raises(CtapError) as excinfo:
            Config(ctap, protocol, token).toggle_always_uv()
        assert excinfo.value.code == ERR.PIN_AUTH_INVALID
        assert _info(ctap)[4]["alwaysUv"] is False
    _config(ctap, protocol).toggle_always_uv()
    assert _info(ctap)[4]["alwaysUv"] is True


def test_configuration_authentication_errors_are_ordered(ctap: Ctap2, protocol):
    ClientPin(ctap, PinProtocolV1()).set_pin(PIN)
    _error(ctap, {}, ERR.MISSING_PARAMETER)
    for subcommand in (0, 1, 4, 0xFF, 256):
        _error(ctap, {1: subcommand}, ERR.INVALID_PARAMETER)
    _error(ctap, {1: 2, 3: 99}, ERR.PUAT_REQUIRED)
    _error(ctap, {1: 2, 4: b""}, ERR.MISSING_PARAMETER)
    _error(ctap, {1: 2, 3: 99, 4: b""}, ERR.INVALID_PARAMETER)

    config = _config(ctap, protocol)
    for bad_mac in (b"", b"wrong", protocol.authenticate(os.urandom(32), b"\xff" * 32 + b"\x0d\x02")):
        _error(ctap, {1: 2, 3: protocol.VERSION, 4: bad_mac}, ERR.PIN_AUTH_INVALID)
    config.toggle_always_uv()
    _error(ctap, {1: 2}, ERR.PUAT_REQUIRED)
    assert _info(ctap)[4]["alwaysUv"] is True


@pytest.mark.parametrize("parameters", [
    {1: "2"}, {1: True}, {1: -1}, {1: 2, 2: []},
    {1: 2, 3: "1"}, {1: 2, 4: "mac"},
    {1: 3, 2: {1: True}}, {1: 3, 2: {1: -1}},
    {1: 3, 2: {2: RP_ID}}, {1: 3, 2: {2: [1]}},
    {1: 3, 2: {3: 1}}, {1: 3, 2: {4: 1}},
])
def test_configuration_rejects_wrong_cbor_types(ctap: Ctap2, parameters):
    # Authentication fields are processed only while PIN/always-UV protection
    # requires them. Supply the preceding mandatory fields for their checks.
    if 3 in parameters or 4 in parameters:
        ClientPin(ctap, PinProtocolV1()).set_pin(PIN)
        parameters = {3: 1, 4: b"", **parameters}
    expected = ERR.CBOR_UNEXPECTED_TYPE
    if parameters.get(1) == -1 or parameters.get(2) == {1: -1}:
        expected = ERR.INVALID_PARAMETER
    _error(ctap, parameters, expected)
    info = _info(ctap)
    assert info[0x0D] == 4 and info[0x0C] is False
    assert info[4]["alwaysUv"] is False


@pytest.mark.parametrize("payload", [
    b"", b"\xa1\x01", b"\x80", b"\xa2\x01\x02\x01\x03", b"\xa1\x01\x02\x00",
])
def test_configuration_rejects_malformed_cbor(ctap: Ctap2, payload: bytes):
    response = ctap.device.call(CTAPHID.CBOR, bytes([CONFIG]) + payload)
    assert response == bytes([ERR.INVALID_CBOR])
    assert _info(ctap)[4]["alwaysUv"] is False


def test_configuration_authenticates_the_original_parameter_bytes(ctap: Ctap2, protocol):
    pin = ClientPin(ctap, protocol)
    pin.set_pin(PIN)
    token = pin.get_pin_token(PIN, ClientPin.PERMISSION.AUTHENTICATOR_CFG)
    # CBOR simple value zero under an unknown key is valid and ignored. The
    # decoder represents it as undefined; its original byte must be MACed.
    params = b"\xa2\x01\x04\x18\x63\xe0"
    normalized = b"\xa2\x01\x04\x18\x63\xf7"
    message = b"\xff" * 32 + b"\x0d\x03"
    prefix = bytes([CONFIG]) + b"\xa4\x01\x03\x02" + params
    prefix += b"\x03" + cbor.encode(protocol.VERSION) + b"\x04"
    bad = prefix + cbor.encode(protocol.authenticate(token, message + normalized))
    assert ctap.device.call(CTAPHID.CBOR, bad) == bytes([ERR.PIN_AUTH_INVALID])
    good = prefix + cbor.encode(protocol.authenticate(token, message + params))
    assert ctap.device.call(CTAPHID.CBOR, good) == bytes([ERR.SUCCESS])


def test_minimum_policy_failures_do_not_change_settings(ctap: Ctap2):
    Config(ctap).set_min_pin_length(6, [RP_ID])
    for params, expected in (
        ({1: 5}, ERR.PIN_POLICY_VIOLATION),
        ({1: 64}, ERR.INVALID_PARAMETER),
        ({1: 7, 2: [f"{i}.example" for i in range(9)]}, ERR.KEY_STORE_FULL),
        ({1: 7, 2: ["x" * 254]}, ERR.KEY_STORE_FULL),
        ({1: 7, 3: True}, ERR.PIN_NOT_SET),
        ({1: 7, 4: True}, ERR.INVALID_PARAMETER),
        # Lowering the minimum precedes the missing-PIN and storage checks.
        ({1: 5, 2: ["x" * 254], 3: True}, ERR.PIN_POLICY_VIOLATION),
    ):
        _error(ctap, {1: 3, 2: params}, expected)
        assert _info(ctap)[0x0D] == 6
        assert _info(ctap)[0x0C] is False
        credential = client.register(ctap, RP_ID, client.ES256, extensions={"minPinLength": True})
        assert credential.auth_data.extensions == {"minPinLength": 6}
    ctap.config(3, {4: False})
    assert _info(ctap)[0x0D] == 6
    ctap.config(3)
    assert _info(ctap)[0x0D] == 6


def test_minimum_boundary_and_rp_storage_capacity(ctap: Ctap2):
    rps = [f"{i}.config.example" for i in range(8)]
    Config(ctap).set_min_pin_length(63, rps)
    assert _info(ctap)[0x0D] == 63
    for rp_id in (rps[0], rps[-1]):
        credential = client.register(ctap, rp_id, client.ES256, extensions={"minPinLength": True})
        assert credential.auth_data.extensions == {"minPinLength": 63}
    domain = "a" * 63 + "." + "b" * 63 + "." + "c" * 63 + "." + "d" * 61
    assert len(domain.encode()) == 253
    Config(ctap).set_min_pin_length(rp_ids=[domain])
    credential = client.register(ctap, domain, client.ES256, extensions={"minPinLength": True})
    assert credential.auth_data.extensions == {"minPinLength": 63}
    ClientPin(ctap, PinProtocolV1()).set_pin("x" * 63)
    assert _info(ctap)[0x0C] is False


def test_minimum_is_enforced_and_pin_length_counts_code_points(ctap: Ctap2, protocol):
    Config(ctap).set_min_pin_length(6)
    pin = ClientPin(ctap, protocol)
    with pytest.raises(CtapError) as excinfo:
        pin.set_pin(PIN)
    assert excinfo.value.code == ERR.PIN_POLICY_VIOLATION
    assert _info(ctap)[4]["clientPin"] is False
    unicode_pin = "\u00e9" * 6
    pin.set_pin(unicode_pin)
    _config(ctap, protocol, unicode_pin).set_min_pin_length(7)
    assert _info(ctap)[0x0C] is True
    with pytest.raises(CtapError) as excinfo:
        pin.change_pin(unicode_pin, NEW_PIN)
    assert excinfo.value.code == ERR.PIN_POLICY_VIOLATION
    assert _info(ctap)[0x0C] is True
    pin.change_pin(unicode_pin, "\u00e9" * 7)
    assert _info(ctap)[0x0C] is False
    assert pin.get_pin_token("\u00e9" * 7, ClientPin.PERMISSION.AUTHENTICATOR_CFG)
    _config(ctap, protocol, "\u00e9" * 7).set_min_pin_length(8)
    assert _info(ctap)[0x0C] is True, "changePIN must update PINCodePointLength"


def test_forced_change_checks_the_pin_before_refusing_tokens(ctap: Ctap2, protocol):
    pin = ClientPin(ctap, protocol)
    pin.set_pin(PIN)
    _config(ctap, protocol).set_min_pin_length(force_change_pin=True)
    assert _info(ctap)[0x0C] is True
    for permissions, expected in (
        (None, ERR.PIN_INVALID),
        (ClientPin.PERMISSION.AUTHENTICATOR_CFG, ERR.PIN_POLICY_VIOLATION),
    ):
        with pytest.raises(CtapError) as excinfo:
            pin.get_pin_token(WRONG_PIN, permissions)
        assert excinfo.value.code == ERR.PIN_INVALID
        assert pin.get_pin_retries()[0] == MAX_RETRIES - 1
        with pytest.raises(CtapError) as excinfo:
            pin.get_pin_token(PIN, permissions)
        assert excinfo.value.code == expected
        assert pin.get_pin_retries()[0] == MAX_RETRIES
    with pytest.raises(CtapError) as excinfo:
        pin.change_pin(PIN, PIN)
    assert excinfo.value.code == ERR.PIN_POLICY_VIOLATION
    assert _info(ctap)[0x0C] is True
    pin.change_pin(PIN, NEW_PIN)
    assert _info(ctap)[0x0C] is False
    assert pin.get_pin_token(NEW_PIN, ClientPin.PERMISSION.AUTHENTICATOR_CFG)


def test_raising_the_minimum_invalidates_existing_tokens(ctap: Ctap2, protocol):
    credential = client.register(ctap, RP_ID, client.ES256)
    pin = ClientPin(ctap, protocol)
    pin.set_pin(PIN)
    permissions = ClientPin.PERMISSION.AUTHENTICATOR_CFG | ClientPin.PERMISSION.GET_ASSERTION
    token = pin.get_pin_token(PIN, permissions, RP_ID)
    config = Config(ctap, protocol, token)
    config.set_min_pin_length(6)
    assert _info(ctap)[0x0C] is True
    with pytest.raises(CtapError) as excinfo:
        config.toggle_always_uv()
    assert excinfo.value.code == ERR.PIN_AUTH_INVALID
    digest = os.urandom(32)
    with pytest.raises(CtapError) as excinfo:
        client.get_assertion(
            ctap, RP_ID, digest, [credential.credential_id],
            pin_uv_param=protocol.authenticate(token, digest),
            pin_uv_protocol=protocol.VERSION,
        )
    assert excinfo.value.code == ERR.PIN_AUTH_INVALID
    pin.change_pin(PIN, NEW_PIN)
    assert _info(ctap)[0x0D] == 6 and _info(ctap)[0x0C] is False


def test_always_uv_protects_registration_and_up_true_assertions(ctap: Ctap2, protocol):
    credential = client.register(ctap, RP_ID, client.ES256)
    ClientPin(ctap, protocol).set_pin(PIN)
    _config(ctap, protocol).toggle_always_uv()
    with pytest.raises(CtapError) as excinfo:
        client.register(ctap, RP_ID, client.ES256)
    assert excinfo.value.code == ERR.PUAT_REQUIRED
    for options in (None, {"up": True}):
        with pytest.raises(CtapError) as excinfo:
            client.get_assertion(ctap, RP_ID, os.urandom(32), [credential.credential_id], options=options)
        assert excinfo.value.code == ERR.PUAT_REQUIRED

    digest = os.urandom(32)
    response = client.get_assertion(
        ctap, RP_ID, digest, [credential.credential_id], options={"up": False}
    )
    client.AuthData.parse(response[2]).check(RP_ID, up=False, uv=False, at=False)
    client.verify_signature(credential.public_key, response[2] + digest, response[3])

    authenticated = client.pin_uv_auth(ctap, protocol, PIN, ClientPin.PERMISSION.MAKE_CREDENTIAL, RP_ID)
    protected = client.register(ctap, RP_ID, client.ES256, uv=True, **authenticated)
    authenticated = client.pin_uv_auth(ctap, protocol, PIN, ClientPin.PERMISSION.GET_ASSERTION, RP_ID)
    client.authenticate(ctap, protected, uv=True, **authenticated)
    _config(ctap, protocol).toggle_always_uv()
    client.authenticate(ctap, credential)


def test_min_pin_length_extension_is_only_disclosed_to_authorized_rps(ctap: Ctap2):
    config = Config(ctap)
    config.set_min_pin_length(6, [RP_ID])
    for rp_id, extensions, expected in (
        (RP_ID, {"minPinLength": True}, {"minPinLength": 6}),
        (OTHER_RP_ID, {"minPinLength": True}, None),
        (RP_ID, {"minPinLength": False}, None),
        (RP_ID, None, None),
    ):
        credential = client.register(ctap, rp_id, client.ES256, extensions=extensions)
        assert credential.auth_data.extensions == expected
    # §6.11.4 step 8 does nothing with an empty list, retaining RP_ID.
    config.set_min_pin_length(rp_ids=[])
    credential = client.register(ctap, RP_ID, client.ES256, extensions={"minPinLength": True})
    assert credential.auth_data.extensions == {"minPinLength": 6}
    config.set_min_pin_length(rp_ids=[OTHER_RP_ID])
    credential = client.register(ctap, RP_ID, client.ES256, extensions={"minPinLength": True})
    assert credential.auth_data.extensions is None
    credential = client.register(ctap, OTHER_RP_ID, client.ES256, extensions={"minPinLength": True})
    assert credential.auth_data.extensions == {"minPinLength": 6}
    _, auth_data = client.authenticate(ctap, credential, extensions={"minPinLength": True})
    assert auth_data.extensions is None, "minPinLength is a makeCredential extension"


def test_reset_restores_every_configuration_default(ctap: Ctap2, protocol):
    ClientPin(ctap, protocol).set_pin(PIN)
    config = _config(ctap, protocol)
    config.toggle_always_uv()
    config.set_min_pin_length(6, [RP_ID], force_change_pin=True)
    assert _info(ctap)[0x0C] is True
    ctap.reset()
    info = _info(ctap)
    assert info[4]["alwaysUv"] is False
    assert info[4]["makeCredUvNotRqd"] is True
    assert info[4]["clientPin"] is False
    assert info[0x0D] == 4
    assert info[0x0C] is False
    credential = client.register(ctap, RP_ID, client.ES256, extensions={"minPinLength": True})
    assert credential.auth_data.extensions is None
    ClientPin(ctap, protocol).set_pin(PIN)
    assert ClientPin(ctap, protocol).get_pin_token(PIN, ClientPin.PERMISSION.AUTHENTICATOR_CFG)
