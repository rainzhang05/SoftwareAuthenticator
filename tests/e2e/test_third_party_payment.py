"""CTAP 2.3 §12.9 payment metadata, verified over actual HID and signed bytes.

Use raw CTAP inputs: WebAuthn processors may filter unknown or malformed
extensions, and python-fido2's CBOR encoder cannot encode null.
"""
import os

import pytest
from cryptography.exceptions import InvalidSignature
from fido2 import cbor
from fido2.ctap import CtapError
from fido2.ctap2 import ClientPin, CredentialManagement
from fido2.ctap2.pin import PinProtocolV1, PinProtocolV2
from fido2.hid import CTAPHID

import ctap as client

RP = "third-party-payment.e2e.example"
NAME = "thirdPartyPayment"
PIN = "4821"
REPRESENTATIVES = [client.ES256, client.ML_DSA_44, client.RS256]


def _extensions(value):
    return None if value is None else {NAME: value}


def _check(response, data, credential, digest, requested):
    expected = credential.auth_data.credential_id  # Check the actual selected ID too.
    assert response[1]["id"] == expected
    assert bool(data.flags & client.FLAG_ED) == requested
    if requested:
        assert data.extensions == {NAME: credential.payment}
        assert data.raw[37:] == cbor.encode(data.extensions)
        changed = data.raw[:-1] + bytes([data.raw[-1] ^ 1])
        with pytest.raises(InvalidSignature):
            client.verify_signature(credential.public_key, changed + digest, response[3])
    else:
        assert data.extensions is None


@pytest.mark.parametrize("alg", [a.identifier for a in client.ALGORITHMS])
@pytest.mark.parametrize("rk", [False, True])
def test_enabled_all_algorithms_both_modalities(ctap, alg, rk):
    credential = client.register(ctap, RP, alg, options={"rk": rk}, extensions={NAME: True})
    credential.payment = True
    assert credential.auth_data.extensions is None
    assert not credential.auth_data.flags & client.FLAG_ED
    assert len(credential.credential_id) == 33
    assert credential.credential_id[0] == int(rk)
    for count in (1, 2):
        digest = os.urandom(32)
        response, data = client.authenticate(ctap, credential, extensions={NAME: True}, client_data_hash=digest)
        _check(response, data, credential, digest, True)
        assert data.sign_count == count
        assert (4 in response) == rk
    if not rk:
        with pytest.raises(CtapError) as error:
            client.get_assertion(ctap, RP, os.urandom(32), extensions={NAME: True})
        assert error.value.code == CtapError.ERR.NO_CREDENTIALS


@pytest.mark.parametrize("alg", REPRESENTATIVES)
@pytest.mark.parametrize("rk", [False, True])
@pytest.mark.parametrize("creation", [None, False, True])
def test_absent_false_true_inputs_and_ordinary_sealing(ctap, alg, rk, creation):
    credential = client.register(ctap, RP, alg, options={"rk": rk}, extensions=_extensions(creation))
    credential.payment = creation is True
    stored = rk or creation is True or alg == client.RS256
    assert len(credential.credential_id) == (33 if stored else 107)
    assert credential.auth_data.extensions is None
    for count, requested in enumerate((None, False, True), 1):
        digest = os.urandom(32)
        response, data = client.authenticate(ctap, credential, extensions=_extensions(requested), client_data_hash=digest)
        _check(response, data, credential, digest, requested is True)
        assert data.sign_count == count


@pytest.mark.parametrize("value", [None, 0, 1, "true", b"", [], {}])
@pytest.mark.parametrize("command", [1, 2])
def test_malformed_inputs_reach_authenticator_including_cbor_null(ctap, device, value, command):
    digest = os.urandom(32)
    extension = {NAME: True if value is None else value}
    if command == 1:
        request = {1: digest, 2: {"id": RP}, 3: client.user_entity("alice"),
                   4: [{"type": "public-key", "alg": client.ES256}], 6: extension}
    else:
        request = {1: RP, 2: digest, 4: extension}
    payload = bytes([command]) + cbor.encode(request)
    if value is None:
        needle = cbor.encode(NAME) + b"\xf5"
        assert payload.count(needle) == 1
        payload = payload.replace(needle, cbor.encode(NAME) + b"\xf6")
    assert device.call(CTAPHID.CBOR, payload) == bytes([CtapError.ERR.CBOR_UNEXPECTED_TYPE])


@pytest.mark.parametrize("requested", [None, False, True])
def test_mixed_next_assertions_and_reset(ctap, requested):
    credentials = []
    for flag in (True, False, None):
        credential = client.register(ctap, RP, client.ES256, options={"rk": True}, extensions=_extensions(flag))
        credential.payment = flag is True
        credentials.append(credential)
    digest = os.urandom(32)
    first = client.get_assertion(ctap, RP, digest, extensions=_extensions(requested))
    assert first[5] == 3
    responses = [first, client.get_next_assertion(ctap), client.get_next_assertion(ctap)]
    for response, credential in zip(responses, reversed(credentials)):
        client.verify_signature(credential.public_key, response[2] + digest, response[3])
        data = client.AuthData.parse(response[2])
        _check(response, data, credential, digest, requested is True)
        assert data.sign_count == 1
    with pytest.raises(CtapError) as error:
        client.get_next_assertion(ctap)
    assert error.value.code == CtapError.ERR.NOT_ALLOWED
    ctap.reset()
    for credential in credentials:
        with pytest.raises(CtapError) as error:
            client.authenticate(ctap, credential, extensions={NAME: True})
        assert error.value.code == CtapError.ERR.NO_CREDENTIALS


@pytest.mark.parametrize("protocol", [PinProtocolV1, PinProtocolV2])
def test_cm_enumeration_and_user_updates_keep_metadata(ctap, protocol):
    records = []
    for enabled in (True, False):
        user = client.user_entity("enabled" if enabled else "ordinary")
        credential = client.register(ctap, RP, client.ES256, user=user, options={"rk": True}, extensions={NAME: enabled})
        records.append((credential, user, enabled))
    client.register(ctap, RP, client.ES256, extensions={NAME: True})
    protocol = protocol()
    pin = ClientPin(ctap, protocol)
    pin.set_pin(PIN)
    token = pin.get_pin_token(PIN, ClientPin.PERMISSION.CREDENTIAL_MGMT)
    cm = CredentialManagement(ctap, protocol, token)
    entries = cm.enumerate_creds(client.sha256(RP.encode()))
    assert len(entries) == 2
    for credential, user, enabled in records:
        entry = next(e for e in entries if e[7]["id"] == credential.credential_id)
        assert entry[0x0C] is enabled
        updated = {"id": user["id"], "name": "updated", "displayName": "Updated"}
        cm.update_user_info({"type": "public-key", "id": credential.credential_id}, updated)
        entry = next(e for e in cm.enumerate_creds(client.sha256(RP.encode())) if e[7]["id"] == credential.credential_id)
        assert entry[0x0C] is enabled
        assert entry[6] == updated
        _, data = client.authenticate(ctap, credential, extensions={NAME: True})
        assert data.extensions == {NAME: enabled}
