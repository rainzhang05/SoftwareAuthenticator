"""Credential blobs (CTAP 2.3 §12.2), through python-fido2's helper and raw
CBOR for empty, over-limit and wrongly typed inputs the helper filters out.
"""

import os

import pytest
from fido2.ctap import CtapError
from fido2.ctap2 import ClientPin
from fido2.ctap2.extensions import CredBlobExtension
from fido2.ctap2.pin import PinProtocolV1, PinProtocolV2
from fido2.webauthn import PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions

import ctap as client

RP_ID = "cred-blob.e2e.example"
PIN = "4821"
PROTOCOLS = [pytest.param(PinProtocolV1, id="protocol-1"), pytest.param(PinProtocolV2, id="protocol-2")]


def _creation_options(blob):
    return PublicKeyCredentialCreationOptions.from_dict({
        "rp": {"id": RP_ID, "name": RP_ID}, "user": client.user_entity("alice"),
        "challenge": os.urandom(32), "pubKeyCredParams": [{"type": "public-key", "alg": client.ES256}],
        "extensions": {"credBlob": blob},
    })


def _retrieve_inputs(ctap, protocol):
    options = PublicKeyCredentialRequestOptions.from_dict({
        "challenge": os.urandom(32), "rpId": RP_ID, "extensions": {"getCredBlob": True},
    })
    processor = CredBlobExtension().get_assertion(ctap, options, protocol)
    assert processor is not None
    assert processor.prepare_inputs(None, None) == {"credBlob": True}
    return processor.prepare_inputs(None, None)


@pytest.mark.parametrize("alg,rk,stored", [(client.ES256, True, True), (client.ES256, False, False), (client.RS256, False, True)])
@pytest.mark.parametrize("length", [0, 1, 32, 33])
@pytest.mark.parametrize("protocol", PROTOCOLS)
@pytest.mark.parametrize("uv", [False, True])
def test_store_and_retrieve_bounded_blobs(ctap, alg, rk, stored, length, protocol, uv):
    protocol = protocol()
    blob = bytes(range(length))
    processor = CredBlobExtension().make_credential(ctap, _creation_options(blob), protocol)
    if length in (1, 32):
        assert processor is not None
        inputs = processor.prepare_inputs(None)
        assert inputs == {"credBlob": blob}
    else:
        assert processor is None  # Empty and oversized inputs need raw CBOR.
        inputs = {"credBlob": blob}
    if uv:
        ClientPin(ctap, protocol).set_pin(PIN)
    auth = client.pin_uv_auth(ctap, protocol, PIN, ClientPin.PERMISSION.MAKE_CREDENTIAL, RP_ID) if uv else {}
    credential = client.register(ctap, RP_ID, alg, options={"rk": rk}, extensions=inputs, uv=uv, **auth)
    accepted = stored and length <= 32
    assert credential.auth_data.extensions == {"credBlob": accepted}
    auth = client.pin_uv_auth(ctap, protocol, PIN, ClientPin.PERMISSION.GET_ASSERTION, RP_ID) if uv else {}
    _, data = client.authenticate(ctap, credential, extensions=_retrieve_inputs(ctap, protocol), uv=uv, **auth)
    assert data.extensions == {"credBlob": blob if accepted else b""}


def test_missing_blob_and_false_retrieval(ctap):
    credential = client.register(ctap, RP_ID, client.ES256, options={"rk": True})
    assert not credential.auth_data.extensions
    _, data = client.authenticate(ctap, credential, extensions={"credBlob": True})
    assert data.extensions == {"credBlob": b""}
    for inputs in ({}, {"credBlob": False}):
        _, data = client.authenticate(ctap, credential, extensions=inputs)
        assert not data.extensions
        assert not data.flags & client.FLAG_ED


@pytest.mark.parametrize("policy", [1, 2, 3])
def test_cred_protect_controls_blob_disclosure(ctap, policy):
    protocol = PinProtocolV2()
    ClientPin(ctap, protocol).set_pin(PIN)
    auth = client.pin_uv_auth(ctap, protocol, PIN, ClientPin.PERMISSION.MAKE_CREDENTIAL, RP_ID)
    blob = os.urandom(32)
    credential = client.register(ctap, RP_ID, client.ES256, options={"rk": True},
                                 extensions={"credBlob": blob, "credProtect": policy}, uv=True, **auth)
    for allow_list in (False, True):
        allowed = policy == 1 or (policy == 2 and allow_list)
        if allowed:
            _, data = client.authenticate(ctap, credential, allow_list=allow_list, extensions={"credBlob": True})
            assert data.extensions == {"credBlob": blob}
        else:
            with pytest.raises(CtapError) as error:
                client.authenticate(ctap, credential, allow_list=allow_list, extensions={"credBlob": True})
            assert error.value.code == CtapError.ERR.NO_CREDENTIALS
    auth = client.pin_uv_auth(ctap, protocol, PIN, ClientPin.PERMISSION.GET_ASSERTION, RP_ID)
    _, data = client.authenticate(ctap, credential, extensions={"credBlob": True}, uv=True, **auth)
    assert data.extensions == {"credBlob": blob}


def test_next_assertion_returns_each_blob_and_reset_erases_them(ctap):
    credentials = [client.register(ctap, RP_ID, client.ES256, options={"rk": True},
                                  extensions={"credBlob": bytes([i]) * 32}) for i in (1, 2)]
    digest = os.urandom(32)
    first = client.get_assertion(ctap, RP_ID, digest, extensions={"credBlob": True})
    assert first[5] == 2
    next_response = client.get_next_assertion(ctap)
    for response, credential in zip((first, next_response), reversed(credentials)):
        assert response[1]["id"] == credential.credential_id
        data = client.AuthData.parse(response[2])
        assert data.extensions["credBlob"] == bytes([2 if credential is credentials[1] else 1]) * 32
        client.verify_signature(credential.public_key, response[2] + digest, response[3])
    ctap.reset()
    with pytest.raises(CtapError) as error:
        client.authenticate(ctap, credentials[0], extensions={"credBlob": True})
    assert error.value.code == CtapError.ERR.NO_CREDENTIALS


# CBOR null is covered by the engine tests: python-fido2 cannot encode it.
@pytest.mark.parametrize("blob", [True, "blob", 1, []])
def test_registration_rejects_wrong_types(ctap, blob):
    with pytest.raises(CtapError) as error:
        client.register(ctap, RP_ID, client.ES256, extensions={"credBlob": blob})
    assert error.value.code == CtapError.ERR.CBOR_UNEXPECTED_TYPE


@pytest.mark.parametrize("value", [b"", "true", 1])
def test_assertion_rejects_wrong_types(ctap, value):
    credential = client.register(ctap, RP_ID, client.ES256)
    with pytest.raises(CtapError) as error:
        client.authenticate(ctap, credential, extensions={"credBlob": value})
    assert error.value.code == CtapError.ERR.CBOR_UNEXPECTED_TYPE
