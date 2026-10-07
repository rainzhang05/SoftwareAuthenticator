"""Creation-time PRF evaluation (CTAP 2.3 §12.8), using python-fido2 2.2.1's
HmacSecretExtension and independent attestation/assertion verification.
"""

import os

import pytest
from fido2.ctap import CtapError
from fido2.ctap2 import ClientPin
from fido2.ctap2.base import AssertionResponse, AttestationResponse
from fido2.ctap2.extensions import HmacSecretExtension
from fido2.ctap2.pin import PinProtocolV1, PinProtocolV2
from fido2.webauthn import PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions

import ctap as client
from test_hmac_secret import _hmac_secret_input

RP_ID = "hmac-secret-mc.e2e.example"
PIN = "4821"
PROTOCOLS = [pytest.param(PinProtocolV1, id="protocol-1"), pytest.param(PinProtocolV2, id="protocol-2")]


@pytest.mark.parametrize("protocol", PROTOCOLS)
@pytest.mark.parametrize("alg,rk", [(client.ES256, True), (client.ES256, False), (client.RS256, False)])
@pytest.mark.parametrize("uv", [False, True])
@pytest.mark.parametrize("two_salts", [False, True])
def test_prf_at_creation_matches_assertion(ctap, protocol, alg, rk, uv, two_salts):
    """The PRF helper hashes its inputs into salts and evaluates the same
    values at creation and assertion, for the same actual UV state."""
    protocol = protocol()
    if uv:
        ClientPin(ctap, protocol).set_pin(PIN)
    values = {"first": os.urandom(19)}
    if two_salts:
        values["second"] = os.urandom(23)
    user = client.user_entity("alice")
    creation_options = PublicKeyCredentialCreationOptions.from_dict({
        "rp": {"id": RP_ID, "name": RP_ID}, "user": user,
        "challenge": os.urandom(32), "pubKeyCredParams": [{"type": "public-key", "alg": alg}],
        "extensions": {"prf": {"eval": values}},
    })
    extension = HmacSecretExtension()
    processor = extension.make_credential(ctap, creation_options, protocol)
    assert processor is not None
    inputs = processor.prepare_inputs(None)
    assert inputs["hmac-secret"] is True
    assert "hmac-secret-mc" in inputs
    auth = client.pin_uv_auth(ctap, protocol, PIN, ClientPin.PERMISSION.MAKE_CREDENTIAL, RP_ID) if uv else {"client_data_hash": os.urandom(32)}
    response = client.make_credential(ctap, RP_ID, user, [alg], extensions=inputs, options={"rk": rk}, **auth)
    data = client.AuthData.parse(response[2])
    data.check(RP_ID, up=True, uv=uv, at=True)
    client.check_public_key(data.public_key, alg)
    client.verify_attestation(response, data.public_key, auth["client_data_hash"])
    credential = client.Credential(RP_ID, alg, data.credential_id, data.public_key, data)
    created = processor.prepare_outputs(AttestationResponse.from_dict(response), None)["prf"]
    assert created.enabled is True
    assert len(created.results.first) == 32
    assert bool(created.results.second) == two_salts

    options = PublicKeyCredentialRequestOptions.from_dict({
        "challenge": os.urandom(32), "rpId": RP_ID,
        "allowCredentials": [{"type": "public-key", "id": credential.credential_id}],
        "extensions": {"prf": {"eval": values}},
    })
    processor = extension.get_assertion(ctap, options, protocol)
    assert processor is not None
    inputs = processor.prepare_inputs(options.allow_credentials[0], None)
    auth = client.pin_uv_auth(ctap, protocol, PIN, ClientPin.PERMISSION.GET_ASSERTION, RP_ID) if uv else {}
    response, _ = client.authenticate(ctap, credential, extensions=inputs, uv=uv, **auth)
    asserted = processor.prepare_outputs(AssertionResponse.from_dict(response), None)["prf"]
    assert asserted.results.first == created.results.first
    assert asserted.results.second == created.results.second


@pytest.mark.parametrize("companion", [None, False])
def test_missing_or_false_companion_is_refused(ctap, companion):
    extension, _ = _hmac_secret_input(ctap, PinProtocolV1(), os.urandom(32))
    inputs = {"hmac-secret-mc": extension}
    if companion is not None:
        inputs["hmac-secret"] = companion
    with pytest.raises(CtapError) as error:
        client.register(ctap, RP_ID, client.ES256, extensions=inputs)
    assert error.value.code == CtapError.ERR.MISSING_PARAMETER


@pytest.mark.parametrize("protocol", PROTOCOLS)
def test_bad_salt_authentication_does_not_create_a_credential(ctap, protocol):
    extension, _ = _hmac_secret_input(ctap, protocol(), os.urandom(32))
    extension[3] = bytes(len(extension[3]))
    with pytest.raises(CtapError) as error:
        client.register(ctap, RP_ID, client.ES256, options={"rk": True},
                        extensions={"hmac-secret": True, "hmac-secret-mc": extension})
    assert error.value.code == CtapError.ERR.PIN_AUTH_INVALID
    with pytest.raises(CtapError) as error:
        client.get_assertion(ctap, RP_ID, os.urandom(32))
    assert error.value.code == CtapError.ERR.NO_CREDENTIALS
