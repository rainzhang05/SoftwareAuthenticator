"""The hmac-secret extension (CTAP 2.3 §12.7), with the platform's side built
from python-fido2's PIN/UV auth protocols.

The salts are encrypted and authenticated, and the output decrypted, with
python-fido2's PinProtocolV1 and PinProtocolV2: an implementation of the
protocols' key agreement and cryptography independent of the authenticator's.
Every request encapsulates to the authenticator's key agreement key afresh, so
the same salts travel under a different shared secret each time.
"""

import os

import pytest
from fido2.ctap import CtapError
from fido2.ctap2 import ClientPin, Ctap2
from fido2.ctap2.pin import PinProtocolV1, PinProtocolV2

import ctap as client

RP_ID = "hmac-secret.e2e.example"
PIN = "4821"

PROTOCOLS = [pytest.param(PinProtocolV1, id="protocol-1"), pytest.param(PinProtocolV2, id="protocol-2")]


def _register(ctap: Ctap2) -> client.Credential:
    """An ES256 credential created with hmac-secret, as the extension outputs
    in its authenticator data confirm."""
    credential = client.register(ctap, RP_ID, client.ES256, extensions={"hmac-secret": True})
    assert credential.auth_data.extensions == {"hmac-secret": True}
    return credential


def _hmac_secret_input(ctap: Ctap2, protocol, salts: bytes) -> tuple[dict, bytes]:
    """The hmac-secret input of getAssertion carrying `salts` (salt1, or
    salt1 || salt2) over `protocol`, and the shared secret the output will be
    encrypted with."""
    peer = ctap.client_pin(protocol.VERSION, ClientPin.CMD.GET_KEY_AGREEMENT)[ClientPin.RESULT.KEY_AGREEMENT]
    key_agreement, shared_secret = protocol.encapsulate(peer)
    salt_enc = protocol.encrypt(shared_secret, salts)
    salt_auth = protocol.authenticate(shared_secret, salt_enc)
    # keyAgreement, saltEnc, saltAuth and pinUvAuthProtocol.
    return {1: key_agreement, 2: salt_enc, 3: salt_auth, 4: protocol.VERSION}, shared_secret


def _hmac_secret(ctap: Ctap2, credential: client.Credential, protocol, salts: bytes, **kwargs) -> bytes:
    """The decrypted hmac-secret output of an assertion for `salts`, which
    client.authenticate has checked and whose signature it has verified."""
    extension, shared_secret = _hmac_secret_input(ctap, protocol, salts)
    _, auth_data = client.authenticate(ctap, credential, extensions={"hmac-secret": extension}, **kwargs)
    assert set(auth_data.extensions or {}) == {"hmac-secret"}, auth_data.extensions
    return protocol.decrypt(shared_secret, auth_data.extensions["hmac-secret"])


def _user_verification(ctap: Ctap2, protocol) -> dict:
    """getAssertion arguments that verify the user with a new pinUvAuthToken.
    Collecting user presence clears a token's permissions (CTAP 2.3 §6.2.2
    step 9), so every assertion needs a token of its own."""
    token = ClientPin(ctap, protocol).get_pin_token(PIN, ClientPin.PERMISSION.GET_ASSERTION, RP_ID)
    client_data_hash = os.urandom(32)
    return {
        "uv": True,
        "client_data_hash": client_data_hash,
        "pin_uv_param": protocol.authenticate(token, client_data_hash),
        "pin_uv_protocol": protocol.VERSION,
    }


@pytest.mark.parametrize("protocol", PROTOCOLS)
def test_one_salt_gives_32_bytes_and_two_salts_64(ctap: Ctap2, protocol):
    """CTAP 2.3 §12.7: the output is HMAC-SHA-256(CredRandom, salt1), followed
    by HMAC-SHA-256(CredRandom, salt2) if a second salt was sent, so its first
    32 bytes are the same with or without a second salt."""
    pin_protocol = protocol()
    credential = _register(ctap)
    salt1, salt2 = os.urandom(32), os.urandom(32)

    one = _hmac_secret(ctap, credential, pin_protocol, salt1)
    two = _hmac_secret(ctap, credential, pin_protocol, salt1 + salt2)
    assert len(one) == 32
    assert len(two) == 64
    assert two[:32] == one


@pytest.mark.parametrize("protocol", PROTOCOLS)
def test_the_output_depends_on_the_salt_and_the_credential_only(ctap: Ctap2, protocol):
    """The same salt gives the same output, although each request carries it
    under another shared secret. Another salt gives another output, and so
    does another credential, which has a CredRandom of its own (CTAP 2.3
    §12.7)."""
    pin_protocol = protocol()
    credential = _register(ctap)
    salt = os.urandom(32)

    output = _hmac_secret(ctap, credential, pin_protocol, salt)
    assert _hmac_secret(ctap, credential, pin_protocol, salt) == output
    assert _hmac_secret(ctap, credential, pin_protocol, os.urandom(32)) != output
    assert _hmac_secret(ctap, _register(ctap), pin_protocol, salt) != output


def test_the_output_does_not_depend_on_the_protocol_carrying_it(ctap: Ctap2):
    """The PIN/UV auth protocol only protects the salts and the output on their
    way (CTAP 2.3 §12.7), so salts give the same output over either one."""
    credential = _register(ctap)
    salts = os.urandom(64)
    over_protocol_1 = _hmac_secret(ctap, credential, PinProtocolV1(), salts)
    assert _hmac_secret(ctap, credential, PinProtocolV2(), salts) == over_protocol_1


@pytest.mark.parametrize("protocol", PROTOCOLS)
def test_user_verification_selects_another_secret(ctap: Ctap2, protocol):
    """CTAP 2.3 §12.7: a credential has two secrets, CredRandomWithUV and
    CredRandomWithoutUV, and the output comes from the first exactly when the
    assertion has the UV flag set, so an output bound to user verification is
    never given out without it."""
    pin_protocol = protocol()
    credential = _register(ctap)
    salt = os.urandom(32)
    without_uv = _hmac_secret(ctap, credential, pin_protocol, salt)

    # A PIN set over either protocol is the same PIN.
    ClientPin(ctap, PinProtocolV1()).set_pin(PIN)
    with_uv = _hmac_secret(ctap, credential, pin_protocol, salt, **_user_verification(ctap, pin_protocol))
    assert with_uv != without_uv
    again = _hmac_secret(ctap, credential, pin_protocol, salt, **_user_verification(ctap, pin_protocol))
    assert again == with_uv
    # Without user verification a PIN makes no difference.
    assert _hmac_secret(ctap, credential, pin_protocol, salt) == without_uv


@pytest.mark.parametrize("protocol", PROTOCOLS)
def test_a_wrong_salt_auth_is_refused(ctap: Ctap2, protocol):
    """CTAP 2.3 §12.7: the authenticator verifies saltAuth over saltEnc with
    the shared secret, and refuses a mismatch with CTAP2_ERR_PIN_AUTH_INVALID
    rather than decrypt salts it cannot trust."""
    credential = _register(ctap)
    extension, _ = _hmac_secret_input(ctap, protocol(), os.urandom(32))
    extension[3] = bytes([extension[3][0] ^ 0x01]) + extension[3][1:]

    with pytest.raises(CtapError) as excinfo:
        client.get_assertion(
            ctap, RP_ID, os.urandom(32), [credential.credential_id], extensions={"hmac-secret": extension}
        )
    assert excinfo.value.code == CtapError.ERR.PIN_AUTH_INVALID


@pytest.mark.parametrize("protocol", PROTOCOLS)
def test_hmac_secret_needs_user_presence(ctap: Ctap2, protocol):
    """CTAP 2.3 §12.7: with the "up" option false, hmac-secret is refused with
    CTAP2_ERR_UNSUPPORTED_OPTION, so its output never comes from a silent
    assertion. The same request without the extension is answered, silently."""
    credential = _register(ctap)
    extension, _ = _hmac_secret_input(ctap, protocol(), os.urandom(32))

    with pytest.raises(CtapError) as excinfo:
        client.get_assertion(
            ctap,
            RP_ID,
            os.urandom(32),
            [credential.credential_id],
            extensions={"hmac-secret": extension},
            options={"up": False},
        )
    assert excinfo.value.code == CtapError.ERR.UNSUPPORTED_OPTION

    response = client.get_assertion(ctap, RP_ID, os.urandom(32), [credential.credential_id], options={"up": False})
    client.AuthData.parse(response[2]).check(RP_ID, up=False, uv=False, at=False)
