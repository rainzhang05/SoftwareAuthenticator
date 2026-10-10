"""CTAP1 operations and credentials shared with CTAP2 through real HID."""

import os

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fido2.attestation import FidoU2FAttestation
from fido2.cose import ES256
from fido2.ctap import CtapError
from fido2.ctap1 import APDU, ApduError, Ctap1, SignatureData
from fido2.ctap2 import ClientPin
from fido2.ctap2.config import Config
from fido2.webauthn import AttestedCredentialData, AuthenticatorData

import ctap as client
from u2f import poll

RP_ID = "u2f.e2e.example"
APPLICATION = client.sha256(RP_ID.encode())


def register(ctap1):
    challenge = os.urandom(32)
    registration = poll(lambda: ctap1.register(challenge, APPLICATION))
    registration.verify(APPLICATION, challenge)
    assert len(registration.key_handle) == 107
    assert registration.key_handle[0] == 2
    # The WebAuthn verifier consumes the same statement after U2F mapping.
    credential_data = AttestedCredentialData.create(
        bytes(16), registration.key_handle, ES256.from_ctap1(registration.public_key)
    )
    auth_data = AuthenticatorData.create(
        APPLICATION, AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.AT,
        0, credential_data,
    )
    FidoU2FAttestation().verify(
        {"x5c": [registration.certificate], "sig": registration.signature},
        auth_data, challenge,
    )
    return registration


def authenticate(ctap1, handle, public_key, control=3):
    challenge = os.urandom(32)
    if control == 3:
        signature = poll(lambda: ctap1.authenticate(challenge, APPLICATION, handle))
    else:
        body = challenge + APPLICATION + bytes([len(handle)]) + handle
        signature = SignatureData(ctap1.send_apdu(ins=2, p1=control, data=body))
    signature.verify(APPLICATION, challenge, public_key)
    assert signature.user_presence == int(control == 3)
    return signature.counter


def assert_ctap2(ctap, handle, public_key):
    challenge = os.urandom(32)
    response = client.get_assertion(ctap, RP_ID, challenge, [handle])
    auth_data = client.AuthData.parse(response[2])
    auth_data.check(RP_ID, up=True, uv=False, at=False)
    ES256.from_ctap1(public_key).verify(response[2] + challenge, response[3])
    assert response[1] == {"type": "public-key", "id": handle}
    return auth_data.sign_count


def test_version_registration_authentication_and_protocol_crossing(device, ctap):
    ctap1 = Ctap1(device)
    assert ctap1.get_version() == "U2F_V2"
    registration = register(ctap1)
    with pytest.raises(ApduError) as error:
        ctap1.authenticate(os.urandom(32), APPLICATION, registration.key_handle, check_only=True)
    assert error.value.code == APDU.USE_NOT_SATISFIED
    counters = [authenticate(ctap1, registration.key_handle, registration.public_key),
                assert_ctap2(ctap, registration.key_handle, registration.public_key),
                authenticate(ctap1, registration.key_handle, registration.public_key, 8)]
    assert counters == [1, 2, 3], counters
    with pytest.raises(CtapError) as error:
        client.get_assertion(ctap, RP_ID, os.urandom(32))
    assert error.value.code == CtapError.ERR.NO_CREDENTIALS


@pytest.mark.parametrize("protection", [1, 2, 3])
def test_ctap2_credentials_over_u2f(device, ctap, protection):
    credential = client.register(
        ctap, RP_ID, client.ES256, options={"rk": False},
        extensions={"credProtect": protection},
    )
    ctap1 = Ctap1(device)
    public = b"\x04" + credential.public_key[-2] + credential.public_key[-3]
    if protection == 3:
        for control in (3, 7, 8):
            body = os.urandom(32) + APPLICATION + bytes([len(credential.credential_id)]) + credential.credential_id
            with pytest.raises(ApduError) as error:
                ctap1.send_apdu(ins=2, p1=control, data=body)
            assert error.value.code == APDU.WRONG_DATA
        return
    first = authenticate(ctap1, credential.credential_id, public)
    _, assertion = client.authenticate(ctap, credential)
    last = authenticate(ctap1, credential.credential_id, public, 8)
    assert first < assertion.sign_count < last


@pytest.mark.parametrize("algorithm,discoverable", [
    (client.ES256, True), (client.ESP256, False),
    (client.ES384, False), (client.ML_DSA_65, False), (client.RS256, False),
])
def test_ineligible_credentials_are_wrong_data(device, ctap, algorithm, discoverable):
    credential = client.register(ctap, RP_ID, algorithm, options={"rk": discoverable})
    ctap1 = Ctap1(device)
    for control in (3, 7, 8):
        body = os.urandom(32) + APPLICATION + bytes([len(credential.credential_id)]) + credential.credential_id
        with pytest.raises(ApduError) as error:
            ctap1.send_apdu(ins=2, p1=control, data=body)
        assert error.value.code == APDU.WRONG_DATA


def test_wrong_application_tampering_and_reset_reject_handles(device, ctap):
    ctap1 = Ctap1(device)
    registration = register(ctap1)
    for application, handle in [
        (bytes(32), registration.key_handle),
        (APPLICATION, registration.key_handle[:-1] + bytes([registration.key_handle[-1] ^ 1])),
    ]:
        for check_only in (False, True):
            with pytest.raises(ApduError) as error:
                ctap1.authenticate(os.urandom(32), application, handle, check_only=check_only)
            assert error.value.code == APDU.WRONG_DATA
    ctap.reset()
    with pytest.raises(ApduError) as error:
        ctap1.authenticate(os.urandom(32), APPLICATION, registration.key_handle, check_only=True)
    assert error.value.code == APDU.WRONG_DATA


def test_pin_does_not_change_u2f_presence_requirements(device, ctap):
    ClientPin(ctap).set_pin("4821")
    ctap1 = Ctap1(device)
    registration = register(ctap1)
    authenticate(ctap1, registration.key_handle, registration.public_key)
    authenticate(ctap1, registration.key_handle, registration.public_key, 8)


def test_always_uv_disables_registration_and_all_authentication_controls(device, ctap):
    ctap1 = Ctap1(device)
    registration = register(ctap1)
    config = Config(ctap)
    config.toggle_always_uv()
    assert "U2F_V2" not in ctap.get_info().versions
    assert ctap1.get_version() == "U2F_V2"
    with pytest.raises(ApduError) as error:
        ctap1.register(os.urandom(32), APPLICATION)
    assert error.value.code == 0x6986
    for control in (3, 7, 8):
        body = os.urandom(32) + APPLICATION + bytes([len(registration.key_handle)]) + registration.key_handle
        with pytest.raises(ApduError) as error:
            ctap1.send_apdu(ins=2, p1=control, data=body)
        assert error.value.code == 0x6986
    config.toggle_always_uv()
    assert "U2F_V2" in ctap.get_info().versions
    authenticate(ctap1, registration.key_handle, registration.public_key)


def test_self_certificate_contains_only_the_new_credential_key(device, ctap):
    first = register(Ctap1(device))
    second = register(Ctap1(device))
    certificates = [x509.load_der_x509_certificate(item.certificate) for item in (first, second)]
    for registration, certificate in zip((first, second), certificates):
        assert certificate.version == x509.Version.v3
        assert certificate.subject == certificate.issuer
        assert certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "U2F credential"
        assert len(certificate.extensions) == 0
        certificate.public_key().verify(certificate.signature, certificate.tbs_certificate_bytes, ec.ECDSA(certificate.signature_hash_algorithm))
        assert ES256.from_cryptography_key(certificate.public_key()) == ES256.from_ctap1(registration.public_key)
    assert certificates[0].serial_number != certificates[1].serial_number
    assert first.certificate != second.certificate


def test_provisioned_certificate_signs_u2f_registrations(certificate_ctap):
    ctap1 = Ctap1(certificate_ctap.device)
    first, second = register(ctap1), register(ctap1)
    assert first.certificate == second.certificate
    assert first.public_key != second.public_key
    authenticate(ctap1, first.key_handle, first.public_key)
