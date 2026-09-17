"""The packed attestation certificate (WebAuthn Level 3, 8.2 and 8.2.1).

The certificate is read with pyca/cryptography, and the ASN.1 string types and
the serial number's encoding, which cryptography does not expose, are read from
the DER by hand.
"""

from __future__ import annotations

import datetime
import os
from typing import Iterator

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtensionOID, NameOID, ObjectIdentifier, SignatureAlgorithmOID
from fido2.ctap2 import Ctap2

import ctap as client

RP_ID = "e2e.example"

ID_FIDO_GEN_CE_AAGUID = ObjectIdentifier("1.3.6.1.4.1.45724.1.1.4")

# ASN.1 universal tags.
INTEGER = 0x02
OBJECT_IDENTIFIER = 0x06
UTF8_STRING = 0x0C
SEQUENCE = 0x30
SET = 0x31
PRINTABLE_STRING = 0x13

# DER contents of the attribute type OIDs in the subject.
COUNTRY_NAME = bytes.fromhex("550406")
ORGANIZATION_NAME = bytes.fromhex("55040a")
ORGANIZATIONAL_UNIT_NAME = bytes.fromhex("55040b")
COMMON_NAME = bytes.fromhex("550403")


def _elements(data: bytes) -> Iterator[tuple[int, bytes]]:
    """The (tag, contents) of each DER element in `data`."""
    offset = 0
    while offset < len(data):
        tag, length = data[offset], data[offset + 1]
        offset += 2
        if length & 0x80:
            count = length & 0x7F
            length = int.from_bytes(data[offset : offset + count], "big")
            offset += count
        contents = data[offset : offset + length]
        assert len(contents) == length, "truncated DER"
        offset += length
        yield tag, contents


def _only(data: bytes, tag: int) -> bytes:
    """The contents of the single DER element that `data` consists of."""
    elements = list(_elements(data))
    assert len(elements) == 1 and elements[0][0] == tag, elements
    return elements[0][1]


def subject_attributes(certificate: x509.Certificate) -> list[tuple[bytes, int, str]]:
    """(attribute type OID, string tag, value) for each subject attribute."""
    attributes = []
    for tag, rdn in _elements(_only(certificate.subject.public_bytes(), SEQUENCE)):
        assert tag == SET
        attribute = list(_elements(_only(rdn, SEQUENCE)))
        assert len(attribute) == 2 and attribute[0][0] == OBJECT_IDENTIFIER, attribute
        attributes.append((attribute[0][1], attribute[1][0], attribute[1][1].decode()))
    return attributes


def check_attestation_certificate(der: bytes, aaguid: bytes) -> x509.Certificate:
    """Assert what WebAuthn Level 3 8.2.1 requires of attestnCert, and what
    RFC 5280 requires of its serial number."""
    certificate = x509.load_der_x509_certificate(der)

    # "Version MUST be set to 3".
    assert certificate.version == x509.Version.v3

    # Subject-C: ISO 3166 code (PrintableString); Subject-O: legal name of the
    # vendor (UTF8String); Subject-OU: literal "Authenticator Attestation"
    # (UTF8String); Subject-CN: a UTF8String of the vendor's choosing.
    attributes = subject_attributes(certificate)
    assert [(oid, tag) for oid, tag, _ in attributes] == [
        (COUNTRY_NAME, PRINTABLE_STRING),
        (ORGANIZATION_NAME, UTF8_STRING),
        (ORGANIZATIONAL_UNIT_NAME, UTF8_STRING),
        (COMMON_NAME, UTF8_STRING),
    ], attributes
    country, organization, unit, common_name = (value for _, _, value in attributes)
    assert len(country) == 2 and country.isascii() and country.isupper(), country
    assert organization and common_name
    assert unit == "Authenticator Attestation"
    assert certificate.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value == unit

    # id-fido-gen-ce-aaguid: "The extension MUST NOT be marked as critical",
    # the AAGUID "wrapped in two OCTET STRINGS", and (8.2) it "matches the
    # aaguid in authenticatorData".
    extension = certificate.extensions.get_extension_for_oid(ID_FIDO_GEN_CE_AAGUID)
    assert not extension.critical
    assert extension.value.value == b"\x04\x10" + aaguid

    # "The Basic Constraints extension MUST have the CA component set to false."
    basic_constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints)
    assert basic_constraints.value.ca is False

    # No subject alternative name: the subject names the authenticator.
    with pytest.raises(x509.ExtensionNotFound):
        certificate.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)

    # RFC 5280 4.1.2.2: a positive INTEGER of at most 20 octets.
    tbs = list(_elements(_only(certificate.tbs_certificate_bytes, SEQUENCE)))
    assert tbs[0][0] == 0xA0, "explicit version"
    tag, serial = tbs[1]
    assert tag == INTEGER
    assert 1 <= len(serial) <= 20 and serial[0] < 0x80, serial.hex()
    assert certificate.serial_number > 0

    now = datetime.datetime.now(datetime.timezone.utc)
    assert certificate.not_valid_before_utc <= now < certificate.not_valid_after_utc

    # ECDSA P-256 with SHA-256, self-signed.
    assert certificate.signature_algorithm_oid == SignatureAlgorithmOID.ECDSA_WITH_SHA256
    public_key = certificate.public_key()
    assert isinstance(public_key, ec.EllipticCurvePublicKey)
    assert isinstance(public_key.curve, ec.SECP256R1)
    certificate.verify_directly_issued_by(certificate)
    return certificate


@pytest.mark.parametrize(
    "alg",
    [
        pytest.param(client.ES256, id="ES256"),
        pytest.param(client.ML_DSA_44, id="ML-DSA-44"),
        pytest.param(client.ML_DSA_65, id="ML-DSA-65"),
        pytest.param(client.ML_DSA_87, id="ML-DSA-87"),
    ],
)
def test_packed_attestation_certificate(ctap: Ctap2, alg):
    client_data_hash = os.urandom(32)
    response = client.make_credential(ctap, RP_ID, client.user_entity("alice"), [alg], client_data_hash)
    auth_data = client.AuthData.parse(response[2])
    auth_data.check(RP_ID, up=True, uv=False, at=True)

    # Basic attestation: even the largest response, ML-DSA-87, has room for
    # the certificate, so the authenticator does not fall back to self
    # attestation.
    assert response[1] == "packed"
    att_stmt = response[3]
    assert "x5c" in att_stmt, "self attestation instead of basic attestation"
    assert len(att_stmt["x5c"]) == 1

    # The signature, with the certificate's key.
    client.verify_attestation(response, auth_data.public_key, client_data_hash)
    check_attestation_certificate(att_stmt["x5c"][0], auth_data.aaguid)
    assert auth_data.aaguid == client.DEFAULT_AAGUID
