"""CTAP2 client helpers for the end-to-end tests.

python-fido2 is used only as a transport (CTAPHID framing, canonical CBOR) and
for the PIN/UV auth protocols. Requests are built here so the tests control
every parameter, and responses are taken apart here, without python-fido2's
response classes, so the checks do not depend on what python-fido2 accepts.
Signatures are verified with pyca/cryptography.
"""

from __future__ import annotations

import hashlib
import os
import select
import struct
from dataclasses import dataclass
from typing import Any, Mapping

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, mldsa
from fido2.ctap2 import Ctap2
from fido2.hid import CtapHidDevice
from fido2.hid.linux import LinuxCtapHidConnection, get_descriptor

# COSE algorithm identifiers.
ES256 = -7
ML_DSA_44 = -48
ML_DSA_65 = -49
ML_DSA_87 = -50

MLDSA_PUBLIC_KEYS = {
    ML_DSA_44: mldsa.MLDSA44PublicKey,
    ML_DSA_65: mldsa.MLDSA65PublicKey,
    ML_DSA_87: mldsa.MLDSA87PublicKey,
}
# FIPS 204, table 2.
MLDSA_PUBLIC_KEY_SIZES = {ML_DSA_44: 1312, ML_DSA_65: 1952, ML_DSA_87: 2592}
MLDSA_SIGNATURE_SIZES = {ML_DSA_44: 2420, ML_DSA_65: 3309, ML_DSA_87: 4627}

COSE_KTY_EC2 = 2
COSE_KTY_AKP = 7
COSE_CRV_P256 = 1

# The AAGUID pc-hid-runner uses unless --aaguid is given.
DEFAULT_AAGUID = bytes.fromhex("4645495449414E980616525A30310000")

FLAG_UP = 0x01
FLAG_UV = 0x04
FLAG_AT = 0x40
FLAG_ED = 0x80

# How long to wait for any single CTAPHID packet. Operations complete in
# milliseconds; this only turns a hung authenticator into a test failure.
READ_TIMEOUT_S = 15.0


class _TimeoutConnection(LinuxCtapHidConnection):
    """python-fido2's hidraw connection, with a timeout on every read."""

    def read_packet(self) -> bytes:
        ready, _, _ = select.select([self.handle], [], [], READ_TIMEOUT_S)
        if not ready:
            raise TimeoutError(f"no CTAPHID packet within {READ_TIMEOUT_S}s")
        return super().read_packet()


def open_device(path: str) -> CtapHidDevice:
    """Open the hidraw node and allocate a CTAPHID channel (CTAPHID_INIT)."""
    descriptor = get_descriptor(path)
    return CtapHidDevice(descriptor, _TimeoutConnection(descriptor))


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def user_entity(name: str) -> dict[str, Any]:
    return {"id": os.urandom(16), "name": name, "displayName": name.title()}


@dataclass
class AuthData:
    """authenticatorData, parsed by hand (WebAuthn Level 3, 6.1)."""

    raw: bytes
    rp_id_hash: bytes
    flags: int
    sign_count: int
    aaguid: bytes | None = None
    credential_id: bytes | None = None
    public_key: dict | None = None
    extensions: dict | None = None

    @classmethod
    def parse(cls, raw: bytes) -> "AuthData":
        from fido2 import cbor

        if len(raw) < 37:
            raise ValueError(f"authData is only {len(raw)} bytes")
        rp_id_hash, flags, sign_count = raw[:32], raw[32], struct.unpack(">I", raw[33:37])[0]
        parsed = cls(raw, rp_id_hash, flags, sign_count)
        rest = raw[37:]
        if flags & FLAG_AT:
            if len(rest) < 18:
                raise ValueError("attested credential data is truncated")
            parsed.aaguid = rest[:16]
            (id_len,) = struct.unpack(">H", rest[16:18])
            parsed.credential_id = rest[18 : 18 + id_len]
            if len(parsed.credential_id) != id_len:
                raise ValueError("credential ID is truncated")
            parsed.public_key, rest = cbor.decode_from(rest[18 + id_len :])
        if flags & FLAG_ED:
            parsed.extensions, rest = cbor.decode_from(rest)
        if rest:
            raise ValueError(f"{len(rest)} unexpected trailing bytes in authData")
        return parsed

    def check(self, rp_id: str, *, up: bool, uv: bool, at: bool) -> None:
        assert self.rp_id_hash == sha256(rp_id.encode()), "RP ID hash mismatch"
        assert bool(self.flags & FLAG_UP) == up, f"UP flag wrong in flags {self.flags:#04x}"
        assert bool(self.flags & FLAG_UV) == uv, f"UV flag wrong in flags {self.flags:#04x}"
        assert bool(self.flags & FLAG_AT) == at, f"AT flag wrong in flags {self.flags:#04x}"
        assert not self.flags & 0x3A, f"reserved or backup flags set in {self.flags:#04x}"


def check_public_key(cose_key: Mapping[int, Any], alg: int) -> None:
    """Check the COSE_Key structure for an ES256 or ML-DSA (RFC 9964) key."""
    assert cose_key.get(3) == alg, f"COSE alg {cose_key.get(3)} != {alg}"
    if alg == ES256:
        assert cose_key.get(1) == COSE_KTY_EC2
        assert cose_key.get(-1) == COSE_CRV_P256
        assert len(cose_key.get(-2, b"")) == 32 and len(cose_key.get(-3, b"")) == 32
        assert set(cose_key) == {1, 3, -1, -2, -3}, f"unexpected labels {set(cose_key)}"
    else:
        assert cose_key.get(1) == COSE_KTY_AKP
        assert len(cose_key.get(-1, b"")) == MLDSA_PUBLIC_KEY_SIZES[alg]
        assert set(cose_key) == {1, 3, -1}, f"unexpected labels {set(cose_key)}"


def verify_signature(cose_key: Mapping[int, Any], message: bytes, signature: bytes) -> None:
    """Verify with pyca/cryptography; raises InvalidSignature on failure.

    ES256 is ECDSA P-256/SHA-256 with a DER signature. ML-DSA is pure ML-DSA
    (FIPS 204 ML-DSA.Verify) with an empty context, verified by the OpenSSL
    implementation in cryptography's wheels, not by the fips204 crate the
    authenticator signs with.
    """
    alg = cose_key[3]
    if alg == ES256:
        x = int.from_bytes(cose_key[-2], "big")
        y = int.from_bytes(cose_key[-3], "big")
        key = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
        key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
    elif alg in MLDSA_PUBLIC_KEYS:
        if len(signature) != MLDSA_SIGNATURE_SIZES[alg]:
            raise InvalidSignature(f"ML-DSA signature is {len(signature)} bytes")
        MLDSA_PUBLIC_KEYS[alg].from_public_bytes(cose_key[-1]).verify(signature, message)
    else:
        raise ValueError(f"unsupported COSE algorithm {alg}")


def verify_attestation(response: Mapping[int, Any], cose_key: Mapping[int, Any], client_data_hash: bytes) -> None:
    """Verify a packed or none attestation statement's signature."""
    fmt, auth_data, att_stmt = response[1], response[2], response[3]
    signed = auth_data + client_data_hash
    if fmt == "none":
        assert att_stmt == {}
    elif fmt == "packed":
        if "x5c" in att_stmt:
            assert att_stmt["alg"] == ES256, f"attestation alg {att_stmt['alg']}"
            certificate = x509.load_der_x509_certificate(att_stmt["x5c"][0])
            public_key = certificate.public_key()
            assert isinstance(public_key, ec.EllipticCurvePublicKey)
            public_key.verify(att_stmt["sig"], signed, ec.ECDSA(hashes.SHA256()))
        else:
            assert att_stmt["alg"] == cose_key[3]
            verify_signature(cose_key, signed, att_stmt["sig"])
    else:
        raise AssertionError(f"unexpected attestation format {fmt!r}")


def make_credential(
    ctap: Ctap2,
    rp_id: str,
    user: Mapping[str, Any],
    algs: list[int],
    client_data_hash: bytes,
    *,
    options: Mapping[str, bool] | None = None,
    pin_uv_param: bytes | None = None,
    pin_uv_protocol: int | None = None,
) -> Mapping[int, Any]:
    request: dict[int, Any] = {
        1: client_data_hash,
        2: {"id": rp_id, "name": rp_id},
        3: dict(user),
        4: [{"type": "public-key", "alg": alg} for alg in algs],
    }
    if options:
        request[7] = dict(options)
    if pin_uv_param is not None:
        request[8] = pin_uv_param
        request[9] = pin_uv_protocol
    return ctap.send_cbor(Ctap2.CMD.MAKE_CREDENTIAL, request)


def get_assertion(
    ctap: Ctap2,
    rp_id: str,
    client_data_hash: bytes,
    allow_ids: list[bytes] | None = None,
    *,
    pin_uv_param: bytes | None = None,
    pin_uv_protocol: int | None = None,
) -> Mapping[int, Any]:
    request: dict[int, Any] = {1: rp_id, 2: client_data_hash}
    if allow_ids is not None:
        request[3] = [{"type": "public-key", "id": cred_id} for cred_id in allow_ids]
    if pin_uv_param is not None:
        request[6] = pin_uv_param
        request[7] = pin_uv_protocol
    return ctap.send_cbor(Ctap2.CMD.GET_ASSERTION, request)


def get_next_assertion(ctap: Ctap2) -> Mapping[int, Any]:
    return ctap.send_cbor(Ctap2.CMD.GET_NEXT_ASSERTION)


@dataclass
class Credential:
    rp_id: str
    alg: int
    credential_id: bytes
    public_key: dict
    auth_data: AuthData


def register(ctap: Ctap2, rp_id: str, alg: int, *, uv: bool = False, **kwargs) -> Credential:
    """makeCredential, with every check that applies to any registration."""
    client_data_hash = os.urandom(32)
    user = kwargs.pop("user", None) or user_entity("alice")
    response = make_credential(ctap, rp_id, user, [alg], client_data_hash, **kwargs)
    auth_data = AuthData.parse(response[2])
    auth_data.check(rp_id, up=True, uv=uv, at=True)
    assert auth_data.aaguid == DEFAULT_AAGUID
    assert auth_data.credential_id, "empty credential ID"
    check_public_key(auth_data.public_key, alg)
    verify_attestation(response, auth_data.public_key, client_data_hash)
    return Credential(rp_id, alg, auth_data.credential_id, auth_data.public_key, auth_data)


def authenticate(
    ctap: Ctap2, credential: Credential, allow_list: bool = True, *, uv: bool = False, **kwargs
) -> tuple[Mapping[int, Any], AuthData]:
    """getAssertion for one credential, with its signature verified."""
    client_data_hash = os.urandom(32)
    allow_ids = [credential.credential_id] if allow_list else None
    response = get_assertion(ctap, credential.rp_id, client_data_hash, allow_ids, **kwargs)
    assert response[1] == {"type": "public-key", "id": credential.credential_id}
    auth_data = AuthData.parse(response[2])
    auth_data.check(credential.rp_id, up=True, uv=uv, at=False)
    verify_signature(credential.public_key, response[2] + client_data_hash, response[3])
    try:
        verify_signature(credential.public_key, response[2] + os.urandom(32), response[3])
    except InvalidSignature:
        pass
    else:
        raise AssertionError("the signature also verifies over a different client data hash")
    return response, auth_data
